"""Reverse loopback relay for one explicitly policy-bound execution."""
import stat
from urllib.parse import urlsplit

EGRESS_DIR = Path('/run/world-egress')


def egress_socket(token):
    if not re.fullmatch('[0-9a-f]{32}', token):
        raise ValueError('invalid egress execution ID')
    return EGRESS_DIR / (token + '.sock')


def execution_proxy(boot_id, token):
    if not offline_network_ready():
        raise ValueError('policy_unavailable: offline network is unverified')
    try:
        with socket.socket(socket.AF_UNIX) as control:
            control.settimeout(2)
            control.connect(os.fspath(egress_socket(token)))
            with control.makefile('rb') as response:
                record = json.loads(response.readline(1024))
        if record['boot_id'] != boot_id:
            raise ValueError('unexpected bridge boot')
        return record['url']
    except (OSError, ValueError, KeyError) as error:
        raise ValueError('policy_unavailable: guest egress bridge is not ready') from error


async def egress_bridge(boot_id, token):
    if not offline_network_ready():
        raise ValueError('policy_unavailable: offline network is unverified')
    path = egress_socket(token)
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=BRIDGE_LINE)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    transport, protocol = await loop.connect_write_pipe(
        lambda: asyncio.streams.FlowControlMixin(loop=loop), sys.stdout.buffer,
    )
    writer = asyncio.StreamWriter(transport, protocol, None, loop)
    output = asyncio.Lock()
    streams = {}
    tasks = set()
    next_id = 0
    heartbeat = loop.time()

    async def send(kind, stream=0, data=None):
        frame = {'kind': kind, 'id': stream}
        if data is not None:
            frame['data'] = data
        async with output:
            writer.write(json.dumps(frame).encode() + b'\n')
            await asyncio.wait_for(writer.drain(), 3)

    async def receive():
        nonlocal heartbeat
        while line := await reader.readline():
            if len(line) > BRIDGE_LINE:
                raise ValueError('egress bridge frame too large')
            frame = json.loads(line)
            stream, kind = frame['id'], frame['kind']
            if kind == 'shutdown' and stream == 0:
                return
            if kind == 'heartbeat' and stream == 0:
                heartbeat = loop.time()
            elif stream in streams:
                incoming, credit, task = streams[stream]
                if kind == 'ack':
                    if credit.is_set():
                        raise ValueError('unexpected egress stream credit')
                    credit.set()
                elif kind == 'reset':
                    task.cancel()
                elif kind in ('opened', 'data', 'fin'):
                    incoming.put_nowait(frame)
                else:
                    raise ValueError('invalid egress bridge frame')

    async def monitor():
        while True:
            await asyncio.sleep(1)
            if loop.time() - heartbeat > 4 or not offline_network_ready():
                raise RuntimeError('egress bridge heartbeat or offline network lost')
            await send('heartbeat')

    async def client(tcp_in, tcp):
        nonlocal next_id
        if len(streams) >= BRIDGE_LIMIT or loop.time() - heartbeat > 4:
            tcp.close()
            return
        next_id += 1
        stream = next_id
        incoming, credit = asyncio.Queue(2), asyncio.Event()
        credit.set()
        streams[stream] = incoming, credit, asyncio.current_task()
        try:
            await send('open', stream)
            first = await asyncio.wait_for(incoming.get(), 4)
            if first['kind'] != 'opened':
                raise ValueError('egress host refused stream')

            async def upload():
                while True:
                    await credit.wait()
                    credit.clear()
                    data = await tcp_in.read(BRIDGE_CHUNK)
                    if not data:
                        await send('fin', stream)
                        return
                    await send('data', stream, base64.b64encode(data).decode())

            async def download():
                while True:
                    frame = await incoming.get()
                    if frame['kind'] == 'fin':
                        tcp.write_eof()
                        return
                    if frame['kind'] != 'data':
                        raise ValueError('invalid egress stream response')
                    data = base64.b64decode(frame['data'], validate=True)
                    if not 0 < len(data) <= BRIDGE_CHUNK:
                        raise ValueError('invalid egress frame size')
                    tcp.write(data)
                    await tcp.drain()
                    await send('ack', stream)

            async with asyncio.TaskGroup() as transfers:
                transfers.create_task(upload())
                transfers.create_task(download())
        except Exception:
            await send('reset', stream)
        finally:
            streams.pop(stream)
            tcp.close()

    def accept(tcp_in, tcp):
        if len(tasks) >= BRIDGE_LIMIT:
            tcp.close()
            return
        task = asyncio.create_task(client(tcp_in, tcp))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    config = json.loads(await asyncio.wait_for(reader.readline(), 5))
    if config['kind'] != 'config' or config['id'] != 0:
        raise ValueError('invalid egress configuration')
    origin = urlsplit(config['data'])
    if (origin.scheme, origin.hostname, origin.username) != ('http', '127.0.0.1', 'world'):
        raise ValueError('invalid egress host proxy')
    if not re.fullmatch('[0-9a-f]{64}', origin.password or ''):
        raise ValueError('invalid egress credential')
    EGRESS_DIR.mkdir(mode=0o700, exist_ok=True)
    metadata = EGRESS_DIR.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != 0:
        raise ValueError('guest egress control directory must be root-owned and private')
    tcp_server = await asyncio.start_server(
        accept, host='127.0.0.1', port=0, limit=32768, backlog=BRIDGE_LIMIT,
    )
    port = tcp_server.sockets[0].getsockname()[1]
    proxy_url = f'http://world:{origin.password}@127.0.0.1:{port}'

    async def ready(_, local):
        try:
            if loop.time() - heartbeat < 4 and offline_network_ready():
                local.write(json.dumps({'url': proxy_url, 'boot_id': boot_id}).encode() + b'\n')
                await local.drain()
        finally:
            local.close()

    control = None
    workers = []
    try:
        control = await asyncio.start_unix_server(ready, path=path)
        await send('hello', data=boot_id)
        workers = [asyncio.create_task(receive()), asyncio.create_task(monitor())]
        done, _ = await asyncio.wait(workers, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        tcp_server.close()
        if control is not None:
            control.close()
            path.unlink(missing_ok=True)
        cleanup = workers + list(tasks)
        for task in cleanup:
            task.cancel()
        await asyncio.gather(*cleanup, return_exceptions=True)
        writer.close()
        await tcp_server.wait_closed()
        if control is not None:
            await control.wait_closed()
