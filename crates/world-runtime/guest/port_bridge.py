"""Bounded multiplexed TCP bridge. The only target is its authorized loopback port."""
import asyncio

BRIDGE_CHUNK = 8192
BRIDGE_LIMIT = 8
BRIDGE_LINE = 12000


async def bridge(boot_id, name, run_id, port):
    reader = asyncio.StreamReader(limit=BRIDGE_LINE)
    loop = asyncio.get_running_loop()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    transport, protocol = await loop.connect_write_pipe(
        lambda: asyncio.streams.FlowControlMixin(loop=loop), sys.stdout.buffer,
    )
    writer = asyncio.StreamWriter(transport, protocol, None, loop)
    streams = {}
    output_lock = asyncio.Lock()

    async def send(kind, stream=0, data=None):
        frame = {'kind': kind, 'id': stream}
        if data is not None:
            frame['data'] = data
        async with output_lock:
            writer.write(json.dumps(frame).encode() + b'\n')
            await writer.drain()

    async def authorized():
        request = {'action': 'show', 'name': name, 'boot_id': boot_id}
        result = await asyncio.to_thread(service_query, request)
        if result['state'] != 'running' or result['run_id'] != run_id:
            raise RuntimeError('published service run ended')

    async def monitor():
        while True:
            await asyncio.sleep(1)
            await authorized()
            await send('heartbeat')

    async def serve(stream, incoming, credit):
        tcp = None
        try:
            await authorized()
            tcp_in, tcp = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), 5)
            await send('opened', stream)

            async def upload():
                while True:
                    kind, data = await incoming.get()
                    if kind == 'fin':
                        tcp.write_eof()
                        return
                    tcp.write(data)
                    await tcp.drain()
                    await send('ack', stream)

            async def download():
                while True:
                    await credit.wait()
                    credit.clear()
                    data = await tcp_in.read(BRIDGE_CHUNK)
                    if not data:
                        await send('fin', stream)
                        return
                    await send('data', stream, base64.b64encode(data).decode())

            async with asyncio.TaskGroup() as tasks:
                tasks.create_task(upload())
                tasks.create_task(download())
        except (Exception, asyncio.CancelledError):
            # Reset also works if the host has already retired this ID.
            if not asyncio.current_task().cancelling():
                await send('reset', stream)
        finally:
            streams.pop(stream, None)
            if tcp is not None:
                tcp.close()

    async def receive():
        while line := await reader.readline():
            if len(line) > BRIDGE_LINE:
                raise ValueError('bridge frame too large')
            frame = json.loads(line)
            stream = frame['id']
            kind = frame['kind']
            if kind == 'open':
                if stream in streams or len(streams) >= BRIDGE_LIMIT:
                    await send('reset', stream)
                    continue
                incoming, credit = asyncio.Queue(2), asyncio.Event()
                credit.set()
                task = asyncio.create_task(serve(stream, incoming, credit))
                streams[stream] = incoming, credit, task
            elif stream in streams:
                incoming, credit, task = streams[stream]
                if kind == 'data':
                    data = base64.b64decode(frame['data'], validate=True)
                    if not 0 < len(data) <= BRIDGE_CHUNK:
                        raise ValueError('invalid bridge chunk')
                    incoming.put_nowait((kind, data))
                elif kind == 'fin':
                    incoming.put_nowait((kind, None))
                elif kind == 'ack':
                    credit.set()
                elif kind == 'reset':
                    streams.pop(stream)
                    task.cancel()
                else:
                    raise ValueError('invalid bridge frame')
        raise EOFError('host bridge disconnected')

    await authorized()
    await send('hello')
    try:
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(receive())
            tasks.create_task(monitor())
    finally:
        pending = [task for _, _, task in streams.values()]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        writer.close()
