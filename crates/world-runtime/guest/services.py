"""Service supervision for the single-VM development preview."""
import fcntl
import hashlib
import socket

SERVICE_DIR = Path('/var/lib/world/runtime/services')
SERVICE_SOCKET = Path('/run/world/services.sock')
SERVICE_GROUP = CGROUP / 'world-services'
SERVICE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')
MAX_SERVICES = 8
MAX_OPERATIONS = 256
OPERATION_TTL = 24 * 60 * 60
OPERATION_ID = re.compile(r"([0-9]{1,12})-[0-9a-f]{32}")
WRITES = ("start", "stop", "restart", "remove")
LOG_LIMIT = 1024 * 1024
MESSAGE_LIMIT = 128 * 1024


def service_client(boot_id, args):
    payload = json.loads(args[0])
    payload['boot_id'] = boot_id
    request = json.dumps(payload).encode() + b'\n'
    if len(request) > MESSAGE_LIMIT:
        raise ValueError('service request exceeds size limit')
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect(str(SERVICE_SOCKET))
        client.sendall(request)
        response = client.makefile('rb').readline(2 * LOG_LIMIT)
    if not response.endswith(b'\n'):
        raise RuntimeError('service outcome unknown; supervisor response incomplete')
    result = json.loads(response)
    if 'error' in result:
        raise RuntimeError(result['error'])
    print(json.dumps(result['result']))


def service_daemon(boot_id):
    SERVICE_SOCKET.parent.mkdir(mode=0o700, exist_ok=True)
    SERVICE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    SERVICE_GROUP.mkdir(exist_ok=True)
    with (SERVICE_SOCKET.parent / 'services.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return  # Another supervisor owns this boot.
        # A dead supervisor cannot adopt old processes. Clean only its own subtree.
        for group in SERVICE_GROUP.iterdir():
            if group.is_dir():
                clear_service_group(group)
        SERVICE_SOCKET.unlink(missing_ok=True)
        supervisor = Services(boot_id)
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(SERVICE_SOCKET))
            server.listen(8)
            server.settimeout(0.05)
            while True:
                supervisor.poll()
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                with conn:
                    conn.settimeout(1)
                    try:
                        raw = conn.makefile('rb').readline(MESSAGE_LIMIT + 1)
                        if len(raw) > MESSAGE_LIMIT or not raw.endswith(b'\n'):
                            raise ValueError('invalid service request')
                        result = {'result': supervisor.dispatch(json.loads(raw))}
                    except Exception as error:
                        result = {'error': str(error)}
                    try:
                        conn.sendall(json.dumps(result).encode() + b'\n')
                    except OSError:
                        pass  # Lost response does not undo or repeat the operation.


def clear_service_group(group):
    (group / 'cgroup.kill').write_text('1')
    for _ in range(100):
        if 'populated 0' in (group / 'cgroup.events').read_text():
            group.rmdir()
            return
        time.sleep(0.01)
    raise RuntimeError('service cgroup is still populated')


class Services:
    def __init__(self, boot_id):
        self.boot_id = boot_id
        self.live = {}
        self.draining = False
        self.catalog_retry_at = None
        self.journal = SERVICE_DIR / 'operations.json'
        self.operations = json.loads(self.journal.read_text()) if self.journal.exists() else {}
        self.catalog = SERVICE_DIR / 'catalog.json'
        self.records = json.loads(self.catalog.read_text()) if self.catalog.exists() else {}
        for record in self.records.values():
            if record['state'] in ('starting', 'running'):
                record['state'] = 'interrupted'
        self.persist()
        current_runs = {record['run_id'] for record in self.records.values()}
        for path in SERVICE_DIR.iterdir():
            match = re.fullmatch(r'([0-9a-f]{32})\.(stdout|stderr)(\.old)?', path.name)
            if match and match[1] not in current_runs:
                path.unlink()

    def persist(self):
        try:
            write(self.catalog, self.records)
        except OSError:
            self.catalog_retry_at = time.monotonic() + 1
            raise
        self.catalog_retry_at = None

    def log_path(self, record, stream):
        return SERVICE_DIR / f'{record["run_id"]}.{stream}'

    def public(self, record):
        result = {key: value for key, value in record.items() if key != 'argv'}
        if self.catalog_retry_at is not None:
            result['catalog_persistence_pending'] = True
        return result

    def drain(self, record, child):
        for stream in ('stdout', 'stderr'):
            pipe = getattr(child, stream)
            if pipe.closed:
                continue
            try:
                data = os.read(pipe.fileno(), 65536)
            except BlockingIOError:
                continue
            if not data:
                pipe.close()
                continue
            path = self.log_path(record, stream)
            try:
                # Keep two bounded segments per stream. Binary bytes are preserved.
                if path.exists() and path.stat().st_size + len(data) > LOG_LIMIT:
                    path.replace(path.with_suffix(f'.{stream}.old'))
                    record['logs_truncated'] = True
                with path.open('ab') as log:
                    log.write(data)
            except OSError:
                record['logs_truncated'] = True

    def finish(self, name, stopped=False, defer_catalog_error=False):
        child, group = self.live[name]
        record = self.records[name]
        clear_service_group(group)
        code = child.wait(timeout=2)
        for _ in range(32):
            if child.stdout.closed and child.stderr.closed:
                break
            self.drain(record, child)
        for pipe in (child.stdout, child.stderr):
            if not pipe.closed:
                pipe.close()
                record['logs_truncated'] = True
        record.update(state='stopped' if stopped else 'exited', exit_code=code)
        del self.live[name]
        try:
            self.persist()
        except OSError:
            if not defer_catalog_error:
                raise
        return self.public(record)

    def poll(self):
        for name, (child, _) in list(self.live.items()):
            self.drain(self.records[name], child)
            if child.poll() is not None:
                self.finish(name, defer_catalog_error=True)
        if self.catalog_retry_at is not None and time.monotonic() >= self.catalog_retry_at:
            try:
                self.persist()
            except OSError:
                pass  # The live state remains available while the disk is unavailable.

    def start(self, name, argv):
        if not argv or not all(isinstance(arg, str) and '\0' not in arg for arg in argv):
            raise ValueError('invalid service argv')
        previous = self.records.get(name)
        if previous:
            if previous['argv'] != argv:
                raise ValueError('service configuration differs; remove the definition first')
            if name in self.live:
                return self.public(previous)
        elif len(self.records) >= MAX_SERVICES:
            raise ValueError('service definition limit reached')
        run_id = os.urandom(16).hex()
        record = dict(name=name, argv=argv, boot_id=self.boot_id, run_id=run_id,
                      state='starting', logs_truncated=False)
        self.records[name] = record
        self.persist()
        if previous:
            self.remove_logs(previous)
        group = SERVICE_GROUP / run_id
        try:
            group.mkdir()
            child = spawn_workload(argv, group, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as error:
            if group.exists():
                clear_service_group(group)
            record.update(state='failed', error=str(error))
            self.persist()
            raise
        self.live[name] = child, group
        for pipe in (child.stdout, child.stderr):
            os.set_blocking(pipe.fileno(), False)
        record['state'] = 'running'
        self.persist()
        return self.public(record)

    def remove_logs(self, record):
        for stream in ('stdout', 'stderr'):
            path = self.log_path(record, stream)
            path.unlink(missing_ok=True)
            path.with_suffix(f'.{stream}.old').unlink(missing_ok=True)

    def operation(self, req):
        operation_id = req.get('operation_id')
        match = OPERATION_ID.fullmatch(operation_id or '')
        if not match:
            raise ValueError('invalid service operation ID')
        issued_at = int(match[1])
        now = int(time.time())
        if issued_at < now - OPERATION_TTL or issued_at > now + 60:
            raise ValueError('service operation ID expired or clock is out of sync')
        previous = self.operations.get(operation_id)
        if req['action'] == 'operation':
            if previous is None:
                raise ValueError('unknown service operation')
            return self.operation_result(operation_id, previous)
        digest = hashlib.sha256(json.dumps(
            {key: value for key, value in req.items() if key != 'boot_id'},
            sort_keys=True,
        ).encode()).hexdigest()
        if previous is not None:
            if previous['digest'] != digest:
                raise ValueError('service operation ID is already used for a different request')
            if previous['state'] == 'completed':
                return previous['result']
            if previous['state'] == 'failed':
                raise ValueError(previous['error'])
            raise ValueError('service operation outcome unknown; inspect the service before proceeding')
        if self.draining:
            raise ValueError('workspace is draining')
        self.operations = {
            key: value for key, value in self.operations.items()
            if value['issued_at'] >= now - OPERATION_TTL
        }
        if len(self.operations) >= MAX_OPERATIONS:
            raise ValueError('service operation journal is full')
        entry = dict(state='pending', digest=digest, boot_id=self.boot_id, issued_at=issued_at)
        self.operations[operation_id] = entry
        try:
            write(self.journal, self.operations)
        except Exception:
            del self.operations[operation_id]
            raise
        try:
            result = self.dispatch_action(req)
        except ValueError as error:
            entry.update(state='failed', error=str(error))
            write(self.journal, self.operations)
            raise
        result['operation_id'] = operation_id
        result.setdefault('boot_id', self.boot_id)
        entry.update(state='completed', result=result)
        write(self.journal, self.operations)
        return result

    @staticmethod
    def operation_result(operation_id, entry):
        return {
            'operation_id': operation_id,
            **{key: value for key, value in entry.items() if key != 'digest'},
            'state': 'unknown' if entry['state'] == 'pending' else entry['state'],
        }

    def dispatch(self, req):
        if req.get('boot_id') != self.boot_id:
            raise ValueError('VM boot changed; run workspace setup first')
        if req['action'] in (*WRITES, 'operation'):
            return self.operation(req)
        return self.dispatch_action(req)

    def dispatch_action(self, req):
        action = req['action']
        if action == 'list':
            return [self.public(record) for record in self.records.values()]
        if action == 'activate':
            self.draining = False
            return {'state': 'active'}
        if action == 'drain':
            self.draining = True
            for name in list(self.live):
                self.finish(name, stopped=True)
            return {'state': 'drained'}
        name = req['name']
        if not SERVICE_NAME.fullmatch(name):
            raise ValueError('invalid service name')
        if action == 'start':
            return self.start(name, req['argv'])
        record = self.records.get(name)
        if record is None:
            raise ValueError('unknown service')
        if action == 'show':
            return self.public(record)
        if action in ('stop', 'restart'):
            if name in self.live:
                self.finish(name, stopped=True)
            if action == 'restart':
                return self.start(name, record['argv'])
            return self.public(record)
        if action == 'remove':
            if name in self.live:
                raise ValueError('stop the service before removing it')
            self.remove_logs(record)
            del self.records[name]
            self.persist()
            return {'name': name, 'state': 'removed'}
        if action == 'logs':
            stream = req.get('stream', 'stdout')
            if stream not in ('stdout', 'stderr'):
                raise ValueError('invalid log stream')
            path = self.log_path(record, stream)
            data = bytearray()
            total_size = 0
            for part in (path.with_suffix(f'.{stream}.old'), path):
                if part.exists():
                    with part.open('rb') as log:
                        size = os.fstat(log.fileno()).st_size
                        total_size += size
                        log.seek(max(0, size - 65536))
                        data.extend(log.read(65536))
            return {'run_id': record['run_id'], 'stream': stream,
                    'truncated': record['logs_truncated'] or total_size > 65536,
                    'base64': base64.b64encode(data[-65536:]).decode()}
        raise ValueError('unsupported service action')


if __name__ == '__main__':
    sys.exit(main())
