"""Read one real forkfs branch file from a guest-only FUSE mount.

This is a transport proof with one fixed read-only inode. It does not provide
a general filesystem client or expose the forkfs daemon socket to the guest.
"""

import argparse
import base64
import concurrent.futures
import errno
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import threading
import uuid

from virtiofs_branch_probe import IMAGE

GUEST = r"""
import base64, ctypes, errno, json, os, select, stat, struct, sys
from pathlib import Path

PATH = b'/workspace'
NAME = b'proof.txt'
libc = ctypes.CDLL(None, use_errno=True)
fd = os.open('/dev/fuse', os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK)

def reply(unique, data=b'', error=0):
    message = struct.pack('<IiQ', 16 + len(data), -error, unique) + data
    assert os.write(fd, message) == len(message)

class BackingUnavailable(Exception):
    pass

def file_bytes():
    print('read', flush=True)
    if not select.select([sys.stdin], [], [], 5)[0]:
        raise BackingUnavailable()
    line = sys.stdin.readline(8192)
    if not line.endswith('\n'):
        raise BackingUnavailable()
    result = json.loads(line)
    if 'data' not in result:
        raise BackingUnavailable()
    return base64.b64decode(result['data'], validate=True)


def attributes(inode):
    if inode == 1:
        size, mode, links = 0, stat.S_IFDIR | 0o555, 2
    else:
        size, mode, links = len(file_bytes()), stat.S_IFREG | 0o444, 1
    # Protocol 7.8 uses the 80-byte compatibility attribute layout.
    return struct.pack('<6Q8I', inode, size, 0, 0, 0, 0,
                       0, 0, 0, mode, links, 1000, 1000, 0)

mounted = False
try:
    Path('/workspace').mkdir(mode=0o755, exist_ok=True)
    options = f'fd={fd},rootmode=40000,user_id=0,group_id=0,allow_other,default_permissions'
    if libc.mount(b'world-forkfs-probe', PATH, b'fuse', 1, options.encode()) != 0:
        raise OSError(ctypes.get_errno(), 'mount FUSE')
    mounted = True
    while True:
        if not select.select([fd], [], [], 15)[0]:
            raise TimeoutError('guest FUSE request deadline')
        try:
            packet = os.read(fd, 8192)
        except OSError as exc:
            if exc.errno == errno.ENODEV:
                mounted = False
                break
            raise
        length, operation, unique, inode = struct.unpack_from('<IIQQ', packet)
        assert length == len(packet)
        try:
            if operation == 26:  # INIT
                reply(unique, struct.pack('<IIIIHHI', 7, 8, 0, 0, 0, 0, 4096))
                print('ready', flush=True)
            elif operation == 1 and inode == 1 and packet[40:].rstrip(b'\0') == NAME:
                reply(unique, struct.pack('<QQQQII', 2, 1, 0, 0, 0, 0) + attributes(2))
            elif operation == 1:
                reply(unique, error=errno.ENOENT)
            elif operation == 3 and inode in (1, 2):  # GETATTR
                reply(unique, struct.pack('<QII', 0, 0, 0) + attributes(inode))
            elif operation == 14 and inode == 2:  # OPEN
                reply(unique, struct.pack('<QII', 1, 0, 0))
            elif operation == 15 and inode == 2:  # READ
                _, offset, size = struct.unpack_from('<QQI', packet, 40)
                reply(unique, file_bytes()[offset:offset + size])
            elif operation in (18, 25, 38):  # RELEASE, FLUSH, DESTROY
                reply(unique)
            elif operation != 2:  # FORGET has no response
                reply(unique, error=errno.ENOSYS)
        except BackingUnavailable:
            reply(unique, error=errno.EIO)
finally:
    if mounted:
        libc.umount2(PATH, 2)
    os.close(fd)
"""


def exact(channel, size):
    result = bytearray()
    while len(result) < size:
        part = channel.recv(size - len(result))
        if not part:
            raise RuntimeError('truncated forkfs RPC response')
        result.extend(part)
    return bytes(result)


class RpcError(RuntimeError):
    def __init__(self, operation, code, message):
        super().__init__(f'forkfs {operation} failed ({code}): {message}')
        self.code = code


def rpc(endpoint, *fields):
    encoded = [field.encode() if isinstance(field, str) else field for field in fields]
    payload = struct.pack('<I', len(encoded)) + b''.join(
        struct.pack('<I', len(field)) + field for field in encoded
    )
    assert len(payload) <= 1024 * 1024
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(5)
        channel.connect(str(endpoint))
        channel.sendall(b'FFRPC001' + struct.pack('<I', len(payload)) + payload)
        magic, size = struct.unpack('<8sI', exact(channel, 12))
        assert magic == b'FFRSP001' and 4 <= size <= 1024 * 1024
        body = exact(channel, size)
    code, = struct.unpack_from('<I', body)
    if code:
        raise RpcError(fields[0], code, body[4:].decode(errors='replace'))
    return body[4:]


def run(*args, timeout=25, check=True):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} {args[1]} failed: {result.stderr.decode(errors="replace")}')
    return result.stdout


def mount_and_read(endpoint, branch, expected, evidence, *, stop_backing=None):
    name = f'world-forkfs-probe-{uuid.uuid4().hex[:12]}'
    run('container', 'create', '--name', name, '--cpus', '1', '--memory', '512M',
        '--cap-add', 'SYS_ADMIN', IMAGE, 'sleep', '150', timeout=90)
    session = None
    backing_stopped = False
    try:
        run('container', 'start', name, timeout=60)
        session = json.loads(rpc(endpoint, 'session-open', '60000'))['session']
        view = json.loads(rpc(endpoint, 'inode-root', '--world', branch, '--session', session))
        assert view['repository'] and view['inode']['directory']
        ready = threading.Event()
        reads = []
        with (evidence / f'{name}.stderr').open('wb') as errors:
            with subprocess.Popen(
                ['container', 'exec', '-i', name, 'python3', '-u', '-c', GUEST],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
            ) as bridge, concurrent.futures.ThreadPoolExecutor(1) as worker:
                def serve():
                    for message in bridge.stdout:
                        if message == b'ready\n':
                            ready.set()
                            continue
                        if message != b'read\n':
                            raise ValueError('unexpected guest probe request')
                        try:
                            data = rpc(endpoint, 'fs-cat', '/proof.txt', '--world', branch, '--session', session)
                            assert len(data) <= 4096
                            reads.append(len(data))
                            response = {'data': base64.b64encode(data).decode()}
                        except (OSError, RuntimeError):
                            response = {'error': 'forkfs backing is unavailable'}
                        bridge.stdin.write(json.dumps(response).encode() + b'\n')
                        bridge.stdin.flush()

                future = worker.submit(serve)
                try:
                    if not ready.wait(timeout=6):
                        if future.done():
                            future.result()
                        raise TimeoutError('guest FUSE frontend did not become ready')
                    try:
                        rpc(endpoint, 'fs-write', '/proof.txt', b'foreign write', '--world', branch)
                    except RpcError as error:
                        assert error.code == errno.EBUSY + 1, error
                    else:
                        raise AssertionError('forkfs mount lease did not reject a competing write')
                    observed = run('container', 'exec', '--user', '1000:1000', name,
                                   'python3', '-c',
                                   'from pathlib import Path; import os,sys; '
                                   'assert os.getuid() == 1000; '
                                   'caps = next(line for line in Path("/proc/self/status").read_text().splitlines() '
                                   'if line.startswith("CapEff:")); '
                                   'assert int(caps.split()[1], 16) & (1 << 21) == 0; '
                                   'sys.stdout.buffer.write(Path("/workspace/proof.txt").read_bytes())')
                    assert observed == expected and reads, (branch, observed, reads)
                    run('container', 'exec', '--user', '1000:1000', name, 'python3', '-c',
                        'import errno,os\n'
                        'try: os.open("/workspace/proof.txt", os.O_WRONLY)\n'
                        'except OSError as error: assert error.errno in (errno.EROFS, errno.EACCES)\n'
                        'else: raise AssertionError("FUSE projection accepted write")')
                    if stop_backing is not None:
                        stop_backing()
                        backing_stopped = True
                        run('container', 'exec', '--user', '1000:1000', name, 'python3', '-c',
                            'import errno,os\n'
                            'try: os.open("/workspace/proof.txt", os.O_RDONLY)\n'
                            'except OSError as error: assert error.errno == errno.EIO\n'
                            'else: raise AssertionError("FUSE opened a file after forkfs disconnected")')
                    run('container', 'exec', name, 'umount', '/workspace')
                    assert bridge.wait(timeout=5) == 0
                    future.result(timeout=5)
                finally:
                    if bridge.poll() is None:
                        bridge.kill()
                        bridge.wait(timeout=5)
        return {'branch': branch, 'guest_bytes': len(observed), 'rpc_reads': len(reads),
                'uid': 1000, 'readonly': True, 'foreign_write_blocked': True,
                'backing_loss_returns_eio': backing_stopped}
    finally:
        run('container', 'stop', '--time', '1', name, check=False)
        run('container', 'delete', name)
        if session is not None and not backing_stopped:
            rpc(endpoint, 'session-close', session)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('forkfsd', type=Path)
    args = parser.parse_args()
    forkfsd = str(args.forkfsd.resolve(strict=True))
    assert json.loads(run('container', 'list', '--format', 'json')) == []
    evidence = Path(tempfile.mkdtemp(prefix='world-forkfs-guest-', dir='/tmp'))
    print(f'Evidence: {evidence}', flush=True)
    store = evidence / 'store'
    endpoint = evidence / 'rpc.sock'
    run(forkfsd, 'init', str(store))
    outcomes = []
    with subprocess.Popen([forkfsd, 'serve', str(store), '--socket', str(endpoint), '--rpc'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as daemon:
        try:
            assert select.select([daemon.stdout], [], [], 5)[0], 'forkfsd startup timeout'
            assert json.loads(daemon.stdout.readline())['state'] == 'leveldb'
            rpc(endpoint, 'fs-init')
            rpc(endpoint, 'fs-write', '/proof.txt', b'base\x00')
            rpc(endpoint, 'fs-snapshot', 'base')
            for branch in ('branch-a', 'branch-b'):
                rpc(endpoint, 'fs-fork', 'base', branch)
            rpc(endpoint, 'fs-write', '/proof.txt', b'changed in forkfs\x00', '--world', 'branch-a')
            def stop_backing():
                daemon.terminate()
                daemon.wait(timeout=10)

            cases = [('branch-a', b'changed in forkfs\x00'),
                     ('branch-b', b'base\x00'),
                     ('branch-a', b'changed in forkfs\x00')]
            for index, (branch, expected) in enumerate(cases):
                stop = stop_backing if index == len(cases) - 1 else None
                outcome = mount_and_read(endpoint, branch, expected, evidence, stop_backing=stop)
                if stop is None:
                    rpc(endpoint, 'fs-write', '/after-unmount', b'lease released', '--world', branch)
                    outcome['write_after_unmount'] = True
                outcomes.append(outcome)
                (evidence / 'results.json').write_text(json.dumps(outcomes, indent=2) + '\n')
                print(json.dumps(outcome), flush=True)
        finally:
            daemon.terminate()
            _, errors = daemon.communicate(timeout=10)
            (evidence / 'daemon.stderr').write_bytes(errors)
    print('forkfs guest read-only mount probe PASS', flush=True)


if __name__ == '__main__':
    main()
