"""Exercise a writable forkfs branch from a disposable Apple container VM."""

import argparse
import base64
import concurrent.futures
import errno
import json
from pathlib import Path
import select
import subprocess
import tempfile
import threading
import uuid

from forkfs_guest_mount_probe import RpcError, rpc, run
from forkfs_writable_guest import FRAME_SIZE, IO_SIZE
from virtiofs_branch_probe import IMAGE

OPERATIONS = {
    'inode-stat': 1, 'inode-lookup': 2, 'inode-open': 2, 'inode-create': 3,
    'inode-mkdir': 3, 'inode-remove': 4, 'inode-rename': 6,
    'inode-setattr-times': 7, 'inode-sync': 0, 'inode-symlink': 3, 'inode-readlink': 1,
    'fs-hread': 3, 'fs-hwrite': 2, 'fs-hstat': 1, 'fs-close': 1,
    'inode-dir-open': 1, 'fs-dir-entries': 2, 'fs-dir-close': 1,
}

WORKER = r"""
import os, stat, sys
from pathlib import Path

assert os.getuid() == 1000
caps = next(line for line in Path('/proc/self/status').read_text().splitlines()
            if line.startswith('CapEff:'))
assert int(caps.split()[1], 16) & (1 << 21) == 0
os.chdir('/workspace')
case = sys.argv[1]
baseline = Path('base.txt')
expected = b'branch A source\x00' if case == 'rebuild' else b'common baseline\x00'
assert baseline.read_bytes() == expected
source = Path('tree')
file = source / 'résumé.bin'
payload = bytes(range(256)) * 64
if case == 'write':
    baseline.write_bytes(b'branch A source\x00')
    source.mkdir()
    with (source / 'tmp').open('xb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    (source / 'tmp').rename(file)
    assert file.read_bytes() == payload
    with file.open('r+b') as stream:
        stream.seek(4095)
        stream.write(b'\xff\x00')
        stream.truncate(10001)
    file.chmod(0o751)
    (source / 'README').write_text('upper')
    (source / 'readme').write_text('lower')
    (source / 'alias').symlink_to(file.name)
    source.joinpath('obsolete').mkdir()
    (source / 'obsolete').rmdir()
    source.joinpath('scratch').write_text('remove me')
    (source / 'scratch').unlink()
if case in ('write', 'rebuild'):
    assert set(os.listdir(source)) == {'résumé.bin', 'README', 'readme', 'alias'}
    assert file.read_bytes() == payload[:4095] + b'\xff\x00' + payload[4097:10001]
    assert (source / 'alias').read_bytes() == file.read_bytes()
    assert stat.S_IMODE(file.stat().st_mode) == 0o751
    assert baseline.read_bytes() == b'branch A source\x00'
    assert not Path('sibling.txt').exists()
elif case == 'sibling':
    assert set(os.listdir('.')) == {'base.txt'}
    baseline.write_bytes(b'branch B source\x00')
    Path('sibling.txt').write_text('only in branch B')
"""

LOSS_WORKER = r"""
import errno, os

fd = os.open('/workspace/base.txt', os.O_RDONLY)
assert os.read(fd, 1) == b'b'
print('open', flush=True)
assert input() == 'stop'
for read in (lambda: os.pread(fd, 1, 0), lambda: os.open('/workspace/base.txt', os.O_RDONLY)):
    try:
        read()
    except OSError as error:
        assert error.errno == errno.EIO, error
    else:
        raise AssertionError('forkfs read succeeded after backing loss')
"""


def process_request(message, endpoint, branch, session, root):
    try:
        if not message.endswith(b'\n'):
            raise ValueError('incomplete request')
        request = json.loads(message)
        operation, args = request['op'], request['args']
        if not isinstance(args, list) or any(
            not isinstance(arg, str) or len(arg.encode()) > IO_SIZE or '\0' in arg for arg in args
        ):
            raise ValueError('invalid arguments')
        if operation == 'root' and not args and set(request) == {'op', 'args'}:
            return {'data': base64.b64encode(root).decode()}
        binary = operation == 'fs-hwrite'
        keys = {'op', 'args', 'data'} if binary else {'op', 'args'}
        if len(args) != OPERATIONS[operation] or set(request) != keys:
            raise ValueError('invalid operation arguments')
        if operation == 'fs-hread' and not 0 <= int(args[2]) <= IO_SIZE:
            raise ValueError('invalid read size')
        if operation == 'fs-dir-entries' and not 1 <= int(args[1]) <= 64:
            raise ValueError('invalid page size')
        if binary:
            data = base64.b64decode(request['data'], validate=True)
            if len(data) > IO_SIZE:
                raise ValueError('invalid write size')
            args.append(data)
    except (UnicodeError, ValueError, TypeError, KeyError, OverflowError):
        return {'error': 'EINVAL'}
    try:
        result = rpc(endpoint, operation, *args, '--world', branch, '--session', session)
    except RpcError as error:
        # Darwin and Linux assign different numbers to some errno values.
        return {'error': errno.errorcode.get(error.code - 1, 'EIO')}
    except (OSError, RuntimeError):
        return {'error': 'EIO'}
    if len(result) > FRAME_SIZE // 2:
        return {'error': 'EOVERFLOW'}
    return {'data': base64.b64encode(result).decode()}


def verify_backing_loss(name, stop_backing):
    with subprocess.Popen(
        ['container', 'exec', '-i', '--user', '1000:1000', name,
         'python3', '-c', LOSS_WORKER],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as worker:
        try:
            assert select.select([worker.stdout], [], [], 10)[0], 'loss worker did not open file'
            assert worker.stdout.readline() == b'open\n'
            stop_backing()
            _, errors = worker.communicate(b'stop\n', timeout=15)
            assert worker.returncode == 0, errors.decode()
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=5)


def exercise(endpoint, evidence, branch, case, stop_backing=None):
    name = f'world-forkfs-writable-{uuid.uuid4().hex[:12]}'
    run('container', 'create', '--name', name, '--cpus', '1', '--memory', '512M',
        '--cap-add', 'SYS_ADMIN', IMAGE, 'sleep', '150', timeout=90)
    session = None
    try:
        run('container', 'start', name, timeout=60)
        session = json.loads(rpc(endpoint, 'session-open', '60000'))['session']
        view = json.loads(rpc(endpoint, 'inode-root', '--world', branch, '--session', session))
        assert view['repository'] and view['inode']['directory']
        root = json.dumps(view['inode']).encode()
        ready = threading.Event()
        guest = Path(__file__).with_name('forkfs_writable_guest.py').read_text()
        with (evidence / f'{name}.stderr').open('wb') as errors:
            with subprocess.Popen(
                ['container', 'exec', '-i', name, 'python3', '-u', '-c', guest],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
            ) as bridge, concurrent.futures.ThreadPoolExecutor(1) as worker:
                def serve():
                    while True:
                        message = bridge.stdout.readline(FRAME_SIZE)
                        if not message:
                            return
                        if message == b'ready\n':
                            ready.set()
                            continue
                        if not message.endswith(b'\n'):
                            raise ValueError('oversize or incomplete guest request')
                        response = process_request(message, endpoint, branch, session, root)
                        bridge.stdin.write(json.dumps(response).encode() + b'\n')
                        bridge.stdin.flush()

                future = worker.submit(serve)
                try:
                    if not ready.wait(timeout=10):
                        if future.done():
                            future.result()
                        raise TimeoutError('FUSE did not initialize')
                    try:
                        rpc(endpoint, 'fs-write', '/foreign', b'blocked', '--world', branch)
                    except RpcError as error:
                        assert error.code == errno.EBUSY + 1, error
                    else:
                        raise AssertionError('forkfs mount lease accepted a competing write')
                    run('container', 'exec', '--user', '1000:1000', name,
                        'python3', '-c', WORKER, case, timeout=45)
                    if stop_backing:
                        verify_backing_loss(name, stop_backing)
                    run('container', 'exec', name, 'umount', '/workspace')
                    assert bridge.wait(timeout=5) == 0
                    future.result(timeout=5)
                finally:
                    if bridge.poll() is None:
                        bridge.kill()
                        bridge.wait(timeout=5)
        if not stop_backing:
            rpc(endpoint, 'session-close', session)
            session = None
        result = {'branch': branch, 'case': case, 'repository': view['repository'],
                  'root_inode': view['inode']['inode_id'], 'foreign_write_blocked': True}
        if stop_backing:
            result['backing_loss_returns_eio'] = True
        return result
    finally:
        run('container', 'stop', '--time', '1', name, check=False)
        try:
            run('container', 'delete', name)
        finally:
            if session is not None and endpoint.exists():
                rpc(endpoint, 'session-close', session)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('forkfsd', type=Path)
    args = parser.parse_args()
    forkfsd = str(args.forkfsd.resolve(strict=True))
    evidence = Path(tempfile.mkdtemp(prefix='world-forkfs-writable-', dir='/tmp'))
    print(f'Evidence: {evidence}', flush=True)
    store, endpoint = evidence / 'store', evidence / 'rpc.sock'
    environment = {
        'macos': run('sw_vers', '-productVersion').decode().strip(),
        'build': run('sw_vers', '-buildVersion').decode().strip(),
        'provider': run('container', '--version').decode().strip(),
        'architecture': run('uname', '-m').decode().strip(),
        'image': IMAGE,
        'guest_memory_mib': 512,
    }
    (evidence / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
    run(forkfsd, 'init', str(store))
    with (evidence / 'daemon.stderr').open('wb') as errors, subprocess.Popen(
        [forkfsd, 'serve', str(store), '--socket', str(endpoint), '--rpc'],
        stdout=subprocess.PIPE, stderr=errors,
    ) as daemon:
        def stop_backing():
            if daemon.poll() is None:
                daemon.terminate()
                daemon.wait(timeout=10)

        try:
            assert select.select([daemon.stdout], [], [], 5)[0], 'forkfsd startup timeout'
            assert json.loads(daemon.stdout.readline())['state'] == 'leveldb'
            rpc(endpoint, 'fs-init')
            rpc(endpoint, 'fs-write', '/base.txt', b'common baseline\x00')
            base = json.loads(rpc(endpoint, 'fs-snapshot', 'base'))['revision_id']
            for branch in ('branch-a', 'branch-b'):
                rpc(endpoint, 'fs-fork', 'base', branch)
            outcomes = []
            for branch, case in (('branch-a', 'write'), ('branch-b', 'sibling'), ('branch-a', 'rebuild')):
                result = exercise(endpoint, evidence, branch, case,
                                  stop_backing if case == 'rebuild' else None)
                if case != 'rebuild':
                    checkpoint = f'{branch}-checkpoint'
                    revision = json.loads(rpc(endpoint, 'fs-snapshot', checkpoint,
                                              '--world', branch))['revision_id']
                    diff = json.loads(rpc(endpoint, 'fs-diff', 'base', checkpoint, '', '64'))
                    assert diff['eof']
                    assert diff['before_revision_id'] == base and diff['after_revision_id'] == revision
                    changes = {change['path']: change for change in diff['changes']}
                    expected = ({'/base.txt', '/tree', '/tree/résumé.bin', '/tree/README',
                                 '/tree/readme', '/tree/alias'} if case == 'write'
                                else {'/base.txt', '/sibling.txt'})
                    assert set(changes) - {'/'} == expected, changes
                    assert changes['/base.txt']['content_changed']
                    result['checkpoint'] = {'name': checkpoint, 'revision': revision}
                    result['diff'] = diff['changes']
                if case == 'write':
                    rpc(endpoint, 'fs-write', '/after-unmount', b'lease released', '--world', branch)
                    result['foreign_write_after_unmount'] = True
                outcomes.append(result)
                (evidence / 'results.json').write_text(json.dumps(outcomes, indent=2) + '\n')
                print(json.dumps({key: value for key, value in result.items() if key != 'diff'}),
                      flush=True)
            assert outcomes[0]['repository'] == outcomes[2]['repository']
            assert outcomes[0]['root_inode'] == outcomes[2]['root_inode']
        finally:
            stop_backing()
    print('forkfs guest writable mount probe PASS', flush=True)


if __name__ == '__main__':
    main()
