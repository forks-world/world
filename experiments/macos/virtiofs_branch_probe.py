"""Probe storage transport on a disposable Apple container VM.

The source is a host directory used as a stand-in for a branch, not a forkfs
mount. Only this probe's files are shared. Reports non-portable semantics rather
than changing host mount settings to make them pass.
"""

import fcntl
import json
from pathlib import Path
import select
import subprocess
import tempfile
import time
import uuid


IMAGE = 'docker.io/library/python@sha256:bf12ecc0bea3f171d55145dd02c78b5eeb09f30ee2ac9cc2b4c9e4e8f5e30741'
GUEST = r"""
import ctypes, fcntl, json, os, select, socket, stat, sys
from pathlib import Path

root = Path('/workspace')
action = sys.argv[1]
if action == 'facts':
    print(json.dumps({
        'uid': os.getuid(),
        'gid': os.getgid(),
        'mount_owner': root.stat().st_uid,
        'mount_mode': oct(root.stat().st_mode & 0o777),
        'mountinfo': [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                      if line.split(' ')[4] == '/workspace'],
        'fuse_filesystems': [line for line in Path('/proc/filesystems').read_text().splitlines()
                             if 'fuse' in line],
        'fuse_device': Path('/dev/fuse').exists(),
        'seed': (root / 'seed').read_text(),
    }))
elif action == 'write':
    with (root / 'tmp').open('x') as file:
        file.write('guest output')
        file.flush()
        os.fsync(file.fileno())
    (root / 'tmp').chmod(0o700)
    os.replace(root / 'tmp', root / 'artifact')
    (root / 'link').symlink_to('artifact')
    assert (root / 'link').read_text() == 'guest output'
    (root / 'remove-me').unlink()
elif action == 'read':
    print(json.dumps({
        'seed': (root / 'seed').read_text(),
        'artifact': (root / 'artifact').read_text() if (root / 'artifact').exists() else None,
    }))
elif action == 'case':
    (root / 'CaseProbe').touch(exist_ok=False)
    try:
        (root / 'caseprobe').touch(exist_ok=False)
        print('case-sensitive')
    except FileExistsError:
        print('case-folding')
elif action == 'lock':
    with (root / 'artifact').open('r+') as file:
        try:
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print('acquired')
        except BlockingIOError:
            print('blocked')
elif action == 'socket':
    path = str(root / 'probe.sock')
    with socket.socket(socket.AF_UNIX) as server, socket.socket(socket.AF_UNIX) as client:
        server.settimeout(2)
        client.settimeout(2)
        server.bind(path)
        server.listen()
        client.connect(path)
        peer, _ = server.accept()
        with peer:
            client.sendall(b'ok')
            assert peer.recv(2) == b'ok'
    assert stat.S_ISSOCK(os.lstat(path).st_mode)
    os.unlink(path)
elif action == 'watch':
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_CLOEXEC)
    assert fd >= 0
    assert libc.inotify_add_watch(fd, os.fsencode(root), 0x100) >= 0  # IN_CREATE
    print('watching', flush=True)
    if select.select([fd], [], [], 3)[0]:
        print('event', os.read(fd, 4096).hex())
    else:
        print('no event')
    os.close(fd)
else:
    raise ValueError(action)
"""


# A private guest mount with only a FUSE_INIT implementation. This establishes
# whether the VM can host a frontend. It does not expose a filesystem.
FUSE_GUEST = r"""
import ctypes, json, os, select, struct, tempfile
from pathlib import Path

libc = ctypes.CDLL(None, use_errno=True)
fd = os.open('/dev/fuse', os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK)
try:
    with tempfile.TemporaryDirectory(prefix='world-fuse-init-') as directory:
        target = os.fsencode(directory)
        options = f'fd={fd},rootmode=40000,user_id={os.getuid()},group_id={os.getgid()}'
        result = libc.mount(b'world-probe', target, b'fuse', 0, options.encode())
        if result != 0:
            error = ctypes.get_errno()
            print(json.dumps({'mounted': False, 'errno': error, 'error': os.strerror(error)}))
        else:
            try:
                assert select.select([fd], [], [], 3)[0], 'FUSE_INIT did not arrive'
                packet = os.read(fd, 8192)
                length, opcode, unique = struct.unpack_from('<IIQ', packet)
                assert length == len(packet) and opcode == 26, (length, opcode)
                major, minor = struct.unpack_from('<II', packet, 40)
                assert major == 7 and minor >= 8
                payload = struct.pack('<IIIIHHI', 7, 8, 0, 0, 0, 0, 4096)
                os.write(fd, struct.pack('<IiQ', 16 + len(payload), 0, unique) + payload)
                mount = [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                         if line.split(' ')[4] == directory]
                assert any(' - fuse ' in line for line in mount), mount
                print(json.dumps({'mounted': True, 'kernel_protocol': f'{major}.{minor}',
                                  'mountinfo': mount}))
            finally:
                assert libc.umount2(target, 2) == 0, os.strerror(ctypes.get_errno())
finally:
    os.close(fd)
"""


def main():
    root = Path(tempfile.mkdtemp(prefix='world-virtiofs-probe-'))
    report = {'observations': {}}
    print(f'Evidence: {root}', flush=True)

    def save():
        (root / 'results.json').write_text(json.dumps(report, indent=2) + '\n')

    def call(label, args, *, required=True):
        start = time.monotonic()
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        report['observations'][label] = dict(code=result.returncode, stdout=result.stdout,
                                             stderr=result.stderr, seconds=time.monotonic() - start)
        save()
        print(f'{label}: rc={result.returncode}', flush=True)
        if required:
            result.check_returncode()
        return result

    def ctl(label, *args, **kwargs):
        return call(label, ['container', *args], **kwargs)

    def guest(name, action, *, label=None, required=True):
        return ctl(label or action, 'exec', '--user', '1000:1000', name,
                   'python3', '-u', '-c', GUEST, action, required=required)

    def watch(name, source, label, *, from_guest):
        args = ['container', 'exec', '--user', '1000:1000', name, 'python3', '-u',
                '-c', GUEST, 'watch']
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
            try:
                assert select.select([proc.stdout], [], [], 5)[0], 'watch readiness timeout'
                assert proc.stdout.readline().strip() == 'watching'
                file = f'{label}.txt'
                if from_guest:
                    ctl(f'{label}-create', 'exec', '--user', '1000:1000', name,
                        'touch', f'/workspace/{file}')
                else:
                    (source / file).touch()
                out, err = proc.communicate(timeout=8)
                report['observations'][label] = dict(code=proc.returncode, stdout=out, stderr=err)
                save()
                print(f'{label}: {out.strip()}', flush=True)
                assert proc.returncode == 0
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)

    def use_vm(tag, source, run, *options):
        name = f'world-virtiofs-{uuid.uuid4().hex[:16]}'
        mounts = ['--mount', f'type=bind,source={source.resolve()},target=/workspace'] if source else []
        ctl(f'{tag}-create', 'create', '--name', name, '--memory', '512M',
            '--cpus', '1', *mounts, *options, IMAGE, 'sleep', '300')
        try:
            ctl(f'{tag}-start', 'start', name)
            run(name)
        finally:
            ctl(f'{tag}-stop', 'stop', '--time', '1', name, required=False)
            ctl(f'{tag}-delete', 'delete', name)

    call('macos', ['sw_vers'])
    ctl('provider', '--version')
    inventory = ctl('provider-running', 'list', '--format', 'json')
    assert json.loads(inventory.stdout) == [], 'stop other provider VMs before running this probe'
    branch_a, branch_b = root / 'branch-a', root / 'branch-b'
    for label, directory in [('A', branch_a), ('B', branch_b)]:
        directory.mkdir(mode=0o755)
        (directory / 'seed').write_text(label)
        (directory / 'remove-me').touch()

    def first(name):
        facts = json.loads(guest(name, 'facts').stdout)
        assert facts['uid'] == 1000 and facts['seed'] == 'A'
        assert any(' - virtiofs ' in line for line in facts['mountinfo'])
        ctl('fuse-default', 'exec', name, 'python3', '-c', FUSE_GUEST, required=False)
        baseline = guest(name, 'write', label='write-default-permissions', required=False)
        if baseline.returncode != 0:
            # Record the mismatch. Relax host permissions only on this test directory.
            assert not (branch_a / 'tmp').exists() and not (branch_a / 'artifact').exists()
            branch_a.chmod(0o777)
            guest(name, 'write', label='write-permissive-probe-directory')
        assert (branch_a / 'artifact').read_text() == 'guest output'
        assert (branch_a / 'artifact').stat().st_mode & 0o777 == 0o700
        assert (branch_a / 'link').readlink() == Path('artifact')
        assert not (branch_a / 'remove-me').exists()
        guest(name, 'case')
        guest(name, 'socket', required=False)
        with (branch_a / 'artifact').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            guest(name, 'lock', label='host-locked-file', required=False)
        watch(name, branch_a, 'inotify-host-create', from_guest=False)
        watch(name, branch_a, 'inotify-guest-create', from_guest=True)
        ctl('a-restart-stop', 'stop', '--time', '1', name)
        ctl('a-restart-start', 'start', name)
        assert json.loads(guest(name, 'read', label='read-after-restart').stdout) == {
            'seed': 'A', 'artifact': 'guest output',
        }

    def observe(tag, expected_seed, expected_artifact):
        def check(name):
            observed = json.loads(guest(name, 'read', label=tag).stdout)
            assert observed == {'seed': expected_seed, 'artifact': expected_artifact}, observed
        return check

    use_vm('a', branch_a, first)
    use_vm('b', branch_b, observe('different-directory', 'B', None))
    use_vm('a-rebuilt', branch_a, observe('read-after-rebuild', 'A', 'guest output'))
    assert not (branch_b / 'artifact').exists()
    # A separate VM with no host share and a privileged bootstrap only for FUSE.
    use_vm('fuse-bootstrap', None, lambda name: ctl(
        'fuse-with-cap-sys-admin', 'exec', name, 'python3', '-c', FUSE_GUEST, required=False,
    ), '--cap-add', 'SYS_ADMIN')
    report['transport_checks_complete'] = True
    save()
    print('Mount transport probe complete', flush=True)


if __name__ == '__main__':
    main()
