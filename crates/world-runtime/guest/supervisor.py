"""World experimental guest execution protocol v1; installed root-owned.

Workloads run as uid/gid 1000 in their own cgroup v2. The control process stays
outside that cgroup, and kills the entire group on exit, timeout or cancellation.
No host paths, credentials or environment are imported.
"""
import base64
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path('/var/lib/world/executions')
CGROUP = Path('/sys/fs/cgroup')
FORKFS_SOURCE = Path('/opt/world/forkfs-source')
OFFLINE = Path('/opt/world/offline')


def offline_network_ready():
    return OFFLINE.exists() and [name for _, name in socket.if_nameindex()] == ['lo']


def enforce_network():
    if OFFLINE.exists() and not offline_network_ready():
        raise ValueError('policy_unavailable: offline workspace has a non-loopback interface')


def workspace_mount_id():
    source = FORKFS_SOURCE.read_text()
    mounts = [line.split(' - ', 1) for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    workspace = [(fields.split(), fs.split()) for fields, fs in mounts if fields.split()[4] == '/workspace']
    if not workspace:
        return None
    if len(workspace) != 1 or workspace[0][1][:2] != ['fuse', source]:
        raise ValueError('storage_unavailable: unexpected /workspace mount')
    return workspace[0][0][0]


def open_workspace():
    fd = None
    try:
        mount = workspace_mount_id()
        if mount is None:
            raise ValueError('workspace is unmounted')
        fd = os.open('/workspace', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        if f'mnt_id:\t{mount}' not in Path(f'/proc/self/fdinfo/{fd}').read_text().splitlines():
            raise ValueError('workspace mount changed')
        os.fstat(fd)
        return fd
    except (OSError, ValueError) as error:
        if fd is not None:
            os.close(fd)
        raise ValueError(f'storage_unavailable: {error}') from error


def write(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def import_workspace():
    """Extract only into private staging; publish over an empty workspace."""
    destination = Path('/workspace')
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ValueError('import requires an empty /workspace; existing files are never overwritten')
    base = Path('/var/lib/world/imports')
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = base / os.urandom(16).hex()
    staging.mkdir(mode=0o700)
    directories = {'': staging}
    modes = []
    current = None
    remaining = 0
    entries = 0
    committed = False
    begun = False
    finished = False
    try:
        while True:
            raw = sys.stdin.buffer.readline(70_001)
            if not raw:
                break
            if len(raw) > 70_000 or not raw.endswith(b'\n'):
                raise ValueError('oversized or truncated import record')
            record = json.loads(raw)
            kind = record.get('type')
            if not begun:
                if kind != 'begin' or record.get('protocol') != 1:
                    raise ValueError('import protocol mismatch')
                begun = True
                continue
            if finished:
                raise ValueError('data after import finish')
            if kind == 'data':
                if current is None:
                    raise ValueError('data without file')
                data = base64.b64decode(record['data'], validate=True)
                if len(data) > remaining:
                    raise ValueError('file exceeds declared size')
                current.write(data)
                remaining -= len(data)
            elif kind == 'end_file':
                if current is None or remaining:
                    raise ValueError('file truncated or unexpected end')
                current.flush()
                os.fsync(current.fileno())
                current.close()
                current = None
            elif kind == 'finish':
                if current is not None or record['entries'] != entries:
                    raise ValueError('incomplete import')
                finished = True
            else:
                if current is not None:
                    raise ValueError('unfinished file')
                name = record['path']
                if not isinstance(name, str) or not name or len(name.encode()) > 4096:
                    raise ValueError('invalid import path')
                parts = name.split('/')
                if any(p in ('', '.', '..') or '\0' in p for p in parts):
                    raise ValueError('unsafe import path')
                parent_name = '/'.join(parts[:-1])
                if parent_name not in directories:
                    raise ValueError('missing or symlink parent')
                path = directories[parent_name] / parts[-1]
                if path.exists() or path.is_symlink():
                    raise ValueError('duplicate import path')
                entries += 1
                if entries > 1_000_000:
                    raise ValueError('import exceeds entry limit')
                if kind == 'symlink':
                    target = record['target']
                    if not isinstance(target, str) or not target or '\0' in target:
                        raise ValueError('invalid symlink target')
                    path.symlink_to(target)
                    os.lchown(path, 1000, 1000)
                elif kind in ('directory', 'file'):
                    mode = record['mode']
                    if not isinstance(mode, int) or not 0 <= mode <= 0o777:
                        raise ValueError('invalid mode')
                    if kind == 'directory':
                        path.mkdir(mode=0o700)
                        directories[name] = path
                        modes.append((path, mode))
                    else:
                        remaining = record['size']
                        if not isinstance(remaining, int) or remaining < 0:
                            raise ValueError('invalid file size')
                        current = path.open('xb')
                        os.fchown(current.fileno(), 1000, 1000)
                        os.fchmod(current.fileno(), mode)
                else:
                    raise ValueError('unsupported import entry')
        if not finished:
            raise ValueError('import stream truncated; workspace unchanged')
        for path, mode in reversed(modes):
            os.chown(path, 1000, 1000)
            os.chmod(path, mode)
        os.chown(staging, 1000, 1000)
        os.chmod(staging, 0o755)
        # Recheck after receiving; os.replace only replaces an empty directory.
        if destination.is_symlink() or any(destination.iterdir()):
            raise ValueError('workspace changed during import')
        os.replace(staging, destination)
        committed = True
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        print(json.dumps({'state': 'imported', 'entries': entries}))
    finally:
        if current is not None:
            current.close()
        if not committed:
            shutil.rmtree(staging)


def drop_workload_privileges():
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'prctl')


def spawn_workload(argv, group, **streams):
    enforce_network()
    workspace = open_workspace() if FORKFS_SOURCE.exists() else None

    def prepare():
        if workspace is not None:
            os.fchdir(workspace)
            os.close(workspace)
        (group / 'cgroup.procs').write_text(str(os.getpid()))
        drop_workload_privileges()

    try:
        return subprocess.Popen(argv, cwd='/workspace' if workspace is None else None,
                                pass_fds=() if workspace is None else (workspace,), preexec_fn=prepare,
                                env={'PATH': '/usr/local/bin:/usr/bin:/bin',
                                     'HOME': '/home/world', 'USER': 'world',
                                     'LANG': 'C.UTF-8'}, **streams)
    finally:
        if workspace is not None:
            os.close(workspace)


def main():
    mode = sys.argv[1]
    if mode in ('boot-id', 'probe', 'run', 'import', 'export', 'port-bridge', 'service', 'service-daemon',
                'forkfs-mounted', 'forkfs-check', 'forkfs-unmount'):
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        expected = os.environ.get('WORLD_EXPECTED_BOOT_ID')
        if expected is not None and expected != boot_id:
            raise ValueError('guest boot changed; run workspace setup first')
        if mode == 'boot-id':
            print(boot_id)
            return 0
    if mode == 'offline-check':
        if not offline_network_ready():
            raise ValueError('policy_unavailable: guest offline policy is unverified')
        print('offline')
        return 0
    if mode in ('port-bridge', 'export', 'import'):
        enforce_network()
    if mode == 'forkfs-mounted':
        print('mounted' if workspace_mount_id() else 'unmounted')
        return 0
    if mode == 'forkfs-check':
        os.close(open_workspace())
        print('mounted')
        return 0
    if mode == 'forkfs-unmount':
        if workspace_mount_id() is not None:
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.umount2(b'/workspace', 0) != 0:
                raise OSError(ctypes.get_errno(), 'unmount forkfs')
        return 0
    if mode == 'port-bridge':
        if FORKFS_SOURCE.exists():
            os.close(open_workspace())
        asyncio.run(bridge(boot_id, sys.argv[2], sys.argv[3], int(sys.argv[4])))
        return 0
    if mode == 'service-daemon':
        service_daemon(boot_id)
        return 0
    if mode == 'service':
        service_client(boot_id, sys.argv[2:])
        return 0
    if mode == 'export':
        if FORKFS_SOURCE.exists():
            os.close(open_workspace())
        export_workspace()
        return 0
    if mode == 'import':
        if FORKFS_SOURCE.exists():
            raise ValueError('import is unavailable for forkfs-backed workspaces')
        import_workspace()
        return 0
    if mode == 'probe':
        p = CGROUP / ('world-capability-probe-' + str(os.getpid()))
        p.mkdir(exist_ok=True)
        assert (p / 'cgroup.kill').exists()
        p.rmdir()
        print(json.dumps({'protocol': 1, 'uid': os.getuid(), 'cgroup_kill': True, 'import_protocol': 1, 'export_protocol': 1, 'port_protocol': 1, 'boot_id': boot_id, 'service_protocol': 1}))
        return 0
    token = sys.argv[2]
    if not re.fullmatch('[0-9a-f]{32}', token):
        raise ValueError('invalid execution id')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = ROOT / (token + '.json')
    cancel = ROOT / (token + '.cancel')
    if mode == 'cancel':
        cancel.touch(mode=0o600)
        return 0
    if mode == 'status':
        print(result.read_text() if result.exists() else '{"state":"unknown"}')
        return 0
    if mode != 'run':
        raise ValueError('invalid operation')
    # Exclusive claim: a repeated launch must never execute the command again.
    with result.open('x') as f:
        json.dump({'state': 'starting'}, f)
    group = CGROUP / ('world-exec-' + token)
    group.mkdir()
    timed_out = False
    child = None
    try:
        if cancel.exists():
            write(result, {'state': 'cancelled', 'exit_code': 124})
            return 124
        seconds = float(sys.argv[3])
        if not 0 < seconds <= 86400:
            raise ValueError('timeout must be between 0 and 86400 seconds')
        argv = sys.argv[4:]
        if not argv:
            raise ValueError('empty argv')

        child = spawn_workload(argv, group)
        write(result, {'state': 'running'})
        deadline = time.monotonic() + seconds
        while child.poll() is None:
            if cancel.exists() or time.monotonic() >= deadline:
                timed_out = True
                (group / 'cgroup.kill').write_text('1')
                break
            time.sleep(0.05)
        code = child.wait()
        outcome = {'state': 'cancelled' if cancel.exists() else 'timed_out'} if timed_out else {'state': 'exited'}
        outcome['exit_code'] = 124 if timed_out else (code if code >= 0 else 128 - code)
        if code < 0:
            outcome['signal'] = -code
        # Cleanup happens before reporting completion, including detached children.
        (group / 'cgroup.kill').write_text('1')
        for _ in range(100):
            if 'populated 0' in (group / 'cgroup.events').read_text():
                break
            time.sleep(0.01)
        else:
            raise RuntimeError('execution cgroup still populated')
        write(result, outcome)
        return outcome['exit_code']
    except Exception as e:
        write(result, {'state': 'failed', 'error': str(e), 'exit_code': 125})
        raise
    finally:
        (group / 'cgroup.kill').write_text('1')
        if child is not None:
            child.wait()
        try:
            group.rmdir()
        except OSError:
            pass  # Leave evidence; never claim a populated cgroup was removed.
