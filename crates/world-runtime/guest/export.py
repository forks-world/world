"""Stream a descriptor-relative snapshot of the guest workspace."""
import signal
import stat


def export_workspace():
    signal.alarm(600)
    drop_workload_privileges()
    output = sys.stdout.buffer

    def send(kind, **fields):
        output.write(json.dumps(dict(type=kind, **fields)).encode('ascii') + b'\n')

    def stable(value):
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

    count = 0

    def walk(directory, prefix, depth):
        nonlocal count
        before = os.fstat(directory)
        with os.scandir(directory) as items:
            for item in items:
                name = item.name
                path = f'{prefix}/{name}' if prefix else name
                if depth >= 128 or len(path.encode('utf-8')) > 4096:
                    raise ValueError('export path exceeds nesting or length limit')
                count += 1
                if count > 1_000_000:
                    raise ValueError('export exceeds entry limit')
                observed = item.stat(follow_symlinks=False)
                if stat.S_ISLNK(observed.st_mode):
                    target = os.readlink(name, dir_fd=directory)
                    if len(target.encode('utf-8')) > 4096:
                        raise ValueError('export link target exceeds length limit')
                    if stable(observed) != stable(os.stat(name, dir_fd=directory, follow_symlinks=False)):
                        raise ValueError(f'symlink changed during export: {path}')
                    send('symlink', path=path, target=target)
                    continue
                is_dir = stat.S_ISDIR(observed.st_mode)
                if not is_dir and not stat.S_ISREG(observed.st_mode):
                    raise ValueError(f'unsupported special file: {path}')
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if is_dir:
                    flags |= os.O_DIRECTORY
                fd = os.open(name, flags, dir_fd=directory)
                try:
                    opened = os.fstat(fd)
                    if stable(observed) != stable(opened) or opened.st_mode != observed.st_mode:
                        raise ValueError(f'entry changed during export: {path}')
                    mode = stat.S_IMODE(opened.st_mode) & 0o777
                    if is_dir:
                        send('directory', path=path, mode=mode)
                        walk(fd, path, depth + 1)
                    else:
                        send('file', path=path, mode=mode, size=opened.st_size)
                        remaining = opened.st_size
                        while remaining:
                            data = os.read(fd, min(remaining, 48 * 1024))
                            if not data:
                                raise ValueError(f'file truncated during export: {path}')
                            send('data', data=base64.b64encode(data).decode('ascii'))
                            remaining -= len(data)
                        if stable(opened) != stable(os.fstat(fd)):
                            raise ValueError(f'file changed during export: {path}')
                        send('end_file')
                finally:
                    os.close(fd)
        if stable(before) != stable(os.fstat(directory)):
            raise ValueError(f'directory changed during export: {prefix}')

    root = os.open('/workspace', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        send('begin', protocol=1)
        walk(root, '', 0)
        send('finish', entries=count)
        output.flush()
    finally:
        os.close(root)
