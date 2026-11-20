"""Linux FUSE frontend for the local forkfs-backed workspace."""

import base64
import ctypes
import errno
import itertools
import json
import os
from pathlib import Path
import select
import stat
import struct
import sys
import time

WORKSPACE = b'/workspace'
IO_SIZE = 4096
FRAME_SIZE = 128 * 1024
WORKER_ID = 1000
MOUNT_FLAGS = 2 | 4  # Linux MS_NOSUID | MS_NODEV


class Broker:
    def __init__(self):
        self.connected = True

    def call(self, operation, *args, data=None):
        if not self.connected:
            raise OSError(errno.EIO, 'forkfs broker disconnected')
        request = {'op': operation, 'args': [str(arg) for arg in args]}
        if data is not None:
            request['data'] = base64.b64encode(data).decode()
        try:
            print(json.dumps(request), flush=True)
            if not select.select([sys.stdin], [], [], 6)[0]:
                raise TimeoutError('broker timeout')
            line = sys.stdin.readline(FRAME_SIZE)
            if not line.endswith('\n'):
                raise ValueError('incomplete response')
            response = json.loads(line)
            if 'error' not in response:
                return base64.b64decode(response['data'], validate=True)
        except (OSError, ValueError, KeyError) as exc:
            self.connected = False
            raise OSError(errno.EIO, 'forkfs broker disconnected') from exc
        raise OSError(getattr(errno, response['error'], errno.EIO), operation)

    def object(self, *args):
        return json.loads(self.call(*args))


def names(payload, count=1):
    parts = payload.split(b'\0')
    if len(parts) != count + 1 or parts[-1] or not all(parts[:-1]):
        raise OSError(errno.EINVAL, 'invalid FUSE name')
    try:
        return [part.decode() for part in parts[:-1]]
    except UnicodeError as exc:
        raise OSError(errno.EILSEQ, 'forkfs names require UTF-8') from exc


def file_type(node):
    for kind, mode in (('directory', stat.S_IFDIR), ('symlink', stat.S_IFLNK),
                       ('fifo', stat.S_IFIFO), ('socket', stat.S_IFSOCK)):
        if node[kind]:
            return mode
    return stat.S_IFREG


class Frontend:
    def __init__(self, broker):
        self.broker = broker
        self.nodes = {}
        self.inodes = {}
        self.files = {}
        self.directories = {}
        self.handles = itertools.count(1)
        self.node_id(self.broker.object('root'))

    def node_id(self, node):
        inode = node['inode_id']
        if inode not in self.nodes:
            if len(self.nodes) >= 65536:
                raise OSError(errno.ENOSPC, 'probe inode limit')
            self.nodes[inode] = len(self.nodes) + 1
            self.inodes[self.nodes[inode]] = inode
        return self.nodes[inode]

    def attributes(self, node):
        times = [divmod(node[key], 10**9) for key in
                 ('accessed_ns', 'modified_ns', 'changed_ns')]
        return struct.pack(
            '<6Q8I', self.node_id(node), node['size'], (node['allocated_size'] + 511) // 512,
            *(seconds for seconds, _ in times), *(nanos for _, nanos in times),
            file_type(node) | node['mode'], node['links'], WORKER_ID, WORKER_ID, 0,
        )

    def entry(self, node):
        return struct.pack('<QQQQII', self.node_id(node), 1, 0, 0, 0, 0) + self.attributes(node)

    def open_reply(self, token):
        handle = next(self.handles)
        self.files[handle] = token
        return struct.pack('<QII', handle, 1, 0)  # FOPEN_DIRECT_IO

    def lookup(self, parent, name):
        return self.broker.object('inode-lookup', parent, name)

    def directory_records(self, inode):
        cursor = self.broker.object('inode-dir-open', inode)['cursor']
        entries = []
        try:
            while True:
                page = self.broker.object('fs-dir-entries', cursor, 64)
                entries.extend(page['entries'])
                if len(entries) > 4096:
                    raise OSError(errno.EOVERFLOW, 'probe directory entry limit')
                if page['eof']:
                    break
        finally:
            self.broker.call('fs-dir-close', cursor)
        records = []
        for offset, entry in enumerate(entries, 1):
            name = entry['name'].encode()
            node = entry['inode']
            record = struct.pack('<QQII', self.node_id(node), offset, len(name),
                                 file_type(node) >> 12) + name
            records.append(record + bytes(-len(record) % 8))
        return records

    def setattr(self, inode, payload):
        flags, handle, size, _, atime, mtime, _, atime_ns, mtime_ns, _, mode = (
            struct.unpack_from('<I4x6Q4I', payload)
        )
        # MODE, SIZE, ATIME, MTIME, FH, ATIME_NOW, MTIME_NOW, LOCKOWNER, CTIME.
        if flags & ~0x7f9 or mode & 0o6000:
            raise OSError(errno.EOPNOTSUPP, 'unsupported attribute change')
        now = time.time_ns()
        modified = now if flags & 256 else mtime * 10**9 + mtime_ns if flags & 32 else '-'
        accessed = now if flags & 128 else atime * 10**9 + atime_ns if flags & 16 else '-'
        return self.broker.object(
            'inode-setattr-times', inode, mode & 0o1777 if flags & 1 else '-',
            size if flags & 8 else '-', modified, accessed, '-',
            self.files[handle] if flags & 64 else '-',
        )

    def dispatch(self, operation, node_id, payload):
        inode = self.inodes.get(node_id)
        if operation == 1:  # LOOKUP
            name, = names(payload)
            return self.entry(self.lookup(inode, name))
        if operation in (3, 4):  # GETATTR, SETATTR
            node = (self.broker.object('inode-stat', inode) if operation == 3
                    else self.setattr(inode, payload))
            return bytes(16) + self.attributes(node)
        if operation == 5:  # READLINK
            return self.broker.call('inode-readlink', inode)
        if operation == 6:  # SYMLINK
            name, target = names(payload, 2)
            return self.entry(self.broker.object('inode-symlink', inode, name, target))
        if operation == 9:  # MKDIR
            mode, = struct.unpack_from('<I', payload)
            name, = names(payload[8:])
            return self.entry(self.broker.object('inode-mkdir', inode, name, mode & 0o1777))
        if operation in (10, 11):  # UNLINK, RMDIR
            name, = names(payload)
            node = self.lookup(inode, name)
            self.broker.call('inode-remove', inode, name, node['inode_id'],
                             'file' if operation == 10 else 'directory')
            return b''
        if operation == 12:  # RENAME
            target_id, = struct.unpack_from('<Q', payload)
            source, target = names(payload[8:], 2)
            target_parent = self.inodes[target_id]
            source_node = self.lookup(inode, source)
            try:
                expected_target = self.lookup(target_parent, target)['inode_id']
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
                expected_target = '-'
            self.broker.call('inode-rename', inode, source, target_parent, target,
                             source_node['inode_id'], expected_target)
            return b''
        if operation == 14:  # OPEN
            flags, = struct.unpack_from('<I', payload)
            access = {os.O_RDONLY: 'r', os.O_WRONLY: 'w', os.O_RDWR: 'rw'}
            token = self.broker.object('inode-open', inode, access[flags & os.O_ACCMODE])['handle']
            return self.open_reply(token)
        if operation in (15, 16, 28):  # READ, WRITE, READDIR
            handle, offset, size = struct.unpack_from('<QQI', payload)
            if operation == 15:
                return self.broker.call('fs-hread', self.files[handle], offset, min(size, IO_SIZE))
            if operation == 16:
                data = payload[24:]
                if len(data) != size or size > IO_SIZE:
                    raise OSError(errno.EINVAL, 'invalid FUSE write size')
                self.broker.call('fs-hwrite', self.files[handle], offset, data=data)
                return struct.pack('<II', size, 0)
            result = bytearray()
            for record in self.directories[handle][offset:]:
                if len(result) + len(record) > size:
                    break
                result.extend(record)
            return bytes(result)
        if operation == 18:  # RELEASE
            handle, = struct.unpack_from('<Q', payload)
            self.broker.call('fs-close', self.files.pop(handle))
            return b''
        if operation in (20, 25, 30):  # FSYNC, FLUSH, FSYNCDIR
            self.broker.call('inode-sync')
            return b''
        if operation == 27:  # OPENDIR
            if len(self.directories) >= 64:
                raise OSError(errno.EMFILE, 'probe directory handle limit')
            handle = next(self.handles)
            self.directories[handle] = self.directory_records(inode)
            return struct.pack('<QII', handle, 0, 0)
        if operation == 29:  # RELEASEDIR
            handle, = struct.unpack_from('<Q', payload)
            del self.directories[handle]
            return b''
        if operation == 35:  # CREATE
            _, mode = struct.unpack_from('<II', payload)
            name, = names(payload[8:])
            token = self.broker.object('inode-create', inode, name, mode & 0o1777)['handle']
            return self.entry(self.broker.object('fs-hstat', token)) + self.open_reply(token)
        raise OSError(errno.ENOSYS, 'unsupported probe operation')


def serve():
    source = os.environ.get('WORLD_FORKFS_SOURCE', 'world-forkfs-writable-probe')
    expected = os.environ.get('WORLD_EXPECTED_BOOT_ID')
    if expected and Path('/proc/sys/kernel/random/boot_id').read_text().strip() != expected:
        raise ValueError('VM boot changed before forkfs mount')
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open('/dev/fuse', os.O_RDWR | os.O_CLOEXEC)
    mounted = False
    try:
        frontend = Frontend(Broker())
        Path(os.fsdecode(WORKSPACE)).mkdir(mode=0o755, exist_ok=True)
        options = f'fd={fd},rootmode=40000,user_id=0,group_id=0,allow_other,default_permissions'
        if libc.mount(source.encode(), WORKSPACE, b'fuse', MOUNT_FLAGS, options.encode()) != 0:
            raise OSError(ctypes.get_errno(), 'mount FUSE')
        mounted = True
        while True:
            try:
                packet = os.read(fd, 8192)
            except OSError as exc:
                if exc.errno == errno.ENODEV:
                    mounted = False
                    return
                raise
            length, operation, unique, node_id = struct.unpack_from('<IIQQ', packet)
            if length != len(packet):
                raise ValueError('incomplete FUSE request')
            if operation in (2, 42):  # FORGET, BATCH_FORGET have no reply.
                continue
            error = 0
            try:
                if operation == 26:  # INIT. Use the 7.8 compatibility layouts above.
                    result = struct.pack('<IIIIHHI', 7, 8, 0, 0, 0, 0, IO_SIZE)
                elif operation == 38:  # DESTROY
                    result = b''
                else:
                    result = frontend.dispatch(operation, node_id, packet[40:])
            except OSError as exc:
                result, error = b'', exc.errno or errno.EIO
            response = struct.pack('<IiQ', 16 + len(result), -error, unique) + result
            try:
                if os.write(fd, response) != len(response):
                    raise OSError(errno.EIO, 'incomplete FUSE reply')
            except OSError as exc:
                if exc.errno != errno.ENOENT:  # Kernel cancelled the request.
                    raise
            if operation == 26:
                print('ready', flush=True)
    finally:
        if mounted:
            libc.umount2(WORKSPACE, 2)
        os.close(fd)


if __name__ == '__main__':
    serve()
