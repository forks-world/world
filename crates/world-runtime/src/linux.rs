//! Linux kernel isolation: unprivileged user + network namespaces.
//!
//! `world network exec` runs each workload in a fresh network namespace that
//! only has loopback; the egress proxy listener is created inside it and
//! handed back to the supervisor. Landlock limits writes and seccomp refuses
//! socket families that escape a network namespace (e.g. filesystem Unix
//! sockets). `world silo exec` joins a per-World namespace held open by a
//! detached holder process, so executions of one World share localhost.
//!
//! Functions marked "pre_exec" run in the forked child before exec: they must
//! only make raw system calls on data prepared by the parent, never allocate.
use crate::{
    proxy::Proxy,
    run::{self, RunOptions},
};
use anyhow::{Context, Result, bail};
use rand::Rng;
use std::{
    ffi::{CStr, CString},
    io::{Error, Result as IoResult},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, process::CommandExt},
    },
    path::Path,
};
use tokio::{
    process::Command,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

fn check(result: libc::c_int) -> IoResult<libc::c_int> {
    if result < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(result)
    }
}

/// Move a descriptor handed to a child above the standard descriptors: if
/// a library caller has closed 0-2, a new descriptor can land there, and
/// Command replaces 0-2 with the child's stdio before pre_exec runs.
pub(crate) fn above_stdio(fd: OwnedFd) -> IoResult<OwnedFd> {
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor we exclusively own.
    let moved = check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(moved) })
}

/// Maps the caller's own uid/gid into a new user namespace.
pub(crate) struct IdMaps {
    uid: Vec<u8>,
    gid: Vec<u8>,
}

impl IdMaps {
    pub(crate) fn current() -> Self {
        // SAFETY: getuid/getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Self {
            uid: format!("{uid} {uid} 1\n").into_bytes(),
            gid: format!("{gid} {gid} 1\n").into_bytes(),
        }
    }
}

/// pre_exec: write a small procfs file.
unsafe fn write_file(path: &CStr, data: &[u8]) -> IoResult<()> {
    unsafe {
        let fd = check(libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC))?;
        let written = libc::write(fd, data.as_ptr().cast(), data.len());
        let error = Error::last_os_error();
        libc::close(fd);
        if written != data.len() as isize {
            return Err(error);
        }
    }
    Ok(())
}

/// pre_exec: enter new user + network namespaces with loopback up. The new
/// namespace has no other interfaces and therefore no route to the host.
pub(crate) unsafe fn enter_new_namespaces(maps: &IdMaps) -> IoResult<()> {
    unsafe {
        check(libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET))?;
        write_file(c"/proc/self/setgroups", b"deny")?;
        write_file(c"/proc/self/uid_map", &maps.uid)?;
        write_file(c"/proc/self/gid_map", &maps.gid)?;
        // Per-namespace setting: allow ordinary development ports below 1024.
        write_file(c"/proc/sys/net/ipv4/ip_unprivileged_port_start", b"0")?;
        let fd = check(libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        ))?;
        let mut request: libc::ifreq = std::mem::zeroed();
        request.ifr_name[..2].copy_from_slice(&[b'l' as libc::c_char, b'o' as libc::c_char]);
        let mut result = libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut request);
        if result == 0 {
            request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            result = libc::ioctl(fd, libc::SIOCSIFFLAGS, &request);
        }
        let error = Error::last_os_error();
        libc::close(fd);
        if result != 0 {
            return Err(error);
        }
    }
    Ok(())
}

/// Paths that stay writable in a read-only mount view, and the directory
/// to re-enter afterwards (the old working directory keeps the old mount).
pub(crate) struct WritableView {
    paths: Vec<CString>,
    workdir: CString,
}

impl WritableView {
    pub(crate) fn new(workdir: &Path, others: &[&Path]) -> Result<Self> {
        let c = |p: &Path| CString::new(p.as_os_str().as_bytes()).context("path contains NUL");
        Ok(Self {
            paths: std::iter::once(workdir)
                .chain(others.iter().copied())
                .map(c)
                .collect::<Result<_>>()?,
            workdir: c(workdir)?,
        })
    }
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// pre_exec (inside the new user namespace): a private mount namespace in
/// which every mount is read-only except fresh writable binds of `view`.
/// Read-only mounts refuse metadata changes (chmod, chown, utimes, xattr)
/// that Landlock does not mediate.
pub(crate) unsafe fn enter_read_only_view(view: &WritableView) -> IoResult<()> {
    const MOUNT_ATTR_RDONLY: u64 = 1;
    const MOUNT_ATTR_NODEV: u64 = 4;
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    const OPEN_TREE_CLONE: libc::c_uint = 1;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 4;
    let size = std::mem::size_of::<MountAttr>();
    let set = |attr_set, attr_clr| MountAttr {
        attr_set,
        attr_clr,
        propagation: 0,
        userns_fd: 0,
    };
    let syscall = |result: libc::c_long| check(result as libc::c_int);
    unsafe {
        check(libc::unshare(libc::CLONE_NEWNS))?;
        check(libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ))?;
        // Read-only and nodev everywhere: device nodes on any filesystem,
        // including the workdir, stay unusable. The private /dev re-enables
        // only its own harmless nodes.
        let read_only = set(MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV, 0);
        syscall(libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            c"/".as_ptr(),
            AT_RECURSIVE,
            &read_only as *const MountAttr,
            size,
        ))?;
        let writable = set(0, MOUNT_ATTR_RDONLY);
        for path in &view.paths {
            let tree = syscall(libc::syscall(
                libc::SYS_open_tree,
                libc::AT_FDCWD,
                path.as_ptr(),
                OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint | AT_RECURSIVE,
            ))?;
            let result = syscall(libc::syscall(
                libc::SYS_mount_setattr,
                tree,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint | AT_RECURSIVE,
                &writable as *const MountAttr,
                size,
            ))
            .and_then(|_| {
                syscall(libc::syscall(
                    libc::SYS_move_mount,
                    tree,
                    c"".as_ptr(),
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    MOVE_MOUNT_F_EMPTY_PATH,
                ))
            });
            libc::close(tree);
            result?;
        }
        private_dev()?;
        // A null-device stdin is reopened from the private, read-only
        // /dev, so not even a root caller's workload holds the host node.
        let mut stat = std::mem::zeroed::<libc::stat>();
        if libc::fstat(0, &mut stat) == 0
            && stat.st_mode & libc::S_IFMT == libc::S_IFCHR
            && crate::run::is_null_device(stat.st_rdev)
        {
            let null = check(libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY))?;
            check(libc::dup2(null, 0))?;
            libc::close(null);
        }
        check(libc::chdir(view.workdir.as_ptr()))?;
    }
    Ok(())
}

/// pre_exec (inside the private mount namespace): replace /dev with a
/// minimal tmpfs, as containers do. Only harmless host nodes are bound in;
/// there is no /dev/tty or /dev/pts, so the workload cannot reach the host
/// terminal or other device nodes, whose ioctls the read-only view and
/// Landlock ABI < 5 do not restrict.
unsafe fn private_dev() -> IoResult<()> {
    const OPEN_TREE_CLONE: libc::c_uint = 1;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 4;
    const MOUNT_ATTR_NODEV: u64 = 4;
    const NODES: [(&CStr, &CStr); 5] = [
        (c"/dev/null", c"null"),
        (c"/dev/zero", c"zero"),
        (c"/dev/full", c"full"),
        (c"/dev/random", c"random"),
        (c"/dev/urandom", c"urandom"),
    ];
    let syscall = |result: libc::c_long| check(result as libc::c_int);
    unsafe {
        // Detach the host nodes before the new /dev hides them.
        let mut trees = [-1; NODES.len()];
        for (tree, (host, _)) in trees.iter_mut().zip(NODES) {
            *tree = syscall(libc::syscall(
                libc::SYS_open_tree,
                libc::AT_FDCWD,
                host.as_ptr(),
                OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
            ))?;
        }
        check(libc::mount(
            c"tmpfs".as_ptr(),
            c"/dev".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC,
            c"mode=0755,size=64k".as_ptr().cast(),
        ))?;
        let dev = check(libc::open(
            c"/dev".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        ))?;
        let usable = MountAttr {
            attr_set: 0,
            attr_clr: MOUNT_ATTR_NODEV,
            propagation: 0,
            userns_fd: 0,
        };
        for (tree, (_, name)) in trees.into_iter().zip(NODES) {
            syscall(libc::syscall(
                libc::SYS_mount_setattr,
                tree,
                c"".as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint,
                &usable as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            ))?;
            let flags = libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC;
            let file = check(libc::openat(dev, name.as_ptr(), flags, 0o666))?;
            libc::close(file);
            syscall(libc::syscall(
                libc::SYS_move_mount,
                tree,
                c"".as_ptr(),
                dev,
                name.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH,
            ))?;
            libc::close(tree);
        }
        for (target, name) in [
            (c"/proc/self/fd", c"fd"),
            (c"/proc/self/fd/0", c"stdin"),
            (c"/proc/self/fd/1", c"stdout"),
            (c"/proc/self/fd/2", c"stderr"),
        ] {
            check(libc::symlinkat(target.as_ptr(), dev, name.as_ptr()))?;
        }
        check(libc::mkdirat(dev, c"shm".as_ptr(), 0o1777))?;
        libc::close(dev);
        check(libc::mount(
            c"tmpfs".as_ptr(),
            c"/dev/shm".as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=1777,size=64m".as_ptr().cast(),
        ))?;
        check(libc::mount(
            std::ptr::null(),
            c"/dev".as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOEXEC,
            std::ptr::null(),
        ))?;
    }
    Ok(())
}

/// pre_exec, first step: caught handlers inherited from the caller must
/// not run in the forked child (locks held by vanished threads); reset them
/// to the default. Ignored signals stay ignored, as exec would keep them.
pub(crate) unsafe fn reset_caught_handlers() {
    unsafe {
        for signal in 1..=libc::SIGRTMAX() {
            let mut action = std::mem::zeroed::<libc::sigaction>();
            if libc::sigaction(signal, std::ptr::null(), &mut action) == 0
                && action.sa_sigaction != libc::SIG_DFL
                && action.sa_sigaction != libc::SIG_IGN
            {
                libc::signal(signal, libc::SIG_DFL);
            }
        }
    }
}

/// pre_exec: join namespaces held by another process. User namespace first:
/// it grants the capability needed to join the network namespace it owns.
pub(crate) unsafe fn join_namespaces(user: RawFd, net: RawFd) -> IoResult<()> {
    unsafe {
        check(libc::setns(user, libc::CLONE_NEWUSER))?;
        check(libc::setns(net, libc::CLONE_NEWNET))?;
    }
    Ok(())
}

/// pre_exec: the workload gets no capabilities, even when the caller is
/// root and therefore maps to UID 0 inside the user namespace. Root's
/// automatic capabilities are disabled and locked, ambient capabilities
/// cleared and the bounding set emptied, so exec yields an empty set.
/// (Creating the user namespace already emptied the inheritable set.)
pub(crate) unsafe fn drop_capabilities() -> IoResult<()> {
    const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
    const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
    unsafe {
        check(libc::prctl(
            libc::PR_SET_SECUREBITS,
            SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
        ))?;
        check(libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ))?;
        let mut cap = 0;
        while libc::prctl(libc::PR_CAPBSET_READ, cap) >= 0 {
            check(libc::prctl(libc::PR_CAPBSET_DROP, cap))?;
            cap += 1;
        }
    }
    Ok(())
}

/// pre_exec: close every descriptor from `first` on. close_range needs
/// Linux 5.9, which the silo backend does not otherwise require.
unsafe fn close_from(first: libc::c_int) -> IoResult<()> {
    unsafe {
        if libc::syscall(libc::SYS_close_range, first as u32, u32::MAX, 0u32) == 0 {
            return Ok(());
        }
        close_each_from(first)
    }
}

unsafe fn close_each_from(first: libc::c_int) -> IoResult<()> {
    // Closing while listing can skip entries; list again until a pass
    // finds nothing left, as glibc's closefrom fallback does. Errors from
    // close itself leave the descriptor closed (or never open) on Linux.
    while unsafe {
        for_each_open_descriptor(first, |fd| {
            libc::close(fd);
            Ok(())
        })?
    } {}
    Ok(())
}

/// pre_exec: call `f` for every open descriptor >= `first`, found through
/// /proc/self/fd with raw getdents64 (no allocation). Unlike an
/// RLIMIT_NOFILE bound, this sees descriptors opened before the limit was
/// lowered. A listing that cannot start or is incomplete is an error,
/// never a silent success. Returns whether `f` was called at all.
unsafe fn for_each_open_descriptor(
    first: libc::c_int,
    mut f: impl FnMut(libc::c_int) -> IoResult<()>,
) -> IoResult<bool> {
    unsafe {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        // No rlimit-bounded fallback: a descriptor may lie above even a
        // lowered hard limit, so an unlistable table is an error.
        let dir = check(libc::open(c"/proc/self/fd".as_ptr(), flags))?;
        let result = list_descriptors(dir, first, &mut f);
        libc::close(dir);
        result
    }
}

/// The getdents64 loop of for_each_open_descriptor over an open `dir`.
unsafe fn list_descriptors(
    dir: libc::c_int,
    first: libc::c_int,
    f: &mut impl FnMut(libc::c_int) -> IoResult<()>,
) -> IoResult<bool> {
    unsafe {
        let mut called = false;
        let mut buf = [0u64; 512];
        loop {
            let n = libc::syscall(libc::SYS_getdents64, dir, buf.as_mut_ptr(), 4096usize);
            if n == 0 {
                return Ok(called);
            }
            if n < 0 {
                let error = Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let bytes = buf.as_ptr().cast::<u8>();
            let mut offset = 0usize;
            while offset < n as usize {
                // linux_dirent64: d_ino u64, d_off i64, d_reclen u16,
                // d_type u8, then the NUL-terminated name.
                let entry = bytes.add(offset);
                let reclen = entry.add(16).cast::<u16>().read_unaligned() as usize;
                let mut name = entry.add(19);
                let mut fd: libc::c_int = 0;
                let mut digits = 0;
                while (*name).is_ascii_digit() {
                    fd = fd
                        .saturating_mul(10)
                        .saturating_add((*name - b'0') as libc::c_int);
                    name = name.add(1);
                    digits += 1;
                }
                if digits > 0 && *name == 0 && fd >= first && fd != dir {
                    f(fd)?;
                    called = true;
                }
                offset += reclen;
            }
        }
    }
}

/// Exit like the child whose wait status is `status`. A namespace init
/// cannot signal itself, so it falls back to the shell convention 128+n.
unsafe fn relay_exit(status: libc::c_int) -> ! {
    unsafe {
        if libc::WIFSIGNALED(status) {
            let signal = libc::WTERMSIG(status);
            libc::signal(signal, libc::SIG_DFL);
            libc::kill(libc::getpid(), signal);
            libc::_exit(128 + signal);
        }
        libc::_exit(libc::WEXITSTATUS(status));
    }
}

/// Wait for `child`, reaping any other exited processes on the way.
unsafe fn wait_for(child: libc::pid_t) -> ! {
    unsafe {
        // Hold no pipes: spawn sees exec (or its error) from the workload,
        // and output ends when the workload's descendants close it.
        if close_from(0).is_err() {
            libc::_exit(125);
        }
        loop {
            let mut status = 0;
            let pid = libc::waitpid(-1, &mut status, 0);
            if pid == child {
                relay_exit(status);
            }
            if pid < 0 && *libc::__errno_location() != libc::EINTR {
                libc::_exit(125);
            }
        }
    }
}

/// pre_exec (with CAP_SYS_ADMIN in the current user namespace), last step:
/// run the workload in a new PID namespace under a minimal init. When the
/// workload exits, init exits with its status and the kernel kills every
/// process left in the namespace, including descendants that left the
/// process group. The workload is PID 2, so its own signal semantics are
/// unchanged. The forked-off ancestors only relay the exit status.
pub(crate) unsafe fn enter_pid_namespace() -> IoResult<()> {
    unsafe {
        // The wrappers wait for their children: a caller's ignored SIGCHLD
        // or reaping handler must not take the workload's status first.
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        check(libc::unshare(libc::CLONE_NEWPID))?;
        let init = check(libc::fork())?;
        if init != 0 {
            wait_for(init);
        }
        let workload = libc::fork();
        if workload < 0 {
            libc::_exit(125);
        }
        if workload != 0 {
            wait_for(workload);
        }
    }
    Ok(())
}

/// pre_exec: no descriptor beyond stdio survives exec.
pub(crate) unsafe fn close_extra_descriptors() -> IoResult<()> {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    unsafe {
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) == 0 {
            return Ok(());
        }
        for_each_open_descriptor(3, |fd| {
            if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                let error = Error::last_os_error();
                // Closed since it was listed: nothing left to inherit.
                if error.raw_os_error() != Some(libc::EBADF) {
                    return Err(error);
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// pre_exec: listen on loopback inside the workload namespace and pass the
/// listeners to the supervisor. The port is free: the namespace is new.
unsafe fn send_listeners(channel: RawFd, port: u16) -> IoResult<()> {
    unsafe {
        let v4 = check(libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        ))?;
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = port.to_be();
        addr.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
        check(libc::bind(
            v4,
            (&addr as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&addr) as libc::socklen_t,
        ))?;
        check(libc::listen(v4, 1024))?;
        let mut fds = [v4, -1];
        // IPv6 is optional: it may be disabled on the host kernel.
        let v6 = libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if v6 >= 0 {
            let one: libc::c_int = 1;
            let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_port = port.to_be();
            addr.sin6_addr.s6_addr = std::net::Ipv6Addr::LOCALHOST.octets();
            if libc::setsockopt(
                v6,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            ) == 0
                && libc::bind(
                    v6,
                    (&addr as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of_val(&addr) as libc::socklen_t,
                ) == 0
                && libc::listen(v6, 1024) == 0
            {
                fds[1] = v6;
            } else {
                libc::close(v6);
            }
        }
        let count = if fds[1] < 0 { 1 } else { 2 };
        let mut control = [0u64; 8];
        let space = libc::CMSG_SPACE((count * std::mem::size_of::<RawFd>()) as u32) as usize;
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN((count * std::mem::size_of::<RawFd>()) as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast::<RawFd>(), count);
        let sent = libc::sendmsg(channel, &msg, libc::MSG_NOSIGNAL);
        let error = Error::last_os_error();
        for fd in &fds[..count] {
            libc::close(*fd);
        }
        if sent != 1 {
            return Err(error);
        }
    }
    Ok(())
}

fn receive_listeners(channel: &OwnedFd) -> Result<Vec<std::net::TcpListener>> {
    let mut control = [0u64; 8];
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    // SAFETY: msghdr points at live stack buffers for the duration of recvmsg.
    let received = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        // The child sent before exec, and spawn returns only after exec.
        let n = libc::recvmsg(
            channel.as_raw_fd(),
            &mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        );
        if n != 1 || msg.msg_flags & libc::MSG_CTRUNC != 0 {
            bail!("workload namespace did not provide the proxy listener");
        }
        let mut listeners = Vec::new();
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    let fd = OwnedFd::from_raw_fd(data.add(i).read_unaligned());
                    listeners.push(std::net::TcpListener::from(fd));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        listeners
    };
    if received.is_empty() {
        bail!("workload namespace did not provide the proxy listener");
    }
    Ok(received)
}

mod landlock {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    const CREATE_RULESET_VERSION: u32 = 1;
    const RULE_PATH_BENEATH: u32 = 1;
    const WRITE_FILE: u64 = 1 << 1;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_BLOCK: u64 = 1 << 11;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13;
    const TRUNCATE: u64 = 1 << 14;
    const IOCTL_DEV: u64 = 1 << 15;
    const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    const SCOPE_SIGNAL: u64 = 1 << 1;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }
    #[repr(C, packed)]
    struct PathBeneath {
        allowed_access: u64,
        parent_fd: i32,
    }

    pub fn abi() -> i64 {
        // SAFETY: a version query passes no pointers.
        unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        }
    }

    /// Build (in the parent) a ruleset that denies writes except beneath
    /// `dirs` and to `files`. Signals leaving the sandbox are scoped when
    /// the kernel supports it (Landlock ABI 6, Linux 6.12).
    /// Returns the ruleset and the rights granted beneath writable dirs.
    pub fn write_ruleset(dirs: &[&Path], files: &[&Path]) -> Result<(OwnedFd, u64)> {
        let abi = abi();
        if abi < 1 {
            bail!(
                "Landlock is unavailable ({}); refusing unsandboxed execution",
                Error::last_os_error()
            );
        }
        // ABI 3 (Linux 6.2) is the first to mediate truncate and O_TRUNC.
        if abi < 3 {
            bail!("Landlock ABI {abi} cannot restrict truncation; Linux 6.2+ is required");
        }
        let write = WRITE_FILE | TRUNCATE;
        // ABI 5 (Linux 6.10) mediates device ioctls, granted only on the
        // listed files. Older ABIs rely on the nodev view and private /dev.
        let (file_rights, ioctl) = if abi >= 5 {
            (write | IOCTL_DEV, IOCTL_DEV)
        } else {
            (write, 0)
        };
        let dir_rights = write
            | REMOVE_DIR
            | REMOVE_FILE
            | MAKE_CHAR
            | MAKE_DIR
            | MAKE_REG
            | MAKE_SOCK
            | MAKE_FIFO
            | MAKE_BLOCK
            | MAKE_SYM
            | REFER;
        let attr = RulesetAttr {
            handled_access_fs: dir_rights | ioctl,
            handled_access_net: 0,
            scoped: if abi >= 6 {
                SCOPE_SIGNAL | SCOPE_ABSTRACT_UNIX_SOCKET
            } else {
                0
            },
        };
        // SAFETY: attr is a live, correctly sized ruleset attribute.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if fd < 0 {
            return Err(Error::last_os_error()).context("create Landlock ruleset");
        }
        // SAFETY: the kernel returned a new descriptor we exclusively own.
        let ruleset = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        let rules = dirs
            .iter()
            .map(|p| (*p, dir_rights))
            .chain(files.iter().map(|p| (*p, file_rights)));
        for (path, rights) in rules {
            let file = std::fs::File::options()
                .read(true)
                .custom_flags(libc::O_PATH)
                .open(path)
                .with_context(|| format!("open {}", path.display()))?;
            let rule = PathBeneath {
                allowed_access: rights,
                parent_fd: file.as_raw_fd(),
            };
            // SAFETY: rule is a live path-beneath attribute; both fds are open.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset.as_raw_fd(),
                    RULE_PATH_BENEATH,
                    &rule as *const PathBeneath,
                    0u32,
                )
            };
            if result != 0 {
                return Err(Error::last_os_error())
                    .with_context(|| format!("Landlock rule for {}", path.display()));
            }
        }
        Ok((above_stdio(ruleset)?, dir_rights))
    }

    /// pre_exec: grant `rights` beneath a directory that only exists in the
    /// child's mount namespace, before the ruleset is enforced.
    pub unsafe fn allow_dir(ruleset: RawFd, path: &CStr, rights: u64) -> IoResult<()> {
        unsafe {
            let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
            let dir = check(libc::open(path.as_ptr(), flags))?;
            let rule = PathBeneath {
                allowed_access: rights,
                parent_fd: dir,
            };
            let result = libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset,
                RULE_PATH_BENEATH,
                &rule as *const PathBeneath,
                0u32,
            );
            let error = Error::last_os_error();
            libc::close(dir);
            if result != 0 {
                return Err(error);
            }
        }
        Ok(())
    }

    /// pre_exec: requires no_new_privs.
    pub unsafe fn restrict_self(ruleset: RawFd) -> IoResult<()> {
        unsafe {
            if libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) != 0 {
                return Err(Error::last_os_error());
            }
        }
        Ok(())
    }
}

mod seccomp {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const JGE_K: u16 = 0x35;
    const AND_K: u16 = 0x54;
    const RET_K: u16 = 0x06;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;

    fn op(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    /// Refuse socket families that are not confined by the network
    /// namespace (filesystem Unix sockets, vsock, ...), datagram socket
    /// pairs, io_uring, which can create sockets without these calls, and
    /// key management, since the caller's session keyring is inherited.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn socket_filter() -> Result<Vec<libc::sock_filter>> {
        // x32 system calls share the x86_64 audit architecture.
        Ok(build(ARCH, cfg!(target_arch = "x86_64")))
    }

    /// Jump offsets are relative, so the optional x32 guard does not move
    /// any other jump target.
    fn build(arch: u32, x32_guard: bool) -> Vec<libc::sock_filter> {
        let mut filter = vec![
            op(LD_W_ABS, 4, 0, 0),
            op(JEQ_K, arch, 1, 0),
            op(RET_K, RET_KILL_PROCESS, 0, 0),
            op(LD_W_ABS, 0, 0, 0),
        ];
        if x32_guard {
            filter.push(op(JGE_K, 0x4000_0000, 18, 0));
        }
        let flags = (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u32;
        filter.extend([
            op(JEQ_K, libc::SYS_socket as u32, 6, 0),
            op(JEQ_K, libc::SYS_socketpair as u32, 10, 0),
            op(JEQ_K, libc::SYS_io_uring_setup as u32, 15, 0),
            // The caller's session keyring survives namespace creation.
            op(JEQ_K, libc::SYS_keyctl as u32, 14, 0),
            op(JEQ_K, libc::SYS_add_key as u32, 13, 0),
            op(JEQ_K, libc::SYS_request_key as u32, 12, 0),
            op(RET_K, RET_ALLOW, 0, 0),
            // socket: seccomp_data.args[0] (domain), low word.
            op(LD_W_ABS, 16, 0, 0),
            op(JEQ_K, libc::AF_INET as u32, 8, 0),
            op(JEQ_K, libc::AF_INET6 as u32, 7, 0),
            op(JEQ_K, libc::AF_NETLINK as u32, 6, 0),
            op(RET_K, RET_ERRNO | libc::EACCES as u32, 0, 0),
            // socketpair: args[1] (type) without flags. Connected stream and
            // seqpacket pairs ignore destinations; a datagram end could be
            // redirected to a host Unix socket with connect or sendto.
            op(LD_W_ABS, 24, 0, 0),
            op(AND_K, !flags, 0, 0),
            op(JEQ_K, libc::SOCK_STREAM as u32, 2, 0),
            op(JEQ_K, libc::SOCK_SEQPACKET as u32, 1, 0),
            op(RET_K, RET_ERRNO | libc::EACCES as u32, 0, 0),
            op(RET_K, RET_ALLOW, 0, 0),
            op(RET_K, RET_ERRNO | libc::EPERM as u32, 0, 0),
        ]);
        filter
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn socket_filter() -> Result<Vec<libc::sock_filter>> {
        bail!("socket filter is not implemented for this architecture");
    }

    /// pre_exec: must be the last restriction before exec.
    pub unsafe fn install(filter: &[libc::sock_filter]) -> IoResult<()> {
        let program = libc::sock_fprog {
            len: filter.len() as libc::c_ushort,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        unsafe {
            check(libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            ))?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Minimal classic-BPF evaluator for the instructions used above,
        /// rejecting out-of-range jumps like the kernel verifier.
        fn run_filter(filter: &[libc::sock_filter], arch: u32, nr: u32, a0: u32, a1: u32) -> u32 {
            let (mut pc, mut acc) = (0usize, 0u32);
            loop {
                let ins = filter[pc];
                let (jt, jf) = (ins.jt as usize, ins.jf as usize);
                pc += 1;
                match ins.code {
                    LD_W_ABS => {
                        acc = match ins.k {
                            0 => nr,
                            4 => arch,
                            16 => a0,
                            24 => a1,
                            k => panic!("load {k}"),
                        }
                    }
                    AND_K => acc &= ins.k,
                    RET_K => return ins.k,
                    JEQ_K | JGE_K => {
                        let taken = if ins.code == JEQ_K {
                            acc == ins.k
                        } else {
                            acc >= ins.k
                        };
                        pc += if taken { jt } else { jf };
                    }
                    code => panic!("opcode {code:#x}"),
                }
                assert!(pc < filter.len(), "jump beyond program end");
            }
        }

        #[test]
        fn filter_decisions_for_both_layouts() {
            for x32_guard in [true, false] {
                let filter = build(ARCH, x32_guard);
                let socket = libc::SYS_socket as u32;
                let eval = |arch, nr, arg0| run_filter(&filter, arch, nr, arg0, 0);
                assert_eq!(eval(ARCH ^ 1, socket, 0), RET_KILL_PROCESS);
                for family in [libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK] {
                    assert_eq!(eval(ARCH, socket, family as u32), RET_ALLOW);
                }
                for family in [libc::AF_UNIX, libc::AF_VSOCK, libc::AF_PACKET] {
                    assert_eq!(
                        eval(ARCH, socket, family as u32),
                        RET_ERRNO | libc::EACCES as u32
                    );
                }
                let (socketpair, unix) = (libc::SYS_socketpair as u32, libc::AF_UNIX as u32);
                let pair = |k: i32| run_filter(&filter, ARCH, socketpair, unix, k as u32);
                for kind in [libc::SOCK_STREAM, libc::SOCK_SEQPACKET] {
                    assert_eq!(pair(kind), RET_ALLOW);
                    assert_eq!(pair(kind | libc::SOCK_CLOEXEC), RET_ALLOW);
                }
                for kind in [libc::SOCK_DGRAM, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC] {
                    assert_eq!(pair(kind), RET_ERRNO | libc::EACCES as u32);
                }
                for nr in [
                    libc::SYS_io_uring_setup,
                    libc::SYS_keyctl,
                    libc::SYS_add_key,
                    libc::SYS_request_key,
                ] {
                    assert_eq!(eval(ARCH, nr as u32, 0), RET_ERRNO | libc::EPERM as u32);
                }
                assert_eq!(eval(ARCH, libc::SYS_getpid as u32, 0), RET_ALLOW);
                let x32 = eval(ARCH, 0x4000_0000 | socket, libc::AF_UNIX as u32);
                if x32_guard {
                    assert_eq!(x32, RET_ERRNO | libc::EPERM as u32);
                }
            }
        }
    }
}

/// `world network exec`: private network namespace plus egress proxy.
pub(crate) async fn run(options: RunOptions, cancel: CancellationToken) -> Result<i32> {
    let deadline = Instant::now() + options.timeout;
    // Before this function opens any descriptor that could land on a
    // closed fd 0 and make it look like an unsupported stdin.
    let stdin = run::pin_linux_stdin()?;
    let dir = run::workdir(&options.workdir)?;
    // The private /dev hides anything beneath the host /dev.
    if dir.starts_with("/dev") {
        bail!("workdir under /dev is not supported; use a regular filesystem");
    }
    let mut parent = std::env::temp_dir().canonicalize()?;
    if parent.starts_with("/dev") {
        parent = "/tmp".into();
    }
    let temp = tempfile::Builder::new()
        .prefix("world-network-")
        .tempdir_in(parent)?;
    let temp_path = temp.path().canonicalize()?;
    let (ruleset, dir_rights) =
        landlock::write_ruleset(&[&dir, &temp_path], &[Path::new("/dev/null")])?;
    let filter = seccomp::socket_filter()?;
    let prepared = if options.policy.allow.is_empty() {
        None
    } else {
        tokio::select! {biased;
            _=cancel.cancelled()=>return Ok(124),
            _=sleep_until(deadline)=>return Ok(124),
            p=Proxy::prepare(&options.policy)=>Some(p?),
        }
    };
    // Every port is free in the new namespace; stay inside its default
    // ephemeral range (the kernel's own choice for bind(0)), which services
    // with fixed ports avoid, as the macOS backend's host proxy port does.
    let port: u16 = rand::thread_rng().gen_range(32768..=60999);
    let channel = match prepared {
        None => None,
        Some(_) => {
            let mut fds = [0; 2];
            // SAFETY: socketpair writes two descriptors into fds on success.
            check(unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            })?;
            // SAFETY: both descriptors are new and exclusively owned here.
            let (parent, child) =
                unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            Some((above_stdio(parent)?, above_stdio(child)?))
        }
    };
    let mut cmd = Command::new(&options.command[0]);
    cmd.args(&options.command[1..])
        .current_dir(&dir)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", &temp_path)
        .env("TMPDIR", &temp_path)
        .env("PWD", &dir)
        .env("LANG", "C.UTF-8")
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    if let Some(prepared) = &prepared {
        for key in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "all_proxy",
        ] {
            cmd.env(key, prepared.url(port));
        }
    }
    let maps = IdMaps::current();
    let view = WritableView::new(&dir, &[&temp_path])?;
    let ruleset_fd = ruleset.as_raw_fd();
    let child_channel = channel.as_ref().map(|(_, child)| child.as_raw_fd());
    // SAFETY: the closure only makes raw system calls on data prepared above.
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            reset_caught_handlers();
            enter_new_namespaces(&maps)?;
            // Private System V IPC and POSIX message queues.
            check(libc::unshare(libc::CLONE_NEWIPC))?;
            enter_read_only_view(&view)?;
            landlock::allow_dir(ruleset_fd, c"/dev/shm", dir_rights)?;
            if let Some(channel) = child_channel {
                send_listeners(channel, port)?;
            }
            close_extra_descriptors()?;
            check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
            landlock::restrict_self(ruleset_fd)?;
            drop_capabilities()?;
            seccomp::install(&filter)?;
            enter_pid_namespace()
        });
    }
    if cancel.is_cancelled() || Instant::now() >= deadline {
        return Ok(124);
    }
    // The validated descriptor itself, never whatever fd 0 is now. A
    // closed stdin becomes the null device, reopened inside the sandbox.
    cmd.stdin(match stdin {
        Some(fd) => std::process::Stdio::from(fd),
        None => std::process::Stdio::null(),
    });
    let workload = run::spawn(cmd)?;
    drop(ruleset);
    let mut proxy = match (prepared, channel) {
        (Some(prepared), Some((parent, child))) => {
            drop(child);
            Some(prepared.serve(port, receive_listeners(&parent)?)?)
        }
        _ => None,
    };
    let result = run::wait(workload, deadline, cancel, &mut proxy, None).await;
    if let Some(proxy) = &mut proxy {
        proxy.close().await;
    }
    result
}

/// Identity of a process holding a World's namespaces. Start time and
/// namespace inodes guard against PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holder {
    pub pid: u32,
    start_time: u64,
    user_ns: u64,
    net_ns: u64,
}

fn start_time(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // Fields after the parenthesized command name; start time is field 22.
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|v| v.parse().ok())
        .context("parse process start time")
}

impl Holder {
    pub(crate) fn observe(pid: u32) -> Result<Self> {
        let inode = |kind: &str| -> Result<u64> {
            Ok(std::fs::metadata(format!("/proc/{pid}/ns/{kind}"))?.ino())
        };
        Ok(Self {
            pid,
            start_time: start_time(pid)?,
            user_ns: inode("user")?,
            net_ns: inode("net")?,
        })
    }

    /// Open the held namespaces, verifying they still belong to this holder.
    pub(crate) fn open(&self) -> Result<(OwnedFd, OwnedFd)> {
        self.verify()?
            .context("World namespace holder is no longer running")
    }

    /// `Ok(None)` only when the holder is definitely gone: the process no
    /// longer exists, or its namespaces or start time differ from the
    /// record. Anything else (e.g. EMFILE) is an error, so callers keep the
    /// record instead of forgetting a live holder.
    pub(crate) fn verify(&self) -> Result<Option<(OwnedFd, OwnedFd)>> {
        let gone = |err: &std::io::Error| {
            err.kind() == std::io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH)
        };
        let open = |kind: &str, expected: u64| -> Result<Option<OwnedFd>> {
            let file = match std::fs::File::open(format!("/proc/{}/ns/{kind}", self.pid)) {
                Ok(file) => file,
                Err(err) if gone(&err) => return Ok(None),
                Err(err) => return Err(err.into()),
            };
            Ok((file.metadata()?.ino() == expected).then(|| file.into()))
        };
        let Some(user) = open("user", self.user_ns)? else {
            return Ok(None);
        };
        let Some(net) = open("net", self.net_ns)? else {
            return Ok(None);
        };
        // Checked after opening: descriptors keep the namespaces alive.
        match start_time(self.pid) {
            Ok(time) if time == self.start_time => Ok(Some((user, net))),
            Ok(_) => Ok(None),
            Err(err) if err.downcast_ref::<std::io::Error>().is_some_and(gone) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// Forked child of start_holder; never returns. The double fork reparents
/// the holder to init (or a subreaper), which reaps it after teardown, so a
/// long-lived caller of setup never accumulates zombies.
unsafe fn holder_process(
    maps: &IdMaps,
    report: RawFd,
    ack: RawFd,
    report_read: RawFd,
    ack_write: RawFd,
) -> ! {
    unsafe {
        if libc::setsid() < 0 {
            libc::_exit(125);
        }
        let holder = libc::fork();
        if holder != 0 {
            libc::_exit(if holder > 0 { 0 } else { 125 });
        }
        libc::chdir(c"/".as_ptr());
        // The report pipe becomes fd 0 and the acknowledgment pipe fd 1.
        // The other ends are closed explicitly, so the wait below sees EOF
        // if the caller goes away, even if the bulk cleanup fails.
        if libc::dup2(report, 0) < 0 || libc::dup2(ack, 1) < 0 {
            libc::_exit(125);
        }
        for fd in [report, ack, report_read, ack_write] {
            libc::close(fd);
        }
        let send = |value: libc::pid_t| {
            let size = std::mem::size_of_val(&value);
            libc::write(0, (&value as *const libc::pid_t).cast(), size) == size as isize
        };
        // The holder never execs, so close-on-exec does not apply: drop
        // every other inherited descriptor, so it never keeps the caller's
        // sockets or files alive. A failure is reported only after the PID
        // has been pinned, so the caller can always identify and reap us.
        let cleanup = close_from(2);
        // Signals are still blocked (see start_holder); reset every
        // disposition before unblocking them.
        reset_signals();
        // PID first, so the caller can pin (and, if we fail and it adopted
        // us as a subreaper, reap) the holder; then the result.
        if !send(libc::getpid()) {
            libc::_exit(125);
        }
        // One byte from the caller, or exit on EOF: the caller went away.
        let expect = || {
            let mut byte = 0u8;
            loop {
                match libc::read(1, (&mut byte as *mut u8).cast(), 1) {
                    1 => return,
                    n if n < 0 && *libc::__errno_location() == libc::EINTR => {}
                    _ => libc::_exit(125),
                }
            }
        };
        // Pinned: never run unpinned.
        expect();
        if let Err(error) = cleanup.and_then(|()| enter_new_namespaces(maps)) {
            send(-error.raw_os_error().unwrap_or(libc::EIO));
            libc::_exit(125);
        }
        libc::prctl(libc::PR_SET_NAME, c"world-holder".as_ptr());
        if !send(0) {
            libc::_exit(125);
        }
        // Recorded: a holder whose setup died before persisting its record
        // could never be found or torn down, so it exits instead.
        expect();
        libc::close(1);
        hold()
    }
}

/// Start a detached process that keeps new namespaces alive.
pub(crate) fn start_holder() -> Result<StartedHolder> {
    let maps = IdMaps::current();
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two new descriptors into fds on success.
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: both descriptors are new and exclusively owned here.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let (read, write) = (above_stdio(read)?, above_stdio(write)?);
    let report = write.as_raw_fd();
    // Parent -> holder: "pinned", then "committed". The holder waits for
    // them, so it is alive (its PID not reusable) while it is pinned. A
    // socket, so the parent can send with MSG_NOSIGNAL: a dead holder must
    // yield EPIPE, not a SIGPIPE that kills the caller.
    // SAFETY: socketpair writes two new descriptors into fds on success.
    check(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })?;
    // SAFETY: both descriptors are new and exclusively owned here.
    let (ack_read, ack_write) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let (ack_read, ack_write) = (above_stdio(ack_read)?, above_stdio(ack_write)?);
    let ack = ack_read.as_raw_fd();
    let (report_read, ack_write_fd) = (read.as_raw_fd(), ack_write.as_raw_fd());
    // A raw double fork rather than Command: no exec and no exec-status
    // pipe, so the holder can report its PID and wait to be pinned even
    // when a later step fails, and any embedding executable works.
    // Block every signal across the fork, so no caller handler can run in
    // the child before the holder has reset all dispositions (it unblocks
    // only afterwards); this thread's mask is restored right after.
    // SAFETY: sigset operations on live local sets.
    let mut all = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut previous);
    }
    // SAFETY: after fork the child makes only raw system calls on data
    // prepared above and never returns.
    let intermediate = unsafe { libc::fork() };
    if intermediate == 0 {
        unsafe { holder_process(&maps, report, ack, report_read, ack_write_fd) }
    }
    // SAFETY: restores this thread's own previous mask.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
    let intermediate = check(intermediate)?;
    // Reap the intermediate, which exits at once. A caller that ignores
    // SIGCHLD or reaps children itself may already have done so (ECHILD).
    let mut status = 0;
    // SAFETY: status is a live int; the PID is our own unreaped child.
    while unsafe { libc::waitpid(intermediate, &mut status, 0) } < 0
        && Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
    {}
    drop((write, ack_read));
    let mut report = std::fs::File::from(read);
    // read_exact retries EINTR and short reads.
    let mut next = || -> Result<libc::pid_t> {
        let mut bytes = [0u8; std::mem::size_of::<libc::pid_t>()];
        std::io::Read::read_exact(&mut report, &mut bytes)
            .context("World namespace holder did not start")?;
        Ok(libc::pid_t::from_ne_bytes(bytes))
    };
    let pid = next()?;
    // Pin the holder before it continues: it is blocked waiting for the
    // acknowledgment below, so it is alive and its PID cannot be reused.
    // SAFETY: pidfd_open takes plain integers and returns a new descriptor.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if pidfd < 0 {
        let error = Error::last_os_error();
        // Only a kernel without pidfds (before 5.3) may go on unpinned, as
        // teardown then does too. On any other failure, return without the
        // acknowledgment: the holder sees EOF and exits before setup.
        if error.raw_os_error() != Some(libc::ENOSYS) {
            return Err(error).context("pin World namespace holder");
        }
    }
    // SAFETY: a non-negative result is a new descriptor we exclusively own.
    let pidfd = (pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) });
    // Let the holder continue only now that it is pinned. If that fails,
    // closing the pipe makes the waiting holder exit before any setup.
    if let Err(error) = send_byte(&ack_write, b'p') {
        drop(ack_write);
        reap_if_child(pidfd.as_ref());
        return Err(error).context("start World namespace holder");
    }
    let status = next().inspect_err(|_| reap_if_child(pidfd.as_ref()))?;
    if status != 0 {
        // A subreaper caller adopted the failed holder: reap it.
        reap_if_child(pidfd.as_ref());
        return Err(Error::from_raw_os_error(-status)).context("start World namespace holder");
    }
    let started = |holder| StartedHolder {
        holder,
        pid,
        pidfd,
        commit: Some(ack_write),
    };
    match Holder::observe(pid as u32) {
        Ok(holder) => Ok(started(holder)),
        Err(err) => {
            let unrecorded = started(Holder {
                pid: pid as u32,
                start_time: 0,
                user_ns: 0,
                net_ns: 0,
            });
            match unrecorded.kill() {
                Ok(()) => Err(err),
                Err(kill) => Err(err.context(format!("could not stop holder {pid}: {kill}"))),
            }
        }
    }
}

/// After killing a holder, reap it if it became our child: a caller that
/// is a child subreaper adopts the double-forked holder. Only
/// waitid(P_PIDFD) (Linux 5.4+) identifies exactly the holder; any wait by
/// numeric PID could consume an unrelated child that reused the PID after
/// someone else reaped the holder. So without it nothing is reaped, and a
/// subreaper caller on an older kernel must reap its own children (a
/// caller that does so, or init, leaves no zombie either way).
fn reap_if_child(pidfd: Option<&OwnedFd>) {
    const P_PIDFD: libc::idtype_t = 3;
    let Some(fd) = pidfd else {
        return;
    };
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let id = fd.as_raw_fd() as libc::id_t;
    // SAFETY: info is a live siginfo_t; the pidfd is open. ECHILD (not our
    // child) and EINVAL (no P_PIDFD) both mean there is nothing to do.
    while unsafe { libc::waitid(P_PIDFD, id, info.as_mut_ptr(), libc::WEXITED) } < 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

/// Reap a recorded holder that died (e.g. killed externally) and became
/// our zombie because this process is a child subreaper. A zombie keeps
/// its PID, so pidfd_open pins it; the recorded start time then confirms
/// the identity before waitid(P_PIDFD) reaps it without blocking. A
/// reused PID fails the start-time check and nothing is reaped.
pub(crate) fn reap_stale_holder(holder: &Holder) {
    // SAFETY: pidfd_open takes plain integers and returns a new descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, holder.pid as libc::pid_t, 0u32) };
    if fd < 0 {
        return;
    }
    // SAFETY: the kernel returned a new descriptor we exclusively own.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    if start_time(holder.pid).ok() != Some(holder.start_time) {
        return;
    }
    const P_PIDFD: libc::idtype_t = 3;
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let id = pidfd.as_raw_fd() as libc::id_t;
    let flags = libc::WEXITED | libc::WNOHANG;
    // SAFETY: info is a live siginfo_t; the pidfd is open.
    while unsafe { libc::waitid(P_PIDFD, id, info.as_mut_ptr(), flags) } < 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

/// Send one handshake byte to the holder, retrying EINTR. MSG_NOSIGNAL:
/// if the holder died this returns EPIPE instead of raising SIGPIPE.
fn send_byte(fd: &OwnedFd, byte: u8) -> IoResult<()> {
    loop {
        let data = (&byte as *const u8).cast();
        // SAFETY: sends one byte from a live local on an owned socket.
        match unsafe { libc::send(fd.as_raw_fd(), data, 1, libc::MSG_NOSIGNAL) } {
            1 => return Ok(()),
            _ => {
                let error = Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

/// A holder this process just started, pinned by pidfd when available.
pub(crate) struct StartedHolder {
    pub holder: Holder,
    pid: libc::pid_t,
    pidfd: Option<OwnedFd>,
    /// Until `commit`, the holder waits here and exits if this closes.
    commit: Option<OwnedFd>,
}

impl StartedHolder {
    /// Tell the holder its record has been persisted; it starts holding.
    /// Dropping without this (e.g. the process dies) makes it exit.
    /// On failure the holder has exited or will on EOF; its persisted
    /// record is then stale and the next setup replaces it.
    pub(crate) fn commit(mut self) -> IoResult<()> {
        match self.commit.take() {
            Some(fd) => send_byte(&fd, b'c'),
            None => Ok(()),
        }
    }

    /// Stop the holder if it cannot be recorded. Signalling the pinned
    /// pidfd opens nothing and reads nothing from /proc, so descriptor
    /// pressure cannot make this fail; without pidfd (before Linux 5.3)
    /// the PID is still ours, as the holder only exits when signalled.
    pub(crate) fn kill(&self) -> IoResult<()> {
        // SAFETY: plain-integer signalling; the pidfd is open when present.
        let result = unsafe {
            match &self.pidfd {
                Some(fd) => {
                    let null = std::ptr::null::<libc::siginfo_t>();
                    let fd = fd.as_raw_fd();
                    libc::syscall(libc::SYS_pidfd_send_signal, fd, libc::SIGKILL, null, 0u32)
                        as libc::c_int
                }
                None => libc::kill(self.pid, libc::SIGKILL),
            }
        };
        check(result)?;
        reap_if_child(self.pidfd.as_ref());
        Ok(())
    }
}

pub(crate) fn stop_holder(holder: &Holder) -> Result<()> {
    // Pin the process first, then verify it: the signal cannot reach a
    // process that reused the PID after verification.
    // SAFETY: pidfd_open takes plain integers and returns a new descriptor.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, holder.pid as libc::pid_t, 0u32) };
    if pidfd < 0 {
        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOSYS) {
            return Err(error).context("open holder pidfd");
        }
        // Before Linux 5.3: verify, then signal by PID. Only a PID reused
        // between these two calls could be hit.
        let _namespaces = holder.open()?;
        // SAFETY: kill takes plain integers.
        check(unsafe { libc::kill(holder.pid as libc::pid_t, libc::SIGKILL) })?;
        reap_if_child(None);
        return Ok(());
    }
    // SAFETY: the kernel returned a new descriptor we exclusively own.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
    let _namespaces = holder.open()?;
    // SAFETY: pidfd is open; no siginfo is passed.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if result != 0 {
        return Err(Error::last_os_error()).context("stop holder");
    }
    reap_if_child(Some(&pidfd));
    Ok(())
}

/// pre_exec: the holder's whole life. Default signal handling (so plain
/// kill stops it) and no descriptors: closing spawn's status pipe is what
/// tells the caller that setup succeeded.
/// Holder: default disposition for every signal, real-time ones included,
/// and none blocked. The caller's handlers must never run in this post-fork
/// process (locks held by vanished threads), and plain kill must stop it.
unsafe fn reset_signals() {
    unsafe {
        // glibc's internal signals (32 and 33, just below SIGRTMIN) refuse
        // the change with EINVAL; their handlers are glibc's own.
        for signal in 1..=libc::SIGRTMAX() {
            libc::signal(signal, libc::SIG_DFL);
        }
        let mut empty = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
    }
}

unsafe fn hold() -> ! {
    unsafe {
        if close_from(0).is_err() {
            libc::_exit(125);
        }
        loop {
            libc::pause();
        }
    }
}

#[cfg(test)]
mod tests {
    /// A holder whose setup never committed its record (e.g. the setup
    /// process died) must exit rather than run unrecorded.
    #[test]
    fn uncommitted_holder_exits() {
        let started = super::start_holder().unwrap();
        let pid = started.holder.pid;
        assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
        drop(started);
        for _ in 0..50 {
            // Gone, or a zombie awaiting its reaper (state Z).
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let state = stat.rsplit_once(')').map(|(_, rest)| rest.trim_start());
            if state.is_none_or(|rest| rest.starts_with('Z')) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("uncommitted holder is still running");
    }

    #[test]
    fn close_fallback_sees_descriptors_above_a_lowered_limit() {
        let file = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: the forked child only duplicates, lowers its own limit,
        // closes descriptors and exits without returning into the harness.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let high = 900;
                libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&file), high);
                let limit = libc::rlimit {
                    rlim_cur: 64,
                    rlim_max: 64,
                };
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
                super::close_each_from(3).unwrap();
                libc::_exit(if libc::fcntl(high, libc::F_GETFD) < 0 {
                    0
                } else {
                    1
                });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        }
    }

    #[test]
    fn close_fallback_closes_every_descriptor() {
        let (read, write) = std::os::unix::net::UnixStream::pair().unwrap();
        // SAFETY: the forked child only closes descriptors, checks one with
        // fcntl and exits without returning into the test harness.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                super::close_each_from(3).unwrap();
                let closed = libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&write), libc::F_GETFD);
                libc::_exit(if closed < 0 { 0 } else { 1 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        }
        drop((read, write));
    }
}
