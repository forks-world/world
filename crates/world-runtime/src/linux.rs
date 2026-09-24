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
        let read_only = set(MOUNT_ATTR_RDONLY, 0);
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
        check(libc::chdir(view.workdir.as_ptr()))?;
    }
    Ok(())
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

/// pre_exec: no descriptor beyond stdio survives exec.
pub(crate) unsafe fn close_extra_descriptors() -> IoResult<()> {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    unsafe {
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) == 0 {
            return Ok(());
        }
        let limit = libc::sysconf(libc::_SC_OPEN_MAX);
        if limit < 0 {
            return Err(Error::last_os_error());
        }
        for fd in 3..limit as i32 {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
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
    pub fn write_ruleset(dirs: &[&Path], files: &[&Path]) -> Result<OwnedFd> {
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
        let file_rights = WRITE_FILE | TRUNCATE;
        let dir_rights = file_rights
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
            handled_access_fs: dir_rights,
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
        Ok(ruleset)
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
    /// pairs, and io_uring, which can create sockets without these calls.
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
            filter.push(op(JGE_K, 0x4000_0000, 15, 0));
        }
        let flags = (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u32;
        filter.extend([
            op(JEQ_K, libc::SYS_socket as u32, 3, 0),
            op(JEQ_K, libc::SYS_socketpair as u32, 7, 0),
            op(JEQ_K, libc::SYS_io_uring_setup as u32, 12, 0),
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
                let io_uring = libc::SYS_io_uring_setup as u32;
                assert_eq!(eval(ARCH, io_uring, 0), RET_ERRNO | libc::EPERM as u32);
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
    let dir = run::workdir(&options.workdir)?;
    let temp = tempfile::Builder::new()
        .prefix("world-network-")
        .tempdir()?;
    let temp_path = temp.path().canonicalize()?;
    let ruleset = landlock::write_ruleset(&[&dir, &temp_path], &[Path::new("/dev/null")])?;
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
            Some(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
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
            enter_new_namespaces(&maps)?;
            enter_read_only_view(&view)?;
            if let Some(channel) = child_channel {
                send_listeners(channel, port)?;
            }
            close_extra_descriptors()?;
            check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
            landlock::restrict_self(ruleset_fd)?;
            seccomp::install(&filter)
        });
    }
    run::check_stdin()?;
    if cancel.is_cancelled() || Instant::now() >= deadline {
        return Ok(124);
    }
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
        let open = |kind: &str, expected: u64| -> Result<OwnedFd> {
            let file = std::fs::File::open(format!("/proc/{}/ns/{kind}", self.pid))?;
            if file.metadata()?.ino() != expected {
                bail!("namespace changed");
            }
            Ok(file.into())
        };
        let (user, net) = (open("user", self.user_ns)?, open("net", self.net_ns)?);
        // Checked after opening: descriptors keep the namespaces alive.
        if start_time(self.pid)? != self.start_time {
            bail!("holder process replaced");
        }
        Ok((user, net))
    }
}

/// Start a detached process that keeps new namespaces alive.
pub(crate) fn start_holder() -> Result<Holder> {
    let maps = IdMaps::current();
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(["silo", "hold"])
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: the closure only makes raw system calls on data prepared above.
    unsafe {
        cmd.pre_exec(move || {
            check(libc::setsid())?;
            enter_new_namespaces(&maps)?;
            close_extra_descriptors()
        });
    }
    let child = cmd.spawn().context("start World namespace holder")?;
    Holder::observe(child.id())
}

pub(crate) fn stop_holder(holder: &Holder) -> Result<()> {
    // Pin the process first, then verify it: the signal cannot reach a
    // process that reused the PID after verification.
    // SAFETY: pidfd_open takes plain integers and returns a new descriptor.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, holder.pid as libc::pid_t, 0u32) };
    if pidfd < 0 {
        return Err(Error::last_os_error()).context("open holder pidfd");
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
    Ok(())
}

/// Body of the hidden `world silo hold` command.
pub fn hold() -> ! {
    loop {
        // SAFETY: pause has no arguments.
        unsafe { libc::pause() };
    }
}
