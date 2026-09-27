//! Host access to a Linux workspace's listeners (issue #8).
//!
//! A workspace's servers listen inside its network namespace, usually on
//! 127.0.0.1. While `world exec` runs a workload, it forwards every TCP port
//! the workspace listens on from the workspace's own host address
//! (`127.77.x.y`, from the registry) into the namespace: workspaces can use
//! the same port and still be told apart from the host, as on macOS, where
//! the workspace address is what their localhost binds to. Every running
//! exec of a workspace forwards all of its listeners (with SO_REUSEPORT, so
//! they coexist); a workspace process only runs while some exec does.
//!
//! Sockets into the namespace come from a small single-threaded connector
//! process that joined the workspace's user and network namespaces (a
//! multithreaded process cannot join a user namespace, and joining only the
//! network namespace needs privilege in our own). It creates sockets there
//! on request and passes them back; a socket stays in the namespace it was
//! created in, so this process connects it.

use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    io::{Error, Result as IoResult},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
    sync::{Arc, Mutex},
    time::Duration,
};

fn check(result: libc::c_int) -> IoResult<libc::c_int> {
    if result < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(result)
    }
}

/// Creates sockets inside a workspace's network namespace (see the module
/// documentation). Ends with this value: the child exits on EOF.
pub(crate) struct NsConnector {
    channel: Mutex<Option<OwnedFd>>,
    pid: libc::pid_t,
}

impl NsConnector {
    /// Fork the connector and join it to the namespaces held by `user` and
    /// `net` (descriptors of the workspace holder's namespaces).
    pub(crate) fn start(user: RawFd, net: RawFd) -> Result<Self> {
        let mut fds = [0; 2];
        // SAFETY: socketpair writes two new descriptors into fds.
        check(unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        })
        .context("create the workspace connector channel")?;
        // SAFETY: both descriptors are new and exclusively owned here.
        let (ours, theirs) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let (ours_fd, theirs_fd) = (ours.as_raw_fd(), theirs.as_raw_fd());
        // No caller signal handler may run in the child: block everything
        // across the fork; the child resets handlers before unblocking.
        // SAFETY: sigset operations on live local sets, this thread only.
        let mut all = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        unsafe {
            libc::sigfillset(&mut all);
            libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut previous);
        }
        // SAFETY: the child only makes raw system calls and never returns.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { connector(user, net, ours_fd, theirs_fd) }
        }
        // SAFETY: restores this thread's own previous mask.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
        let pid = check(pid).context("start the workspace connector")?;
        drop(theirs);
        Ok(Self {
            channel: Mutex::new(Some(ours)),
            pid,
        })
    }

    /// A new non-blocking, unconnected TCP socket in the workspace's network
    /// namespace. Blocking: call from a blocking context.
    pub(crate) fn socket(&self, v6: bool) -> IoResult<OwnedFd> {
        let guard = self.channel.lock().unwrap_or_else(|e| e.into_inner());
        let channel = guard
            .as_ref()
            .ok_or(Error::from_raw_os_error(libc::EPIPE))?;
        let family = if v6 { 6u8 } else { 4u8 };
        // SAFETY: a one-byte send on an open descriptor.
        let sent = unsafe {
            libc::send(
                channel.as_raw_fd(),
                (&family as *const u8).cast(),
                1,
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != 1 {
            return Err(Error::last_os_error());
        }
        let mut status = 0u8;
        let mut iov = libc::iovec {
            iov_base: (&mut status as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0u64; 8]; // u64: cmsghdr alignment
        // SAFETY: msghdr points at live local buffers for the call.
        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let received = loop {
            // SAFETY: as above; the kernel fills the buffers.
            let n =
                unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
            if n < 0 && Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break n;
        };
        if received < 0 {
            return Err(Error::last_os_error());
        }
        if received == 0 {
            return Err(Error::from_raw_os_error(libc::EPIPE));
        }
        if status != 0 {
            return Err(Error::from_raw_os_error(status as i32));
        }
        // SAFETY: walking the control buffer the kernel filled in.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null()
                || (*header).cmsg_level != libc::SOL_SOCKET
                || (*header).cmsg_type != libc::SCM_RIGHTS
            {
                return Err(Error::from_raw_os_error(libc::EPROTO));
            }
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header) as *const RawFd);
            Ok(OwnedFd::from_raw_fd(fd))
        }
    }
}

impl Drop for NsConnector {
    fn drop(&mut self) {
        // Closing the channel ends the child; reap it (it is our child).
        drop(
            self.channel
                .get_mut()
                .unwrap_or_else(|e| e.into_inner())
                .take(),
        );
        // SAFETY: signalling and reaping our own child by PID.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            while libc::waitpid(self.pid, std::ptr::null_mut(), 0) < 0
                && *libc::__errno_location() == libc::EINTR
            {}
        }
    }
}

/// The connector process; never returns. Raw system calls only (forked from
/// a multithreaded process).
unsafe fn connector(user: RawFd, net: RawFd, parent_end: RawFd, channel: RawFd) -> ! {
    unsafe {
        libc::close(parent_end);
        crate::linux::reset_caught_handlers();
        let mut empty = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
        // End with the exec that started us, even if it is killed.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        libc::prctl(libc::PR_SET_NAME, c"world-connect".as_ptr());
        if libc::setns(user, libc::CLONE_NEWUSER) < 0 || libc::setns(net, libc::CLONE_NEWNET) < 0 {
            libc::_exit(1);
        }
        loop {
            let mut family = 0u8;
            let n = libc::recv(channel, (&mut family as *mut u8).cast(), 1, 0);
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            if n != 1 {
                libc::_exit(0);
            }
            let domain = if family == 6 {
                libc::AF_INET6
            } else {
                libc::AF_INET
            };
            let flags = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
            let fd = libc::socket(domain, flags, 0);
            let mut status: u8 = if fd < 0 {
                (*libc::__errno_location()).clamp(1, 255) as u8
            } else {
                0
            };
            let mut iov = libc::iovec {
                iov_base: (&mut status as *mut u8).cast(),
                iov_len: 1,
            };
            let mut control = [0u64; 8]; // u64: cmsghdr alignment
            let mut message = std::mem::zeroed::<libc::msghdr>();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            if fd >= 0 {
                let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = space;
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
                std::ptr::write_unaligned(libc::CMSG_DATA(header) as *mut RawFd, fd);
            }
            let sent = libc::sendmsg(channel, &message, libc::MSG_NOSIGNAL);
            if fd >= 0 {
                libc::close(fd);
            }
            if sent < 0 {
                libc::_exit(0);
            }
        }
    }
}

/// Where to connect, inside the namespace, for a listener bound to `ip`:
/// the loopback address of its family for a wildcard bind.
fn target(ip: IpAddr, port: u16) -> SocketAddr {
    let ip = match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, port)
}

/// Parse a /proc/net/tcp{,6} table: the listening sockets, as the address
/// to connect to inside the namespace, by port. IPv4 wins over IPv6.
pub(crate) fn listeners(v4: &str, v6: &str) -> HashMap<u16, SocketAddr> {
    let mut found = HashMap::new();
    for (table, is_v6) in [(v6, true), (v4, false)] {
        for line in table.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // sl local_address rem_address st ...; 0A is LISTEN.
            if fields.len() < 4 || fields[3] != "0A" {
                continue;
            }
            let Some((address, port)) = fields[1].split_once(':') else {
                continue;
            };
            let Ok(port) = u16::from_str_radix(port, 16) else {
                continue;
            };
            let ip = if is_v6 {
                let Ok(raw) = u128::from_str_radix(address, 16) else {
                    continue;
                };
                // Four host-order 32-bit words.
                let mut bytes = [0u8; 16];
                for (i, word) in raw.to_be_bytes().chunks(4).enumerate() {
                    let word = u32::from_be_bytes(word.try_into().unwrap());
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            } else {
                let Ok(raw) = u32::from_str_radix(address, 16) else {
                    continue;
                };
                IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
            };
            found.insert(port, target(ip, port));
        }
    }
    found
}

/// A listener on `ip:port` on the host that other forwarding execs of the
/// same workspace can share (SO_REUSEPORT).
fn bind_shared(ip: Ipv4Addr, port: u16) -> IoResult<tokio::net::TcpListener> {
    // SAFETY: a new socket we own; setsockopt/bind/listen on it.
    unsafe {
        let fd = check(libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        ))?;
        let socket = OwnedFd::from_raw_fd(fd);
        let one: libc::c_int = 1;
        for option in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
            check(libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            ))?;
        }
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        check(libc::bind(
            fd,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        ))?;
        check(libc::listen(fd, 128))?;
        let listener = std::net::TcpListener::from_raw_fd(socket.into_raw_fd());
        tokio::net::TcpListener::from_std(listener)
    }
}

/// Relay one host connection into the workspace.
async fn relay(
    mut inbound: tokio::net::TcpStream,
    connector: Arc<NsConnector>,
    target: SocketAddr,
) -> IoResult<()> {
    let v6 = target.is_ipv6();
    let fd = tokio::task::spawn_blocking(move || connector.socket(v6))
        .await
        .map_err(Error::other)??;
    // SAFETY: a new, non-blocking TCP socket passed to us by the connector.
    let socket = unsafe { tokio::net::TcpSocket::from_raw_fd(fd.into_raw_fd()) };
    let mut outbound = socket.connect(target).await?;
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

/// Forward the workspace's listeners from `ip` on the host until dropped.
/// Rescans every second, through the connector: it lives in the
/// workspace's network namespace exactly as long as this exec, so neither
/// a torn-down holder nor a reused PID changes what is seen.
pub(crate) async fn forward(id: String, ip: Ipv4Addr, connector: NsConnector) {
    let pid = connector.pid;
    let connector = Arc::new(connector);
    // Dropped with this future (on `Forwarding` drop): every per-port task
    // stops with it, and with each its relays.
    let mut active: HashMap<u16, (SocketAddr, AbortOnDrop)> = HashMap::new();
    let read =
        |name: &str| std::fs::read_to_string(format!("/proc/{pid}/net/{name}")).unwrap_or_default();
    // Announce only ports that open while this exec runs (its own server,
    // typically), not every listener of the workspace on every exec.
    let mut announced: std::collections::HashSet<u16> =
        listeners(&read("tcp"), &read("tcp6")).into_keys().collect();
    let mut reported = std::collections::HashSet::new();
    loop {
        let wanted = listeners(&read("tcp"), &read("tcp6"));
        // Also restart a relay whose target changed (e.g. the IPv4 listener
        // closed and an IPv6 one on the same port remains).
        active.retain(|port, (target, task)| {
            wanted.get(port) == Some(target) && !task.0.is_finished()
        });
        for (&port, &target) in &wanted {
            if active.contains_key(&port) {
                continue;
            }
            let listener = match bind_shared(ip, port) {
                Ok(listener) => listener,
                Err(err) => {
                    if reported.insert(port) {
                        let hint = if err.raw_os_error() == Some(libc::EACCES) {
                            " (ports below net.ipv4.ip_unprivileged_port_start need privilege on the host: use a higher port, or lower it with sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0)"
                        } else {
                            ""
                        };
                        eprintln!(
                            "world: workspace {id}: port {port} cannot be reached from the host at {ip}:{port}: {err}{hint}"
                        );
                    }
                    continue;
                }
            };
            if announced.insert(port) {
                eprintln!(
                    "world: workspace {id}: port {port} is reachable from the host at {ip}:{port}"
                );
            }
            let connector = connector.clone();
            let task = tokio::spawn(async move {
                let mut relays = tokio::task::JoinSet::new();
                while let Ok((inbound, _)) = listener.accept().await {
                    relays.spawn(relay(inbound, connector.clone(), target));
                    // Forget finished relays.
                    while relays.try_join_next().is_some() {}
                }
            });
            active.insert(port, (target, AbortOnDrop(task)));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// A task aborted when its handle is dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Stops forwarding when dropped.
pub(crate) struct Forwarding(tokio::task::JoinHandle<()>);

impl Forwarding {
    pub(crate) fn start(id: String, ip: Ipv4Addr, connector: NsConnector) -> Self {
        Self(tokio::spawn(forward(id, ip, connector)))
    }
}

impl Drop for Forwarding {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dropping `Forwarding` stops every per-port listener, not just the
    /// scan: nothing stays exposed on the host after the workload.
    #[test]
    fn dropping_forwarding_closes_host_listeners() {
        let _serial = crate::linux::HOLDER_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("var/tmp")).unwrap();
        std::fs::create_dir(root.path().join("tmp")).unwrap();
        let temp = crate::linux::PrivateTemp::new(root.path()).unwrap();
        let started = crate::linux::start_holder(&temp, None).unwrap();
        let namespaces = started.holder.open().unwrap();
        let connector =
            NsConnector::start(namespaces.user.as_raw_fd(), namespaces.net.as_raw_fd()).unwrap();
        // A listener inside the workspace: a socket made there by the
        // connector, bound and listening from here.
        let inside = unsafe {
            std::net::TcpListener::from_raw_fd(connector.socket(false).unwrap().into_raw_fd())
        };
        let socket = unsafe { OwnedFd::from_raw_fd(libc::dup(inside.as_raw_fd())) };
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::LOCALHOST).to_be(),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: bind/listen on a socket we own.
        unsafe {
            check(libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            ))
            .unwrap();
            check(libc::listen(socket.as_raw_fd(), 8)).unwrap();
        }
        let port = inside.local_addr().unwrap().port();
        let ip = Ipv4Addr::new(127, 77, 250, 1);
        let host = SocketAddr::new(IpAddr::V4(ip), port);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let forwarding = Forwarding::start("test".into(), ip, connector);
            let mut reached = false;
            for _ in 0..50 {
                if tokio::net::TcpStream::connect(host).await.is_ok() {
                    reached = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(reached, "the workspace listener was not forwarded");
            drop(forwarding);
            let mut closed = false;
            for _ in 0..50 {
                if tokio::net::TcpStream::connect(host).await.is_err() {
                    closed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(closed, "a host listener outlived its Forwarding");
        });
        drop((inside, socket, namespaces));
        started.kill().unwrap();
    }

    #[test]
    fn listeners_parses_both_tables() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0 100 0 0 10 0
   1: 00000000:1F92 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2 1 0 100 0 0 10 0
   2: 0100007F:1F93 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0 100 0 0 10 0
";
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F94 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4 1 0 100 0 0 10 0
   1: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 5 1 0 100 0 0 10 0
";
        let found = listeners(v4, v6);
        assert_eq!(found[&8081], "127.0.0.1:8081".parse().unwrap(), "IPv4 wins");
        assert_eq!(
            found[&8082],
            "127.0.0.1:8082".parse().unwrap(),
            "wildcard -> loopback"
        );
        assert!(!found.contains_key(&8083), "established, not listening");
        assert_eq!(found[&8084], "[::1]:8084".parse().unwrap());
    }
}
