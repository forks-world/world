//! An ordinary application fixture: no World/silo dependencies or rewriting.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    time::Duration,
};

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(if e.kind() == std::io::ErrorKind::PermissionDenied {
            77
        } else {
            78
        });
    }
}
fn run() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if ["bash", "zsh", "sh", "python3"]
        .iter()
        .any(|name| std::path::Path::new(&args[0]).file_name().unwrap() == *name)
    {
        print!("{}", serde_json::to_string(&args).unwrap());
        return Ok(());
    }
    match args[1].as_str() {
        "burst" => {
            let bytes = vec![b'x'; 16384];
            if args[2] == "stderr" {
                std::io::stderr().write_all(&bytes)?;
            } else {
                std::io::stdout().write_all(&bytes)?;
            }
        }
        "serve" => {
            let listener = TcpListener::bind(&args[2])?;
            println!("READY {}", listener.local_addr()?.port());
            for stream in listener.incoming() {
                stream?.write_all(args[3].as_bytes())?;
            }
        }
        "udp-serve" => {
            let socket = UdpSocket::bind(&args[2])?;
            println!("READY {}", socket.local_addr()?.port());
            loop {
                let mut buf = [0; 100];
                let (_, peer) = socket.recv_from(&mut buf)?;
                socket.send_to(args[3].as_bytes(), peer)?;
            }
        }
        "get" => {
            let mut stream =
                TcpStream::connect_timeout(&args[2].parse().unwrap(), Duration::from_secs(1))?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut value = String::new();
            stream.read_to_string(&mut value)?;
            print!("{value}");
        }
        "udp-get" => {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            socket.send_to(b"ping", &args[2])?;
            let mut buf = [0; 100];
            let (n, _) = socket.recv_from(&mut buf)?;
            print!("{}", String::from_utf8_lossy(&buf[..n]));
        }
        "dial" => {
            TcpStream::connect_timeout(&args[2].parse().unwrap(), Duration::from_secs(1))?;
        }
        "udp-dial" => {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.connect(&args[2])?;
        }
        "unix" => {
            #[cfg(unix)]
            {
                std::os::unix::net::UnixStream::connect(&args[2])?;
            }
        }
        "unix-sunlen" => {
            // Bind and connect through a heap-allocated sockaddr_un sized to
            // exactly SUN_LEN(path) -- no padding out to the full 106-byte
            // struct -- so the interposer sees a buffer only as large as the
            // caller actually promised via its socklen_t.
            let path = &args[2];
            let sockaddr_un = |path: &str| -> Vec<u8> {
                let total = 2 + path.len() + 1;
                let mut v = vec![0u8; total];
                v[0] = total as u8;
                v[1] = libc::AF_UNIX as u8;
                v[2..2 + path.len()].copy_from_slice(path.as_bytes());
                v
            };
            unsafe {
                let listener = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if listener < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let bind_addr = sockaddr_un(path);
                if libc::bind(
                    listener,
                    bind_addr.as_ptr().cast(),
                    bind_addr.len() as libc::socklen_t,
                ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::listen(listener, 1) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let dialer = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if dialer < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let connect_addr = sockaddr_un(path);
                if libc::connect(
                    dialer,
                    connect_addr.as_ptr().cast(),
                    connect_addr.len() as libc::socklen_t,
                ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(dialer);
                libc::close(listener);
            }
            print!("ok");
        }
        "pair" => {
            let (mut a, mut b) = std::os::unix::net::UnixStream::pair()?;
            a.write_all(b"pair")?;
            let mut buf = [0; 4];
            b.read_exact(&mut buf)?;
            print!("{}", String::from_utf8_lossy(&buf));
        }
        "pair-dgram" => {
            let (a, _b) = std::os::unix::net::UnixDatagram::pair()?;
            a.send_to(b"escape", &args[2])?;
        }
        "write" => {
            std::fs::write(&args[2], "escape")?;
        }
        "child" => {
            let status = std::process::Command::new(std::env::current_exe()?)
                .args(&args[2..])
                .status()?;
            std::process::exit(status.code().unwrap_or(99));
        }
        "raw-spawn"
        | "raw-exec"
        | "raw-spawn-chdir"
        | "raw-spawn-fchdir"
        | "raw-spawn-chdir-posix"
        | "raw-spawn-fchdir-posix" => {
            use std::{ffi::CString, os::unix::ffi::OsStrExt};
            let argv: Vec<_> = std::iter::once(&args[2])
                .chain(
                    args[if args[1].starts_with("raw-spawn-") {
                        4
                    } else {
                        3
                    }..]
                        .iter(),
                )
                .map(|s| CString::new(s.as_bytes()).unwrap())
                .collect();
            let env: Vec<_> = std::env::vars_os()
                .map(|(k, v)| {
                    let mut entry = k.as_bytes().to_vec();
                    entry.push(b'=');
                    entry.extend_from_slice(v.as_bytes());
                    CString::new(entry).unwrap()
                })
                .collect();
            let mut argp: Vec<_> = argv.iter().map(|s| s.as_ptr()).collect();
            let mut envp: Vec<_> = env.iter().map(|s| s.as_ptr()).collect();
            argp.push(std::ptr::null());
            envp.push(std::ptr::null());
            unsafe {
                if args[1] == "raw-exec" {
                    libc::execve(argv[0].as_ptr(), argp.as_ptr(), envp.as_ptr());
                    return Err(std::io::Error::last_os_error());
                }
                let mut actions =
                    std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
                let has_actions = args[1].starts_with("raw-spawn-");
                let directory_file = if has_actions {
                    Some(std::fs::File::open(&args[3])?)
                } else {
                    None
                };
                #[cfg(target_os = "macos")]
                let fileport = if has_actions {
                    Some(SpawnFileport::new()?)
                } else {
                    None
                };
                if has_actions {
                    let result = libc::posix_spawn_file_actions_init(actions.as_mut_ptr());
                    if result != 0 {
                        return Err(std::io::Error::from_raw_os_error(result));
                    }
                    let directory = CString::new(args[3].as_bytes()).unwrap();
                    use std::os::fd::AsRawFd;
                    let result = add_directory_action(
                        actions.as_mut_ptr(),
                        directory.as_ptr(),
                        directory_file.as_ref().unwrap().as_raw_fd(),
                        &args[1],
                    );
                    if result != 0 {
                        libc::posix_spawn_file_actions_destroy(actions.as_mut_ptr());
                        return Err(std::io::Error::from_raw_os_error(result));
                    }
                }
                // Force handle growth, then move the opaque object to another
                // stack location before spawning, as native callers can do.
                if has_actions {
                    #[cfg(target_os = "macos")]
                    for _ in 0..128 {
                        let result = posix_spawn_file_actions_add_fileportdup2_np(
                            actions.as_mut_ptr(),
                            fileport.as_ref().unwrap().0,
                            100,
                        );
                        if result != 0 {
                            return Err(std::io::Error::from_raw_os_error(result));
                        }
                    }
                    for _ in 0..64 {
                        let result =
                            libc::posix_spawn_file_actions_adddup2(actions.as_mut_ptr(), 2, 2);
                        if result != 0 {
                            return Err(std::io::Error::from_raw_os_error(result));
                        }
                    }
                }
                let mut moved = if has_actions {
                    Some(actions.assume_init())
                } else {
                    None
                };
                let mut pid = 0;
                let result = libc::posix_spawn(
                    &mut pid,
                    argv[0].as_ptr(),
                    moved.as_ref().map_or(std::ptr::null(), |actions| actions),
                    std::ptr::null(),
                    argp.as_ptr().cast(),
                    envp.as_ptr().cast(),
                );
                if let Some(actions) = moved.as_mut() {
                    libc::posix_spawn_file_actions_destroy(actions);
                }
                #[cfg(target_os = "macos")]
                drop(fileport);
                if result != 0 {
                    return Err(std::io::Error::from_raw_os_error(result));
                }
                let mut status = 0;
                if libc::waitpid(pid, &mut status, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                std::process::exit(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    99
                });
            }
        }
        "udp-disconnect" => {
            use std::os::fd::AsRawFd;
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.connect(&args[2])?;
            let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
            addr.sa_family = libc::AF_UNSPEC as _;
            let result = unsafe {
                libc::connect(socket.as_raw_fd(), &addr, std::mem::size_of_val(&addr) as _)
            };
            print!(
                "{}",
                if result == 0 {
                    0
                } else {
                    std::io::Error::last_os_error().raw_os_error().unwrap()
                }
            );
        }
        "tamper-child" => {
            // This single-threaded fixture deliberately changes its inherited
            // injection environment before trying intercepted child launches.
            unsafe {
                std::env::set_var(&args[3], &args[4]);
            }
            let mut cmd = std::process::Command::new(std::env::current_exe()?);
            cmd.args(["fd", "999"]);
            if args[2] == "exec" {
                use std::os::unix::process::CommandExt;
                return Err(cmd.exec());
            }
            std::process::exit(cmd.status()?.code().unwrap_or(99));
        }
        "launch-envpath" | "exec-envpath" => {
            let mut cmd = std::process::Command::new(&args[3]);
            cmd.env("PATH", &args[2]).args(&args[4..]);
            if args[1] == "exec-envpath" {
                use std::os::unix::process::CommandExt;
                return Err(cmd.exec());
            }
            std::process::exit(cmd.status()?.code().unwrap_or(99));
        }
        "launch-envpath-nocwd" | "exec-envpath-nocwd" => {
            // Like "launch-envpath"/"exec-envpath", but the cwd is removed
            // right after this process is placed in it, so our own (not
            // interposed) getcwd fails ENOENT by the time PATH is searched:
            // a redirected, absolute PATH entry must still be honored.
            let dir = &args[2];
            std::fs::create_dir(dir)?;
            std::env::set_current_dir(dir)?;
            std::fs::remove_dir(dir)?;
            let mut cmd = std::process::Command::new(&args[4]);
            cmd.env("PATH", &args[3]).args(&args[5..]);
            if args[1] == "exec-envpath-nocwd" {
                use std::os::unix::process::CommandExt;
                return Err(cmd.exec());
            }
            std::process::exit(cmd.status()?.code().unwrap_or(99));
        }
        "launch" => {
            let status = std::process::Command::new(&args[2])
                .args(&args[3..])
                .status()?;
            std::process::exit(status.code().unwrap_or(99));
        }
        "launch-in" => {
            // Like "launch", but chdir first so a relative PATH entry is
            // resolved against a caller-chosen directory rather than this
            // process's own cwd.
            std::env::set_current_dir(&args[2])?;
            let status = std::process::Command::new(&args[3])
                .args(&args[4..])
                .status()?;
            std::process::exit(status.code().unwrap_or(99));
        }
        "exec" => {
            use std::os::unix::process::CommandExt;
            return Err(std::process::Command::new(&args[2]).args(&args[3..]).exec());
        }
        "temp-suite" => {
            // Ordinary shared-temp usage below /tmp/<name> and /var/tmp/<name>.
            use std::os::unix::net::{UnixListener, UnixStream};
            let dir = std::path::PathBuf::from("/tmp").join(&args[2]);
            std::fs::create_dir_all(dir.join("sub"))?;
            std::fs::write(dir.join("draft"), "data")?;
            std::fs::rename(dir.join("draft"), dir.join("file"))?;
            std::os::unix::fs::symlink(dir.join("file"), dir.join("link"))?;
            // A relative symlink whose target's ".." must be resolved by the
            // kernel against the symlink's own directory, not lexically
            // against the redirected path text.
            std::fs::create_dir_all(dir.join("a/b/c"))?;
            std::os::unix::fs::symlink("b/c", dir.join("a/link"))?;
            std::fs::write(dir.join("a/b/x"), "symlink-parent")?;
            let listener = UnixListener::bind(dir.join("s.sock"))?;
            UnixStream::connect(dir.join("s.sock"))?;
            let socket = listener.local_addr()?;
            let template =
                std::ffi::CString::new(dir.join("mk.XXXXXX").into_os_string().into_encoded_bytes())
                    .unwrap();
            let template = template.into_raw();
            let fd = unsafe { libc::mkstemp(template) };
            let template = unsafe { std::ffi::CString::from_raw(template) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let var = std::path::PathBuf::from("/var/tmp").join(&args[2]);
            std::fs::create_dir_all(&var)?;
            std::fs::write(var.join("file"), "var")?;
            std::env::set_current_dir(&dir)?;
            let report = serde_json::json!({
                "read": std::fs::read_to_string("/tmp/".to_owned() + &args[2] + "/link")?,
                "symlink_parent": std::fs::read_to_string(
                    "/tmp/".to_owned() + &args[2] + "/a/link/../x",
                )?,
                "readlink": std::fs::read_link(dir.join("link"))?,
                "canonical": std::fs::canonicalize(dir.join("link"))?,
                "cwd": std::env::current_dir()?,
                "socket": socket.as_pathname(),
                "mkstemp": template.to_string_lossy(),
                "entries": std::fs::read_dir(&dir)?.count(),
                "var": std::fs::read_to_string(var.join("file"))?,
                "tmpdir": std::env::var("TMPDIR").ok(),
            });
            print!("{report}");
        }
        "temp-hold" => {
            use std::os::fd::AsRawFd;
            let path = std::path::Path::new(&args[2]);
            std::fs::create_dir_all(path.parent().unwrap())?;
            let lock = std::fs::File::create(path.with_extension("lock"))?;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let _ = std::fs::remove_file(path.with_extension("sock"));
            let _listener = std::os::unix::net::UnixListener::bind(path.with_extension("sock"))?;
            println!("READY 0");
            std::thread::sleep(Duration::from_secs(30));
        }
        "fd" => {
            let fd: i32 = args[2].parse().unwrap();
            #[cfg(unix)]
            unsafe {
                let mut addr: libc::sockaddr_storage = std::mem::zeroed();
                let mut size = std::mem::size_of_val(&addr) as libc::socklen_t;
                if libc::getpeername(
                    fd,
                    (&mut addr as *mut libc::sockaddr_storage).cast(),
                    &mut size,
                ) == 0
                {
                    std::process::exit(99);
                }
            }
            print!("descriptor-closed");
        }
        "getsockname-short" => {
            // Exercise getsockname with a caller buffer smaller than the
            // reported address, the way the kernel truncates but still
            // reports the untruncated length.
            use std::os::fd::AsRawFd;
            let cap: libc::socklen_t = args[3].parse().unwrap();
            let path = std::path::Path::new(&args[2]);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let _ = std::fs::remove_file(path);
            let listener = std::os::unix::net::UnixListener::bind(path)?;
            let mut buf = [0xAAu8; 128];
            let mut len = cap;
            if unsafe { libc::getsockname(listener.as_raw_fd(), buf.as_mut_ptr().cast(), &mut len) }
                != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let cap = (cap as usize).min(buf.len());
            let region = &buf[2.min(cap)..cap];
            let prefix = region.split(|&b| b == 0).next().unwrap_or(&[]);
            let report = serde_json::json!({
                "len": len,
                "prefix": String::from_utf8_lossy(prefix),
                "guard_intact": buf[cap..].iter().all(|&b| b == 0xAA),
            });
            print!("{report}");
        }
        "temp-escape" => {
            // A symlink inside the redirected temp root, then enough ".." to
            // leave it entirely: the kernel must resolve the symlink first,
            // so the escape lands back in the *private* root, not on the
            // host's real /tmp.
            let n = &args[2];
            let dir = std::path::PathBuf::from("/tmp").join(n);
            std::fs::create_dir_all(dir.join("b/c"))?;
            std::os::unix::fs::symlink("b/c", dir.join("link"))?;
            std::fs::write(dir.join("f"), "escaped-ok")?;
            let via_link = match std::fs::read_to_string(format!("/tmp/{n}/link/../../../{n}/f")) {
                Ok(s) => s,
                Err(e) => format!("error:{:?}", e.kind()),
            };
            let hosts = std::fs::File::open(format!("/tmp/{n}/b/../../../etc/hosts")).is_ok();
            let missing = std::fs::read_to_string(format!("/tmp/{n}/missing/../../../etc/hosts"))
                .err()
                .and_then(|e| e.raw_os_error());
            let report = serde_json::json!({
                "via_link": via_link,
                "hosts": hosts,
                "missing": missing,
            });
            print!("{report}");
        }
        "temp-relative" => {
            // Relative-path mapping (map_at) directly: a relative operand
            // containing ".." can reach a host temp root just as an absolute
            // one can, and, once the cwd is already inside a workspace's
            // private tree, a further relative ".." must land on the
            // *reported* (host) location, not wherever it physically resolves
            // inside that tree. `n` is this test's unique name; `k` is the
            // depth (in "/"-separated components) of this process's own cwd,
            // computed by the caller so the right number of ".." reaches "/".
            use std::ffi::CString;
            let n = &args[2];
            let k: usize = args[3].parse().unwrap();
            let up = "../".repeat(k);
            let cstr = |s: &str| CString::new(s).unwrap();

            // The parent directories are created with relative mkdir calls
            // (a bare, cwd-aware path); "tmp" itself may already exist.
            for rel in [format!("{up}tmp"), format!("{up}tmp/{n}")] {
                if unsafe { libc::mkdir(cstr(&rel).as_ptr(), 0o755) } != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EEXIST) {
                        return Err(err);
                    }
                }
            }

            let f_rel = format!("{up}tmp/{n}/f");
            let fd =
                unsafe { libc::open(cstr(&f_rel).as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe {
                libc::write(fd, b"f".as_ptr().cast(), 1);
                libc::close(fd);
            }

            // The same relative text, resolved this time against a real
            // directory fd rather than the AT_FDCWD sentinel.
            let dirfd =
                unsafe { libc::open(cstr(".").as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
            if dirfd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let f2_rel = format!("{up}tmp/{n}/f2");
            let fd2 = unsafe {
                libc::openat(
                    dirfd,
                    cstr(&f2_rel).as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY,
                    0o644,
                )
            };
            if fd2 < 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe {
                libc::write(fd2, b"f2".as_ptr().cast(), 2);
                libc::close(fd2);
                libc::close(dirfd);
            }

            let s_rel = format!("{up}tmp/{n}/s");
            drop(std::os::unix::net::UnixListener::bind(&s_rel)?);

            // A named (non-temp) component that does not exist at all,
            // popped by "..", with "tmp" still following: must ask the
            // kernel and report its ENOENT, not silently map into the
            // workspace.
            let absent = format!("/wt-absent-{n}/../tmp/{n}/f");
            let absent_errno = unsafe {
                let fd = libc::open(cstr(&absent).as_ptr(), libc::O_RDONLY);
                if fd >= 0 {
                    libc::close(fd);
                    None
                } else {
                    std::io::Error::last_os_error().raw_os_error()
                }
            };

            // Now with the cwd itself already inside the redirected root,
            // enough ".." to leave it and reach a completely unrelated host
            // path must land on the reported name, not the physical one.
            if unsafe { libc::chdir(cstr(&format!("/tmp/{n}")).as_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let hosts_readable = unsafe {
                let fd = libc::open(cstr("../../../etc/hosts").as_ptr(), libc::O_RDONLY);
                if fd >= 0 {
                    libc::close(fd);
                    true
                } else {
                    false
                }
            };

            let report = serde_json::json!({
                "absent_errno": absent_errno,
                "hosts_readable": hosts_readable,
            });
            print!("{report}");
        }
        "temp-rootrel" => {
            // No ".." anywhere: the redirected root is reached purely by a
            // relative path's *first* component being "tmp" (or, via a
            // dirfd/cwd on "/private", "var"), straight off "/" and off a
            // dirfd opened on "/" and on "/private".
            use std::ffi::CString;
            let n = &args[2];
            let cstr = |s: &str| CString::new(s).unwrap();

            if unsafe { libc::chdir(cstr("/").as_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let dir_rel = format!("tmp/{n}");
            if unsafe { libc::mkdir(cstr(&dir_rel).as_ptr(), 0o755) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let f_rel = format!("tmp/{n}/f");
            let fd = unsafe {
                libc::open(
                    cstr(&f_rel).as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
                    0o644,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe {
                libc::write(fd, b"f".as_ptr().cast(), 1);
                libc::close(fd);
            }

            let dirfd =
                unsafe { libc::open(cstr("/").as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
            if dirfd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let f2_rel = format!("tmp/{n}/f2");
            let fd2 = unsafe {
                libc::openat(
                    dirfd,
                    cstr(&f2_rel).as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
                    0o644,
                )
            };
            if fd2 < 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe {
                libc::write(fd2, b"f2".as_ptr().cast(), 2);
                libc::close(fd2);
                libc::close(dirfd);
            }

            let pfd = unsafe {
                libc::open(
                    cstr("/private").as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )
            };
            if pfd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let var_tmp_rel = format!("var/tmp/{n}");
            if unsafe { libc::mkdirat(pfd, cstr(&var_tmp_rel).as_ptr(), 0o755) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            unsafe {
                libc::close(pfd);
            }

            print!("{}", serde_json::json!({}));
        }
        "cwd-sized" => {
            // Exercise getcwd with buffers sized against the (shorter) host
            // name, including the NULL-buffer allocating form.
            let n = &args[2];
            let dir = std::path::PathBuf::from("/tmp").join(n);
            std::fs::create_dir_all(&dir)?;
            std::env::set_current_dir(&dir)?;
            let host = format!("/private/tmp/{n}");
            let call = |size: usize| -> serde_json::Value {
                let mut buf = vec![0u8; size.max(1)];
                let r = unsafe { libc::getcwd(buf.as_mut_ptr().cast(), size) };
                if r.is_null() {
                    serde_json::json!({ "errno": std::io::Error::last_os_error().raw_os_error() })
                } else {
                    let s = unsafe { std::ffi::CStr::from_ptr(r) }
                        .to_string_lossy()
                        .into_owned();
                    serde_json::json!(s)
                }
            };
            let call_null = |size: usize| -> serde_json::Value {
                let r = unsafe { libc::getcwd(std::ptr::null_mut(), size) };
                if r.is_null() {
                    serde_json::json!({ "errno": std::io::Error::last_os_error().raw_os_error() })
                } else {
                    let s = unsafe { std::ffi::CStr::from_ptr(r) }
                        .to_string_lossy()
                        .into_owned();
                    unsafe { libc::free(r.cast()) };
                    serde_json::json!(s)
                }
            };
            let report = serde_json::json!({
                "fit": call(host.len() + 1),
                "exact": call(host.len()),
                "null_fit": call_null(host.len() + 1),
                "null_zero": call_null(0),
            });
            print!("{report}");
        }
        "readlink-sized" => {
            // Exercise readlink with a buffer sized against the (shorter)
            // host target name, and one too small to hold it.
            let n = &args[2];
            let dir = std::path::PathBuf::from("/tmp").join(n);
            std::fs::create_dir_all(&dir)?;
            let target = format!("/tmp/{n}/target");
            std::os::unix::fs::symlink(&target, dir.join("l"))?;
            let link = std::ffi::CString::new(dir.join("l").into_os_string().into_encoded_bytes())
                .unwrap();
            let host_target = format!("/private/tmp/{n}/target");
            let read = |size: usize| -> (String, isize) {
                let mut buf = vec![0u8; size.max(1)];
                let r = unsafe { libc::readlink(link.as_ptr(), buf.as_mut_ptr().cast(), size) };
                if r < 0 {
                    (String::new(), r as isize)
                } else {
                    (
                        String::from_utf8_lossy(&buf[..r as usize]).into_owned(),
                        r as isize,
                    )
                }
            };
            let (full, full_ret) = read(host_target.len());
            let (short, short_ret) = read(10);
            let report = serde_json::json!({
                "full": full,
                "full_ret": full_ret,
                "short": short,
                "short_ret": short_ret,
            });
            print!("{report}");
        }
        "symlink-read" => {
            // A symlink target the mapper cannot map lexically (its ".."
            // needs the kernel to judge) must still be creatable and stored
            // verbatim, even when it points nowhere real.
            let target = &args[2];
            let link = &args[3];
            std::os::unix::fs::symlink(target, link)?;
            let report = serde_json::json!({
                "readlink": std::fs::read_link(link)?,
            });
            print!("{report}");
        }
        _ => panic!("unknown probe"),
    }
    Ok(())
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn fileport_makeport(fd: libc::c_int, port: *mut libc::mach_port_t) -> libc::c_int;
    fn mach_port_deallocate(task: libc::mach_port_t, port: libc::mach_port_t) -> libc::c_int;
    static mach_task_self_: libc::mach_port_t;
    fn posix_spawn_file_actions_add_fileportdup2_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        port: libc::mach_port_t,
        newfd: libc::c_int,
    ) -> libc::c_int;
}
#[cfg(target_os = "macos")]
struct SpawnFileport(libc::mach_port_t);
#[cfg(target_os = "macos")]
impl SpawnFileport {
    fn new() -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open("/dev/null")?;
        let mut port = 0;
        if unsafe { fileport_makeport(file.as_raw_fd(), &mut port) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(port))
    }
}
#[cfg(target_os = "macos")]
impl Drop for SpawnFileport {
    fn drop(&mut self) {
        unsafe { mach_port_deallocate(mach_task_self_, self.0) };
    }
}

#[cfg(target_os = "macos")]
core::arch::global_asm!(
    ".weak_reference _posix_spawn_file_actions_addchdir",
    ".weak_reference _posix_spawn_file_actions_addfchdir",
);
unsafe fn add_directory_action(
    actions: *mut libc::posix_spawn_file_actions_t,
    path: *const libc::c_char,
    fd: libc::c_int,
    mode: &str,
) -> libc::c_int {
    unsafe extern "C" {
        fn posix_spawn_file_actions_addchdir_np(
            actions: *mut libc::posix_spawn_file_actions_t,
            path: *const libc::c_char,
        ) -> libc::c_int;
        fn posix_spawn_file_actions_addfchdir_np(
            actions: *mut libc::posix_spawn_file_actions_t,
            fd: libc::c_int,
        ) -> libc::c_int;
        #[cfg(target_os = "macos")]
        fn posix_spawn_file_actions_addchdir(
            actions: *mut libc::posix_spawn_file_actions_t,
            path: *const libc::c_char,
        ) -> libc::c_int;
        #[cfg(target_os = "macos")]
        fn posix_spawn_file_actions_addfchdir(
            actions: *mut libc::posix_spawn_file_actions_t,
            fd: libc::c_int,
        ) -> libc::c_int;
    }
    unsafe {
        #[cfg(target_os = "macos")]
        if mode.ends_with("-posix") {
            return if mode.contains("fchdir") {
                posix_spawn_file_actions_addfchdir(actions, fd)
            } else {
                posix_spawn_file_actions_addchdir(actions, path)
            };
        }
        if mode.contains("fchdir") {
            posix_spawn_file_actions_addfchdir_np(actions, fd)
        } else {
            posix_spawn_file_actions_addchdir_np(actions, path)
        }
    }
}
