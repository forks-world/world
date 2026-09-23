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
        "write" => {
            std::fs::write(&args[2], "escape")?;
        }
        "child" => {
            let status = std::process::Command::new(std::env::current_exe()?)
                .args(&args[2..])
                .status()?;
            std::process::exit(status.code().unwrap_or(99));
        }
        "raw-spawn" | "raw-exec" => {
            use std::{ffi::CString, os::unix::ffi::OsStrExt};
            let argv: Vec<_> = args[2..]
                .iter()
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
                let mut pid = 0;
                let result = libc::posix_spawn(
                    &mut pid,
                    argv[0].as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    argp.as_ptr().cast(),
                    envp.as_ptr().cast(),
                );
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
        "launch" => {
            let status = std::process::Command::new(&args[2])
                .args(&args[3..])
                .status()?;
            std::process::exit(status.code().unwrap_or(99));
        }
        "exec" => {
            use std::os::unix::process::CommandExt;
            return Err(std::process::Command::new(&args[2]).args(&args[3..]).exec());
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
        _ => panic!("unknown probe"),
    }
    Ok(())
}
