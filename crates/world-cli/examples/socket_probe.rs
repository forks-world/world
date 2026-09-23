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
