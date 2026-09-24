use crate::{policy::Policy, proxy::Proxy};
use anyhow::{Context, Result, bail};
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;

pub struct RunOptions {
    pub policy: Policy,
    pub workdir: PathBuf,
    pub command: Vec<OsString>,
    pub timeout: Duration,
}

pub fn validate_command(command: &[OsString], duration: Duration) -> Result<()> {
    if command.is_empty() || command[0].is_empty() {
        bail!("command required");
    }
    if duration.is_zero() || duration > Duration::from_secs(86400) {
        bail!("timeout must be positive and at most 24h");
    }
    Ok(())
}

pub fn workdir(path: &Path) -> Result<PathBuf> {
    let dir = path.canonicalize().context("workdir")?;
    if !dir.is_dir() {
        bail!("workdir must be an existing directory");
    }
    let home = std::env::var_os("HOME").and_then(|p| PathBuf::from(p).canonicalize().ok());
    if dir == Path::new("/") || home.is_some_and(|h| h.starts_with(&dir)) {
        bail!("workdir must be a dedicated workspace");
    }
    Ok(dir)
}

pub async fn run(options: RunOptions, cancel: CancellationToken) -> Result<i32> {
    options.policy.validate()?;
    validate_command(&options.command, options.timeout)?;
    #[cfg(unix)]
    if stdin_writes_storage()? {
        bail!("writable file stdin is not allowed; open it read-only or use a pipe");
    }
    #[cfg(target_os = "macos")]
    {
        seatbelt(options, cancel).await
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux::run(options, cancel).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = cancel;
        bail!("network isolation backend requires macOS or Linux; refusing unsandboxed execution");
    }
}

#[cfg(target_os = "macos")]
async fn seatbelt(options: RunOptions, cancel: CancellationToken) -> Result<i32> {
    let deadline = Instant::now() + options.timeout;
    let dir = workdir(&options.workdir)?;
    let temp = tempfile::Builder::new()
        .prefix("world-network-")
        .tempdir()?;
    let temp_path = temp.path().canonicalize()?;
    let mut proxy = if options.policy.allow.is_empty() {
        None
    } else {
        tokio::select! {biased; _=cancel.cancelled()=>return Ok(124),_=sleep_until(deadline)=>return Ok(124),p=Proxy::start(&options.policy)=>Some(p?)}
    };
    let profile = seatbelt_profile(&dir, &temp_path, proxy.as_ref().map(Proxy::port))?;
    let mut cmd = Command::new("/bin/sh");
    cmd.args([
        "-c",
        CLOSE_DESCRIPTORS,
        "world-fd-guard",
        "/usr/bin/sandbox-exec",
        "-p",
        &profile,
        "--",
    ])
    .args(&options.command)
    .current_dir(&dir)
    .env_clear()
    .env(
        "PATH",
        "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
    )
    .env("HOME", &temp_path)
    .env("TMPDIR", &temp_path)
    .env("PWD", &dir)
    .env("LANG", "en_US.UTF-8")
    .env("NO_PROXY", "")
    .env("no_proxy", "");
    if let Some(proxy) = &proxy {
        for key in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "all_proxy",
        ] {
            cmd.env(key, proxy.url());
        }
    }
    let result = supervise(cmd, deadline, cancel, &mut proxy, None).await;
    if let Some(proxy) = &mut proxy {
        proxy.close().await;
    }
    result
}

/// Whether stdin must be relayed: anything but an anonymous pipe (or a
/// socket, refused elsewhere) is a filesystem or device inode, and even a
/// read-only descriptor allows fchmod, fchown, futimens and fsetxattr on it.
#[cfg(target_os = "linux")]
pub(crate) fn stdin_needs_relay() -> Result<bool> {
    const PIPEFS_MAGIC: u32 = 0x5049_5045;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the provided stat structure only on success.
    if unsafe { libc::fstat(libc::STDIN_FILENO, stat.as_mut_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            return Ok(false);
        }
        return Err(error.into());
    }
    match unsafe { stat.assume_init() }.st_mode & libc::S_IFMT {
        libc::S_IFSOCK => Ok(false),
        libc::S_IFIFO => {
            let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: fstatfs initializes the structure only on success.
            if unsafe { libc::fstatfs(libc::STDIN_FILENO, fs.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // f_type's integer type differs between C libraries.
            Ok(unsafe { fs.assume_init() }.f_type as u32 != PIPEFS_MAGIC)
        }
        _ => Ok(true),
    }
}

/// An inherited descriptor keeps its access mode inside the sandbox, so a
/// writable file or block device as stdin would bypass the write boundary.
#[cfg(unix)]
fn stdin_writes_storage() -> Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the provided stat structure only on success.
    if unsafe { libc::fstat(libc::STDIN_FILENO, stat.as_mut_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            return Ok(false);
        }
        return Err(error.into());
    }
    let kind = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG && kind != libc::S_IFBLK {
        return Ok(false);
    }
    // SAFETY: F_GETFL takes no pointer argument.
    let flags = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(flags & libc::O_ACCMODE != libc::O_RDONLY)
}

#[cfg(unix)]
fn stdin_is_socket() -> Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the provided stat structure only on success.
    if unsafe { libc::fstat(libc::STDIN_FILENO, stat.as_mut_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            return Ok(false);
        }
        return Err(error.into());
    }
    Ok(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFSOCK)
}

pub(crate) fn check_stdin() -> Result<()> {
    #[cfg(unix)]
    if stdin_is_socket()? {
        bail!("socket stdin is not allowed; use a pipe");
    }
    Ok(())
}

type Forward = JoinHandle<std::io::Result<u64>>;

/// A started workload whose process group is killed when dropped.
pub(crate) struct Workload {
    child: Child,
    guard: ProcessGroup,
    out: Forward,
    err: Forward,
    relay: Option<StdinRelay>,
}

/// Copies the caller's stdin into the workload's stdin pipe on a thread
/// that reads only when poll reports input, so cancelling it never leaves
/// a read pending that would consume input meant for someone else.
#[cfg(unix)]
struct StdinRelay {
    cancel: std::os::fd::OwnedFd,
    /// Held across "check cancelled, then read": once drop sets it, no
    /// further read of the caller's stdin can start.
    cancelled: std::sync::Arc<std::sync::Mutex<bool>>,
}

#[cfg(unix)]
impl StdinRelay {
    fn start(input: tokio::process::ChildStdin) -> Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let source = relay_source()?;
        let target = input.into_owned_fd()?;
        // Our own pipe end: block on writes instead of spinning.
        // SAFETY: fcntl on an owned descriptor with integer arguments.
        unsafe {
            let flags = libc::fcntl(target.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(target.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        let mut fds = [0; 2];
        // SAFETY: pipe writes two new descriptors into fds on success.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: both descriptors are new and exclusively owned here.
        let wake = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let cancel = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        for fd in [&wake, &cancel] {
            // SAFETY: fcntl on an owned descriptor with integer arguments.
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        let cancelled = std::sync::Arc::new(std::sync::Mutex::new(false));
        let flag = cancelled.clone();
        std::thread::spawn(move || {
            use std::io::Write;
            let mut target = std::fs::File::from(target);
            let mut buf = [0u8; 16384];
            loop {
                let mut polls = [
                    libc::pollfd {
                        fd: source.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: wake.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                // SAFETY: polls is a live array of two pollfd structures.
                if unsafe { libc::poll(polls.as_mut_ptr(), 2, -1) } < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return;
                }
                if polls[1].revents != 0 {
                    return;
                }
                let (fd, len) = (source.as_raw_fd(), buf.len());
                let n = {
                    let stop = flag.lock().unwrap_or_else(|e| e.into_inner());
                    if *stop {
                        return;
                    }
                    // Never blocks: see relay_source.
                    // SAFETY: buf is a live, writable buffer of the given length.
                    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), len) }
                };
                if n < 0 {
                    let error = std::io::Error::last_os_error();
                    // Another reader took the input first; wait again.
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) {
                        continue;
                    }
                    return;
                }
                // EOF, or the workload stopped reading (EPIPE).
                if n == 0 || target.write_all(&buf[..n as usize]).is_err() {
                    return;
                }
            }
        });
        Ok(Self { cancel, cancelled })
    }
}

/// The relay's own descriptor for stdin. Terminals and FIFOs may be
/// shared with another reader that consumes input between poll and read,
/// so they are reopened as a separate, non-blocking open file description:
/// the read (held under the cancellation lock) never blocks, and the
/// caller's own stdin flags stay untouched. Reads from regular files,
/// directories and block devices never block, so those are duplicated.
#[cfg(unix)]
fn relay_source() -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};
    let stdin = std::io::stdin().as_fd().try_clone_to_owned()?;
    let kind = std::fs::File::from(stdin.try_clone()?)
        .metadata()?
        .file_type();
    use std::os::unix::fs::FileTypeExt;
    if !(kind.is_fifo() || kind.is_char_device()) {
        return Ok(stdin);
    }
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: a NUL-terminated literal path and integer flags.
    let fd = unsafe { libc::open(c"/proc/self/fd/0".as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("reopen stdin for relaying");
    }
    // SAFETY: open returned a new descriptor we exclusively own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
impl Drop for StdinRelay {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // Waits out a read already in progress, then forbids new ones.
        *self.cancelled.lock().unwrap_or_else(|e| e.into_inner()) = true;
        // Wakes the relay's poll. A write blocked on a full pipe ends with
        // EPIPE once the workload, which holds the other end, is killed.
        // SAFETY: writes one byte from a static buffer to an owned pipe.
        unsafe { libc::write(self.cancel.as_raw_fd(), b"x".as_ptr().cast(), 1) };
    }
}

/// `relay_stdin`: pass stdin through a pipe instead of the inherited
/// descriptor, so the workload holds no descriptor for the underlying file.
pub(crate) fn spawn(mut cmd: Command, relay_stdin: bool) -> Result<Workload> {
    cmd.stdin(if relay_stdin {
        Stdio::piped()
    } else {
        Stdio::inherit()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    #[cfg(unix)]
    cmd.as_std_mut().process_group(0);
    let mut child = cmd.spawn().context("start workload")?;
    let pid = child.id().context("child PID unavailable")?;
    // Armed first: any later error kills the whole group, including the
    // PID-namespace init and workload behind the spawned wrapper.
    let guard = ProcessGroup(pid);
    let relay = child.stdin.take().map(StdinRelay::start).transpose()?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out =
        tokio::spawn(async move { tokio::io::copy(&mut stdout, &mut tokio::io::stdout()).await });
    let err =
        tokio::spawn(async move { tokio::io::copy(&mut stderr, &mut tokio::io::stderr()).await });
    Ok(Workload {
        child,
        guard,
        out,
        err,
        relay,
    })
}

pub(crate) async fn supervise(
    cmd: Command,
    deadline: Instant,
    cancel: CancellationToken,
    proxy: &mut Option<Proxy>,
    ack: Option<&Path>,
) -> Result<i32> {
    check_stdin()?;
    if cancel.is_cancelled() || Instant::now() >= deadline {
        return Ok(124);
    }
    wait(spawn(cmd, false)?, deadline, cancel, proxy, ack).await
}

pub(crate) async fn wait(
    workload: Workload,
    deadline: Instant,
    cancel: CancellationToken,
    proxy: &mut Option<Proxy>,
    ack: Option<&Path>,
) -> Result<i32> {
    let Workload {
        mut child,
        guard,
        out,
        err,
        relay,
    } = workload;
    let injection_failure = async {
        if let Some(path) = ack {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if std::fs::read(path).unwrap_or_default() != b"world-silo-v1" {
                return;
            }
        }
        std::future::pending::<()>().await;
    };
    let mut status = tokio::select! {biased;
        _=injection_failure=>None,
        _=cancel.cancelled()=>None,
        _=sleep_until(deadline)=>None,
        result=child.wait()=>Some(result?),
    };
    if let Some(proxy) = proxy {
        proxy.close().await;
    }
    drop(guard);
    drop(relay);
    if status.is_none() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    for mut task in [out, err] {
        if status.is_some() {
            // A slow consumer is normal: retain every byte on successful exit.
            // Cancellation and the execution deadline still bound the drain.
            let result = tokio::select! { biased;
                _ = cancel.cancelled() => None,
                _ = sleep_until(deadline) => None,
                result = &mut task => Some(result),
            };
            if let Some(result) = result {
                result
                    .context("output forwarding task")?
                    .context("forward workload output")?;
                continue;
            }
            status = None;
        }
        if timeout(Duration::from_secs(1), &mut task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
    }
    if let Some(path) = ack
        && std::fs::read(path).unwrap_or_default() != b"world-silo-v1"
    {
        bail!("silo injection was not confirmed; this executable is unsupported");
    }
    Ok(match status {
        None => 124,
        Some(status) => status.code().unwrap_or_else(|| {
            #[cfg(unix)]
            {
                128 + status.signal().unwrap_or(0)
            }
            #[cfg(not(unix))]
            {
                125
            }
        }),
    })
}

pub(crate) struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: kill uses an integer process-group ID, with no borrowed pointers.
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}

#[cfg(target_os = "macos")]
const CLOSE_DESCRIPTORS: &str = r#"
for file in /dev/fd/*; do
 fd=${file##*/}
 case "$fd" in 0|1|2) continue ;; ''|*[!0-9]*) exit 125 ;; esac
 eval "exec ${fd}>&-" || exit 125
done
exec "$@"
"#;

#[cfg(target_os = "macos")]
fn seatbelt_profile(workdir: &Path, temp: &Path, port: Option<u16>) -> Result<String> {
    let quote = |p: &Path| -> Result<String> {
        Ok(serde_json::to_string(
            p.to_str().context("non-UTF8 sandbox path")?,
        )?)
    };
    let mut profile = format!(
        r#"(version 1)
(allow default)
(deny network*)
(deny mach-lookup)
(deny mach-register)
(deny ipc-posix*)
(deny ipc-sysv*)
(deny process-info*)
(allow process-info* (target self))
(deny signal)
(allow signal (target same-sandbox))
(deny file-write*)
(allow file-write* (subpath {}) (subpath {}) (literal "/dev/null"))
"#,
        quote(workdir)?,
        quote(temp)?
    );
    if let Some(port) = port {
        profile.push_str(&format!(
            "(allow network-outbound (remote tcp \"localhost:{port}\"))\n"
        ));
    }
    Ok(profile)
}
