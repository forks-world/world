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

/// Linux network exec accepts stdin only as the read end of an anonymous
/// pipe, the null device (replaced inside the sandbox) or closed. Any other file, FIFO,
/// terminal or device is an inode the workload could modify through the
/// inherited descriptor (fchmod, fchown, futimens, fsetxattr, ioctl).
#[cfg(target_os = "linux")]
pub(crate) fn check_linux_stdin() -> Result<()> {
    const PIPEFS_MAGIC: u32 = 0x5049_5045;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes the provided stat structure only on success.
    if unsafe { libc::fstat(libc::STDIN_FILENO, stat.as_mut_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EBADF) {
            return Ok(());
        }
        return Err(error.into());
    }
    let stat = unsafe { stat.assume_init() };
    let accepted = match stat.st_mode & libc::S_IFMT {
        libc::S_IFIFO => {
            let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: fstatfs initializes the structure only on success.
            if unsafe { libc::fstatfs(libc::STDIN_FILENO, fs.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // f_type's integer type differs between C libraries.
            let pipe = unsafe { fs.assume_init() }.f_type as u32 == PIPEFS_MAGIC;
            // Only a read end: a write end would be a channel to the host.
            // SAFETY: F_GETFL takes no pointer argument.
            let flags = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) };
            pipe && flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY
        }
        libc::S_IFCHR => is_null_device(stat.st_rdev),
        _ => false,
    };
    if !accepted {
        bail!(
            "stdin must be a pipe or /dev/null for Linux network exec; \
             e.g. `cat FILE | world network exec ...`"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn is_null_device(rdev: libc::dev_t) -> bool {
    libc::major(rdev) == 1 && libc::minor(rdev) == 3
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
}

pub(crate) fn spawn(mut cmd: Command) -> Result<Workload> {
    cmd.stdin(Stdio::inherit())
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
    wait(spawn(cmd)?, deadline, cancel, proxy, ack).await
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
