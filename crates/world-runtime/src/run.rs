use crate::{policy::Policy, proxy::Proxy};
use anyhow::{Context, Result, bail};
#[cfg(unix)]
use std::os::unix::{
    fs::FileTypeExt,
    process::{CommandExt, ExitStatusExt},
};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    process::Command,
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
    if !cfg!(target_os = "macos") {
        bail!("network isolation backend requires macOS; refusing unsandboxed execution");
    }
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

pub(crate) async fn supervise(
    mut cmd: Command,
    deadline: Instant,
    cancel: CancellationToken,
    proxy: &mut Option<Proxy>,
    ack: Option<&Path>,
) -> Result<i32> {
    #[cfg(unix)]
    if std::fs::metadata("/dev/fd/0")?.file_type().is_socket() {
        bail!("socket stdin is not allowed; use a pipe");
    }
    if cancel.is_cancelled() || Instant::now() >= deadline {
        return Ok(124);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.as_std_mut().process_group(0);
    let mut child = cmd.spawn().context("start workload")?;
    let pid = child.id().context("child PID unavailable")?;
    let guard = ProcessGroup(pid);
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out =
        tokio::spawn(async move { tokio::io::copy(&mut stdout, &mut tokio::io::stdout()).await });
    let err =
        tokio::spawn(async move { tokio::io::copy(&mut stderr, &mut tokio::io::stderr()).await });
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

struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: kill uses an integer process-group ID, with no borrowed pointers.
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}

const CLOSE_DESCRIPTORS: &str = r#"
for file in /dev/fd/*; do
 fd=${file##*/}
 case "$fd" in 0|1|2) continue ;; ''|*[!0-9]*) exit 125 ;; esac
 eval "exec ${fd}>&-" || exit 125
done
exec "$@"
"#;

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
