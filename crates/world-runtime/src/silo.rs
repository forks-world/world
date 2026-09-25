//! Per-World localhost for native processes. On macOS: a pinned, locally
//! patched silo-bind injected into supported programs (not a hostile-code
//! sandbox). On Linux: a per-World kernel network namespace.
//! Neither is a forkfs lifecycle implementation.
use crate::run;
use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::Write,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(target_os = "macos")]
use tokio::process::Command;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct World {
    pub id: String,
    pub ip: Ipv4Addr,
    pub workdir: PathBuf,
}

pub fn default_state_dir() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("HOME").context("HOME is required")?)
            .join(".local/share/world/silo"),
    )
}

fn supported() -> Result<()> {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        bail!("silo backend requires macOS or Linux");
    }
    Ok(())
}

fn lock(state: &Path) -> Result<File> {
    std::fs::create_dir_all(state)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("registry.lock"))?;
    lock.lock_exclusive()?;
    Ok(lock)
}

fn persist<T: Serialize>(state: &Path, name: &str, value: &T) -> Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(state)?;
    serde_json::to_writer_pretty(&mut temp, value)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(state.join(name))?;
    File::open(state)?.sync_all()?;
    Ok(())
}

pub fn create(state: &Path, id: &str, workdir: &Path) -> Result<World> {
    supported()?;
    if id.is_empty() || id.len() > 128 || id.contains(['\0', '\r', '\n']) {
        bail!("invalid World ID");
    }
    let workdir = run::workdir(workdir)?;
    let _lock = lock(state)?;
    let mut worlds = registry(state)?;
    if let Some(world) = worlds.get(id) {
        if world.workdir != workdir {
            bail!("World already belongs to another workdir");
        }
        return Ok(world.clone());
    }
    let used: std::collections::HashSet<_> = worlds.values().map(|w| w.ip).collect();
    let ip = (1..=65534u32)
        .map(|n| Ipv4Addr::new(127, 77, (n >> 8) as u8, n as u8))
        // On Linux the address only identifies the World; its namespace
        // provides localhost, and all of 127/8 is always bindable.
        .find(|ip| !used.contains(ip) && (cfg!(target_os = "linux") || !alias_ready(*ip)))
        .context("World address pool exhausted")?;
    let world = World {
        id: id.into(),
        ip,
        workdir,
    };
    worlds.insert(id.into(), world.clone());
    persist(state, "registry.json", &worlds)?;
    Ok(world)
}

fn registry(state: &Path) -> Result<BTreeMap<String, World>> {
    read_map(state, "registry.json")
}

fn read_map<T: serde::de::DeserializeOwned>(
    state: &Path,
    name: &str,
) -> Result<BTreeMap<String, T>> {
    match File::open(state.join(name)) {
        Ok(file) => Ok(serde_json::from_reader(file)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e.into()),
    }
}

pub fn inspect(state: &Path, id: &str) -> Result<World> {
    let world = registry(state)?
        .remove(id)
        .context("unknown World; create it first")?;
    if world.id != id || world.ip.octets()[..2] != [127, 77] {
        bail!("invalid World registry entry");
    }
    Ok(world)
}

pub fn alias_ready(ip: Ipv4Addr) -> bool {
    // macOS only binds assigned aliases. Linux treats all of 127/8 as local.
    TcpListener::bind(SocketAddrV4::new(ip, 0)).is_ok()
}

#[cfg(target_os = "linux")]
fn holder(state: &Path, id: &str) -> Result<crate::linux::Holder> {
    read_map(state, "holders.json")?
        .remove(id)
        .context("World namespace is not running; run world silo setup")
}

/// macOS: add the World loopback alias (sudo). Linux: start the process
/// holding the World network namespace; no privilege is required.
pub fn setup(state: &Path, world: &World) -> Result<()> {
    supported()?;
    #[cfg(target_os = "linux")]
    {
        let _lock = lock(state)?;
        let mut holders = read_map::<crate::linux::Holder>(state, "holders.json")?;
        if let Some(holder) = holders.get(&world.id) {
            // A transient verification error must not orphan a live holder.
            if holder.verify()?.is_some() {
                return Ok(());
            }
            crate::linux::reap_stale_holder(holder);
        }
        let started = crate::linux::start_holder()?;
        holders.insert(world.id.clone(), started.holder);
        if let Err(err) = persist(state, "holders.json", &holders) {
            // An unrecorded holder could never be torn down or reused.
            if let Err(kill) = started.kill() {
                let pid = started.holder.pid;
                return Err(err.context(format!("could not stop unrecorded holder {pid}: {kill}")));
            }
            return Err(err);
        }
        started
            .commit()
            .context("World namespace holder exited before its record was committed")?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state;
        if alias_ready(world.ip) {
            return Ok(());
        }
        let status = std::process::Command::new("/usr/bin/sudo")
            .args([
                "/sbin/ifconfig",
                "lo0",
                "alias",
                &world.ip.to_string(),
                "netmask",
                "255.0.0.0",
            ])
            .status()?;
        if !status.success() || !alias_ready(world.ip) {
            bail!("loopback setup failed; World is not ready");
        }
        Ok(())
    }
}

/// Linux: stop the namespace holder. Processes still running in the World
/// keep its namespace, but later executions can no longer join it.
pub fn teardown(state: &Path, world: &World) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _lock = lock(state)?;
        let mut holders = read_map::<crate::linux::Holder>(state, "holders.json")?;
        if let Some(holder) = holders.remove(&world.id) {
            // Forget the record only once the holder is stopped or gone;
            // a transient verification error keeps it for a retry.
            if holder.verify()?.is_some() {
                crate::linux::stop_holder(&holder)?;
            } else {
                crate::linux::reap_stale_holder(&holder);
            }
            persist(state, "holders.json", &holders)?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state;
        bail!(
            "teardown is Linux-only; remove the alias with sudo ifconfig lo0 -alias {}",
            world.ip
        );
    }
}

pub async fn exec(
    state: &Path,
    world: World,
    command: Vec<OsString>,
    duration: Duration,
    cancel: CancellationToken,
) -> Result<i32> {
    run::validate_command(&command, duration)?;
    run::check_sigchld()?;
    #[cfg(target_os = "linux")]
    {
        linux_exec(state, world, command, duration, cancel).await
    }
    #[cfg(target_os = "macos")]
    {
        let _ = state;
        macos_exec(world, command, duration, cancel).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (state, world, cancel);
        bail!("silo backend requires macOS or Linux; refusing unisolated execution");
    }
}

#[cfg(target_os = "linux")]
async fn linux_exec(
    state: &Path,
    world: World,
    command: Vec<OsString>,
    duration: Duration,
    cancel: CancellationToken,
) -> Result<i32> {
    use std::os::fd::AsRawFd;
    let deadline = Instant::now() + duration;
    let dir = run::workdir(&world.workdir)?;
    // The checked descriptor itself, never whatever fd 0 is at spawn: a
    // host socket swapped in by another thread would cross into the World.
    let stdin = run::pin_stdin_with(false)?;
    let (user, net) = holder(state, &world.id)?.open().with_context(|| {
        format!(
            "World namespace is not running; run world silo setup --world {}",
            world.id
        )
    })?;
    let (user, net) = (
        crate::linux::above_stdio(user)?,
        crate::linux::above_stdio(net)?,
    );
    let (user_fd, net_fd) = (user.as_raw_fd(), net.as_raw_fd());
    let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(key, _)| key != "WORLD_ID")
        .collect();
    env.push(("WORLD_ID".into(), world.id.clone().into()));
    let setup = move || -> std::io::Result<()> {
        // SAFETY: raw system calls on open descriptors (see linux::Spawn).
        unsafe {
            crate::linux::join_namespaces(user_fd, net_fd)?;
            crate::linux::close_extra_descriptors()?;
            crate::linux::enter_pid_namespace()
        }
    };
    if cancel.is_cancelled() || Instant::now() >= deadline {
        return Ok(124);
    }
    let workload = run::raw_workload(crate::linux::spawn(crate::linux::Spawn {
        program: command[0].clone(),
        args: command[1..].to_vec(),
        cwd: dir,
        env,
        stdin,
        setup: Box::new(setup),
    })?);
    let result = run::wait(workload, deadline, cancel, &mut None, None).await;
    drop((user, net));
    result
}

#[cfg(target_os = "macos")]
async fn macos_exec(
    world: World,
    command: Vec<OsString>,
    duration: Duration,
    cancel: CancellationToken,
) -> Result<i32> {
    if !alias_ready(world.ip) {
        bail!(
            "World loopback alias is not configured; run world silo setup --world {}",
            world.id
        );
    }
    let dir = run::workdir(&world.workdir)?;
    let executable = resolve_executable(&command[0], &dir)?;
    let library = std::env::current_exe()?
        .parent()
        .context("executable directory")?
        .join("libworld_silo_bind.dylib")
        .canonicalize()
        .context("build/install libworld_silo_bind.dylib beside world")?;
    let ack = tempfile::NamedTempFile::new()?;
    let mut cmd = Command::new(executable);
    // Validate/execute the canonical binary while preserving alias-sensitive argv[0].
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.as_std_mut().arg0(&command[0]);
    }
    cmd.args(&command[1..]).current_dir(&dir);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("DYLD_") || name.starts_with("SILO_") || name.starts_with("WORLD_SILO_")
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("DYLD_INSERT_LIBRARIES", library)
        .env("SILO_IP", world.ip.to_string())
        .env("SILO_CONNECT", "1")
        .env("WORLD_SILO_ACTIVE", "1")
        .env("WORLD_SILO_ACK", ack.path())
        .env("WORLD_ID", world.id);
    #[cfg(unix)]
    // SAFETY: after fork only async-signal-safe fcntl calls are made. Mark all
    // additional descriptors CLOEXEC without running a SIP-protected shell.
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::sysconf(libc::_SC_OPEN_MAX);
            if limit < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for fd in 3..limit as i32 {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
    run::supervise(
        cmd,
        None,
        Instant::now() + duration,
        cancel,
        &mut None,
        Some(ack.path()),
    )
    .await
}

#[cfg(target_os = "macos")]
fn executable_file(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    path.is_file()
        && std::ffi::CString::new(path.as_os_str().as_bytes())
            .is_ok_and(|path| unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 })
}

#[cfg(target_os = "macos")]
fn resolve_executable(name: &std::ffi::OsStr, workdir: &Path) -> Result<PathBuf> {
    let path = Path::new(name);
    let path = if path.components().count() > 1 || path.is_absolute() {
        workdir.join(path)
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| workdir.join(p).join(name))
            .find(|p| executable_file(p))
            .context("executable not found in PATH")?
    }
    .canonicalize()?;
    if ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/System"]
        .iter()
        .any(|p| path.starts_with(p))
    {
        bail!(
            "SIP-protected executable unsupported: {}; use a non-SIP toolchain",
            path.display()
        );
    }
    use std::os::unix::fs::PermissionsExt;
    if path.metadata()?.permissions().mode() & 0o6000 != 0 {
        bail!("privileged executable unsupported: setuid/setgid can suppress silo injection");
    }
    let mut file = File::open(&path)?;
    let mut header = [0u8; 32];
    use std::io::Read;
    let n = file.read(&mut header)?;
    // Scripts may hide a SIP-protected interpreter. Require an explicit
    // non-SIP interpreter, e.g. world silo exec -- python3 script.py.
    if n < 28 || header.starts_with(b"#!") {
        bail!("use an explicit native, non-SIP interpreter for scripts");
    }
    let magic = u32::from_le_bytes(header[..4].try_into().unwrap());
    if ![0xfeedfacf, 0xfeedface, 0xbebafeca, 0xcafebabe].contains(&magic) {
        bail!("unsupported executable format");
    }
    Ok(path)
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests {
    use super::*;
    /// The library API must work from any executable, not only `world`:
    /// this test binary would not understand a re-exec with CLI arguments.
    #[cfg(target_os = "linux")]
    #[test]
    fn setup_works_from_an_embedding_executable() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let world = create(state.path(), "embedded", work.path()).unwrap();
        setup(state.path(), &world).unwrap();
        let holder = holder(state.path(), "embedded").unwrap();
        assert!(
            holder.verify().unwrap().is_some(),
            "holder did not survive setup"
        );
        teardown(state.path(), &world).unwrap();
        for _ in 0..50 {
            if holder.verify().unwrap().is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("holder still running after teardown");
    }

    /// A caller that is a child subreaper adopts the double-forked holder;
    /// teardown must reap it rather than leave a zombie behind.
    #[cfg(target_os = "linux")]
    #[test]
    fn teardown_reaps_holder_adopted_by_subreaper() {
        // SAFETY: prctl with integer arguments on this test process.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let world = create(state.path(), "adopted", work.path()).unwrap();
        setup(state.path(), &world).unwrap();
        let pid = holder(state.path(), "adopted").unwrap().pid;
        let parent = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(parent.contains(&format!("PPid:\t{}\n", std::process::id())));
        teardown(state.path(), &world).unwrap();
        // SAFETY: as above.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) };
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "holder left as a zombie"
        );
    }

    /// A holder killed externally stays a zombie of a subreaper caller;
    /// replacing its stale record must reap it.
    #[cfg(target_os = "linux")]
    #[test]
    fn setup_reaps_externally_killed_holder_of_subreaper() {
        // SAFETY: prctl with integer arguments on this test process.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let world = create(state.path(), "killed", work.path()).unwrap();
        setup(state.path(), &world).unwrap();
        let old = holder(state.path(), "killed").unwrap().pid;
        // SAFETY: kill with integer arguments.
        unsafe { libc::kill(old as libc::pid_t, libc::SIGKILL) };
        std::thread::sleep(Duration::from_millis(100));
        setup(state.path(), &world).unwrap();
        teardown(state.path(), &world).unwrap();
        // SAFETY: as above.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) };
        assert!(
            !std::path::Path::new(&format!("/proc/{old}")).exists(),
            "killed holder left as a zombie"
        );
    }

    #[test]
    fn allocation_serializes_world_identity() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let s = state.path().to_path_buf();
            let w = work.path().to_path_buf();
            jobs.push(std::thread::spawn(move || create(&s, "A", &w).unwrap().ip));
        }
        let ips: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
        assert!(ips.iter().all(|ip| ip == &ips[0]));
        let other = create(state.path(), "B", work.path()).unwrap();
        assert_ne!(other.ip, ips[0]);
        let another = tempfile::tempdir().unwrap();
        assert!(create(state.path(), "A", another.path()).is_err());
    }
}
