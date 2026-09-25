//! Per-World localhost for native processes. On macOS: a pinned, locally
//! patched silo-bind injected into supported programs (not a hostile-code
//! sandbox). On Linux: a per-World kernel network namespace.
//! Neither is a forkfs lifecycle implementation.
use crate::run;
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{CString, OsString},
    fs::{File, OpenOptions},
    io::Write,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{process::Command, time::Instant};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct World {
    pub id: String,
    pub ip: Ipv4Addr,
    pub workdir: PathBuf,
    /// `home/.world/tmp/<ip>`, fixed at `create` time from that process's
    /// `HOME` and persisted here so later executions -- possibly from a
    /// process with a different `HOME` -- keep sharing the same directory.
    /// `None` only for entries a pre-recording build of `world` created;
    /// `get` fills it in on first access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_root: Option<PathBuf>,
}

pub fn default_state_dir() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("HOME").context("HOME is required")?)
            .join(".local/share/world/workspaces"),
    )
}

fn supported() -> Result<()> {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        bail!("workspace localhost isolation requires macOS or Linux");
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

fn save(state: &Path, worlds: &BTreeMap<String, World>) -> Result<()> {
    persist(state, "registry.json", worlds)
}

pub fn create(state: &Path, id: &str, workdir: &Path) -> Result<World> {
    create_in(state, id, workdir, host_home)
}

/// `home` is taken as a callback, rather than read from the environment,
/// so tests can exercise creation under a chosen `HOME` without mutating
/// global process state; it is only invoked when a temp root actually needs
/// computing (a brand-new entry, or filling in a legacy one), never for an
/// already-recorded entry.
fn create_in(
    state: &Path,
    id: &str,
    workdir: &Path,
    home: impl FnOnce() -> Result<PathBuf>,
) -> Result<World> {
    supported()?;
    if id.is_empty() || id.len() > 128 || id.contains(['\0', '\r', '\n']) {
        bail!("invalid workspace ID");
    }
    let workdir = run::workdir(workdir)?;
    reject_shared_temp(&workdir, "workdir")?;
    let _lock = lock(state)?;
    let mut worlds = registry(state)?;
    if let Some(world) = worlds.get(id) {
        if world.workdir != workdir {
            bail!("workspace already belongs to another workdir");
        }
        // Never recompute a stored root from the current process's HOME:
        // only a legacy entry (predating this field) still has none.
        let mut world = world.clone();
        if cfg!(target_os = "macos") && world.temp_root.is_none() {
            world.temp_root = Some(root_for(&home()?, world.ip));
            worlds.insert(id.into(), world.clone());
            save(state, &worlds)?;
        }
        return Ok(world);
    }
    let used: std::collections::HashSet<_> = worlds.values().map(|w| w.ip).collect();
    let ip = (1..=65534u32)
        .map(|n| Ipv4Addr::new(127, 77, (n >> 8) as u8, n as u8))
        // On Linux the address only identifies the workspace; its namespace
        // provides localhost, and all of 127/8 is always bindable.
        .find(|ip| !used.contains(ip) && (cfg!(target_os = "linux") || !alias_ready(*ip)))
        .context("workspace address pool exhausted")?;
    let world = World {
        id: id.into(),
        ip,
        workdir,
        // Only macOS redirects /tmp; Linux records no temp root.
        temp_root: if cfg!(target_os = "macos") {
            Some(root_for(&home()?, ip))
        } else {
            None
        },
    };
    worlds.insert(id.into(), world.clone());
    save(state, &worlds)?;
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

pub fn get(state: &Path, id: &str) -> Result<World> {
    get_in(state, id, host_home)
}

fn valid(world: &World, id: &str) -> Result<()> {
    if world.id != id || world.ip.octets()[..2] != [127, 77] {
        bail!("invalid workspace registry entry");
    }
    Ok(())
}

/// `home` is only invoked for a legacy entry (one predating the `temp_root`
/// field) that still needs one filled in; a registry that already records a
/// temp root never calls it.
fn get_in(state: &Path, id: &str, home: impl FnOnce() -> Result<PathBuf>) -> Result<World> {
    let world = registry(state)?
        .remove(id)
        .context("unknown workspace; run world workspace create first")?;
    valid(&world, id)?;
    if !cfg!(target_os = "macos") || world.temp_root.is_some() {
        return Ok(world);
    }
    // Legacy entry: fill in the temp root under lock, re-reading first in
    // case another process already did.
    let _lock = lock(state)?;
    let mut worlds = registry(state)?;
    let mut stored = worlds
        .remove(id)
        .context("unknown workspace; run world workspace create first")?;
    valid(&stored, id)?;
    if cfg!(target_os = "macos") && stored.temp_root.is_none() {
        stored.temp_root = Some(root_for(&home()?, stored.ip));
        worlds.insert(id.into(), stored.clone());
        save(state, &worlds)?;
    }
    Ok(stored)
}

/// Host temp directories every process shares; `world exec` redirects them.
const SHARED_TEMP: [&str; 2] = ["/private/tmp", "/private/var/tmp"];

fn reject_shared_temp(path: &Path, what: &str) -> Result<()> {
    if SHARED_TEMP.iter().any(|temp| path.starts_with(temp)) {
        bail!(
            "{what} must not be under /tmp or /var/tmp: they are redirected inside the workspace"
        );
    }
    Ok(())
}

/// Canonical `HOME` of the process running `world`, rejecting one below a
/// host temp directory (where the workspace's own temp tree would end up
/// redirected right back into itself).
fn host_home() -> Result<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is required")?)
        .canonicalize()
        .context("HOME")?;
    reject_shared_temp(&home, "HOME")?;
    Ok(home)
}

/// Where a workspace's temp tree lives under `home`. Pure and cheap: it
/// performs no I/O and is used both to compute a fresh root and to validate
/// one already recorded in the registry.
fn root_for(home: &Path, ip: Ipv4Addr) -> PathBuf {
    home.join(".world/tmp").join(ip.to_string())
}

/// Per-workspace replacement for /tmp and /var/tmp, shared by all executions
/// of the workspace. It must not be below a host temp directory, or its own
/// path would be redirected. Keyed by the loopback address, which is already
/// host-global, and kept short: Unix socket names are limited to 104 bytes.
///
/// The root itself is *not* derived from the calling process's `HOME`: it was
/// fixed once, in `world.temp_root`, when the workspace was created (or, for
/// a legacy entry, on first access afterward), so executions from a process
/// with a different `HOME` still land in the same tree instead of getting
/// their own. This only rebuilds/hardens it under the home that root implies.
pub fn temp_root(world: &World) -> Result<PathBuf> {
    let root = world
        .temp_root
        .as_deref()
        .context("workspace has no temp root")?;
    let ip_name = world.ip.to_string();
    let shape_ok = root.is_absolute()
        && !root.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        && root.file_name() == Some(std::ffi::OsStr::new(&ip_name))
        && root.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("tmp"))
        && root
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            == Some(std::ffi::OsStr::new(".world"));
    if !shape_ok {
        bail!(
            "workspace temp root has an unexpected shape: {}",
            root.display()
        );
    }
    let home = root
        .ancestors()
        .nth(3)
        .context("workspace temp root is too shallow")?;
    reject_shared_temp(home, "workspace temp root")?;
    let got = temp_root_in(home, world.ip).with_context(|| {
        format!(
            "workspace temp root {} is unavailable (fixed when the workspace was created)",
            root.display()
        )
    })?;
    ensure!(
        got == root,
        "workspace temp root resolved to an unexpected location"
    );
    Ok(got)
}

/// Open (creating if absent) a single path component below `parent`, never
/// following a symlink placed at that name: `mkdirat` accepts an existing
/// directory but fails otherwise, then the child is reopened with
/// `O_NOFOLLOW` so a symlink swapped in for it (before or after the mkdirat)
/// is rejected rather than traversed, and its owner is checked before any of
/// its permissions are trusted. `create_mode` only applies when the entry is
/// freshly created; an existing directory's mode is judged or fixed by the
/// caller afterward.
fn step(parent: &OwnedFd, name: &str, create_mode: u32, label: &str) -> Result<OwnedFd> {
    let cname = CString::new(name).context("path contains NUL")?;
    // SAFETY: `parent` is a valid, open directory descriptor and `cname` is
    // NUL-terminated; `mkdirat` writes no memory through either pointer.
    let created = unsafe {
        libc::mkdirat(
            parent.as_raw_fd(),
            cname.as_ptr(),
            create_mode as libc::mode_t,
        )
    };
    if created != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err).with_context(|| format!("create {label}"));
        }
    }
    // SAFETY: same preconditions as above; O_NOFOLLOW makes the kernel
    // reject a symlink at this name instead of resolving it.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            cname.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
            bail!("{label} must be a real directory, not a symlink");
        }
        return Err(err).with_context(|| format!("open {label}"));
    }
    // SAFETY: `fd` was just returned by `openat` above and is owned here.
    let child = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `child` is a valid, open descriptor and `st` is a valid
    // out-pointer sized for `libc::stat`.
    if unsafe { libc::fstat(child.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("stat {label}"));
    }
    // SAFETY: getuid takes no arguments and always succeeds.
    if st.st_uid != unsafe { libc::getuid() } {
        bail!("{label} is not owned by this user");
    }
    Ok(child)
}

/// Reject a directory writable by group or other, without altering it.
fn require_private(fd: &OwnedFd, label: &str) -> Result<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a valid, open descriptor and `st` is a valid out-pointer.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("stat {label}"));
    }
    if st.st_mode & 0o022 != 0 {
        bail!("{label} must not be writable by group or other");
    }
    Ok(())
}

/// Force a directory this function owns end to end to the given mode.
fn chmod_dir(fd: &OwnedFd, mode: u32, label: &str) -> Result<()> {
    // SAFETY: `fd` is a valid, open directory descriptor.
    if unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("chmod {label}"));
    }
    Ok(())
}

/// Build (or reuse) `home/.world/tmp/<ip>` and its `tmp`/`var`/`var/tmp`
/// children by descriptor, so a symlink swapped in at any level -- before
/// this runs or between our own checks -- is rejected rather than followed.
/// `create_dir_all` plus path-based `set_permissions` do not have this
/// property: both accept and follow a pre-existing symlink. `.world` and
/// `.world/tmp` are shared by every workspace, so their permissions are only
/// checked, never fixed; everything below the per-workspace `<ip>` directory
/// is owned end to end by this function and is hardened to the exact mode it
/// needs on every call.
fn temp_root_in(home: &Path, ip: Ipv4Addr) -> Result<PathBuf> {
    let home_cstr = CString::new(home.as_os_str().as_bytes()).context("HOME contains NUL")?;
    // SAFETY: `home_cstr` is NUL-terminated; the returned fd is owned below.
    let home_fd = unsafe {
        libc::open(
            home_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if home_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open HOME");
    }
    // SAFETY: `home_fd` was just returned by `open` above.
    let home_fd = unsafe { OwnedFd::from_raw_fd(home_fd) };

    let world_fd = step(&home_fd, ".world", 0o700, "temp root .world")?;
    require_private(&world_fd, "temp root .world")?;
    let tmp_root_fd = step(&world_fd, "tmp", 0o700, "temp root .world/tmp")?;
    require_private(&tmp_root_fd, "temp root .world/tmp")?;

    let ip_name = ip.to_string();
    let ip_fd = step(&tmp_root_fd, &ip_name, 0o700, "workspace temp root")?;
    chmod_dir(&ip_fd, 0o700, "workspace temp root")?;
    let tmp_fd = step(&ip_fd, "tmp", 0o700, "workspace temp root/tmp")?;
    chmod_dir(&tmp_fd, 0o1777, "workspace temp root/tmp")?;
    let var_fd = step(&ip_fd, "var", 0o700, "workspace temp root/var")?;
    chmod_dir(&var_fd, 0o700, "workspace temp root/var")?;
    let var_tmp_fd = step(&var_fd, "tmp", 0o700, "workspace temp root/var/tmp")?;
    chmod_dir(&var_tmp_fd, 0o1777, "workspace temp root/var/tmp")?;

    // silo-bind's `..`-escape handling asks the kernel where a physical
    // prefix resolves and compares that against WORLD_TMP textually, so the
    // root must already be exactly canonical: nothing above rewrites it.
    let root = home.join(".world/tmp").join(&ip_name);
    let canonical = root.canonicalize().context("temp root")?;
    if canonical != root {
        bail!("workspace temp root resolved to an unexpected location");
    }
    Ok(root)
}

#[cfg(all(test, unix))]
mod temp_root_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn ip() -> Ipv4Addr {
        Ipv4Addr::new(127, 77, 0, 1)
    }

    // tempdir() on macOS lands under /var/folders, itself a host temp
    // directory in disguise via /private; canonicalizing first gives
    // temp_root_in a HOME it would actually accept.
    fn home() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        (dir, home)
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn hardens_a_fresh_tree_and_is_idempotent() {
        let (_dir, home) = home();
        let root = temp_root_in(&home, ip()).unwrap();
        assert_eq!(root, home.join(".world/tmp").join(ip().to_string()));
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("tmp")), 0o1777);
        assert_eq!(mode(&root.join("var")), 0o700);
        assert_eq!(mode(&root.join("var/tmp")), 0o1777);
        assert_eq!(temp_root_in(&home, ip()).unwrap(), root);
    }

    #[test]
    fn rejects_a_symlinked_tmp_without_touching_its_target() {
        let (_dir, home) = home();
        let outside = tempfile::tempdir().unwrap();
        std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let ip_dir = home.join(".world/tmp").join(ip().to_string());
        std::fs::create_dir_all(&ip_dir).unwrap();
        symlink(outside.path(), ip_dir.join("tmp")).unwrap();
        let err = temp_root_in(&home, ip()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert_eq!(mode(outside.path()), 0o755);
    }

    #[test]
    fn rejects_a_symlinked_var() {
        let (_dir, home) = home();
        let outside = tempfile::tempdir().unwrap();
        let ip_dir = home.join(".world/tmp").join(ip().to_string());
        std::fs::create_dir_all(&ip_dir).unwrap();
        symlink(outside.path(), ip_dir.join("var")).unwrap();
        let err = temp_root_in(&home, ip()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn rejects_a_symlinked_var_tmp() {
        let (_dir, home) = home();
        let outside = tempfile::tempdir().unwrap();
        let ip_dir = home.join(".world/tmp").join(ip().to_string());
        std::fs::create_dir_all(ip_dir.join("var")).unwrap();
        symlink(outside.path(), ip_dir.join("var").join("tmp")).unwrap();
        let err = temp_root_in(&home, ip()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn rejects_a_symlinked_dot_world() {
        let (_dir, home) = home();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), home.join(".world")).unwrap();
        let err = temp_root_in(&home, ip()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn rejects_a_regular_file_in_place_of_tmp() {
        let (_dir, home) = home();
        let ip_dir = home.join(".world/tmp").join(ip().to_string());
        std::fs::create_dir_all(&ip_dir).unwrap();
        std::fs::File::create(ip_dir.join("tmp")).unwrap();
        let err = temp_root_in(&home, ip()).unwrap_err();
        assert!(err.to_string().contains("real directory"), "{err}");
    }

    #[test]
    fn rejects_a_group_writable_dot_world_without_fixing_it() {
        let (_dir, home) = home();
        let world_dir = home.join(".world");
        std::fs::create_dir_all(&world_dir).unwrap();
        std::fs::set_permissions(&world_dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = temp_root_in(&home, ip()).unwrap_err();
        assert!(err.to_string().contains("group or other"), "{err}");
        assert_eq!(mode(&world_dir), 0o770);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod registry_tests {
    use super::*;

    fn home() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        (dir, home)
    }

    fn fixed(home: PathBuf) -> impl FnOnce() -> Result<PathBuf> {
        move || Ok(home)
    }

    /// A `home` callback that fails the test if it is ever invoked: used
    /// where the registry already has a recorded temp root, which must be
    /// returned without recomputing it.
    fn unreachable_home() -> Result<PathBuf> {
        panic!("a registry with a recorded temp root must never call home()");
    }

    #[test]
    fn create_in_stores_the_root_for_the_creating_home() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let (_h, home) = home();
        let world = create_in(state.path(), "A", work.path(), fixed(home.clone())).unwrap();
        assert_eq!(world.temp_root, Some(root_for(&home, world.ip)));
    }

    #[test]
    fn create_in_keeps_the_stored_root_across_different_homes() {
        let state = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let (_h1, home1) = home();
        let (_h2, _home2) = home();
        let first = create_in(state.path(), "A", work.path(), fixed(home1.clone())).unwrap();
        // A second create for the same id+workdir must never recompute the
        // root from `home`, so a `home` that panics if called still passes.
        let second = create_in(state.path(), "A", work.path(), unreachable_home).unwrap();
        assert_eq!(second.temp_root, first.temp_root);
        assert_eq!(first.temp_root, Some(root_for(&home1, first.ip)));
    }

    #[test]
    fn get_in_fills_and_persists_a_legacy_entry_once() {
        let state = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(state.path()).unwrap();
        let legacy = serde_json::json!({
            "A": {"id": "A", "ip": "127.77.0.9", "workdir": "/tmp/nonexistent"},
        });
        std::fs::write(
            state.path().join("registry.json"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();
        let (_h1, home1) = home();
        let filled = get_in(state.path(), "A", fixed(home1.clone())).unwrap();
        let expected = root_for(&home1, filled.ip);
        assert_eq!(filled.temp_root, Some(expected.clone()));
        let raw = std::fs::read_to_string(state.path().join("registry.json")).unwrap();
        assert!(raw.contains(expected.to_str().unwrap()), "{raw}");

        // Already filled: a `home` that panics if called still passes.
        let again = get_in(state.path(), "A", unreachable_home).unwrap();
        assert_eq!(again.temp_root, Some(expected));
    }

    #[test]
    fn temp_root_builds_the_tree_for_a_stored_root() {
        let (_h, home) = home();
        let ip = Ipv4Addr::new(127, 77, 0, 5);
        let world = World {
            id: "A".into(),
            ip,
            workdir: home.clone(),
            temp_root: Some(root_for(&home, ip)),
        };
        let root = temp_root(&world).unwrap();
        assert_eq!(root, root_for(&home, ip));
        assert!(root.join("tmp").is_dir());
        assert!(root.join("var/tmp").is_dir());
    }

    #[test]
    fn temp_root_rejects_a_mismatched_ip_name() {
        let (_h, home) = home();
        let ip = Ipv4Addr::new(127, 77, 0, 5);
        let world = World {
            id: "A".into(),
            ip,
            workdir: home.clone(),
            temp_root: Some(home.join(".world/tmp").join("127.77.0.6")),
        };
        let err = temp_root(&world).unwrap_err();
        assert!(err.to_string().contains("unexpected shape"), "{err}");
    }

    #[test]
    fn temp_root_rejects_a_root_missing_the_dot_world_tmp_structure() {
        let (_h, home) = home();
        let ip = Ipv4Addr::new(127, 77, 0, 5);
        let mut world = World {
            id: "A".into(),
            ip,
            workdir: home.clone(),
            temp_root: Some(home.join("elsewhere").join(ip.to_string())),
        };
        assert!(
            temp_root(&world)
                .unwrap_err()
                .to_string()
                .contains("unexpected shape")
        );
        world.temp_root = Some(home.join("other/tmp").join(ip.to_string()));
        assert!(
            temp_root(&world)
                .unwrap_err()
                .to_string()
                .contains("unexpected shape")
        );
    }

    #[test]
    fn temp_root_rejects_a_relative_root() {
        let ip = Ipv4Addr::new(127, 77, 0, 5);
        let world = World {
            id: "A".into(),
            ip,
            workdir: PathBuf::from("."),
            temp_root: Some(PathBuf::from(".world/tmp").join(ip.to_string())),
        };
        let err = temp_root(&world).unwrap_err();
        assert!(err.to_string().contains("unexpected shape"), "{err}");
    }

    #[test]
    fn temp_root_rejects_a_root_containing_dotdot() {
        let (_h, home) = home();
        let ip = Ipv4Addr::new(127, 77, 0, 5);
        let world = World {
            id: "A".into(),
            ip,
            workdir: home.clone(),
            temp_root: Some(home.join(".world/tmp/../tmp").join(ip.to_string())),
        };
        let err = temp_root(&world).unwrap_err();
        assert!(err.to_string().contains("unexpected shape"), "{err}");
    }

    #[test]
    fn temp_root_rejects_a_root_under_a_host_temp_directory() {
        let ip = Ipv4Addr::new(127, 77, 0, 5);
        let world = World {
            id: "A".into(),
            ip,
            workdir: PathBuf::from("/private/tmp/x"),
            temp_root: Some(PathBuf::from("/private/tmp/x/.world/tmp").join(ip.to_string())),
        };
        let err = temp_root(&world).unwrap_err();
        assert!(err.to_string().contains("must not be under"), "{err}");
    }

    #[test]
    fn temp_root_reports_a_deleted_home_as_unavailable() {
        let (dir, home) = home();
        let ip = Ipv4Addr::new(127, 77, 0, 5);
        let world = World {
            id: "A".into(),
            ip,
            workdir: home.clone(),
            temp_root: Some(root_for(&home, ip)),
        };
        drop(dir);
        let err = temp_root(&world).unwrap_err();
        assert!(err.to_string().contains("unavailable"), "{err}");
    }

    #[test]
    fn unknown_field_is_still_rejected() {
        let json = serde_json::json!({
            "id": "A",
            "ip": "127.77.0.1",
            "workdir": "/some/dir",
            "bogus": true,
        });
        let err = serde_json::from_value::<World>(json).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }
}

pub fn alias_ready(ip: Ipv4Addr) -> bool {
    // macOS only binds assigned aliases. Linux treats all of 127/8 as local.
    TcpListener::bind(SocketAddrV4::new(ip, 0)).is_ok()
}

#[cfg(target_os = "linux")]
fn holder(state: &Path, id: &str) -> Result<crate::linux::Holder> {
    read_map(state, "holders.json")?
        .remove(id)
        .context("workspace namespace is not running; run world workspace setup")
}

/// macOS: add the workspace loopback alias (sudo). Linux: start the process
/// holding the workspace network namespace; no privilege is required.
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
            .context("workspace namespace holder exited before its record was committed")?;
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
            bail!("loopback setup failed; workspace is not ready");
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
        bail!(
            "workspace localhost isolation requires macOS or Linux; refusing unisolated execution"
        );
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
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    let dir = run::workdir(&world.workdir)?;
    // The checked descriptor itself, never whatever fd 0 is at spawn: a
    // host socket swapped in by another thread would cross into the World.
    let stdin = match run::pin_stdin_with(false)? {
        Some(fd) => std::process::Stdio::from(fd),
        None => std::process::Stdio::null(),
    };
    let (user, net) = holder(state, &world.id)?.open().with_context(|| {
        format!(
            "workspace namespace is not running; run world workspace setup {}",
            world.id
        )
    })?;
    let (user, net) = (
        crate::linux::above_stdio(user)?,
        crate::linux::above_stdio(net)?,
    );
    let (user_fd, net_fd) = (user.as_raw_fd(), net.as_raw_fd());
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .current_dir(&dir)
        .env("WORLD_ID", &world.id);
    // SAFETY: the closure only makes raw system calls on open descriptors.
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            crate::linux::reset_caught_handlers();
            crate::linux::join_namespaces(user_fd, net_fd)?;
            crate::linux::close_extra_descriptors()?;
            crate::linux::enter_pid_namespace()
        });
    }
    let result = run::supervise(
        cmd,
        Some(stdin),
        Instant::now() + duration,
        cancel,
        &mut None,
        None,
    )
    .await;
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
            "workspace loopback alias is not configured; run world workspace setup {}",
            world.id
        );
    }
    let dir = run::workdir(&world.workdir)?;
    reject_shared_temp(&dir, "workdir")?;
    let temp = temp_root(&world)?;
    let executable = resolve_executable(&command[0], &dir, &temp)?;
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
        if name.starts_with("DYLD_")
            || name.starts_with("SILO_")
            || name.starts_with("WORLD_SILO_")
            || name == "WORLD_TMP"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("DYLD_INSERT_LIBRARIES", library)
        .env("SILO_IP", world.ip.to_string())
        .env("SILO_CONNECT", "1")
        .env("WORLD_SILO_ACTIVE", "1")
        .env("WORLD_SILO_ACK", ack.path())
        .env("WORLD_TMP", &temp)
        .env("TMPDIR", temp.join("tmp/"))
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
    path.is_file()
        && std::ffi::CString::new(path.as_os_str().as_bytes())
            .is_ok_and(|path| unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 })
}

/// Map a candidate executable path the same way its containing workspace's
/// temp directories are redirected at exec time, so an entry point below the
/// host's `/tmp` resolves to the workspace's private copy instead. `Ok(None)`
/// means the candidate does not exist and the caller should keep searching;
/// any other error (a malformed root, an overlong result) is not a "try the
/// next candidate" situation and is propagated instead.
#[cfg(target_os = "macos")]
fn map_candidate(temp: &Path, candidate: &Path) -> Result<Option<PathBuf>> {
    match world_tmp_path::map_under(temp, candidate) {
        Ok(mapped) => Ok(Some(mapped)),
        Err(e) if e.raw_os_error().is_some_and(world_tmp_path::skippable) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("resolve {}", candidate.display())),
    }
}

#[cfg(target_os = "macos")]
fn resolve_executable(name: &std::ffi::OsStr, workdir: &Path, temp: &Path) -> Result<PathBuf> {
    resolve_executable_with_path(
        name,
        workdir,
        temp,
        &std::env::var_os("PATH").unwrap_or_default(),
    )
}

/// `path_var` is taken as a parameter, rather than read from the
/// environment, so tests can exercise PATH search without mutating global
/// process state.
#[cfg(target_os = "macos")]
fn resolve_executable_with_path(
    name: &std::ffi::OsStr,
    workdir: &Path,
    temp: &Path,
    path_var: &std::ffi::OsStr,
) -> Result<PathBuf> {
    let path = Path::new(name);
    let path = if path.components().count() > 1 || path.is_absolute() {
        map_candidate(temp, &workdir.join(path))?.context("executable not found")?
    } else {
        let mut found = None;
        for entry in std::env::split_paths(path_var) {
            let candidate = workdir.join(entry).join(name);
            let Some(mapped) = map_candidate(temp, &candidate)? else {
                continue;
            };
            if executable_file(&mapped) {
                found = Some(mapped);
                break;
            }
        }
        found.context("executable not found in PATH")?
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
        bail!("privileged executable unsupported: setuid/setgid can suppress localhost isolation");
    }
    let mut file = File::open(&path)?;
    let mut header = [0u8; 32];
    use std::io::Read;
    let n = file.read(&mut header)?;
    // Scripts may hide a SIP-protected interpreter. Require an explicit
    // non-SIP interpreter, e.g. world exec W1 -- python3 script.py.
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

    #[cfg(target_os = "macos")]
    fn unique_name() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!(
            "wrt-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[cfg(target_os = "macos")]
    // A copy of the running test binary: a real, native, non-SIP Mach-O
    // executable that resolve_executable's SIP/setuid/magic checks accept.
    fn place_copy(temp: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp.join("tmp").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("x");
        std::fs::copy(std::env::current_exe().unwrap(), &bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_executable_maps_an_absolute_entry_point_below_host_tmp() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp = temp_dir.path().canonicalize().unwrap();
        let workdir = tempfile::tempdir().unwrap();
        let name = unique_name();
        let bin = place_copy(&temp, &name);
        let requested = format!("/tmp/{name}/x");
        let resolved = resolve_executable_with_path(
            std::ffi::OsStr::new(&requested),
            workdir.path(),
            &temp,
            std::ffi::OsStr::new(""),
        )
        .unwrap();
        assert_eq!(resolved, bin.canonicalize().unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_executable_maps_a_path_search_entry_point_below_host_tmp() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp = temp_dir.path().canonicalize().unwrap();
        let workdir = tempfile::tempdir().unwrap();
        let name = unique_name();
        let bin = place_copy(&temp, &name);
        let path_var = format!("/tmp/{name}");
        let resolved = resolve_executable_with_path(
            std::ffi::OsStr::new("x"),
            workdir.path(),
            &temp,
            std::ffi::OsStr::new(&path_var),
        )
        .unwrap();
        assert_eq!(resolved, bin.canonicalize().unwrap());
    }
}
