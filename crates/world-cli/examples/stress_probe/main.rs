//! Stress/concurrency probe for World workspaces: threaded storms of file,
//! socket, spawn, and fork/exec operations under a shared directory tree.
//! Companion to `socket_probe`, but aimed at interleaving and races rather
//! than single-syscall behavior. std + libc + serde_json only -- no new
//! dependencies.
//!
//! Modes (see each `cmd_*` function for exact behavior):
//!   storm --threads T --iters N --seed S --dir /tmp/R
//!   spawn-storm --threads T --iters N --dir /tmp/R
//!   fork-exec-storm --threads T --iters N --dir /tmp/R
//!   touch <path> <marker>
//!   pause <marker>   (test-only helper: blocks forever; see STRESS_PROBE_HANG)
//!   report <marker>
//!
//! Safety: every mode that touches a directory tree (storm, spawn-storm,
//! fork-exec-storm) refuses to run unless `--dir` is under a redirected
//! `/tmp` (see `check_dir_allowed`), so a bug here can never reach outside
//! whatever `/tmp`/`/private/tmp` is redirected to (the macOS shim's
//! WORLD_TMP tree, or a Linux bind mount) -- never the real host filesystem.
//! The lexical check is backed by `verify_redirected` and `open_validated`
//! (no symlinked component below /tmp); `verify_redirected` proves (without
//! writing anything) that `/tmp` really is the redirected tree, and fails
//! closed otherwise.
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Tiny splitmix64 PRNG: deterministic across platforms for a given seed, no
/// external RNG dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Shared error/violation bookkeeping across worker threads.
#[derive(Default)]
struct Report {
    ops: AtomicU64,
    errors: Mutex<BTreeMap<String, u64>>,
    violations: Mutex<Vec<String>>,
}

impl Report {
    fn op(&self) {
        self.ops.fetch_add(1, Ordering::Relaxed);
    }

    fn error(&self, kind: &str) {
        *self
            .errors
            .lock()
            .unwrap()
            .entry(kind.to_string())
            .or_insert(0) += 1;
    }

    fn violation(&self, msg: String) {
        self.violations.lock().unwrap().push(msg);
    }

    /// Print the JSON summary and exit: 0 if nothing violated an invariant,
    /// 1 otherwise. Never returns.
    fn finish(&self, expected_files: Vec<String>) -> ! {
        let errors = self.errors.lock().unwrap().clone();
        let violations = self.violations.lock().unwrap().clone();
        let summary = serde_json::json!({
            "ops": self.ops.load(Ordering::Relaxed),
            "errors_by_kind": errors,
            "expected_files": expected_files,
            "violations": violations,
        });
        println!("{summary}");
        std::process::exit(if violations.is_empty() { 0 } else { 1 });
    }
}

/// Join every worker; a panicked worker is a violation, never silently
/// dropped (its share of the invariants was not checked).
fn join_workers(handles: Vec<std::thread::JoinHandle<()>>, report: &Report) {
    for (n, h) in handles.into_iter().enumerate() {
        if let Err(payload) = h.join() {
            let why = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic".into());
            report.error("worker_panic");
            report.violation(format!("worker {n} panicked: {why}"));
        }
    }
}

/// SIGKILL `pid` (and its process group, if it leads one) and reap it with a
/// bounded (2 s) `WNOHANG` poll, so a hung child is neither leaked nor waited
/// on forever. Returns whether the child was reaped.
fn kill_and_reap(pid: libc::pid_t) -> bool {
    // SAFETY: plain signals and waitpid on a pid this process forked/spawned.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
        libc::kill(pid, libc::SIGKILL);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut status = 0;
    loop {
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if w == pid {
            return true;
        }
        if w < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // ECHILD: already reaped elsewhere.
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn cstr(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).expect("path contains NUL")
}

/// Minimal `--name value` flag parser; unrecognized/positional tokens are
/// ignored so callers only need to look up what they expect.
fn parse_flags(args: &[String]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(name) = args[i].strip_prefix("--") {
            let value = args.get(i + 1).cloned().unwrap_or_default();
            map.insert(name.to_string(), value);
            i += 2;
        } else {
            i += 1;
        }
    }
    map
}

fn flag_u64(flags: &BTreeMap<String, String>, name: &str, default: u64) -> u64 {
    flags
        .get(name)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Where a validated `--dir` is anchored.
enum Root {
    /// The lexical `/tmp` or `/private/tmp` prefix (must be proven redirected).
    Tmp(&'static str),
    /// `$STRESS_PROBE_EXTRA_ROOT`: a genuinely separate scratch root.
    Extra(PathBuf),
}

/// Refuse to operate outside a redirected /tmp: `--dir` must start with
/// "/tmp/" or "/private/tmp/" so that under the macOS shim, or a Linux bind
/// mount, every path this binary touches can only ever land inside the
/// workspace's own private tree -- never the real host filesystem, no
/// matter what bug this process might otherwise have. A test harness that
/// owns a genuinely separate scratch root (not under /tmp at all, e.g. for
/// an unshimmed smoke run) can opt a specific prefix in via
/// `STRESS_PROBE_EXTRA_ROOT`; a stray/unexpected invocation can never set
/// that for itself.
///
/// `Root::Tmp` means the `/tmp` prefix matched, so the caller must also
/// pass `verify_redirected`; `Root::Extra` means the
/// `STRESS_PROBE_EXTRA_ROOT` branch matched (no redirection to prove).
fn check_dir_allowed(dir: &Path) -> Result<Root, String> {
    // A `..` component could climb out of the allowed prefix textually.
    if dir
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("--dir {} must not contain `..`", dir.display()));
    }
    let s = dir.to_string_lossy();
    for prefix in ["/tmp", "/private/tmp"] {
        if s.starts_with(prefix) && s[prefix.len()..].starts_with('/') {
            return Ok(Root::Tmp(prefix));
        }
    }
    if let Ok(extra) = std::env::var("STRESS_PROBE_EXTRA_ROOT")
        && !extra.is_empty()
        && dir.starts_with(&extra)
    {
        return Ok(Root::Extra(PathBuf::from(extra)));
    }
    Err(format!(
        "--dir {} is not under /tmp or /private/tmp (and not under $STRESS_PROBE_EXTRA_ROOT); refusing to run",
        dir.display()
    ))
}

/// Host temp roots a "physical root" must never be, or live under: were it
/// one of them, "/tmp is redirected to <phys>/tmp" would be tautological.
const HOST_TEMP_ROOTS: [&str; 4] = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"];

/// Prove, without writing anything, that `/tmp` is redirected to a private
/// tree rather than being the shared host temp dir. The physical root comes
/// from `STRESS_PROBE_PHYSICAL_ROOT` (the Linux harness passes the workspace
/// temp root) or else `WORLD_TMP` (the macOS shim's root); it must be set,
/// absolute, `..`-free, and not the filesystem root, `/private`, or anything
/// at or under a host temp root. Then `stat("/tmp")` (redirected by the shim
/// or bind-mounted on Linux, so it names `<phys>/tmp`) must be the very same
/// (st_dev, st_ino) as `lstat("<phys>/tmp")`, which the shim never remaps
/// because `<phys>` is outside every temp root. Unshimmed, `/tmp` is the host
/// temp dir and the identities differ. Every failure -- including any I/O
/// error -- refuses (fail closed).
///
/// The proof is made on an fd: `prefix` (the lexical "/tmp" or
/// "/private/tmp" the caller's `--dir` starts with) is opened with
/// `O_DIRECTORY|O_CLOEXEC`, and that fd is `fstat`ed and compared against
/// `lstat("<phys>/tmp")`. The returned fd is the anchor `open_validated`
/// walks from, so there is no window between "verified" and "used", and a
/// `/private/tmp` dir is never accepted on the strength of `/tmp` alone.
fn verify_redirected(prefix: &str) -> Result<OwnedFd, String> {
    use std::os::unix::fs::MetadataExt;
    let fail =
        |why: String| -> Result<OwnedFd, String> { Err(format!("not running redirected: {why}")) };

    let phys = std::env::var_os("STRESS_PROBE_PHYSICAL_ROOT")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("WORLD_TMP").filter(|v| !v.is_empty()));
    let Some(phys) = phys else {
        return fail("neither STRESS_PROBE_PHYSICAL_ROOT nor WORLD_TMP is set".into());
    };
    let phys = PathBuf::from(phys);
    if !phys.is_absolute() {
        return fail(format!("physical root {} is not absolute", phys.display()));
    }
    if phys
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return fail(format!("physical root {} contains `..`", phys.display()));
    }
    let real = match std::fs::canonicalize(&phys) {
        Ok(r) => r,
        Err(e) => {
            return fail(format!(
                "cannot resolve physical root {}: {e}",
                phys.display()
            ));
        }
    };
    let too_broad = real == Path::new("/") || real == Path::new("/private");
    let under_host_temp = |p: &Path| HOST_TEMP_ROOTS.iter().any(|r| p.starts_with(r));
    if too_broad || under_host_temp(&real) || under_host_temp(&phys) {
        return fail(format!(
            "physical root {} (resolves to {}) is a host temp root or too broad",
            phys.display(),
            real.display()
        ));
    }
    let root_fd = match open_dir_fd(libc::AT_FDCWD, &cstr(Path::new(prefix)), false) {
        Ok(fd) => fd,
        Err(e) => return fail(format!("open {prefix}: {e}")),
    };
    let redirected = match fstat_fd(&root_fd) {
        Ok(st) => st,
        Err(e) => return fail(format!("fstat {prefix}: {e}")),
    };
    let private_tmp = real.join("tmp");
    let private = match std::fs::symlink_metadata(&private_tmp) {
        Ok(m) => m,
        Err(e) => return fail(format!("lstat {}: {e}", private_tmp.display())),
    };
    if !private.is_dir()
        || (redirected.st_dev as u64, redirected.st_ino as u64) != (private.dev(), private.ino())
    {
        return fail(format!(
            "{prefix} is not {} (a shared host temp dir would be touched)",
            private_tmp.display()
        ));
    }
    Ok(root_fd)
}

/// `openat(dirfd, path, O_RDONLY|O_DIRECTORY[|O_NOFOLLOW]|O_CLOEXEC)`.
fn open_dir_fd(dirfd: libc::c_int, path: &CString, nofollow: bool) -> std::io::Result<OwnedFd> {
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    // SAFETY: `path` is a valid NUL-terminated string for the whole call.
    let fd = unsafe { libc::openat(dirfd, path.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat_fd(fd: &OwnedFd) -> std::io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is a valid out-pointer; `fd` is an open descriptor.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded, so `st` is initialized.
    Ok(unsafe { st.assume_init() })
}

const NOT_PRIVATE: &str = "not a real directory inside the private tree";

/// Resolve `dir` to an fd, proving every component is a real directory
/// inside the private tree. The anchor is `verify_redirected`'s fd for a
/// `/tmp` dir (or an fd opened on `$STRESS_PROBE_EXTRA_ROOT`); the remaining
/// components are walked fd-relative: `.`/`..`/empty components are refused,
/// each is `mkdirat`ed first when `create` (EEXIST ignored), then
/// `openat`ed with `O_DIRECTORY|O_NOFOLLOW` (a symlink yields ELOOP/ENOTDIR
/// and is refused), and must stay on the root's device (no crossing
/// mounts). A pre-existing symlink below `/tmp` can therefore never redirect
/// a later absolute-path operation on `dir`, because the caller only goes on
/// once this returns.
///
/// Remaining race: the storm operations themselves use absolute paths (they
/// exist to exercise the shim's absolute-path interposition), so another
/// writer that already has access to the private tree could swap a validated
/// component for a symlink between this walk and the operation. The private
/// tree is owned by the harness, so that is outside the threat model; only
/// the final component of each storm operation is `O_NOFOLLOW`.
fn open_validated(dir: &Path, create: bool) -> Result<OwnedFd, String> {
    let (root_fd, rest) = match check_dir_allowed(dir)? {
        Root::Tmp(prefix) => {
            let fd = verify_redirected(prefix)?;
            let rest = dir.as_os_str().as_bytes()[prefix.len()..].to_vec();
            (fd, rest)
        }
        Root::Extra(extra) => {
            let fd = open_dir_fd(libc::AT_FDCWD, &cstr(&extra), false)
                .map_err(|e| format!("open {}: {e}", extra.display()))?;
            let rest = dir.strip_prefix(&extra).map_err(|e| e.to_string())?;
            let mut rest_bytes = b"/".to_vec();
            rest_bytes.extend_from_slice(rest.as_os_str().as_bytes());
            (fd, rest_bytes)
        }
    };
    let root_dev = fstat_fd(&root_fd)
        .map_err(|e| format!("fstat root: {e}"))?
        .st_dev;
    let mut cur = root_fd;
    // `rest` is "" (the root itself) or "/a/b/c".
    if rest.is_empty() || rest == b"/" {
        return Ok(cur);
    }
    for comp in rest[1..].split(|&b| b == b'/') {
        if comp.is_empty() || comp == b"." || comp == b".." {
            return Err(format!("{}: {NOT_PRIVATE} (bad component)", dir.display()));
        }
        let name = CString::new(comp).map_err(|_| "path contains NUL".to_string())?;
        if create {
            // SAFETY: `cur` is an open directory fd; `name` is NUL-terminated.
            let r = unsafe { libc::mkdirat(cur.as_raw_fd(), name.as_ptr(), 0o755) };
            if r != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(format!("mkdir {}: {e}", dir.display()));
                }
            }
        }
        let next = match open_dir_fd(cur.as_raw_fd(), &name, true) {
            Ok(fd) => fd,
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::EMLINK)
                ) =>
            {
                return Err(format!("{}: {NOT_PRIVATE}", dir.display()));
            }
            Err(e) => return Err(format!("open {}: {e}", dir.display())),
        };
        let st = fstat_fd(&next).map_err(|e| format!("fstat {}: {e}", dir.display()))?;
        if st.st_dev != root_dev {
            return Err(format!(
                "{}: {NOT_PRIVATE} (crosses a mount)",
                dir.display()
            ));
        }
        cur = next;
    }
    Ok(cur)
}

fn flag_dir(flags: &BTreeMap<String, String>) -> PathBuf {
    let dir = PathBuf::from(
        flags
            .get("dir")
            .unwrap_or_else(|| panic!("--dir is required")),
    );
    exit_on_err(open_validated(&dir, true));
    dir
}

/// Validate (creating) `<dir>/<t>`; exits 2 if it is not a real directory
/// inside the private tree.
fn thread_dir(dir: &Path, t: usize) {
    exit_on_err(open_validated(&dir.join(t.to_string()), true));
}

fn exit_on_err(r: Result<OwnedFd, String>) -> OwnedFd {
    match r {
        Ok(fd) => fd,
        Err(msg) => {
            eprintln!("stress_probe: {msg}");
            std::process::exit(2);
        }
    }
}

/// Read a file without following a symlink in the final component.
fn read_nofollow(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut s = String::new();
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .read_to_string(&mut s)?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// storm

/// `storm --threads T --iters N --seed S --dir /tmp/R`: T threads, each
/// doing N iterations of absolute-path open/write/rename/unlink and a
/// bind+connect(AF_UNIX)+getsockname round under /tmp/R/<thread>/..., plus
/// one chdir thread repeatedly chdir-ing into /tmp/R/<n> and asserting
/// getcwd never contains the physical root (WORLD_TMP) as a substring.
fn cmd_storm(flags: &BTreeMap<String, String>) {
    let threads = flag_u64(flags, "threads", 4).max(1) as usize;
    let iters = flag_u64(flags, "iters", 20).max(1) as usize;
    let seed = flag_u64(flags, "seed", 1);
    let dir = flag_dir(flags);

    for t in 0..threads {
        thread_dir(&dir, t);
    }

    let report = Arc::new(Report::default());
    let world_tmp = std::env::var("WORLD_TMP").ok().filter(|s| !s.is_empty());

    let mut handles = Vec::new();
    for t in 0..threads {
        let dir = dir.clone();
        let report = Arc::clone(&report);
        let mut rng = SplitMix64::new(seed ^ (t as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        handles.push(std::thread::spawn(move || {
            storm_worker(t, iters, &dir, &report, &mut rng);
        }));
    }
    {
        let dir = dir.clone();
        let report = Arc::clone(&report);
        handles.push(std::thread::spawn(move || {
            chdir_worker(threads, iters, &dir, &report, world_tmp.as_deref());
        }));
    }
    join_workers(handles, &report);

    // Each worker's deterministic final file: the last iteration's renamed
    // file is left in place (see `storm_worker`).
    let expected: Vec<String> = (0..threads)
        .map(|t| {
            dir.join(t.to_string())
                .join(format!("file_{}.ren", iters - 1))
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    for path in &expected {
        if !Path::new(path).is_file() {
            report.violation(format!("missing expected file: {path}"));
        }
    }
    report.finish(expected);
}

fn storm_worker(t: usize, iters: usize, dir: &Path, report: &Report, rng: &mut SplitMix64) {
    let tdir = dir.join(t.to_string());
    for i in 0..iters {
        let file = tdir.join(format!("file_{i}"));
        let renamed = tdir.join(format!("file_{i}.ren"));

        report.op();
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&file)
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"stress"));
        if let Err(e) = written {
            report.error("open");
            report.violation(format!("write {}: {e}", file.display()));
            continue;
        }

        report.op();
        if let Err(e) = std::fs::rename(&file, &renamed) {
            report.error("rename");
            report.violation(format!("rename {}: {e}", file.display()));
            continue;
        }

        // Every iteration but the last cleans up after itself; the last one
        // leaves a deterministic final file (this thread's `expected_files`
        // entry).
        if i + 1 < iters {
            report.op();
            if let Err(e) = std::fs::remove_file(&renamed) {
                report.error("unlink");
                report.violation(format!("unlink {}: {e}", renamed.display()));
            }
        }

        report.op();
        if let Err(msg) = socket_round(&tdir, i, rng) {
            report.error("socket");
            report.violation(msg);
        }
    }
}

/// Whether `got` (as reported by `getsockname`) is `expected`, allowing for
/// the macOS shim's canonical host reporting: a socket bound under /tmp or
/// /var/tmp is reported at its `/private/...` form (see
/// `test_short_getsockname_buffer_is_respected` in tests/test_runtime.py),
/// exactly as it would be for any path under a real symlinked /tmp.
fn matches_reported(expected: &Path, got: Option<&Path>) -> bool {
    let Some(got) = got else { return false };
    if got == expected {
        return true;
    }
    let s = expected.to_string_lossy();
    let canonical = s
        .strip_prefix("/var/tmp/")
        .map(|rest| format!("/private/var/tmp/{rest}"))
        .or_else(|| {
            s.strip_prefix("/tmp/")
                .map(|rest| format!("/private/tmp/{rest}"))
        });
    canonical.is_some_and(|c| got == Path::new(&c))
}

/// One bind+connect+getsockname round over a scratch AF_UNIX socket, cleaned
/// up before returning so it never becomes part of the final file set.
fn socket_round(dir: &Path, i: usize, rng: &mut SplitMix64) -> Result<(), String> {
    let path = dir.join(format!("s{i}-{}.sock", rng.next_u64() % 1000));
    let _ = std::fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("getsockname {}: {e}", path.display()))?;
    if !matches_reported(&path, addr.as_pathname()) {
        let _ = std::fs::remove_file(&path);
        return Err(format!(
            "getsockname mismatch for {}: {addr:?}",
            path.display()
        ));
    }
    let client = match UnixStream::connect(&path) {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(format!("connect {}: {e}", path.display()));
        }
    };
    drop(client);
    drop(listener);
    let _ = std::fs::remove_file(&path);
    Ok(())
}

fn chdir_worker(
    threads: usize,
    iters: usize,
    dir: &Path,
    report: &Report,
    world_tmp: Option<&str>,
) {
    let threads = threads.max(1);
    for i in 0..iters * threads {
        let target = dir.join((i % threads).to_string());
        let c = cstr(&target);
        report.op();
        // SAFETY: `c` is a NUL-terminated path; chdir reads it and has no
        // other preconditions.
        if unsafe { libc::chdir(c.as_ptr()) } != 0 {
            report.error("chdir");
            continue;
        }
        let mut buf = vec![0u8; 4096];
        // SAFETY: `buf` is a valid, writable buffer of the given length,
        // outliving the call.
        let cwd = unsafe { libc::getcwd(buf.as_mut_ptr().cast(), buf.len()) };
        if cwd.is_null() {
            report.error("getcwd");
            continue;
        }
        // SAFETY: `getcwd` returned non-null, i.e. `buf`'s own storage,
        // NUL-terminated within its bounds.
        let cwd = unsafe { std::ffi::CStr::from_ptr(cwd) }
            .to_string_lossy()
            .into_owned();
        if let Some(physical) = world_tmp
            && cwd.contains(physical)
        {
            report.violation(format!(
                "getcwd leaked the physical root: {cwd:?} contains {physical:?}"
            ));
        }
        std::thread::yield_now();
    }
    // SAFETY: "/" is a NUL-terminated literal path that always exists;
    // leaves the process cwd somewhere harmless for any later verification.
    // This is the only chdir target in this binary that is not under
    // `--dir`: it never *stays* under `--dir` once this worker returns, by
    // design, so a caller cannot mistake a leftover cwd for one still
    // inside the (possibly about-to-be-removed) test tree.
    unsafe {
        libc::chdir(c"/".as_ptr());
    }
}

// ---------------------------------------------------------------------------
// spawn-storm

/// `spawn-storm --threads T --iters N --dir /tmp/R`: half the threads
/// concurrently posix_spawn (with file actions redirecting stdout and
/// chdir-ing into /tmp/R/<t>) a `stress_probe report <marker>` child, while
/// the other half only init/destroy file_actions objects, to stress
/// concurrent use of the opaque file-actions object across threads.
fn cmd_spawn_storm(flags: &BTreeMap<String, String>) {
    let threads = flag_u64(flags, "threads", 4).max(2) as usize;
    let iters = flag_u64(flags, "iters", 10).max(1) as usize;
    let dir = flag_dir(flags);

    for t in 0..threads {
        thread_dir(&dir, t);
    }

    let report = Arc::new(Report::default());
    let exe = std::env::current_exe().expect("current_exe");

    let mut handles = Vec::new();
    for t in 0..threads {
        let dir = dir.clone();
        let report = Arc::clone(&report);
        let exe = exe.clone();
        if t % 2 == 0 {
            handles.push(std::thread::spawn(move || {
                spawn_worker(t, iters, &dir, &exe, &report)
            }));
        } else {
            handles.push(std::thread::spawn(move || churn_worker(iters, &report)));
        }
    }
    join_workers(handles, &report);

    let expected: Vec<String> = (0..threads)
        .filter(|t| t % 2 == 0)
        .flat_map(|t| (0..iters).map(move |i| (t, i)))
        .map(|(t, i)| {
            dir.join(t.to_string())
                .join(format!("{i}.out"))
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    for path in &expected {
        if !Path::new(path).is_file() {
            report.violation(format!("missing expected output file: {path}"));
        }
    }
    report.finish(expected);
}

fn spawn_worker(t: usize, iters: usize, dir: &Path, exe: &Path, report: &Report) {
    let tdir = dir.join(t.to_string());
    let tdir_c = cstr(&tdir);
    let exe_c = cstr(exe);
    for i in 0..iters {
        let out = tdir.join(format!("{i}.out"));
        let marker = format!("t{t}-i{i}");
        report.op();
        match spawn_report(&exe_c, &tdir_c, &out, &marker) {
            Ok(0) => {}
            Ok(status) => {
                report.error("spawn_exit");
                report.violation(format!("child exited {status} for {}", out.display()));
                continue;
            }
            Err(e) => {
                report.error("spawn");
                report.violation(format!("spawn failed for {}: {e}", out.display()));
                continue;
            }
        }
        match read_nofollow(&out) {
            Ok(content) if content.trim() == marker => {}
            Ok(content) => {
                report.error("content_mismatch");
                report.violation(format!(
                    "{}: expected {marker:?}, got {content:?}",
                    out.display()
                ));
            }
            Err(e) => {
                report.error("read_output");
                report.violation(format!("read {}: {e}", out.display()));
            }
        }
    }
}

/// Upper bound on how long a spawned child may run before it is killed.
const SPAWN_WAIT: Duration = Duration::from_secs(30);

/// Spawn `exe report <marker>` with stdout redirected to `out` and the cwd
/// changed to `chdir_to`, both via posix_spawn file actions; wait for it and
/// return its exit status.
fn spawn_report(
    exe: &CString,
    chdir_to: &CString,
    out: &Path,
    marker: &str,
) -> std::io::Result<i32> {
    let out_c = cstr(out);
    let report_arg = c"report";
    let marker_c = CString::new(marker).expect("marker contains NUL");
    let argv: [*const libc::c_char; 4] = [
        exe.as_ptr(),
        report_arg.as_ptr(),
        marker_c.as_ptr(),
        std::ptr::null(),
    ];
    // Forward the real environment rather than an empty one: under the
    // macOS shim, a posix_spawn whose envp would silently drop
    // DYLD_INSERT_LIBRARIES/SILO_IP/WORLD_TMP is refused outright (see
    // `spawn_allowed` in vendor/silo-bind/src/world.rs) as a would-be
    // injection escape, not a bug -- so the child must see the same
    // environment this process does.
    let (_env_keep, envp) = build_envp();

    // SAFETY: `actions` is initialized before any other use and destroyed on
    // every exit path below.
    unsafe {
        let mut actions = std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
        let r = libc::posix_spawn_file_actions_init(actions.as_mut_ptr());
        if r != 0 {
            return Err(std::io::Error::from_raw_os_error(r));
        }
        let mut actions = actions.assume_init();
        let r = libc::posix_spawn_file_actions_addopen(
            &mut actions,
            1,
            out_c.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW,
            0o644,
        );
        if r != 0 {
            libc::posix_spawn_file_actions_destroy(&mut actions);
            return Err(std::io::Error::from_raw_os_error(r));
        }
        let r = addchdir_np(&mut actions, chdir_to.as_ptr());
        if r != 0 {
            libc::posix_spawn_file_actions_destroy(&mut actions);
            return Err(std::io::Error::from_raw_os_error(r));
        }
        let mut pid: libc::pid_t = 0;
        let r = libc::posix_spawn(
            &mut pid,
            exe.as_ptr(),
            &actions,
            std::ptr::null(),
            argv.as_ptr().cast(),
            envp.as_ptr().cast(),
        );
        libc::posix_spawn_file_actions_destroy(&mut actions);
        if r != 0 {
            return Err(std::io::Error::from_raw_os_error(r));
        }
        let mut status = 0;
        let deadline = Instant::now() + SPAWN_WAIT;
        loop {
            let w = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if w == pid {
                break;
            }
            if w < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if Instant::now() >= deadline {
                kill_and_reap(pid);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("spawned child {pid} did not exit within {SPAWN_WAIT:?}"),
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        })
    }
}

// macOS declares `posix_spawn_file_actions_addchdir_np` weakly (it is not
// present on every OS version this binary might run on), following the same
// pattern `socket_probe` uses; glibc/musl expose it directly through the
// `libc` crate.
#[cfg(target_os = "macos")]
core::arch::global_asm!(".weak_reference _posix_spawn_file_actions_addchdir_np");
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}

/// # Safety
/// `actions` must be a valid, initialized `posix_spawn_file_actions_t`; the
/// same requirement `posix_spawn_file_actions_addchdir_np` itself has.
unsafe fn addchdir_np(
    actions: *mut libc::posix_spawn_file_actions_t,
    path: *const libc::c_char,
) -> libc::c_int {
    #[cfg(target_os = "macos")]
    // SAFETY: forwarded from the caller's own precondition.
    unsafe {
        posix_spawn_file_actions_addchdir_np(actions, path)
    }
    #[cfg(not(target_os = "macos"))]
    // SAFETY: forwarded from the caller's own precondition.
    unsafe {
        libc::posix_spawn_file_actions_addchdir_np(actions, path)
    }
}

fn churn_worker(iters: usize, report: &Report) {
    for _ in 0..iters * 4 {
        report.op();
        // SAFETY: `actions` is initialized immediately below and destroyed
        // before it goes out of scope; never spawned or otherwise used.
        unsafe {
            let mut actions = std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
            if libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) != 0 {
                report.error("file_actions_init");
                continue;
            }
            let mut actions = actions.assume_init();
            libc::posix_spawn_file_actions_destroy(&mut actions);
        }
        std::thread::yield_now();
    }
}

// ---------------------------------------------------------------------------
// fork-exec-storm

/// `fork-exec-storm --threads T --iters N --dir /tmp/R`: in a multithreaded
/// process, each thread repeatedly forks. On even iterations the child
/// `execve`s `stress_probe touch /tmp/R/<t>/<i> <marker>` (argv/envp built
/// before the fork so the child never allocates), which proves both that the
/// exec path works and that interposition survives exec (the exec'd image
/// runs its own `verify_redirected`); on odd iterations the child does an
/// interposed in-child `open` of the same path then writes the marker and `_exit`s. The parent
/// waits with a bounded deadline (WNOHANG polling) so a hang shows up as pids on stdout and exit
/// 3, never an unbounded wait.
fn cmd_fork_exec_storm(flags: &BTreeMap<String, String>) {
    let threads = flag_u64(flags, "threads", 4).max(1) as usize;
    let iters = flag_u64(flags, "iters", 10).max(1) as usize;
    let dir = flag_dir(flags);

    for t in 0..threads {
        thread_dir(&dir, t);
    }

    let report = Arc::new(Report::default());
    let deadline = Instant::now() + Duration::from_millis(flag_u64(flags, "deadline-ms", 30_000));
    let exe = std::env::current_exe().expect("current_exe");
    let shared = Arc::new(ForkShared {
        outstanding: Mutex::new(BTreeMap::new()),
        stop: AtomicBool::new(false),
        killed: Mutex::new(Vec::new()),
        deadline,
        // Test-only: exec `pause <marker>` instead of `touch`, so a child
        // hangs and the timeout path can be exercised.
        hang: std::env::var("STRESS_PROBE_HANG")
            .ok()
            .filter(|m| !m.is_empty()),
    });

    let mut handles = Vec::new();
    for t in 0..threads {
        let dir = dir.clone();
        let report = Arc::clone(&report);
        let shared = Arc::clone(&shared);
        let exe = exe.clone();
        handles.push(std::thread::spawn(move || {
            fork_exec_worker(t, iters, &dir, &exe, &report, &shared);
        }));
    }
    join_workers(handles, &report);

    // Backstop: anything still recorded (a panicked worker's child) is
    // killed and reaped here, never leaked.
    let leftovers: Vec<libc::pid_t> = shared
        .outstanding
        .lock()
        .unwrap()
        .values()
        .copied()
        .collect();
    for pid in leftovers {
        let reaped = kill_and_reap(pid);
        shared.killed.lock().unwrap().push((pid, reaped));
    }
    if shared.stop.load(Ordering::SeqCst) {
        let killed = shared.killed.lock().unwrap();
        let pids: Vec<libc::pid_t> = killed.iter().map(|(p, _)| *p).collect();
        let unreaped: Vec<libc::pid_t> =
            killed.iter().filter(|(_, r)| !r).map(|(p, _)| *p).collect();
        let summary = serde_json::json!({"timeout": true, "pids": pids, "unreaped": unreaped});
        println!("{summary}");
        std::process::exit(3);
    }

    let expected: Vec<String> = (0..threads)
        .flat_map(|t| (0..iters).map(move |i| (t, i)))
        .map(|(t, i)| {
            dir.join(t.to_string())
                .join(i.to_string())
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    for path in &expected {
        if !Path::new(path).is_file() {
            report.violation(format!("missing expected file: {path}"));
        }
    }
    report.finish(expected);
}

/// The environment as a NUL-terminated `envp`, forwarded whole: under the
/// macOS shim an exec whose envp drops DYLD_INSERT_LIBRARIES/WORLD_TMP is
/// refused as an injection escape.
fn build_envp() -> (Vec<CString>, Vec<*const libc::c_char>) {
    let env_entries: Vec<CString> = std::env::vars_os()
        .map(|(k, v)| {
            let mut entry = k.into_encoded_bytes();
            entry.push(b'=');
            entry.extend_from_slice(&v.into_encoded_bytes());
            CString::new(entry).expect("environment entry contains NUL")
        })
        .collect();
    let mut envp: Vec<*const libc::c_char> = env_entries.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());
    (env_entries, envp)
}

/// State shared by the fork-exec-storm workers.
struct ForkShared {
    /// The pid each worker is currently waiting on.
    outstanding: Mutex<BTreeMap<usize, libc::pid_t>>,
    /// Set when the shared deadline passes: every worker stops forking, kills
    /// and reaps its own child, and returns.
    stop: AtomicBool,
    /// `(pid, reaped)` for every child killed because of the timeout.
    killed: Mutex<Vec<(libc::pid_t, bool)>>,
    deadline: Instant,
    /// Test-only hang marker (`STRESS_PROBE_HANG`).
    hang: Option<String>,
}

/// Timeout path of a worker: kill and reap its own child, recording whether
/// it was reaped.
fn give_up(shared: &ForkShared, t: usize, pid: libc::pid_t) {
    let reaped = kill_and_reap(pid);
    shared.killed.lock().unwrap().push((pid, reaped));
    shared.outstanding.lock().unwrap().remove(&t);
}

fn fork_exec_worker(
    t: usize,
    iters: usize,
    dir: &Path,
    exe: &Path,
    report: &Report,
    shared: &ForkShared,
) {
    let (outstanding, stop, deadline) = (&shared.outstanding, &shared.stop, shared.deadline);
    let tdir = dir.join(t.to_string());
    for i in 0..iters {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let path = tdir.join(i.to_string());
        let path_c = cstr(&path);
        let exec = i % 2 == 0;
        let marker = format!("fe-t{t}-i{i}");
        // Everything the exec branch needs is built before the fork.
        let exe_c = cstr(exe);
        let touch_c = c"touch";
        let marker_c = CString::new(marker.as_str()).expect("marker contains NUL");
        let pause_c = c"pause";
        let hang_c = shared
            .hang
            .as_deref()
            .map(|m| CString::new(m).expect("hang marker contains NUL"));
        let argv: [*const libc::c_char; 5] = match &hang_c {
            Some(h) => [
                exe_c.as_ptr(),
                pause_c.as_ptr(),
                h.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            ],
            None => [
                exe_c.as_ptr(),
                touch_c.as_ptr(),
                path_c.as_ptr(),
                marker_c.as_ptr(),
                std::ptr::null(),
            ],
        };
        let (_env_keep, envp) = build_envp();

        report.op();
        // SAFETY: fork() has no preconditions of its own; only the child
        // branch below must stay async-signal-safe (no allocation, no
        // locking -- `path_c` was already built above).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            report.error("fork");
            report.violation(format!(
                "fork failed for {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
            continue;
        }
        if pid == 0 {
            // SAFETY: async-signal-safe only: a direct execve/open/write/
            // close/_exit, nothing allocated or locked since the fork above; argv
            // and envp are NUL-terminated arrays of pointers into CStrings
            // that outlive the child's use of them.
            unsafe {
                // Its own process group, so a timeout can kill the whole group.
                libc::setpgid(0, 0);
                if exec {
                    libc::execve(exe_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
                    libc::_exit(127);
                }
                let fd = libc::open(
                    path_c.as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW,
                    0o644,
                );
                if fd >= 0 {
                    let bytes = marker_c.as_bytes();
                    let n = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
                    libc::close(fd);
                    libc::_exit(if n == bytes.len() as isize { 0 } else { 1 });
                }
                libc::_exit(1);
            }
        }

        outstanding.lock().unwrap().insert(t, pid);
        if stop.load(Ordering::SeqCst) {
            give_up(shared, t, pid);
            return;
        }
        let mut status = 0;
        loop {
            // SAFETY: `pid` was just returned by `fork` above, in this
            // thread, and is only waited on here.
            let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if w == pid {
                break;
            }
            if w < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                report.error("waitpid");
                report.violation(format!("waitpid failed for pid {pid}: {err}"));
                break;
            }
            if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                stop.store(true, Ordering::SeqCst);
                give_up(shared, t, pid);
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        outstanding.lock().unwrap().remove(&t);

        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);
            if code == 127 && exec {
                report.error("exec_failed");
                report.violation(format!("exec failed for {}", path.display()));
            } else if code != 0 {
                report.error("child_exit");
                report.violation(format!("child for {} exited {code}", path.display()));
            } else {
                match read_nofollow(&path) {
                    Ok(content) if content == marker => {}
                    Ok(content) => {
                        report.error("content_mismatch");
                        report.violation(format!(
                            "{}: expected {marker:?}, got {content:?}",
                            path.display()
                        ));
                    }
                    Err(e) => {
                        report.error("read_output");
                        report.violation(format!("read {}: {e}", path.display()));
                    }
                }
            }
        } else {
            report.error("child_signal");
            report.violation(format!(
                "child for {} did not exit normally",
                path.display()
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// report

/// `report <marker>`: child target for spawn-storm/fork-exec-storm. Writes
/// `marker` to stdout, which -- for spawn-storm -- is a file redirected by
/// posix_spawn file actions.
fn cmd_report(args: &[String]) {
    let marker = args.get(2).cloned().unwrap_or_default();
    print!("{marker}");
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// `touch <path> <marker>`: child target for fork-exec-storm. Refuses (exit
/// 2) unless the path's parent passes `open_validated` (lexical `/tmp` check,
/// `verify_redirected`, and a no-follow walk, so this also proves
/// interposition survived exec), then `openat`s the name in that parent with
/// `O_NOFOLLOW`, creating/truncating it, and writes `marker` to it.
fn cmd_touch(args: &[String]) {
    use std::io::Write;
    let (Some(path), Some(marker)) = (args.get(2), args.get(3)) else {
        eprintln!("usage: stress_probe touch <path> <marker>");
        std::process::exit(2);
    };
    let raw = path.as_bytes();
    let Some(slash) = raw.iter().rposition(|&b| b == b'/') else {
        eprintln!("stress_probe: {path} has no parent");
        std::process::exit(2);
    };
    let (parent, name) = (&path[..slash], &path[slash + 1..]);
    if name.is_empty() || name == "." || name == ".." || parent.is_empty() {
        eprintln!("stress_probe: {path} does not name a file");
        std::process::exit(2);
    }
    let pfd = exit_on_err(open_validated(Path::new(parent), false));
    let name_c = CString::new(name).expect("name contains NUL");
    // SAFETY: `pfd` is an open directory fd and `name_c` is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            pfd.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644 as libc::c_uint,
        )
    };
    if fd < 0 {
        eprintln!(
            "stress_probe: touch {path}: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
    // SAFETY: `fd` was just returned by openat and is owned by nobody else.
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    if let Err(e) = f.write_all(marker.as_bytes()) {
        eprintln!("stress_probe: touch {path}: {e}");
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: stress_probe <storm|spawn-storm|fork-exec-storm|touch|report> ...");
        std::process::exit(2);
    }
    match args[1].as_str() {
        "report" => cmd_report(&args),
        "touch" => cmd_touch(&args),
        "pause" => loop {
            // Test-only helper for STRESS_PROBE_HANG: blocks until killed.
            // SAFETY: pause() has no preconditions.
            unsafe { libc::pause() };
        },
        "storm" => cmd_storm(&parse_flags(&args[2..])),
        "spawn-storm" => cmd_spawn_storm(&parse_flags(&args[2..])),
        "fork-exec-storm" => cmd_fork_exec_storm(&parse_flags(&args[2..])),
        other => {
            eprintln!("unknown mode: {other}");
            std::process::exit(2);
        }
    }
}
