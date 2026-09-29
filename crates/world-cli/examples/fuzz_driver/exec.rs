//! Real-side execution: run one `world_fsmodel::Op` against the real
//! filesystem (through the macOS shim, or Linux's bind-mounted /tmp) and
//! report an `Outcome` shaped exactly like `Model::apply`'s, so `main.rs` can
//! compare them directly.
//!
//! # Safety
//!
//! This process is the *managed* process: real, mutating syscalls are the
//! whole point. Every one of them goes through the guarantees below, which
//! together are what make it safe to run this unattended against generated
//! (and possibly buggy) operation sequences:
//!
//! 1. This process's own ambient working directory is **never** changed.
//!    `Op::Chdir` is implemented by opening the target directory with
//!    `openat` and remembering the resulting `dirfd` (`RealState::cwd_fd`);
//!    every relative-path op after that resolves against that `dirfd`, never
//!    against an ambient cwd. `Op::Getcwd`/`Op::Realpath` (which need a real
//!    ambient cwd to exercise the real `getcwd(3)`/`realpath(3)` entry
//!    points) run that one call in a short-lived forked child that
//!    `fchdir`s to `cwd_fd` and reports back over a pipe; the parent's own
//!    cwd is never touched.
//! 2. Before any *mutating* real syscall (`mkdir`, `open` with `O_CREAT`,
//!    `symlink`, `rename`, `unlink`, `rmdir`, `bind`, `mkstemp`, ...), the
//!    target's parent directory is opened (following symlinks, exactly as
//!    the kernel would for every non-final path component) and its own
//!    canonical path is re-resolved fresh (`F_GETPATH` on macOS,
//!    `/proc/self/fd` on Linux) and checked against the run's sandbox roots
//!    (`parent_allowed`, in `guarded_parent`). A mismatch is refused
//!    *before* the syscall runs -- `ExecError::Harness`, which `main.rs`
//!    turns into a harness abort (exit 2), never executing the op. This is a
//!    second, independent layer under the generator's own rule of never
//!    generating a mutating op whose parent doesn't resolve inside the
//!    sandbox in the model (see `gen.rs`).
//!    Every `open` whose flags can change anything (`O_CREAT`, `O_TRUNC`, or
//!    a writable access mode -- `open_mutates`) gets the same guard, *and*
//!    the final component is chased by hand: a symlink there is read with
//!    `readlinkat` and its own parent is guarded in turn (`open_mutating`),
//!    since `openat` alone would follow the link wherever it points. The
//!    fd that comes back is finally re-checked against the sandbox as a
//!    backstop. Read-only opens (`Open`, `OpenAt`, `OpenDir`, `List`) refuse
//!    FIFOs and devices up front (an outside FIFO would block forever) and
//!    only keep an fd that is inside the sandbox or a directory that is an
//!    ancestor of a sandbox root (`/`, `/tmp`, ...): `open_readonly_guarded`.
//! 3. `bind`/`connect` have no `*at` form (and a `sockaddr_un` path is at most
//!    ~104 bytes, less than a shimmed physical path): they run in a
//!    short-lived forked child that `fchdir`s to the already-guarded parent
//!    directory and uses the bare final name. `mkstemp` is executed as a
//!    guarded create-exclusive of the literal name (see `mkstemp_like`).
//! 4. `remove_sandbox_tree` (the final cleanup) walks only via `*at` calls
//!    opened with `O_NOFOLLOW`, so it can never be redirected through a
//!    symlink planted (deliberately, for the escaping-link corpus, or by a
//!    bug) inside the tree.
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use world_fsmodel::{Op, OpenFlags, Outcome, Start, at_start};

/// A real, open resource kept alive under the *model's* fd number (never the
/// real OS fd number, which is purely an implementation detail here).
pub enum RealFd {
    Dir(OwnedFd),
    File(File),
}

/// Everything the executor needs across a whole run: the process's
/// never-chdir'd virtual cwd, a handle on the real root (for `Start::Root`),
/// the model-fd -> real-resource table, and the run's own identity (for the
/// sandbox guard).
pub struct RealState {
    pub cwd_fd: OwnedFd,
    pub root_fd: OwnedFd,
    pub fds: HashMap<u32, RealFd>,
    pub run_id: String,
    /// `WORLD_TMP` (the macOS shim's physical root), if set: real path
    /// results (readlink/getcwd/realpath) must never contain it.
    pub physical_root: Option<Vec<u8>>,
    /// Bound-and-listening sockets created by `Bind` (see `bind_like`): kept
    /// open for the rest of the run so a later `Connect` to the same path
    /// succeeds instead of `ECONNREFUSED`, exactly matching the model's own
    /// "any `Socket` node is connect-able" simplification. Closed
    /// implicitly when the process exits.
    pub listeners: Vec<OwnedFd>,
    /// The modelled kernel's `MAXSYMLINKS` (`Model::max_symlinks`: 32 on the
    /// macOS shim, 40 on Linux): the hop limit for chasing a final symlink
    /// by hand in `open_mutating`.
    pub max_symlinks: u32,
}

/// Distinguishes a legitimate POSIX outcome (compared against the model like
/// any other) from a refusal to even attempt the syscall.
pub enum ExecError {
    /// An ordinary POSIX resolution failure while opening/checking the
    /// parent (e.g. the parent itself doesn't exist): the caller turns this
    /// back into a normal `Outcome`, exactly as if the whole op had failed
    /// with this errno.
    Errno(i32),
    /// A harness-level safety refusal: the caller must abort the whole run
    /// (exit 2). The op was never executed.
    Harness(String),
}

pub type ExecResult<T> = Result<T, ExecError>;

fn ok(ret: i64) -> Outcome {
    Outcome {
        ret,
        errno: 0,
        data: Vec::new(),
    }
}
fn data_ok(ret: i64, data: Vec<u8>) -> Outcome {
    Outcome {
        ret,
        errno: 0,
        data,
    }
}
fn err(e: i32) -> Outcome {
    Outcome {
        ret: -1,
        errno: e,
        data: Vec::new(),
    }
}
fn io_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}
fn cstr(bytes: &[u8]) -> Result<CString, i32> {
    CString::new(bytes).map_err(|_| libc::EINVAL)
}

// ---------------------------------------------------------------------
// Path splitting, mirroring `world_fsmodel`'s own (private) `parent_and_name`
// exactly -- see that function's doc comment in `crates/world-fsmodel/src/
// lib.rs` and its round-trip tests.
// ---------------------------------------------------------------------

/// `(parent-dir text, bare final name, trailing)`: every trailing `/` is
/// trimmed from the name (the guard checks the bare name) and `trailing`
/// records that there was at least one, so the real syscall can be given the
/// original spelling back (`literal`): a trailing slash changes what
/// unlink/rmdir/rename/symlink/bind/O_EXCL do (the model implements the
/// per-profile rules).
fn split_parent_name(path: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), i32> {
    // POSIX: an empty pathname is ENOENT; `/` has no final component to name.
    if path.is_empty() {
        return Err(libc::ENOENT);
    }
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    if end == 0 {
        return Err(libc::EINVAL);
    }
    let trailing = end < path.len();
    let trimmed = &path[..end];
    match trimmed.iter().rposition(|&b| b == b'/') {
        Some(0) => Ok((b"/".to_vec(), trimmed[1..].to_vec(), trailing)),
        Some(i) => Ok((trimmed[..i].to_vec(), trimmed[i + 1..].to_vec(), trailing)),
        None => Ok((b".".to_vec(), trimmed.to_vec(), trailing)),
    }
}

/// The name as the syscall must see it: with the original trailing slash
/// re-appended (a single `/` is enough; the kernel treats `x//` like `x/`).
fn literal(name: &[u8], trailing: bool) -> Vec<u8> {
    let mut out = name.to_vec();
    if trailing {
        out.push(b'/');
    }
    out
}

// ---------------------------------------------------------------------
// Sandbox guard.
// ---------------------------------------------------------------------

/// A dirfd's own canonical path, re-resolved fresh every call (never
/// cached): `F_GETPATH` on macOS, `/proc/self/fd/<n>` on Linux.
fn dirfd_realpath(dirfd: RawFd) -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let ret = unsafe { libc::fcntl(dirfd, libc::F_GETPATH, buf.as_mut_ptr()) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::read_link(format!("/proc/self/fd/{dirfd}"))
    }
}

fn sandbox_roots(run_id: &str, phys: Option<&[u8]>) -> Vec<String> {
    let mut roots = vec![
        format!("/tmp/{run_id}"),
        format!("/private/tmp/{run_id}"),
        format!("/var/tmp/{run_id}"),
        format!("/private/var/tmp/{run_id}"),
    ];
    // Under the macOS shim `F_GETPATH` is a documented gap: it reports the
    // *physical* location (WORLD_TMP/tmp/<run-id>), not the virtual one.
    if let Some(p) = phys.and_then(|p| std::str::from_utf8(p).ok()) {
        let p = p.trim_end_matches('/');
        roots.push(format!("{p}/tmp/{run_id}"));
        roots.push(format!("{p}/var/tmp/{run_id}"));
    }
    roots
}

fn bare_tmp_roots(phys: Option<&[u8]>) -> Vec<String> {
    let mut roots: Vec<String> = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Some(p) = phys.and_then(|p| std::str::from_utf8(p).ok()) {
        let p = p.trim_end_matches('/');
        roots.push(format!("{p}/tmp"));
        roots.push(format!("{p}/var/tmp"));
    }
    roots
}

/// Whether a directory whose own canonical path is `parent` may have `name`
/// created/renamed/removed inside it for this run: either it is already
/// nested under one of the run's own sandbox roots, or (the one bootstrap
/// exception) it is a bare tmp root and `name` is *exactly* the run id
/// itself (creating a sandbox root for the very first time).
fn parent_allowed(parent: &Path, name: &[u8], run_id: &str, phys: Option<&[u8]>) -> bool {
    let p = parent.to_string_lossy();
    for base in sandbox_roots(run_id, phys) {
        if p == base.as_str() || p.starts_with(&format!("{base}/")) {
            return true;
        }
    }
    if name == run_id.as_bytes() {
        return bare_tmp_roots(phys).iter().any(|base| p == base.as_str());
    }
    false
}

/// Same acceptance list, for a target directory itself (`Chdir`, cleanup):
/// must already be inside one of the run's own sandbox roots.
fn target_allowed(target: &Path, run_id: &str, phys: Option<&[u8]>) -> bool {
    let p = target.to_string_lossy();
    sandbox_roots(run_id, phys)
        .iter()
        .any(|base| p == base.as_str() || p.starts_with(&format!("{base}/")))
}

fn start_fd(state: &RealState, start: Start) -> Result<RawFd, i32> {
    match start {
        Start::Cwd => Ok(state.cwd_fd.as_raw_fd()),
        Start::Root => Ok(state.root_fd.as_raw_fd()),
        Start::Fd(n) => match state.fds.get(&n) {
            Some(RealFd::Dir(fd)) => Ok(fd.as_raw_fd()),
            Some(RealFd::File(_)) => Err(libc::ENOTDIR),
            None => Err(libc::EBADF),
        },
    }
}

/// Open (following symlinks) the literal parent directory of `path` (relative
/// to `start`), then check it against the sandbox before handing it back.
/// Never returns a parent that failed the guard: that case is always
/// `Err(ExecError::Harness(..))`, and the caller must not run any syscall.
fn guarded_parent(
    state: &RealState,
    start: Start,
    path: &[u8],
) -> ExecResult<(OwnedFd, Vec<u8>, bool)> {
    // An invalid start fd can never resolve to anything: that is an
    // ordinary EBADF/ENOTDIR outcome, not a safety refusal.
    // The kernel rejects a whole path of PATH_MAX bytes or more; the
    // syscalls below only ever see the split-up pieces.
    if path.len() >= libc::PATH_MAX as usize {
        return Err(ExecError::Errno(libc::ENAMETOOLONG));
    }
    let base = start_fd(state, start).map_err(ExecError::Errno)?;
    guarded_parent_at(state, base, path)
}

/// `guarded_parent` against an explicit base directory fd (used to chase a
/// symlink target, which is relative to the link's own directory or, when
/// absolute, to the real root).
fn guarded_parent_at(
    state: &RealState,
    base: RawFd,
    path: &[u8],
) -> ExecResult<(OwnedFd, Vec<u8>, bool)> {
    let (dir, name, trailing) = split_parent_name(path).map_err(ExecError::Errno)?;
    let parent_fd = if dir == b"." {
        let dup = unsafe { libc::fcntl(base, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(ExecError::Errno(io_errno()));
        }
        unsafe { OwnedFd::from_raw_fd(dup) }
    } else {
        let c = cstr(&dir).map_err(ExecError::Errno)?;
        let fd = unsafe { libc::openat(base, c.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(ExecError::Errno(io_errno()));
        }
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    let real_path = dirfd_realpath(parent_fd.as_raw_fd()).map_err(|e| {
        ExecError::Harness(format!("could not resolve parent's canonical path: {e}"))
    })?;
    if !parent_allowed(
        &real_path,
        &name,
        &state.run_id,
        state.physical_root.as_deref(),
    ) {
        return Err(ExecError::Harness(format!(
            "refusing to touch {:?} under parent {} (run {}): outside the sandbox",
            String::from_utf8_lossy(&name),
            real_path.display(),
            state.run_id
        )));
    }
    Ok((parent_fd, name, trailing))
}

/// Safety check for a trailing-slash final component. Whether a kernel
/// follows a symlink given as `link/` differs by OS and version (macOS 15 and
/// 27 measured differently for `unlink lf/`; macOS follows it for rename and
/// rmdir and creates at a dangling link's target for mkdir and rename-onto),
/// and a target that is a plain file can still be reached. So the guard does
/// not depend on any of that: when `trailing` is set and `name` in `parent`
/// is a symlink, whatever the operation and whatever the target's type, the
/// whole link chain is walked (bounded by the kernel's MAXSYMLINKS) with
/// `readlinkat`,
/// requiring every hop's parent (`guarded_parent_at`) and the final target to
/// be inside the sandbox; otherwise the call is refused with a harness error
/// before any syscall. A link ending in `.`, `..` or naming `/` has no
/// bare final name: it is opened `O_DIRECTORY` and its resolved path must be
/// a sandbox node with an allowed parent. An hop that fails with
/// ENOENT/ENOTDIR/ELOOP/ENAMETOOLONG stays `Ok`: the kernel fails there too.
/// So does a chain (or loop) that stays inside the sandbox for more hops than
/// the kernel will ever follow: every hop's parent was verified, and the
/// kernel gives up with ELOOP (or ENOTDIR on Linux, which rejects the
/// trailing slash on a non-directory first) before reaching anything the
/// walk did not check.
const KERNEL_MAXSYMLINKS: u32 = if cfg!(target_os = "linux") { 40 } else { 32 };

fn check_trailing(state: &RealState, parent: RawFd, name: &[u8], trailing: bool) -> ExecResult<()> {
    if !trailing {
        return Ok(());
    }
    let run_id = state.run_id.as_str();
    let is_link = |dirfd: RawFd, n: &[u8]| -> ExecResult<bool> {
        let c = cstr(n).map_err(ExecError::Errno)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::fstatat(dirfd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        Ok(r == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK)
    };
    if !is_link(parent, name)? {
        return Ok(());
    }
    let refuse = |why: String| {
        Err(ExecError::Harness(format!(
            "refusing trailing-slash use of symlink {:?} (run {run_id}): {why}",
            String::from_utf8_lossy(name)
        )))
    };
    let mut hold: Option<OwnedFd> = None;
    let mut hop_parent = parent;
    let mut hop_name = name.to_vec();
    for _ in 0..=state.max_symlinks.max(KERNEL_MAXSYMLINKS) {
        if !is_link(hop_parent, &hop_name)? {
            // The end of the chain: the parent was already checked.
            return Ok(());
        }
        let hc = cstr(&hop_name).map_err(ExecError::Errno)?;
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let n = unsafe {
            libc::readlinkat(hop_parent, hc.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
        };
        if n == 0 {
            // An empty link: the kernel fails it with ENOENT.
            return Ok(());
        }
        if n < 0 || n as usize >= buf.len() {
            return refuse("cannot read a link in the chain".to_string());
        }
        buf.truncate(n as usize);
        let base = if buf[0] == b'/' {
            state.root_fd.as_raw_fd()
        } else {
            hop_parent
        };
        let dotted = match split_parent_name(&buf) {
            Err(libc::EINVAL) => true,
            Ok((_, n, _)) => n == b"." || n == b"..",
            Err(_) => false,
        };
        if dotted {
            return check_dir_target(state, base, &buf, &refuse);
        }
        match guarded_parent_at(state, base, &buf) {
            Ok((pfd, n, _)) => {
                hop_parent = pfd.as_raw_fd();
                hop_name = n;
                hold = Some(pfd);
            }
            // The kernel would fail resolving it as well.
            Err(ExecError::Errno(_)) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    // Every hop's parent was verified and the walk exceeded the kernel's own
    // link limit: the kernel fails with ELOOP/ENOTDIR here.
    drop(hold);
    Ok(())
}

/// End of a link chain that names a directory without a bare final name
/// (`.`, `..`, `/`): open it and require the resolved directory to be a
/// sandbox node whose own parent passes `parent_allowed`.
fn check_dir_target(
    state: &RealState,
    base: RawFd,
    path: &[u8],
    refuse: &dyn Fn(String) -> ExecResult<()>,
) -> ExecResult<()> {
    let (run_id, phys) = (state.run_id.as_str(), state.physical_root.as_deref());
    let c = cstr(path).map_err(ExecError::Errno)?;
    let fd = unsafe { libc::openat(base, c.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = io_errno();
        if matches!(
            e,
            libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::ENAMETOOLONG
        ) {
            return Ok(());
        }
        return refuse(format!("cannot open its target as a directory (errno {e})"));
    }
    let target = unsafe { OwnedFd::from_raw_fd(fd) };
    let real = match dirfd_realpath(target.as_raw_fd()) {
        Ok(p) => p,
        Err(e) => return refuse(format!("could not resolve its target: {e}")),
    };
    let target_parent_ok = match (real.parent(), real.file_name()) {
        (Some(pp), Some(n)) => {
            use std::os::unix::ffi::OsStrExt;
            parent_allowed(pp, n.as_bytes(), run_id, phys)
        }
        _ => false,
    };
    if !target_allowed(&real, run_id, phys) || !target_parent_ok {
        return refuse(format!(
            "its target {} is outside the sandbox",
            real.display()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// fork-isolated real cwd (for Getcwd/Realpath only -- see module docs).
// ---------------------------------------------------------------------

#[derive(Clone)]
enum CwdQuery {
    Getcwd,
    Realpath(Vec<u8>),
    Connect(Vec<u8>),
}

/// Run `query` in a short-lived forked child that `fchdir`s to `cwd_fd`
/// first, so the *real* libc entry point sees a genuine ambient cwd without
/// this process ever calling `chdir` itself. The child never allocates
/// before `fchdir` succeeds/fails, and always `_exit`s; the parent reaps it
/// with a bounded wait.
fn in_virtual_cwd(cwd_fd: RawFd, query: &CwdQuery) -> ExecResult<Outcome> {
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(ExecError::Harness(format!(
            "pipe: {}",
            io::Error::last_os_error()
        )));
    }
    let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);
    let query = query.clone();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Err(ExecError::Harness(format!(
            "fork: {}",
            io::Error::last_os_error()
        )));
    }
    if pid == 0 {
        unsafe { libc::close(read_fd) };
        let (ret, errno, data) = child_cwd_query(cwd_fd, &query);
        let mut out = Vec::with_capacity(16 + data.len());
        out.extend_from_slice(&ret.to_le_bytes());
        out.extend_from_slice(&errno.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
        let mut f = unsafe { File::from_raw_fd(write_fd) };
        let _ = f.write_all(&out);
        drop(f);
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(write_fd) };
    let buf = collect_child_result(read_fd, pid, CHILD_TIMEOUT)?;
    if buf.len() < 16 {
        return Err(ExecError::Harness(
            "cwd-query child reported a truncated result".to_string(),
        ));
    }
    let ret = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let errno = i32::from_le_bytes(buf[8..12].try_into().unwrap());
    let len = u32::from_le_bytes(buf[12..16].try_into().unwrap()) as usize;
    let data = buf.get(16..16 + len).unwrap_or_default().to_vec();
    if errno != 0 {
        Ok(err(errno))
    } else {
        Ok(data_ok(ret, data))
    }
}

/// Wall-clock budget for one forked helper child (read its result, then
/// reap it).
const CHILD_TIMEOUT: Duration = Duration::from_secs(10);

/// SIGKILL `pid` and reap it with a bounded (2 s) wait, so a hung child is
/// neither leaked nor waited on forever.
fn kill_and_reap(pid: libc::pid_t) {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut status = 0;
    loop {
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if w == pid || (w < 0 && io_errno() != libc::EINTR) || Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Block until `fd` is readable (data or EOF/hangup), polling in 50 ms
/// slices. Past `deadline` the child `pid` is killed and reaped and this
/// returns `Harness("child timed out")`: the IPC read must never hang the
/// whole run just because the child did.
fn wait_readable(fd: RawFd, pid: libc::pid_t, deadline: Instant) -> ExecResult<()> {
    loop {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut p, 1, 50) };
        if r > 0 {
            return Ok(());
        }
        if r < 0 && io_errno() != libc::EINTR {
            let e = io::Error::last_os_error();
            kill_and_reap(pid);
            return Err(ExecError::Harness(format!("poll on child pipe: {e}")));
        }
        if Instant::now() >= deadline {
            kill_and_reap(pid);
            return Err(ExecError::Harness(format!("child {pid} timed out")));
        }
    }
}

/// Read a forked child's whole result from `read_fd` (which this takes
/// ownership of and closes) until EOF, then reap the child, all under one
/// shared `timeout`. A child that hangs is killed and reaped and reported as
/// `Harness`, never waited on forever.
fn collect_child_result(
    read_fd: RawFd,
    pid: libc::pid_t,
    timeout: Duration,
) -> ExecResult<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut f = unsafe { File::from_raw_fd(read_fd) };
    unsafe {
        let fl = libc::fcntl(read_fd, libc::F_GETFL);
        libc::fcntl(read_fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        wait_readable(read_fd, pid, deadline)?;
        match f.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => {
                kill_and_reap(pid);
                return Err(ExecError::Harness(format!(
                    "read from cwd-query child: {e}"
                )));
            }
        }
    }
    drop(f);
    reap_until(pid, deadline)?;
    Ok(buf)
}

/// Runs only in the forked child: never touches `state`/heap-shared data,
/// only `cwd_fd` (inherited, still open) and the query's own bytes.
fn child_cwd_query(cwd_fd: RawFd, query: &CwdQuery) -> (i64, i32, Vec<u8>) {
    if unsafe { libc::fchdir(cwd_fd) } != 0 {
        return (-1, io_errno(), Vec::new());
    }
    match query {
        CwdQuery::Getcwd => {
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let p = unsafe { libc::getcwd(buf.as_mut_ptr().cast(), buf.len()) };
            if p.is_null() {
                return (-1, io_errno(), Vec::new());
            }
            let len = unsafe { libc::strlen(buf.as_ptr().cast()) };
            buf.truncate(len);
            (len as i64, 0, buf)
        }
        CwdQuery::Connect(name) => {
            let Some((addr, len)) = unix_sockaddr(name) else {
                return (-1, libc::ENAMETOOLONG, Vec::new());
            };
            let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if sock < 0 {
                return (-1, io_errno(), Vec::new());
            }
            let r = unsafe { libc::connect(sock, (&addr as *const libc::sockaddr_un).cast(), len) };
            let errno = if r == 0 { 0 } else { io_errno() };
            unsafe { libc::close(sock) };
            if r == 0 {
                (0, 0, Vec::new())
            } else {
                (-1, errno, Vec::new())
            }
        }
        CwdQuery::Realpath(path) => {
            let Ok(c) = cstr(path) else {
                return (-1, libc::EINVAL, Vec::new());
            };
            let mut out = vec![0u8; libc::PATH_MAX as usize];
            let p = unsafe { libc::realpath(c.as_ptr(), out.as_mut_ptr().cast()) };
            if p.is_null() {
                return (-1, io_errno(), Vec::new());
            }
            let len = unsafe { libc::strlen(out.as_ptr().cast()) };
            out.truncate(len);
            (len as i64, 0, out)
        }
    }
}

// ---------------------------------------------------------------------
// Flags translation.
// ---------------------------------------------------------------------

fn translate_flags(flags: &OpenFlags) -> libc::c_int {
    let mut f = if flags.write {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    if flags.create {
        f |= libc::O_CREAT;
    }
    if flags.excl {
        f |= libc::O_EXCL;
    }
    if flags.trunc {
        f |= libc::O_TRUNC;
    }
    if flags.directory {
        f |= libc::O_DIRECTORY;
    }
    if flags.nofollow {
        f |= libc::O_NOFOLLOW;
    }
    f | libc::O_CLOEXEC
}

fn kind_code(mode: libc::mode_t) -> u8 {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => 0,
        libc::S_IFLNK => 2,
        libc::S_IFSOCK => 3,
        _ => 1,
    }
}

/// A newly created/opened fd-like resource, pending adoption under the
/// model's own fd number once the caller has seen the model agree (or
/// dropped -- which closes it -- if the model disagreed).
pub struct Pending(pub RealFd);

/// The result of applying one op: the `Outcome` to compare against the
/// model, plus (for fd-returning ops that succeeded) the real resource to
/// adopt under the model's fd number.
pub struct Applied {
    pub outcome: Outcome,
    pub pending: Option<Pending>,
}

fn plain(outcome: Outcome) -> Applied {
    Applied {
        outcome,
        pending: None,
    }
}

/// Apply one op to the real filesystem. `Err(ExecError::Harness(..))` means
/// "refuse, never executed, caller must abort the whole run" -- this never
/// happens for an ordinary POSIX-legal failure (those come back as a normal
/// `Outcome` with a nonzero errno, via `Err(ExecError::Errno(..))` from an
/// inner helper, which every op below propagates with `?` rather than
/// executing anything further).
pub fn apply_real(state: &mut RealState, op: &Op) -> ExecResult<Applied> {
    // Replay files cannot carry a NUL (rejected at parse time); this is the
    // backstop so e.g. a bind/connect name can never be silently truncated.
    if op.path_operands().iter().any(|p| p.contains(&0)) {
        return Err(ExecError::Harness("operand contains NUL".to_string()));
    }
    match op {
        Op::Mkdir { path, mode } => mkdir_like(state, Start::Cwd, path, *mode),
        Op::MkdirAt { dirfd, path } => mkdir_like(state, at_start(*dirfd, path), path, 0o755),
        Op::Open { path, flags } => open_like(state, Start::Cwd, path, flags),
        Op::OpenAt { dirfd, path, flags } => open_like(state, at_start(*dirfd, path), path, flags),
        Op::OpenDir { path } => opendir_like(state, Start::Cwd, path),
        Op::Write { fd, data } => Ok(plain(write_fd(state, *fd, data))),
        Op::Read { fd, len } => Ok(plain(read_fd(state, *fd, *len))),
        Op::CloseFd { fd } => Ok(plain(close_fd(state, *fd))),
        Op::Symlink { target, path } => Ok(plain(symlink_like(state, target, path)?)),
        Op::Readlink { path } => Ok(plain(readlink_like(state, path)?)),
        Op::Rename { from, to } => Ok(plain(rename_like(state, from, to)?)),
        Op::Unlink { path } => Ok(plain(unlink_like(state, Start::Cwd, path, false)?)),
        Op::Rmdir { path } => Ok(plain(unlink_like(state, Start::Cwd, path, true)?)),
        Op::UnlinkAt { dirfd, path, rmdir } => Ok(plain(unlink_like(
            state,
            at_start(*dirfd, path),
            path,
            *rmdir,
        )?)),
        Op::Chdir { path } => chdir_like(state, path),
        Op::Getcwd => Ok(plain(in_virtual_cwd(
            state.cwd_fd.as_raw_fd(),
            &CwdQuery::Getcwd,
        )?)),
        Op::Realpath { path } => Ok(plain(in_virtual_cwd(
            state.cwd_fd.as_raw_fd(),
            &CwdQuery::Realpath(path.clone()),
        )?)),
        Op::Stat { path } => Ok(plain(stat_like(state, path, true)?)),
        Op::Lstat { path } => Ok(plain(stat_like(state, path, false)?)),
        Op::Bind { path } => Ok(plain(bind_like(state, path)?)),
        Op::Connect { path } => Ok(plain(connect_like(state, path)?)),
        Op::MkstempAdopt { name } => mkstemp_like(state, name),
        Op::List { path } => Ok(plain(list_like(state, path)?)),
    }
}

fn mkdir_like(state: &mut RealState, start: Start, path: &[u8], mode: u32) -> ExecResult<Applied> {
    let (parent, name, trailing) = guarded_parent(state, start, path)?;
    check_trailing(state, parent.as_raw_fd(), &name, trailing)?;
    let c = cstr(&literal(&name, trailing)).map_err(ExecError::Errno)?;
    let r = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), mode as libc::mode_t) };
    Ok(plain(if r == 0 { ok(0) } else { err(io_errno()) }))
}

/// Whether an `open` with these flags can change the filesystem (create,
/// truncate, or open for writing): only those need the mutation guard.
fn open_mutates(f: &OpenFlags) -> bool {
    f.write || f.trunc || f.create
}

fn open_like(
    state: &mut RealState,
    start: Start,
    path: &[u8],
    flags: &OpenFlags,
) -> ExecResult<Applied> {
    let osflags = translate_flags(flags);
    let fd = if open_mutates(flags) {
        match open_mutating(state, start, path, flags, osflags)? {
            Ok(fd) => fd,
            Err(e) => return Ok(plain(err(e))),
        }
    } else {
        let base = start_fd(state, start).map_err(ExecError::Errno)?;
        match open_readonly_guarded(state, base, path, osflags)? {
            Ok(fd) => fd,
            Err(e) => return Ok(plain(err(e))),
        }
    };
    Ok(Applied {
        outcome: ok(0),
        pending: Some(Pending(classify_fd(fd.into_raw_fd()))),
    })
}

/// A creating/truncating/writable open. The parent directory is guarded
/// exactly like any other mutation, and -- because `openat` would otherwise
/// follow a symlink in the *final* component to wherever it points -- that
/// component is chased by hand: every hop's own parent is guarded too, up to
/// the modelled kernel's `MAXSYMLINKS`. `O_NOFOLLOW` and `O_CREAT|O_EXCL`
/// never dereference the final component, so they skip the chase. The
/// canonical path of the fd that comes back is a last backstop.
///
/// `Ok(Err(errno))` is an ordinary POSIX failure (compared with the model).
fn open_mutating(
    state: &RealState,
    start: Start,
    path: &[u8],
    flags: &OpenFlags,
    osflags: libc::c_int,
) -> ExecResult<Result<OwnedFd, i32>> {
    let (mut parent, mut name, mut trailing) = guarded_parent(state, start, path)?;
    if !flags.nofollow && !(flags.create && flags.excl) {
        let mut hops = 0u32;
        loop {
            let c = cstr(&name).map_err(ExecError::Errno)?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let r = unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if r != 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFLNK {
                break;
            }
            hops += 1;
            if hops > state.max_symlinks {
                return Err(ExecError::Errno(libc::ELOOP));
            }
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let n = unsafe {
                libc::readlinkat(
                    parent.as_raw_fd(),
                    c.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if n < 0 {
                // Raced away: let the open below report whatever it finds.
                break;
            }
            buf.truncate(n as usize);
            if buf.is_empty() {
                return Err(ExecError::Errno(libc::ENOENT));
            }
            trailing |= buf.len() > 1 && buf.ends_with(b"/");
            let base = if buf[0] == b'/' {
                state.root_fd.as_raw_fd()
            } else {
                parent.as_raw_fd()
            };
            let (p, n, _) = match guarded_parent_at(state, base, &buf) {
                Ok(v) => v,
                // A target that names nothing (`/`): opening it for writing
                // is EISDIR, as the kernel reports.
                Err(ExecError::Errno(libc::EINVAL)) => {
                    return Err(ExecError::Errno(libc::EISDIR));
                }
                Err(e) => return Err(e),
            };
            parent = p;
            name = n;
        }
    }
    let c = cstr(&literal(&name, trailing)).map_err(ExecError::Errno)?;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), c.as_ptr(), osflags, 0o644) };
    if fd < 0 {
        return Ok(Err(io_errno()));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let real = dirfd_realpath(owned.as_raw_fd()).map_err(|e| {
        ExecError::Harness(format!(
            "could not resolve opened file's canonical path: {e}"
        ))
    })?;
    if !target_allowed(&real, &state.run_id, state.physical_root.as_deref()) {
        return Err(ExecError::Harness(format!(
            "opened {} (run {}): outside the sandbox",
            real.display(),
            state.run_id
        )));
    }
    Ok(Ok(owned))
}

/// Whether directory `p` is a bare ancestor of one of the run's sandbox
/// roots (`/`, `/tmp`, `/private`, `/var/tmp`, the shim's physical `tmp`,
/// ...): opening it read-only is harmless and the model allows it.
fn ancestor_of_root(p: &Path, run_id: &str, phys: Option<&[u8]>) -> bool {
    let p = p.to_string_lossy();
    let p = p.trim_end_matches('/');
    sandbox_roots(run_id, phys)
        .iter()
        .any(|base| p.is_empty() || base == p || base.starts_with(&format!("{p}/")))
}

/// A read-only open (`Open`, `OpenAt`, `OpenDir`, `List`): refuse a FIFO or
/// device before opening it (an outside FIFO would block `openat` forever),
/// and afterwards keep the fd only if it is inside the sandbox or a
/// directory that is an ancestor of a sandbox root.
///
/// `Ok(Err(errno))` is an ordinary POSIX failure (compared with the model).
fn open_readonly_guarded(
    state: &RealState,
    base: RawFd,
    path: &[u8],
    osflags: libc::c_int,
) -> ExecResult<Result<OwnedFd, i32>> {
    let c = cstr(path).map_err(ExecError::Errno)?;
    let stat_flag = if osflags & libc::O_NOFOLLOW != 0 {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(base, c.as_ptr(), &mut st, stat_flag) } == 0 {
        let kind = st.st_mode & libc::S_IFMT;
        if matches!(kind, libc::S_IFIFO | libc::S_IFCHR | libc::S_IFBLK) {
            return Err(ExecError::Harness(format!(
                "refusing to open {:?}: a FIFO or device (outside the sandbox)",
                String::from_utf8_lossy(path)
            )));
        }
    }
    let fd = unsafe { libc::openat(base, c.as_ptr(), osflags, 0o644) };
    if fd < 0 {
        return Ok(Err(io_errno()));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let real = dirfd_realpath(owned.as_raw_fd()).map_err(|e| {
        ExecError::Harness(format!(
            "could not resolve opened path's canonical path: {e}"
        ))
    })?;
    let phys = state.physical_root.as_deref();
    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    let is_dir = unsafe { libc::fstat(owned.as_raw_fd(), &mut fst) } == 0
        && (fst.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    if target_allowed(&real, &state.run_id, phys)
        || (is_dir && ancestor_of_root(&real, &state.run_id, phys))
    {
        Ok(Ok(owned))
    } else {
        Err(ExecError::Harness(format!(
            "opened {} (run {}): outside the sandbox",
            real.display(),
            state.run_id
        )))
    }
}

fn classify_fd(fd: RawFd) -> RealFd {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        RealFd::Dir(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        RealFd::File(unsafe { File::from_raw_fd(fd) })
    }
}

fn opendir_like(state: &mut RealState, start: Start, path: &[u8]) -> ExecResult<Applied> {
    let base = start_fd(state, start).map_err(ExecError::Errno)?;
    let osflags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    match open_readonly_guarded(state, base, path, osflags)? {
        Ok(fd) => Ok(Applied {
            outcome: ok(0),
            pending: Some(Pending(RealFd::Dir(fd))),
        }),
        Err(e) => Ok(plain(err(e))),
    }
}

fn write_fd(state: &mut RealState, fd: u32, data: &[u8]) -> Outcome {
    match state.fds.get_mut(&fd) {
        Some(RealFd::File(f)) => match f.write(data) {
            Ok(n) => ok(n as i64),
            Err(e) => err(e.raw_os_error().unwrap_or(libc::EIO)),
        },
        Some(RealFd::Dir(_)) => err(libc::EBADF),
        None => err(libc::EBADF),
    }
}

fn read_fd(state: &mut RealState, fd: u32, len: usize) -> Outcome {
    match state.fds.get_mut(&fd) {
        Some(RealFd::File(f)) => {
            let mut buf = vec![0u8; len];
            match f.read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    data_ok(n as i64, buf)
                }
                Err(e) => err(e.raw_os_error().unwrap_or(libc::EIO)),
            }
        }
        Some(RealFd::Dir(_)) => err(libc::EBADF),
        None => err(libc::EBADF),
    }
}

fn close_fd(state: &mut RealState, fd: u32) -> Outcome {
    if state.fds.remove(&fd).is_some() {
        ok(0)
    } else {
        err(libc::EBADF)
    }
}

fn symlink_like(state: &mut RealState, target: &[u8], path: &[u8]) -> ExecResult<Outcome> {
    let (parent, name, trailing) = guarded_parent(state, Start::Cwd, path)?;
    check_trailing(state, parent.as_raw_fd(), &name, trailing)?;
    // `target` is stored verbatim, never resolved/guarded by this harness
    // (a dangling or "weird" target is exactly the point of testing
    // symlinks): the shim's own lexical rewriting of it is under test.
    let t = cstr(target).map_err(ExecError::Errno)?;
    let n = cstr(&literal(&name, trailing)).map_err(ExecError::Errno)?;
    let r = unsafe { libc::symlinkat(t.as_ptr(), parent.as_raw_fd(), n.as_ptr()) };
    Ok(if r == 0 { ok(0) } else { err(io_errno()) })
}

fn readlink_like(state: &RealState, path: &[u8]) -> ExecResult<Outcome> {
    let base = start_fd(state, Start::Cwd).map_err(ExecError::Errno)?;
    let c = cstr(path).map_err(ExecError::Errno)?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let n = unsafe { libc::readlinkat(base, c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Ok(err(io_errno()));
    }
    buf.truncate(n as usize);
    Ok(data_ok(n as i64, buf))
}

fn rename_like(state: &mut RealState, from: &[u8], to: &[u8]) -> ExecResult<Outcome> {
    let (from_parent, from_name, from_trailing) = guarded_parent(state, Start::Cwd, from)?;
    let (to_parent, to_name, to_trailing) = guarded_parent(state, Start::Cwd, to)?;
    check_trailing(state, from_parent.as_raw_fd(), &from_name, from_trailing)?;
    check_trailing(state, to_parent.as_raw_fd(), &to_name, to_trailing)?;
    let fname = cstr(&literal(&from_name, from_trailing)).map_err(ExecError::Errno)?;
    let tname = cstr(&literal(&to_name, to_trailing)).map_err(ExecError::Errno)?;
    let r = unsafe {
        libc::renameat(
            from_parent.as_raw_fd(),
            fname.as_ptr(),
            to_parent.as_raw_fd(),
            tname.as_ptr(),
        )
    };
    Ok(if r == 0 { ok(0) } else { err(io_errno()) })
}

fn unlink_like(
    state: &mut RealState,
    start: Start,
    path: &[u8],
    is_rmdir: bool,
) -> ExecResult<Outcome> {
    let (parent, name, trailing) = guarded_parent(state, start, path)?;
    check_trailing(state, parent.as_raw_fd(), &name, trailing)?;
    let c = cstr(&literal(&name, trailing)).map_err(ExecError::Errno)?;
    let flag = if is_rmdir { libc::AT_REMOVEDIR } else { 0 };
    let r = unsafe { libc::unlinkat(parent.as_raw_fd(), c.as_ptr(), flag) };
    Ok(if r == 0 { ok(0) } else { err(io_errno()) })
}

fn chdir_like(state: &mut RealState, path: &[u8]) -> ExecResult<Applied> {
    let base = start_fd(state, Start::Cwd).map_err(ExecError::Errno)?;
    let c = cstr(path).map_err(ExecError::Errno)?;
    let fd = unsafe { libc::openat(base, c.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Ok(plain(err(io_errno())));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let real_path = dirfd_realpath(owned.as_raw_fd()).map_err(|e| {
        ExecError::Harness(format!(
            "could not resolve chdir target's canonical path: {e}"
        ))
    })?;
    if !target_allowed(&real_path, &state.run_id, state.physical_root.as_deref()) {
        return Err(ExecError::Harness(format!(
            "refusing to chdir into {} (run {}): outside the sandbox",
            real_path.display(),
            state.run_id
        )));
    }
    state.cwd_fd = owned;
    Ok(plain(ok(0)))
}

fn stat_like(state: &RealState, path: &[u8], follow: bool) -> ExecResult<Outcome> {
    let base = start_fd(state, Start::Cwd).map_err(ExecError::Errno)?;
    let c = cstr(path).map_err(ExecError::Errno)?;
    let flag = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatat(base, c.as_ptr(), &mut st, flag) };
    if r != 0 {
        return Ok(err(io_errno()));
    }
    Ok(data_ok(0, vec![kind_code(st.st_mode)]))
}

fn unix_sockaddr(path: &[u8]) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if path.len() >= addr.sun_path.len() {
        return None;
    }
    for (dst, &src) in addr.sun_path.iter_mut().zip(path.iter()) {
        *dst = src as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
    Some((addr, len))
}

/// A `sockaddr_un` holds at most ~104 bytes of path, but under the macOS
/// shim the guarded parent's canonical (physical) path alone can exceed
/// that. So `bind`/`connect` run in a short-lived forked child that
/// `fchdir`s to the *already guarded* parent and uses the bare final name
/// (`bind`/`connect` have no `*at` form); the parent's own cwd is untouched.
fn bind_like(state: &mut RealState, path: &[u8]) -> ExecResult<Outcome> {
    let (parent, name, trailing) = guarded_parent(state, Start::Cwd, path)?;
    check_trailing(state, parent.as_raw_fd(), &name, trailing)?;
    let Some((addr, len)) = unix_sockaddr(&literal(&name, trailing)) else {
        return Ok(err(libc::ENAMETOOLONG));
    };
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err(ExecError::Harness(format!(
            "socketpair: {}",
            io::Error::last_os_error()
        )));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
        return Err(ExecError::Harness(format!(
            "fork: {}",
            io::Error::last_os_error()
        )));
    }
    if pid == 0 {
        unsafe { libc::close(sv[0]) };
        let (errno, sock) = child_bind(parent.as_raw_fd(), &addr, len);
        send_status(sv[1], errno, if errno == 0 { sock } else { -1 });
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(sv[1]) };
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let ready = wait_readable(sv[0], pid, deadline);
    let received = if ready.is_ok() {
        recv_status(sv[0])
    } else {
        Err("child produced no status".to_string())
    };
    unsafe { libc::close(sv[0]) };
    ready?;
    reap_until(pid, deadline)?;
    let (errno, fd) = received.map_err(|e| ExecError::Harness(format!("bind child: {e}")))?;
    if errno != 0 {
        return Ok(err(errno));
    }
    // Keep the bound+listening socket open for the rest of the run: the
    // model treats any `Socket` node as connect-able (it does not model
    // "is anyone listening"), so a later `Connect` must succeed too.
    match fd {
        Some(fd) => state.listeners.push(fd),
        None => {
            return Err(ExecError::Harness(
                "bind child sent no descriptor".to_string(),
            ));
        }
    }
    Ok(ok(0))
}

/// Child side of `bind_like`: `(errno, listening socket or -1)`.
fn child_bind(dir: RawFd, addr: &libc::sockaddr_un, len: libc::socklen_t) -> (i32, RawFd) {
    if unsafe { libc::fchdir(dir) } != 0 {
        return (io_errno(), -1);
    }
    let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if sock < 0 {
        return (io_errno(), -1);
    }
    let bound = unsafe { libc::bind(sock, (addr as *const libc::sockaddr_un).cast(), len) } == 0;
    if bound && unsafe { libc::listen(sock, libc::SOMAXCONN) } == 0 {
        (0, sock)
    } else {
        (io_errno(), -1)
    }
}

fn send_status(chan: RawFd, errno: i32, fd: RawFd) {
    unsafe {
        let mut payload = errno.to_le_bytes();
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if fd >= 0 {
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                (&fd as *const RawFd).cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<RawFd>(),
            );
        }
        libc::sendmsg(chan, &msg, 0);
    }
}

fn recv_status(chan: RawFd) -> Result<(i32, Option<OwnedFd>), String> {
    unsafe {
        let mut payload = [0u8; 4];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut cbuf = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.len() as _;
        let n = libc::recvmsg(chan, &mut msg, 0);
        if n != 4 {
            return Err(format!("short status read ({n})"));
        }
        let errno = i32::from_le_bytes(payload);
        let mut fd = None;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        {
            let mut raw: RawFd = -1;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                (&mut raw as *mut RawFd).cast::<u8>(),
                std::mem::size_of::<RawFd>(),
            );
            if raw >= 0 {
                fd = Some(OwnedFd::from_raw_fd(raw));
            }
        }
        Ok((errno, fd))
    }
}

/// Bounded wait for a forked child; on timeout the child is killed and
/// reaped rather than leaked.
fn reap_until(pid: libc::pid_t, deadline: Instant) -> ExecResult<()> {
    let mut status = 0;
    loop {
        if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
            return Ok(());
        }
        if Instant::now() >= deadline {
            kill_and_reap(pid);
            return Err(ExecError::Harness(format!(
                "child {pid} did not exit in time"
            )));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn connect_like(state: &mut RealState, path: &[u8]) -> ExecResult<Outcome> {
    // Non-mutating (connect never changes the filesystem namespace): the
    // parent is opened like any read-only lookup, no guard needed beyond the
    // generator's own rule of keeping every path inside the sandbox.
    // The generator never puts a trailing slash on a connect path, so the
    // bare name is used.
    let (dir, name, _) = split_parent_name(path).map_err(ExecError::Errno)?;
    let base = start_fd(state, Start::Cwd).map_err(ExecError::Errno)?;
    let c = cstr(&dir).map_err(ExecError::Errno)?;
    let fd = unsafe { libc::openat(base, c.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Ok(err(io_errno()));
    }
    let parent = unsafe { OwnedFd::from_raw_fd(fd) };
    in_virtual_cwd(parent.as_raw_fd(), &CwdQuery::Connect(name))
}

fn mkstemp_like(state: &mut RealState, name: &[u8]) -> ExecResult<Applied> {
    // The model's `MkstempAdopt` always creates a literal file relative to
    // its own cwd (`Model::do_mkstemp`), whatever picked the name: mirror
    // that with a plain create-exclusive open of the literal name, rather
    // than calling the real `mkstemp(3)` (whose own random suffix is never
    // seed-controlled, which would make `replay` irreproducible -- the
    // *name itself* is what exercises the tmp-path redirection under test,
    // not how it was picked; `gen.rs` picks a fresh name up front instead).
    // The model's `do_mkstemp` rejects an empty name or one with a `/`.
    if name.is_empty() || name.contains(&b'/') {
        return Ok(plain(err(libc::EINVAL)));
    }
    let (parent, literal, _) = guarded_parent(state, Start::Cwd, name)?;
    let c = cstr(&literal).map_err(ExecError::Errno)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Ok(plain(err(io_errno())));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(Applied {
        outcome: ok(0),
        pending: Some(Pending(RealFd::File(file))),
    })
}

fn list_like(state: &RealState, path: &[u8]) -> ExecResult<Outcome> {
    let base = start_fd(state, Start::Cwd).map_err(ExecError::Errno)?;
    let osflags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let fd = match open_readonly_guarded(state, base, path, osflags)? {
        Ok(fd) => fd.into_raw_fd(),
        Err(e) => return Ok(err(e)),
    };
    let mut names = match read_dir_names(fd) {
        Ok(n) => n,
        Err(e) => return Ok(err(e)),
    };
    names.sort();
    let mut data = Vec::new();
    for (i, n) in names.iter().enumerate() {
        if i > 0 {
            data.push(b'\n');
        }
        data.extend_from_slice(n);
    }
    Ok(data_ok(names.len() as i64, data))
}

/// Takes ownership of `dirfd` (via `fdopendir`) and returns its entry names.
fn read_dir_names(dirfd: RawFd) -> Result<Vec<Vec<u8>>, i32> {
    let dirp = unsafe { libc::fdopendir(dirfd) };
    if dirp.is_null() {
        let e = io_errno();
        unsafe { libc::close(dirfd) };
        return Err(e);
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_bytes()
            .to_vec();
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    unsafe { libc::closedir(dirp) };
    Ok(names)
}

// ---------------------------------------------------------------------
// Final sandbox-root removal: `*at` only, `O_NOFOLLOW` on every directory
// this walks into, so a symlink anywhere in the tree (deliberate or not)
// can never redirect the walk outside it.
// ---------------------------------------------------------------------

/// Remove everything under `root` (a real, absolute path this process
/// itself created, e.g. `/tmp/<run-id>`), then `root` itself. Refuses unless
/// `root`'s own canonical form is nested under one of the run's sandbox
/// roots. A missing `root` is not an error (nothing to clean up).
pub fn remove_sandbox_tree(run_id: &str, phys: Option<&[u8]>, root: &[u8]) -> io::Result<()> {
    let c = CString::new(root).map_err(io::Error::other)?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(e);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let canonical = dirfd_realpath(owned.as_raw_fd())?;
    if !target_allowed(&canonical, run_id, phys) {
        return Err(io::Error::other(format!(
            "refusing to remove {} (run {}): outside the sandbox",
            canonical.display(),
            run_id
        )));
    }
    remove_tree_contents(owned.as_raw_fd())?;
    drop(owned);
    let r = unsafe { libc::rmdir(c.as_ptr()) };
    if r != 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    Ok(())
}

fn remove_tree_contents(dirfd: RawFd) -> io::Result<()> {
    for (name, is_dir) in list_dir_types(dirfd)? {
        let c = CString::new(name.clone()).map_err(io::Error::other)?;
        if is_dir {
            let sub = unsafe {
                libc::openat(
                    dirfd,
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if sub >= 0 {
                remove_tree_contents(sub)?;
                unsafe { libc::close(sub) };
                unsafe { libc::unlinkat(dirfd, c.as_ptr(), libc::AT_REMOVEDIR) };
            } else {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ELOOP) {
                    // A symlink masquerading as a dir entry (`d_type` can lie
                    // on some filesystems): remove it as a plain entry,
                    // never follow it.
                    unsafe { libc::unlinkat(dirfd, c.as_ptr(), 0) };
                } else {
                    return Err(e);
                }
            }
        } else {
            unsafe { libc::unlinkat(dirfd, c.as_ptr(), 0) };
        }
    }
    Ok(())
}

/// Directory entries with an `is_dir` flag from `lstat` (never dereferencing
/// a symlink): a name flagged `is_dir` is only ever recursed into via
/// `openat(..., O_NOFOLLOW)` above, so even a wrong flag here cannot cause a
/// symlink to be followed.
fn list_dir_types(dirfd: RawFd) -> io::Result<Vec<(Vec<u8>, bool)>> {
    // Duplicate the fd: `fdopendir` takes ownership, but the caller still
    // owns `dirfd` for the `openat`/`unlinkat` calls above.
    let dup = unsafe { libc::fcntl(dirfd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        let e = io::Error::last_os_error();
        unsafe { libc::close(dup) };
        return Err(e);
    }
    let mut out = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_bytes()
            .to_vec();
        if name == b"." || name == b".." {
            continue;
        }
        let c = CString::new(name.clone()).map_err(io::Error::other)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let is_dir =
            unsafe { libc::fstatat(dirfd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0
                && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        out.push((name, is_dir));
    }
    unsafe { libc::closedir(dirp) };
    Ok(out)
}

/// Whether `data` (a real path result: readlink/getcwd/realpath) leaks the
/// macOS shim's physical `WORLD_TMP` root.
pub fn leaks_physical_root(state: &RealState, data: &[u8]) -> bool {
    match &state.physical_root {
        Some(root) if !root.is_empty() => data.windows(root.len()).any(|w| w == root.as_slice()),
        _ => false,
    }
}

// ---------------------------------------------------------------------
// Real-tree walk, for the final whole-tree comparison against
// `Model::tree(View::Virtual, ...)`.
// ---------------------------------------------------------------------

/// A recursive, sorted listing of `root` (a real, absolute path), shaped
/// exactly like `Model::tree`'s own `Entry` list, so the two can be compared
/// with a plain `==`. Never follows a symlink (`O_NOFOLLOW` throughout,
/// matching `remove_sandbox_tree`'s own walk).
pub fn real_tree(root: &[u8]) -> io::Result<Vec<world_fsmodel::Entry>> {
    let c = CString::new(root).map_err(io::Error::other)?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut out = Vec::new();
    walk_real_tree(owned.as_raw_fd(), &[], &mut out)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn walk_real_tree(
    dirfd: RawFd,
    prefix: &[u8],
    out: &mut Vec<world_fsmodel::Entry>,
) -> io::Result<()> {
    use world_fsmodel::{Entry, EntryKind};
    let dup = unsafe { libc::fcntl(dirfd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        let e = io::Error::last_os_error();
        unsafe { libc::close(dup) };
        return Err(e);
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_bytes()
            .to_vec();
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
    unsafe { libc::closedir(dirp) };
    for name in names {
        let mut path = prefix.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(&name);
        let c = CString::new(name.clone()).map_err(io::Error::other)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dirfd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            // Raced away between readdir and stat: skip it, exactly as a
            // concurrently-changing real directory would leave it out.
            continue;
        }
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                out.push(Entry {
                    path: path.clone(),
                    kind: EntryKind::Dir,
                });
                let sub = unsafe {
                    libc::openat(
                        dirfd,
                        c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if sub >= 0 {
                    walk_real_tree(sub, &path, out)?;
                    unsafe { libc::close(sub) };
                }
            }
            libc::S_IFLNK => {
                let mut buf = vec![0u8; libc::PATH_MAX as usize];
                let n = unsafe {
                    libc::readlinkat(dirfd, c.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
                };
                let target = if n >= 0 {
                    buf[..n as usize].to_vec()
                } else {
                    Vec::new()
                };
                out.push(Entry {
                    path,
                    kind: EntryKind::Symlink { target },
                });
            }
            libc::S_IFSOCK => out.push(Entry {
                path,
                kind: EntryKind::Socket,
            }),
            _ => out.push(Entry {
                path,
                kind: EntryKind::File {
                    len: st.st_size as usize,
                },
            }),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Pure unit tests: none of these touches the filesystem (the child
    //! test only forks a process that calls `pause()`).
    use super::*;

    #[test]
    fn hung_child_times_out_and_is_reaped() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Holds the write end open and never answers.
            unsafe {
                libc::close(r);
                libc::pause();
                libc::_exit(0);
            }
        }
        unsafe { libc::close(w) };
        let started = Instant::now();
        let res = collect_child_result(r, pid, Duration::from_secs(1));
        assert!(matches!(res, Err(ExecError::Harness(_))));
        assert!(started.elapsed() < Duration::from_secs(3));
        // Already killed and reaped: nothing left to wait for.
        let mut status = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(w, -1);
        assert_eq!(io_errno(), libc::ECHILD);
    }

    #[test]
    fn split_parent_name_cases() {
        assert_eq!(split_parent_name(b""), Err(libc::ENOENT));
        assert_eq!(split_parent_name(b"/"), Err(libc::EINVAL));
        assert_eq!(split_parent_name(b"//"), Err(libc::EINVAL));
        assert_eq!(
            split_parent_name(b"/a/b/"),
            Ok((b"/a".to_vec(), b"b".to_vec(), true))
        );
        assert_eq!(
            split_parent_name(b"/tmp/r/f/"),
            Ok((b"/tmp/r".to_vec(), b"f".to_vec(), true))
        );
        assert_eq!(
            split_parent_name(b"f//"),
            Ok((b".".to_vec(), b"f".to_vec(), true))
        );
        assert_eq!(
            split_parent_name(b"x"),
            Ok((b".".to_vec(), b"x".to_vec(), false))
        );
        assert_eq!(
            split_parent_name(b"/x"),
            Ok((b"/".to_vec(), b"x".to_vec(), false))
        );
        assert_eq!(literal(b"f", true), b"f/".to_vec());
        assert_eq!(literal(b"f", false), b"f".to_vec());
    }

    #[test]
    fn parent_and_target_allowed() {
        let run = "fz-0123456789";
        assert!(parent_allowed(
            Path::new("/tmp/fz-0123456789/a"),
            b"x",
            run,
            None
        ));
        assert!(parent_allowed(
            Path::new("/private/var/tmp/fz-0123456789"),
            b"x",
            run,
            None
        ));
        // A sibling run and the bare tmp root are not allowed...
        assert!(!parent_allowed(
            Path::new("/tmp/fz-0123456789x"),
            b"x",
            run,
            None
        ));
        assert!(!parent_allowed(Path::new("/tmp"), b"x", run, None));
        // ...except to create the run's own root.
        assert!(parent_allowed(Path::new("/tmp"), run.as_bytes(), run, None));
        assert!(!parent_allowed(
            Path::new("/etc"),
            run.as_bytes(),
            run,
            None
        ));
        let phys = Some(&b"/home/u/.world/tmp/127.0.0.1/"[..]);
        assert!(parent_allowed(
            Path::new("/home/u/.world/tmp/127.0.0.1/tmp/fz-0123456789/d"),
            b"x",
            run,
            phys
        ));
        assert!(target_allowed(Path::new("/tmp/fz-0123456789"), run, None));
        assert!(target_allowed(
            Path::new("/tmp/fz-0123456789/a/b"),
            run,
            None
        ));
        assert!(!target_allowed(Path::new("/tmp"), run, None));
        assert!(!target_allowed(Path::new("/tmp/other"), run, None));
        assert!(!target_allowed(Path::new("/etc/passwd"), run, None));
    }

    #[test]
    fn ancestors_of_a_sandbox_root() {
        let run = "fz-0123456789";
        for ok in [
            "/",
            "/tmp",
            "/private",
            "/private/tmp",
            "/var/tmp",
            "/tmp/fz-0123456789",
        ] {
            assert!(ancestor_of_root(Path::new(ok), run, None), "{ok}");
        }
        for bad in ["/etc", "/tmp/other", "/Users", "/private/etc"] {
            assert!(!ancestor_of_root(Path::new(bad), run, None), "{bad}");
        }
    }

    #[test]
    fn open_mutates_covers_write_trunc_create() {
        let ro = OpenFlags::default();
        assert!(!open_mutates(&ro));
        for f in [
            OpenFlags {
                write: true,
                ..Default::default()
            },
            OpenFlags {
                trunc: true,
                ..Default::default()
            },
            OpenFlags {
                create: true,
                ..Default::default()
            },
        ] {
            assert!(open_mutates(&f));
        }
    }
}

#[cfg(test)]
mod trailing_slash_guard_tests {
    //! These touch the filesystem, but only inside their own `tempfile`
    //! directories: a fake "physical root" holding the sandbox, and a separate
    //! victim directory outside it that must never change.
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    struct Fixture {
        _t: tempfile::TempDir,
        _v: tempfile::TempDir,
        sandbox: PathBuf,
        victim: PathBuf,
        state: RealState,
    }

    const RUN: &str = "fz-guardtest";

    fn fixture() -> Fixture {
        let t = tempfile::tempdir().unwrap();
        let v = tempfile::tempdir().unwrap();
        let troot = t.path().canonicalize().unwrap();
        let victim = v.path().canonicalize().unwrap();
        std::fs::write(victim.join("keep"), b"keep").unwrap();
        std::fs::create_dir(victim.join("sub")).unwrap();
        let sandbox = troot.join("tmp").join(RUN);
        std::fs::create_dir_all(&sandbox).unwrap();
        std::fs::create_dir(sandbox.join("d")).unwrap();
        std::os::unix::fs::symlink(&victim, sandbox.join("out")).unwrap();
        std::os::unix::fs::symlink("d", sandbox.join("in")).unwrap();
        let open_dir = |p: &Path| {
            let c = CString::new(p.as_os_str().as_bytes()).unwrap();
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
            assert!(fd >= 0);
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        let state = RealState {
            cwd_fd: open_dir(&sandbox),
            root_fd: open_dir(Path::new("/")),
            fds: HashMap::new(),
            run_id: RUN.to_string(),
            physical_root: Some(troot.as_os_str().as_bytes().to_vec()),
            listeners: Vec::new(),
            max_symlinks: 32,
        };
        Fixture {
            _t: t,
            _v: v,
            sandbox,
            victim,
            state,
        }
    }

    fn victim_untouched(f: &Fixture) {
        let mut names: Vec<_> = std::fs::read_dir(&f.victim)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["keep", "sub"]);
        assert_eq!(std::fs::read(f.victim.join("keep")).unwrap(), b"keep");
    }

    fn abs(f: &Fixture, rel: &str) -> Vec<u8> {
        let mut p = f.sandbox.as_os_str().as_bytes().to_vec();
        p.push(b'/');
        p.extend_from_slice(rel.as_bytes());
        p
    }

    fn refused<T>(r: ExecResult<T>) -> bool {
        matches!(r, Err(ExecError::Harness(_)))
    }

    #[test]
    fn trailing_slash_use_of_an_escaping_symlink_is_refused() {
        let mut f = fixture();
        // rename source, rename destination, rmdir, mkdir, unlink, symlink
        // and bind with `out/`: every one is refused before a syscall.
        let out = abs(&f, "out/");
        let y = abs(&f, "y");
        assert!(refused(rename_like(&mut f.state, &out, &y)));
        let d = abs(&f, "d");
        assert!(refused(rename_like(&mut f.state, &d, &out)));
        assert!(refused(unlink_like(&mut f.state, Start::Cwd, &out, true)));
        assert!(refused(unlink_like(&mut f.state, Start::Cwd, &out, false)));
        assert!(refused(mkdir_like(&mut f.state, Start::Cwd, &out, 0o755)));
        assert!(refused(symlink_like(&mut f.state, b"x", &out)));
        assert!(refused(bind_like(&mut f.state, &out)));
        victim_untouched(&f);
        // A dangling link into the victim: mkdir and rename-onto would
        // create there, so both are refused; so is an unlink (the guard does
        // not depend on the OS-specific errno).
        std::os::unix::fs::symlink(f.victim.join("newdir"), f.sandbox.join("dang")).unwrap();
        let dang = abs(&f, "dang/");
        assert!(refused(mkdir_like(&mut f.state, Start::Cwd, &dang, 0o755)));
        assert!(refused(rename_like(&mut f.state, &d, &dang)));
        assert!(refused(unlink_like(&mut f.state, Start::Cwd, &dang, false)));
        assert!(!f.victim.join("newdir").exists());
        victim_untouched(&f);
        // Without the slash the link itself is the operand: fine, and the
        // victim is still untouched.
        let bare = abs(&f, "out");
        assert!(unlink_like(&mut f.state, Start::Cwd, &bare, false).is_ok());
        assert!(!f.sandbox.join("out").exists());
        victim_untouched(&f);
    }

    #[test]
    fn trailing_slash_use_of_a_symlink_to_an_outside_file_is_refused() {
        let mut f = fixture();
        std::os::unix::fs::symlink(f.victim.join("keep"), f.sandbox.join("outf")).unwrap();
        let outf = abs(&f, "outf/");
        let y = abs(&f, "y");
        assert!(refused(unlink_like(&mut f.state, Start::Cwd, &outf, false)));
        assert!(refused(unlink_like(&mut f.state, Start::Cwd, &outf, true)));
        assert!(refused(rename_like(&mut f.state, &outf, &y)));
        victim_untouched(&f);
        // A link to `..` of the sandbox root's parent ends in `..`.
        std::os::unix::fs::symlink("../..", f.sandbox.join("up")).unwrap();
        let up = abs(&f, "up/");
        assert!(refused(rmdir_or_unlink(&mut f.state, &up)));
        victim_untouched(&f);
    }

    fn rmdir_or_unlink(state: &mut RealState, p: &[u8]) -> ExecResult<()> {
        unlink_like(state, Start::Cwd, p, true).map(|_| ())
    }

    #[test]
    fn trailing_slash_use_of_an_inside_symlink_is_allowed() {
        let f = fixture();
        let ok = check_trailing(&f.state, f.state.cwd_fd.as_raw_fd(), b"in", true);
        assert!(ok.is_ok());
        // A non-symlink and a missing name are never refused here.
        for name in [&b"d"[..], b"missing"] {
            let r = check_trailing(&f.state, f.state.cwd_fd.as_raw_fd(), name, true);
            assert!(r.is_ok());
        }
    }

    /// The errno a real call ends with; a harness refusal fails the test.
    fn errno_of(r: ExecResult<Outcome>) -> i32 {
        match r {
            Ok(o) => o.errno,
            Err(ExecError::Errno(e)) => e,
            Err(ExecError::Harness(m)) => panic!("harness refusal: {m}"),
        }
    }

    #[test]
    fn trailing_slash_use_of_an_inside_symlink_loop_is_not_refused() {
        let mut f = fixture();
        std::os::unix::fs::symlink("lb", f.sandbox.join("la")).unwrap();
        std::os::unix::fs::symlink("la", f.sandbox.join("lb")).unwrap();
        for i in 0..42 {
            let next = if i == 41 {
                "d".to_string()
            } else {
                format!("c{}", i + 1)
            };
            std::os::unix::fs::symlink(next, f.sandbox.join(format!("c{i}"))).unwrap();
        }
        let cwd = f.state.cwd_fd.as_raw_fd();
        assert!(check_trailing(&f.state, cwd, b"la", true).is_ok());
        assert!(check_trailing(&f.state, cwd, b"c0", true).is_ok());
        for link in ["la/", "c0/"] {
            let l = abs(&f, link);
            let y = abs(&f, "y");
            let d = abs(&f, "d");
            let outs = [
                rename_like(&mut f.state, &l, &y),
                rename_like(&mut f.state, &d, &l),
                unlink_like(&mut f.state, Start::Cwd, &l, false),
                unlink_like(&mut f.state, Start::Cwd, &l, true),
                mkdir_like(&mut f.state, Start::Cwd, &l, 0o755).map(|a| a.outcome),
            ];
            for o in outs {
                assert_ne!(errno_of(o), 0, "{link}");
            }
        }
        victim_untouched(&f);
    }

    #[test]
    fn absolute_at_paths_ignore_the_dirfd() {
        let mut f = fixture();
        let n = abs(&f, "n");
        let a = mkdir_like(&mut f.state, at_start(99, &n), &n, 0o755).map(|a| a.outcome);
        assert_eq!(errno_of(a), 0);
        assert!(f.sandbox.join("n").is_dir());
        let file = abs(&f, "d/f");
        let flags = OpenFlags {
            create: true,
            write: true,
            ..OpenFlags::default()
        };
        let a = open_like(&mut f.state, at_start(99, &file), &file, &flags).map(|a| a.outcome);
        assert_eq!(errno_of(a), 0);
        // A relative path with the same bogus fd is still EBADF.
        let a = mkdir_like(&mut f.state, at_start(99, b"m"), b"m", 0o755).map(|a| a.outcome);
        assert_eq!(errno_of(a), libc::EBADF);
        // Read-only open too.
        let ro = OpenFlags::default();
        let a = open_like(&mut f.state, at_start(99, &file), &file, &ro).map(|a| a.outcome);
        assert_eq!(errno_of(a), 0);
        victim_untouched(&f);
    }

    #[test]
    fn nul_operand_and_path_max_are_refused_or_enametoolong() {
        let mut f = fixture();
        let op = Op::Bind {
            path: b"a\0b".to_vec(),
        };
        assert!(refused(apply_real(&mut f.state, &op)));
        let mut long = abs(&f, "");
        long.resize(libc::PATH_MAX as usize, b'a');
        let a = mkdir_like(&mut f.state, Start::Root, &long, 0o755).map(|a| a.outcome);
        assert_eq!(errno_of(a), libc::ENAMETOOLONG);
        victim_untouched(&f);
    }
}
