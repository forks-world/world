//! `fuzz_driver`: Layer-2 differential fuzzer for the macOS silo shim and
//! Linux's bind-mounted `/tmp`. See `docs/testing.md` and the module docs on
//! `exec` (safety) and `gen.rs` (generation) for the design; this file is only
//! orchestration: argument parsing, the sandboxed run loop, comparison
//! against the model, and the JSON summary line.
//!
//! ```text
//! fuzz_driver run --profile mac|linux --seed S --ops N --run-id R [--allow-escaping-links] [--keep] [--out FILE]
//! fuzz_driver replay FILE [--run-id R] [--keep]
//! fuzz_driver minimize FILE --out FILE2 [--timeout SECS]
//! ```
//!
//! Exit codes: 0 = pass, 1 = a genuine divergence was found, 2 = harness
//! error (a safety refusal, a bad run id, or an I/O failure setting up the
//! sandbox) -- never a divergence verdict.
mod ddmin;
mod exec;
#[path = "gen.rs"]
mod gen_ops;

use std::collections::HashMap;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use world_fsmodel::{Entry, Model, Op, Outcome, Profile, Start, View, errno_equiv};

use exec::RealState;
use gen_ops::{Effect, GenStep, Generator};

#[derive(Parser)]
#[command(
    name = "fuzz_driver",
    about = "Layer-2 differential fuzzer for World's /tmp redirection"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Run {
        #[arg(long, value_enum)]
        profile: ProfileArg,
        #[arg(long)]
        seed: u64,
        #[arg(long, default_value_t = 40)]
        ops: usize,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        allow_escaping_links: bool,
        #[arg(long)]
        keep: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Replay {
        file: PathBuf,
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        keep: bool,
    },
    Minimize {
        file: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Mac,
    Linux,
}

impl ProfileArg {
    fn is_mac(self) -> bool {
        matches!(self, ProfileArg::Mac)
    }
    fn label(self) -> &'static str {
        match self {
            ProfileArg::Mac => "mac",
            ProfileArg::Linux => "linux",
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Run {
            profile,
            seed,
            ops,
            run_id,
            allow_escaping_links,
            keep,
            out,
        } => cmd_run(profile, seed, ops, run_id, allow_escaping_links, keep, out),
        Cmd::Replay { file, run_id, keep } => cmd_replay(&file, run_id, keep),
        Cmd::Minimize { file, out, timeout } => ddmin::minimize(&file, &out, timeout),
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------
// Run-id validation (mandatory, see the module docs and the task's safety
// rules): `^fz-[0-9a-f]{8,}$`, checked with plain byte matching (no regex
// dependency).
// ---------------------------------------------------------------------

pub fn valid_run_id(id: &str) -> bool {
    match id.strip_prefix("fz-") {
        Some(rest) => {
            rest.len() >= 8
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

static FRESH_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn fresh_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = FRESH_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("fz-{:x}{:x}{:x}", nanos, std::process::id(), n)
}

// ---------------------------------------------------------------------
// .ops file format: `# key value` header lines, then one op per line via
// `Op::to_line`/`Op::from_line`. Owned by this driver (not a frozen format
// elsewhere), so headers beyond `profile`/`seed` are our own addition.
// ---------------------------------------------------------------------

pub struct OpsFile {
    pub profile: String,
    pub seed: u64,
    pub run_id: String,
    pub allow_escaping_links: bool,
    pub ops: Vec<Op>,
}

pub fn render_ops_file(
    profile: &str,
    seed: u64,
    run_id: &str,
    allow_escaping_links: bool,
    ops: &[Op],
) -> String {
    let mut s = String::new();
    s.push_str(&format!("# profile {profile}\n"));
    s.push_str(&format!("# seed {seed}\n"));
    s.push_str(&format!("# run-id {run_id}\n"));
    s.push_str(&format!(
        "# allow-escaping-links {}\n",
        if allow_escaping_links { 1 } else { 0 }
    ));
    for op in ops {
        s.push_str(&op.to_line());
        s.push('\n');
    }
    s
}

pub fn parse_ops_file(text: &str) -> Result<OpsFile, String> {
    let mut profile = None;
    let mut seed = 0u64;
    let mut run_id = None;
    let mut allow_escaping_links = false;
    let mut ops = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# profile ") {
            profile = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("# seed ") {
            seed = rest
                .trim()
                .parse()
                .map_err(|_| format!("line {}: bad seed", lineno + 1))?;
        } else if let Some(rest) = line.strip_prefix("# run-id ") {
            run_id = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("# allow-escaping-links ") {
            allow_escaping_links = rest.trim() == "1";
        } else if line.starts_with('#') {
            continue;
        } else {
            let op = Op::from_line(line)
                .ok_or_else(|| format!("line {}: unparseable op: {line:?}", lineno + 1))?;
            ops.push(op);
        }
    }
    Ok(OpsFile {
        profile: profile.ok_or("missing '# profile' header")?,
        seed,
        run_id: run_id.ok_or("missing '# run-id' header")?,
        allow_escaping_links,
        ops,
    })
}

/// Rewrite every occurrence of `old_run_id` to `new_run_id` across the whole
/// file text (headers included), before parsing: run ids are plain
/// `[a-z0-9-]` text, never `%XX`-escaped by `Op::to_line`, so a literal
/// string replace is exact and safe.
pub fn retarget_run_id(text: &str, old_run_id: &str, new_run_id: &str) -> String {
    text.replace(old_run_id, new_run_id)
}

// ---------------------------------------------------------------------
// `run`
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cmd_run(
    profile: ProfileArg,
    seed: u64,
    ops: usize,
    run_id: String,
    allow_escaping_links: bool,
    keep: bool,
    out: Option<PathBuf>,
) -> i32 {
    if !valid_run_id(&run_id) {
        eprintln!("fuzz_driver: refusing invalid run id {run_id:?} (expected ^fz-[0-9a-f]{{8,}}$)");
        return 2;
    }
    let mut g = Generator::new(seed, &run_id, profile.is_mac(), allow_escaping_links);
    let mut prefix = g.bootstrap();
    prefix.extend(g.build_fixture());
    // The main-phase ops are deliberately *not* pre-generated here: each one
    // is produced by `Generator::next_op` only once every earlier op has
    // actually been applied to the model and recorded (see `execute`'s
    // `StepSource::Generated` arm) -- `next_op` reads back the generator's
    // own bookkeeping (cwd, known nodes, open fds), which is only accurate
    // once that feedback loop has run.
    let outcome = execute(
        profile,
        &run_id,
        prefix,
        StepSource::Generated(ops),
        &mut g,
        keep,
    );
    if let Some(path) = &out {
        let text = render_ops_file(
            profile.label(),
            seed,
            &run_id,
            allow_escaping_links,
            &outcome.history,
        );
        if let Err(e) = std::fs::write(path, text) {
            eprintln!(
                "fuzz_driver: warning: could not write --out {}: {e}",
                path.display()
            );
        }
    }
    finish(seed, ops, &run_id, outcome)
}

// ---------------------------------------------------------------------
// `replay`
// ---------------------------------------------------------------------

fn cmd_replay(file: &std::path::Path, run_id_override: Option<String>, keep: bool) -> i32 {
    let raw = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("fuzz_driver: could not read {}: {e}", file.display());
            return 2;
        }
    };
    let parsed = match parse_ops_file(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("fuzz_driver: could not parse {}: {e}", file.display());
            return 2;
        }
    };
    if !valid_run_id(&parsed.run_id) {
        eprintln!(
            "fuzz_driver: refusing invalid run id {:?} in the header of {} (expected ^fz-[0-9a-f]{{8,}}$)",
            parsed.run_id,
            file.display()
        );
        return 2;
    }
    let new_run_id = run_id_override.unwrap_or_else(fresh_run_id);
    if !valid_run_id(&new_run_id) {
        eprintln!(
            "fuzz_driver: refusing invalid run id {new_run_id:?} (expected ^fz-[0-9a-f]{{8,}}$)"
        );
        return 2;
    }
    let text = retarget_run_id(&raw, &parsed.run_id, &new_run_id);
    let parsed = match parse_ops_file(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "fuzz_driver: could not re-parse {} after retargeting the run id: {e}",
                file.display()
            );
            return 2;
        }
    };
    let profile = match parsed.profile.as_str() {
        "mac" => ProfileArg::Mac,
        "linux" => ProfileArg::Linux,
        other => {
            eprintln!(
                "fuzz_driver: unknown profile {other:?} in {}",
                file.display()
            );
            return 2;
        }
    };
    let steps: Vec<GenStep> = parsed
        .ops
        .into_iter()
        .map(|op| GenStep {
            op,
            on_success: Effect::None,
            known_gap_candidate: false,
        })
        .collect();
    let mut g = Generator::new(
        parsed.seed,
        &new_run_id,
        profile.is_mac(),
        parsed.allow_escaping_links,
    );
    let outcome = execute(
        profile,
        &new_run_id,
        Vec::new(),
        StepSource::Fixed(steps),
        &mut g,
        keep,
    );
    let op_count = outcome.history.len();
    finish(parsed.seed, op_count, &new_run_id, outcome)
}

// ---------------------------------------------------------------------
// Shared execution engine.
// ---------------------------------------------------------------------

struct Divergence {
    index: usize,
    op_line: String,
    model_ret: i64,
    model_errno: i32,
    real_ret: i64,
    real_errno: i32,
    detail: String,
}

impl Divergence {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "index": self.index,
            "op": self.op_line,
            "model_ret": self.model_ret,
            "model_errno": self.model_errno,
            "real_ret": self.real_ret,
            "real_errno": self.real_errno,
            "detail": self.detail,
        })
    }
}

struct RunOutcome {
    history: Vec<Op>,
    first_divergence: Option<Divergence>,
    known_divergences: Vec<Divergence>,
    tree_mismatch: Option<String>,
    /// `Model::tree_json` of the virtual sandbox tmp root, captured before
    /// cleanup (which -- unless `--keep` -- removes it from disk).
    model_tree_json: String,
    /// Same, for the `/var/tmp/<run-id>` sandbox root.
    model_var_tree_json: String,
    /// Report-only: `lstat` of each absolute path operand of the diverging op
    /// (and, for a symlink, its `readlink` and its target's `lstat`), taken
    /// right after the divergence. Never fed back into the run.
    operand_snapshot: serde_json::Value,
}

/// Report-only `lstat` snapshot of the absolute paths named by `op_line`.
fn operand_snapshot(op_line: &str) -> serde_json::Value {
    use std::os::unix::fs::MetadataExt;
    let describe = |p: &std::path::Path| match std::fs::symlink_metadata(p) {
        Ok(m) => {
            let ft = m.file_type();
            let kind = if ft.is_symlink() {
                "symlink"
            } else if ft.is_dir() {
                "dir"
            } else if ft.is_file() {
                "file"
            } else {
                "other"
            };
            serde_json::json!({ "kind": kind, "ino": m.ino(), "size": m.len() })
        }
        Err(e) => serde_json::json!({ "error": e.raw_os_error() }),
    };
    let mut out = serde_json::Map::new();
    for tok in op_line.split_whitespace().filter(|t| t.starts_with('/')) {
        let bare = tok.trim_end_matches('/');
        let bare = if bare.is_empty() { "/" } else { bare };
        let path = std::path::Path::new(bare);
        let mut entry = describe(path);
        if let Ok(target) = std::fs::read_link(path) {
            let resolved = path.parent().unwrap_or(path).join(&target);
            entry["link"] = serde_json::json!(target.to_string_lossy());
            entry["target"] = describe(&resolved);
        }
        out.insert(tok.to_string(), entry);
    }
    serde_json::Value::Object(out)
}

/// Execute `steps` against a fresh model and the real filesystem, in
/// lockstep, stopping at the first genuine (non-"known") divergence. Always
/// returns (never panics on an ordinary POSIX failure): a harness-level
/// safety refusal is the only thing that aborts the process outright, via
/// `abort_harness` below.
/// Where the *main*-phase ops (after `prefix`, i.e. bootstrap + fixture)
/// come from: a fixed, already-parsed list (`replay`), or generated live,
/// one at a time, interleaved with execution (`run`) -- see `execute`'s doc
/// comment for why the live case cannot be pre-generated as a batch.
enum StepSource {
    Fixed(Vec<GenStep>),
    Generated(usize),
}

#[allow(clippy::too_many_arguments)]
fn run_one_step(
    index: usize,
    step: GenStep,
    model: &mut Model,
    state: &mut RealState,
    g: &mut Generator,
    linux: bool,
    history: &mut Vec<Op>,
    known_divergences: &mut Vec<Divergence>,
) -> Option<Divergence> {
    let GenStep {
        op,
        on_success,
        known_gap_candidate,
    } = step;
    history.push(op.clone());
    let model_out = model.apply(&op);
    let applied = match exec::apply_real(state, &op) {
        Ok(a) => a,
        Err(exec::ExecError::Errno(e)) => exec::Applied {
            outcome: Outcome {
                ret: -1,
                errno: e,
                data: Vec::new(),
            },
            pending: None,
        },
        Err(exec::ExecError::Harness(msg)) => {
            abort_harness(&format!("op {index} ({}): {msg}", op.to_line()))
        }
    };
    let real_out = applied.outcome;

    if model_out.errno == 0
        && let Some(pending) = applied.pending
    {
        state.fds.insert(model_out.ret as u32, pending.0);
    }
    g.record(&on_success, model_out.ret, model_out.errno);

    if let Some(detail) = compare(&op, model, state, linux, &model_out, &real_out) {
        let d = Divergence {
            index,
            op_line: op.to_line(),
            model_ret: model_out.ret,
            model_errno: model_out.errno,
            real_ret: real_out.ret,
            real_errno: real_out.errno,
            detail,
        };
        if known_gap_candidate {
            known_divergences.push(d);
            return None;
        }
        return Some(d);
    }
    None
}

/// Execute `prefix` (bootstrap + fixture, already fully generated -- see
/// `gen.rs`'s `build_fixture` doc comment for why that one *is* safe to
/// pre-generate as a batch), then the main-phase ops from `source`.
///
/// For `StepSource::Generated`, each main-phase op is produced by
/// `Generator::next_op` only right before it is applied -- never ahead of
/// time -- because `next_op` reads the generator's own bookkeeping (the
/// tracked cwd, known nodes, open fds), which `Generator::record` only
/// updates once it has seen the *model's* actual outcome for every earlier
/// op. Pre-generating a whole batch up front would have every call after
/// the first see an empty/stale tree.
fn execute(
    profile: ProfileArg,
    run_id: &str,
    prefix: Vec<GenStep>,
    source: StepSource,
    g: &mut Generator,
    keep: bool,
) -> RunOutcome {
    let model_profile = if profile.is_mac() {
        Profile::MacShim {
            root: b"/nonexistent-fuzz-driver-model-root".to_vec(),
        }
    } else {
        Profile::LinuxMount {
            root: b"/nonexistent-fuzz-driver-model-root".to_vec(),
        }
    };
    let mut model = Model::new(model_profile);
    model.set_case_insensitive(profile.is_mac());

    let root_fd =
        open_root_fd().unwrap_or_else(|e| abort_harness(&format!("could not open \"/\": {e}")));
    let cwd_fd = open_root_fd()
        .unwrap_or_else(|e| abort_harness(&format!("could not open \"/\" for cwd: {e}")));
    let mut state = RealState {
        cwd_fd,
        root_fd,
        fds: HashMap::new(),
        run_id: run_id.to_string(),
        physical_root: std::env::var_os("WORLD_TMP").map(|v| {
            use std::os::unix::ffi::OsStrExt;
            v.as_bytes().to_vec()
        }),
        listeners: Vec::new(),
        max_symlinks: if profile.is_mac() { 32 } else { 40 },
    };

    let linux = !profile.is_mac();
    let mut history = Vec::with_capacity(prefix.len());
    let mut first_divergence = None;
    let mut known_divergences = Vec::new();
    let mut index = 0usize;

    for step in prefix {
        if let Some(d) = run_one_step(
            index,
            step,
            &mut model,
            &mut state,
            g,
            linux,
            &mut history,
            &mut known_divergences,
        ) {
            first_divergence = Some(d);
        }
        index += 1;
        if first_divergence.is_some() {
            break;
        }
    }

    if first_divergence.is_none() {
        match source {
            StepSource::Fixed(steps) => {
                for step in steps {
                    if let Some(d) = run_one_step(
                        index,
                        step,
                        &mut model,
                        &mut state,
                        g,
                        linux,
                        &mut history,
                        &mut known_divergences,
                    ) {
                        first_divergence = Some(d);
                    }
                    index += 1;
                    if first_divergence.is_some() {
                        break;
                    }
                }
            }
            StepSource::Generated(n) => {
                for _ in 0..n {
                    let step = g.next_op();
                    if let Some(d) = run_one_step(
                        index,
                        step,
                        &mut model,
                        &mut state,
                        g,
                        linux,
                        &mut history,
                        &mut known_divergences,
                    ) {
                        first_divergence = Some(d);
                    }
                    index += 1;
                    if first_divergence.is_some() {
                        break;
                    }
                }
            }
        }
    }

    let operand_snapshot = first_divergence
        .as_ref()
        .map(|d| operand_snapshot(&d.op_line))
        .unwrap_or(serde_json::Value::Null);
    let tree_mismatch = if first_divergence.is_none() {
        check_final_tree(&model, run_id, profile.is_mac())
    } else {
        None
    };
    let model_tree_json = model.tree_json(View::Virtual, &format!("/tmp/{run_id}").into_bytes());
    let model_var_tree_json =
        model.tree_json(View::Virtual, &format!("/var/tmp/{run_id}").into_bytes());

    if !keep {
        for root in [g.tmp_root(), g.var_root()] {
            if let Err(e) = exec::remove_sandbox_tree(run_id, state.physical_root.as_deref(), root)
            {
                eprintln!(
                    "fuzz_driver: warning: cleanup of {} failed: {e}",
                    String::from_utf8_lossy(root)
                );
            }
        }
    }

    RunOutcome {
        history,
        first_divergence,
        known_divergences,
        tree_mismatch,
        model_tree_json,
        model_var_tree_json,
        operand_snapshot,
    }
}

/// Lexical canonical form of an absolute path for comparing *spellings* of
/// the same host temp location: collapses `.`/`..`/empty components and
/// (on the mac profile only) drops a leading `private` component
/// (`/private/tmp` == `/tmp`, `/private/var/tmp` == `/var/tmp`), which the
/// shim reports for absolute symlink targets (its documented "readlink
/// reports the host name" rule). On Linux `/private` is an ordinary name.
fn canon_abs(path: &[u8], mac: bool) -> Vec<u8> {
    let mut comps: Vec<&[u8]> = Vec::new();
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                comps.pop();
            }
            other => comps.push(other),
        }
    }
    if mac
        && comps.first() == Some(&&b"private"[..])
        && matches!(comps.get(1), Some(&c) if c == b"tmp" || c == b"var")
    {
        comps.remove(0);
    }
    let mut out = Vec::new();
    for c in comps {
        out.push(b'/');
        out.extend_from_slice(c);
    }
    out
}

/// Two entries agree if identical, or if both are symlinks with *absolute*
/// targets that are merely different spellings of the same location.
fn entries_agree(model: &Model, mac: bool, a: &Entry, b: &Entry) -> bool {
    if a == b {
        return true;
    }
    use world_fsmodel::EntryKind::Symlink;
    if let (Symlink { target: ta }, Symlink { target: tb }) = (&a.kind, &b.kind)
        && a.path == b.path
        && ta.first() == Some(&b'/')
        && tb.first() == Some(&b'/')
    {
        if canon_abs(ta, mac) == canon_abs(tb, mac) {
            return true;
        }
        let ra = model.resolve(View::Virtual, Start::Root, ta, true);
        let rb = model.resolve(View::Virtual, Start::Root, tb, true);
        return matches!((ra, rb), (Ok(x), Ok(y)) if x == y);
    }
    false
}

/// Compare the model's tree against the real one under *both* sandbox roots
/// (`/tmp/<run-id>` and `/var/tmp/<run-id>`), joining the mismatch messages.
fn check_final_tree(model: &Model, run_id: &str, mac: bool) -> Option<String> {
    let msgs: Vec<String> = [format!("/tmp/{run_id}"), format!("/var/tmp/{run_id}")]
        .into_iter()
        .filter_map(|root| check_tree_at(model, mac, root.into_bytes()))
        .collect();
    if msgs.is_empty() {
        None
    } else {
        Some(msgs.join("; "))
    }
}

fn check_tree_at(model: &Model, mac: bool, tmp_root: Vec<u8>) -> Option<String> {
    let model_entries = model.tree(View::Virtual, &tmp_root);
    let real_entries: Vec<Entry> = match exec::real_tree(&tmp_root) {
        Ok(e) => e,
        // A sandbox root that neither side has (e.g. a minimized replay that
        // never created it) agrees trivially.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && model_entries.is_empty() => {
            return None;
        }
        Err(e) => {
            return Some(format!(
                "could not walk the real tree at {}: {e}",
                String::from_utf8_lossy(&tmp_root)
            ));
        }
    };
    let same = model_entries.len() == real_entries.len()
        && model_entries
            .iter()
            .zip(&real_entries)
            .all(|(a, b)| entries_agree(model, mac, a, b));
    if same {
        None
    } else {
        Some(format!(
            "final tree mismatch under {}: model={model_entries:?} real={real_entries:?}",
            String::from_utf8_lossy(&tmp_root)
        ))
    }
}

fn open_root_fd() -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn abort_harness(msg: &str) -> ! {
    eprintln!("fuzz_driver: harness error: {msg}");
    std::process::exit(2);
}

/// Compare one op's model and real outcomes, per `docs/testing.md`'s
/// criteria: errno (via `errno_equiv`), then ret sign, then op-specific data
/// rules (`readlink`'s two cases, `getcwd`/`realpath`'s exact-match-plus-no-
/// leak rule, `stat`/`lstat`'s kind byte, `read`/`list`'s exact bytes).
fn compare(
    op: &Op,
    model: &Model,
    state: &RealState,
    linux: bool,
    model_out: &Outcome,
    real_out: &Outcome,
) -> Option<String> {
    if !errno_equiv(linux, op, model_out.errno, real_out.errno) {
        return Some(format!(
            "errno mismatch: model={} real={}",
            model_out.errno, real_out.errno
        ));
    }
    if model_out.errno != 0 {
        return None;
    }
    if (model_out.ret >= 0) != (real_out.ret >= 0) {
        return Some("ret sign mismatch".to_string());
    }
    match op {
        Op::Readlink { .. } => {
            if real_out.data != model_out.data
                && real_out.data.first() == Some(&b'/')
                && model_out.data.first() == Some(&b'/')
            {
                // Differently *spelled* absolute targets are fine as long as
                // they resolve to the same node; byte-identical text (the
                // common case, including a dangling absolute target that
                // fails to resolve on *both* sides -- see
                // `real_node`/`model_node` below) never needs this at all,
                // since it is trivially the same input to the same
                // resolver.
                let real_node = model.resolve(View::Virtual, Start::Root, &real_out.data, true);
                let model_node = model.resolve(View::Virtual, Start::Root, &model_out.data, true);
                if canon_abs(&real_out.data, !linux) != canon_abs(&model_out.data, !linux)
                    && !matches!((real_node, model_node), (Ok(a), Ok(b)) if a == b)
                {
                    return Some(format!(
                        "readlink absolute target resolves differently: real={:?} model={:?}",
                        String::from_utf8_lossy(&real_out.data),
                        String::from_utf8_lossy(&model_out.data)
                    ));
                }
            } else if real_out.data != model_out.data {
                return Some(format!(
                    "readlink target mismatch: real={:?} model={:?}",
                    String::from_utf8_lossy(&real_out.data),
                    String::from_utf8_lossy(&model_out.data)
                ));
            }
            if real_out.data.first() == Some(&b'/')
                && exec::leaks_physical_root(state, &real_out.data)
            {
                return Some(format!(
                    "readlink leaked the physical root: {:?}",
                    String::from_utf8_lossy(&real_out.data)
                ));
            }
        }
        Op::Getcwd | Op::Realpath { .. } => {
            if real_out.data != model_out.data {
                return Some(format!(
                    "getcwd/realpath mismatch: real={:?} model={:?}",
                    String::from_utf8_lossy(&real_out.data),
                    String::from_utf8_lossy(&model_out.data)
                ));
            }
            if exec::leaks_physical_root(state, &real_out.data) {
                return Some(format!(
                    "getcwd/realpath leaked the physical root: {:?}",
                    String::from_utf8_lossy(&real_out.data)
                ));
            }
        }
        Op::Read { .. } | Op::List { .. } => {
            if real_out.data != model_out.data {
                return Some(format!(
                    "data mismatch: real={:?} model={:?}",
                    String::from_utf8_lossy(&real_out.data),
                    String::from_utf8_lossy(&model_out.data)
                ));
            }
        }
        Op::Stat { .. } | Op::Lstat { .. } if real_out.data.first() != model_out.data.first() => {
            return Some(format!(
                "stat kind mismatch: real={:?} model={:?}",
                real_out.data.first(),
                model_out.data.first()
            ));
        }
        _ => {}
    }
    None
}

fn finish(seed: u64, ops: usize, run_id: &str, outcome: RunOutcome) -> i32 {
    let mut result = "pass";
    let mut first_divergence_json = serde_json::Value::Null;
    if let Some(d) = &outcome.first_divergence {
        result = "diverge";
        first_divergence_json = d.to_json();
    } else if let Some(msg) = &outcome.tree_mismatch {
        result = "diverge";
        first_divergence_json = serde_json::json!({ "detail": msg });
    }
    let known: Vec<serde_json::Value> = outcome
        .known_divergences
        .iter()
        .map(Divergence::to_json)
        .collect();
    // `Model::tree_json` hand-rolls its own JSON text (no serde dependency in
    // world-fsmodel): embed it as a real value when it parses (it always
    // should), falling back to the raw string otherwise.
    let model_tree = serde_json::from_str(&outcome.model_tree_json)
        .unwrap_or(serde_json::Value::String(outcome.model_tree_json.clone()));
    let model_var_tree = serde_json::from_str(&outcome.model_var_tree_json).unwrap_or(
        serde_json::Value::String(outcome.model_var_tree_json.clone()),
    );
    let json = serde_json::json!({
        "seed": seed,
        "ops": ops,
        "run_id": run_id,
        "result": result,
        "first_divergence": first_divergence_json,
        "known_divergences": known,
        "operand_snapshot": outcome.operand_snapshot,
        "model_tree": model_tree,
        "model_var_tree": model_var_tree,
    });
    println!("{json}");
    if result == "diverge" { 1 } else { 0 }
}
