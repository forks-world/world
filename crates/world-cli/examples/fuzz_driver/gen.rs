//! Seeded generation of fixture trees and fuzz operations, entirely in terms
//! of `world_fsmodel::Op`. Every path this module hands out is constructed
//! from a *canonical* absolute path the generator itself is tracking (see
//! `Node`/`self.cwd`): nothing here ever invents a path that could resolve
//! (in the model) outside the run's two sandbox roots, `/tmp/<run-id>` and
//! `/var/tmp/<run-id>` -- that invariant is what lets `main.rs`'s real-side
//! guard (see `exec.rs`) be a pure defense-in-depth check that should never
//! actually fire.
//!
//! Names are lowercase ASCII letters and digits only (APFS is
//! case-insensitive; see `docs/testing.md`'s "known limitations").
use std::collections::HashMap;

use world_fsmodel::{Op, OpenFlags, Rng};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Dir,
    File,
    Symlink,
}

#[derive(Clone)]
struct Node {
    path: Vec<u8>,
    kind: Kind,
}

/// What to update in the generator's own bookkeeping if the op this step
/// produced is applied to the model with `errno == 0`. Kept separate from
/// the op's own path text, which may be a deliberately "weird" spelling of
/// the same canonical target.
pub enum Effect {
    None,
    AddNode(Vec<u8>, Kind),
    /// A file created (and opened) in one call: adds the node *and*
    /// registers the model's returned fd as an open file.
    CreateFile(Vec<u8>),
    Remove(Vec<u8>),
    Rename(Vec<u8>, Vec<u8>),
    Chdir(Vec<u8>),
    /// Registers the model's returned fd as an open directory fd for
    /// `path` (see `Generator::open_dir_paths`).
    RegisterDirFd(Vec<u8>),
    RegisterFileFd,
    Close(u32),
}

pub struct GenStep {
    pub op: Op,
    pub on_success: Effect,
}

fn plain(op: Op, on_success: Effect) -> GenStep {
    GenStep { op, on_success }
}

pub struct Generator {
    rng: Rng,
    mac: bool,
    allow_escaping: bool,
    tmp_root: Vec<u8>,
    var_root: Vec<u8>,
    nodes: Vec<Node>,
    escaping_links: Vec<Vec<u8>>,
    open_dirs: Vec<u32>,
    /// Canonical path each currently-open directory fd refers to: consulted
    /// by `gen_rmdir` so it never targets a directory something still holds
    /// open. The model does track such detached directories (creates in
    /// them are ENOENT, `getcwd` fails), but that behaviour is exercised
    /// only by replaying the `seed-dead-cwd` corpus, not by generation.
    open_dir_paths: HashMap<u32, Vec<u8>>,
    open_files: Vec<u32>,
    sockets: Vec<Vec<u8>>,
    cwd: Vec<u8>,
}

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = dir.to_vec();
    out.push(b'/');
    out.extend_from_slice(name);
    out
}

fn parent_of(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) => b"/".to_vec(),
        Some(i) => path[..i].to_vec(),
        None => Vec::new(),
    }
}

fn basename(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => path[i + 1..].to_vec(),
        None => path.to_vec(),
    }
}

/// If `path` is exactly `from` or nested under it, rewrite that `from`
/// prefix to `to` in place (a rename moves the whole subtree, not just the
/// renamed node's own exact path).
fn rebase(path: &mut Vec<u8>, from: &[u8], to: &[u8]) {
    if path.as_slice() == from {
        *path = to.to_vec();
        return;
    }
    let mut from_prefix = from.to_vec();
    from_prefix.push(b'/');
    if let Some(rest) = path.strip_prefix(from_prefix.as_slice()) {
        let mut out = to.to_vec();
        out.push(b'/');
        out.extend_from_slice(rest);
        *path = out;
    }
}

impl Generator {
    pub fn new(seed: u64, run_id: &str, mac: bool, allow_escaping: bool) -> Generator {
        let tmp_root = format!("/tmp/{run_id}").into_bytes();
        let var_root = format!("/var/tmp/{run_id}").into_bytes();
        Generator {
            rng: Rng::new(seed),
            mac,
            allow_escaping,
            cwd: tmp_root.clone(),
            tmp_root,
            var_root,
            nodes: Vec::new(),
            escaping_links: Vec::new(),
            open_dirs: Vec::new(),
            open_dir_paths: HashMap::new(),
            open_files: Vec::new(),
            sockets: Vec::new(),
        }
    }

    pub fn tmp_root(&self) -> &[u8] {
        &self.tmp_root
    }
    pub fn var_root(&self) -> &[u8] {
        &self.var_root
    }

    /// The three ops that create the run's two sandbox roots and move the
    /// (tracked, never-real-chdir'd) cwd into the first one.
    pub fn bootstrap(&self) -> Vec<GenStep> {
        vec![
            plain(
                Op::Mkdir {
                    path: self.tmp_root.clone(),
                    mode: 0o755,
                },
                Effect::AddNode(self.tmp_root.clone(), Kind::Dir),
            ),
            plain(
                Op::Mkdir {
                    path: self.var_root.clone(),
                    mode: 0o755,
                },
                Effect::AddNode(self.var_root.clone(), Kind::Dir),
            ),
            plain(
                Op::Chdir {
                    path: self.tmp_root.clone(),
                },
                Effect::Chdir(self.tmp_root.clone()),
            ),
        ]
    }

    fn fresh_name(&mut self) -> Vec<u8> {
        let len = 1 + self.rng.below(4) as usize;
        (0..len)
            .map(|_| ALPHABET[self.rng.below(ALPHABET.len() as u64) as usize])
            .collect()
    }

    /// A name for a *new* entry: usually fresh, sometimes an existing
    /// sibling name (to bias towards EEXIST outcomes).
    fn biased_name(&mut self) -> Vec<u8> {
        if !self.nodes.is_empty() && self.rng.chance(1, 4) {
            let n = &self.nodes[self.rng.below(self.nodes.len() as u64) as usize];
            basename(&n.path)
        } else {
            self.fresh_name()
        }
    }

    fn nodes_of_kind(&self, kind: Kind) -> Vec<Vec<u8>> {
        self.nodes
            .iter()
            .filter(|n| n.kind == kind)
            .map(|n| n.path.clone())
            .collect()
    }

    fn pick(&mut self, paths: &[Vec<u8>]) -> Option<Vec<u8>> {
        if paths.is_empty() {
            None
        } else {
            Some(paths[self.rng.below(paths.len() as u64) as usize].clone())
        }
    }

    fn direct_children_of(&self, dir: &[u8], kind: Kind) -> Vec<Vec<u8>> {
        self.nodes
            .iter()
            .filter(|n| n.kind == kind && parent_of(&n.path) == dir)
            .map(|n| n.path.clone())
            .collect()
    }

    /// A random existing path, any kind, or a sandbox root if nothing else
    /// exists yet.
    fn any_existing(&mut self) -> Vec<u8> {
        if self.nodes.is_empty() {
            return self.tmp_root.clone();
        }
        self.nodes[self.rng.below(self.nodes.len() as u64) as usize]
            .path
            .clone()
    }

    /// `any_existing`, minus the escaping links: the target of an op that
    /// *follows* a final symlink (`stat`, `realpath`, an absolute symlink
    /// target a later op would chase). Resolving through an escaping link is
    /// the documented shim gap, so only non-following ops touch them.
    fn any_followable(&mut self) -> Vec<u8> {
        let nodes: Vec<Vec<u8>> = self
            .nodes
            .iter()
            .map(|n| n.path.clone())
            .filter(|p| !self.escaping_links.contains(p))
            .collect();
        self.pick(&nodes).unwrap_or_else(|| self.tmp_root.clone())
    }

    /// True if renaming `path` would move an escaping link (it is one, or a
    /// directory above one): escaping links stay where the fixture put
    /// them, so no other path can ever come to resolve through one.
    fn moves_escaping_link(&self, path: &[u8]) -> bool {
        let mut prefix = path.to_vec();
        prefix.push(b'/');
        self.escaping_links
            .iter()
            .any(|l| l.as_slice() == path || l.starts_with(&prefix))
    }

    /// One of the two sandbox roots, or `dir`'s own siblings, chosen so
    /// building a new name under `dir` cannot itself be malformed.
    fn any_dir(&mut self) -> Vec<u8> {
        let mut dirs = self.nodes_of_kind(Kind::Dir);
        dirs.push(self.tmp_root.clone());
        dirs.push(self.var_root.clone());
        self.pick(&dirs).unwrap_or_else(|| self.tmp_root.clone())
    }

    /// macOS-only alternate spellings of an absolute canonical path that
    /// must resolve identically: `/tmp` vs `/private/tmp` vs a `..` detour
    /// immediately below the real root.
    fn spell_absolute(&mut self, canonical: &[u8]) -> Vec<u8> {
        if !self.mac || self.rng.chance(1, 2) {
            return canonical.to_vec();
        }
        let s = String::from_utf8_lossy(canonical).into_owned();
        let variant = self.rng.below(3);
        if let Some(rest) = s.strip_prefix("/tmp/") {
            return match variant {
                0 => format!("/private/tmp/{rest}").into_bytes(),
                1 => format!("/var/../tmp/{rest}").into_bytes(),
                _ => canonical.to_vec(),
            };
        }
        if let Some(rest) = s.strip_prefix("/var/tmp/") {
            return match variant {
                0 => format!("/private/var/tmp/{rest}").into_bytes(),
                1 => format!("/tmp/../var/tmp/{rest}").into_bytes(),
                _ => canonical.to_vec(),
            };
        }
        canonical.to_vec()
    }

    /// Either an (possibly re-spelled) absolute path, or -- when `canonical`
    /// is the cwd or nested under it -- a relative spelling: bare, `./`
    /// prefixed, or detoured through an existing sibling directory's `..`.
    /// Any spelling, including a bare `.` when `canonical` is the cwd
    /// itself: safe for read-only/navigational targets (`Stat`, `Readlink`,
    /// `Chdir`, `Realpath`, `List`, `OpenDir`), never for a path that names
    /// something to create, remove, or rename -- see `spell_for_mutation`.
    fn spell(&mut self, canonical: &[u8]) -> Vec<u8> {
        self.spell_ex(canonical, true)
    }

    /// Like `spell`, but never renders a bare `.`: `Model::resolve_parent`
    /// (used by every op that creates/removes/renames a name) treats a
    /// literal `.` as always `EINVAL`, which does not universally match a
    /// real kernel's own per-syscall errno for the same case (e.g. `symlink`
    /// gave `EEXIST` when checked by hand) -- a narrow, pre-existing
    /// `world_fsmodel` simplification outside this driver's owned files,
    /// avoided here by construction (see the fuzz_driver report).
    fn spell_for_mutation(&mut self, canonical: &[u8]) -> Vec<u8> {
        self.spell_ex(canonical, false)
    }

    /// `spell_for_mutation`, plus (probability 1/32, and `//` a quarter of
    /// those) a trailing slash, for the operations whose behavior a trailing
    /// slash changes: unlink, rmdir, rename, symlink, bind, open-create. The
    /// model implements the per-profile rules and the driver hands the
    /// original spelling to the real syscall. A name that is a link leaving
    /// the sandbox never gets one: macOS follows such links for rename and
    /// rmdir, which the driver would (correctly) refuse and abort the run.
    fn spell_for_trailing(&mut self, canonical: &[u8]) -> Vec<u8> {
        let mut out = self.spell_for_mutation(canonical);
        // Whether a kernel follows `link/` differs across macOS versions
        // (`unlink lf/` removed the link on 15, gave ENOTDIR on 27), so on
        // macOS no symlink node is ever given a trailing slash.
        let mac_symlink = self.mac
            && self
                .nodes
                .iter()
                .any(|n| n.path == canonical && n.kind == Kind::Symlink);
        if !mac_symlink
            && !self.escaping_links.contains(&canonical.to_vec())
            && self.rng.chance(1, 32)
        {
            out.push(b'/');
            if self.rng.chance(1, 4) {
                out.push(b'/');
            }
        }
        out
    }

    fn spell_ex(&mut self, canonical: &[u8], allow_dot: bool) -> Vec<u8> {
        if canonical == self.cwd.as_slice() {
            return if allow_dot && self.rng.chance(1, 2) {
                b".".to_vec()
            } else {
                self.spell_absolute(canonical)
            };
        }
        let cwd_prefix = {
            let mut p = self.cwd.clone();
            p.push(b'/');
            p
        };
        if let Some(rel) = canonical.strip_prefix(cwd_prefix.as_slice())
            && self.rng.chance(2, 3)
        {
            let mut out = rel.to_vec();
            if self.rng.chance(1, 3) {
                let mut prefixed = b"./".to_vec();
                prefixed.extend_from_slice(&out);
                out = prefixed;
            } else if self.rng.chance(1, 2) {
                let siblings = self.direct_children_of(&self.cwd, Kind::Dir);
                if let Some(sib) = self.pick(&siblings) {
                    let sib_name = basename(&sib);
                    let mut detoured = sib_name;
                    detoured.extend_from_slice(b"/../");
                    detoured.extend_from_slice(&out);
                    out = detoured;
                }
            }
            return out;
        }
        self.spell_absolute(canonical)
    }

    // -------------------------------------------------------------
    // Fixture tree.
    // -------------------------------------------------------------

    /// Builds a small, self-consistent random tree up front: fixture
    /// construction tracks the dirs/files it has just decided to create in
    /// local lists (`dirs`/`files`), never via `self.nodes` -- those only
    /// become authoritative once `Generator::record` sees the *model*
    /// confirm each op actually succeeded, which happens later, op by op,
    /// as `main.rs` executes this same returned list. Querying `self.nodes`
    /// here (before any of that has run) would just see an empty tree.
    pub fn build_fixture(&mut self) -> Vec<GenStep> {
        let mut steps = Vec::new();
        let mut dirs: Vec<Vec<u8>> = vec![self.tmp_root.clone(), self.var_root.clone()];
        let mut files: Vec<Vec<u8>> = Vec::new();
        let mut top_dirs: Vec<Vec<u8>> = Vec::new();

        for _ in 0..3 + self.rng.below(3) {
            let name = self.fresh_name();
            let canonical = join(&self.tmp_root.clone(), &name);
            let path = self.spell_absolute(&canonical);
            steps.push(plain(
                Op::Mkdir { path, mode: 0o755 },
                Effect::AddNode(canonical.clone(), Kind::Dir),
            ));
            top_dirs.push(canonical.clone());
            dirs.push(canonical);
        }
        // A nested chain (depth up to 8) under one of the fresh top-level dirs.
        if let Some(mut cur) = self.pick(&top_dirs) {
            let depth = 1 + self.rng.below(6);
            for _ in 0..depth {
                let name = self.fresh_name();
                let canonical = join(&cur, &name);
                steps.push(plain(
                    Op::Mkdir {
                        path: canonical.clone(),
                        mode: 0o755,
                    },
                    Effect::AddNode(canonical.clone(), Kind::Dir),
                ));
                dirs.push(canonical.clone());
                cur = canonical;
            }
        }
        // A couple of plain files.
        for _ in 0..2 {
            let dir = self.pick(&dirs).unwrap_or_else(|| self.tmp_root.clone());
            let name = self.fresh_name();
            let canonical = join(&dir, &name);
            let flags = OpenFlags {
                create: true,
                write: true,
                ..Default::default()
            };
            steps.push(plain(
                Op::Open {
                    path: canonical.clone(),
                    flags,
                },
                Effect::CreateFile(canonical.clone()),
            ));
            files.push(canonical);
        }
        self.build_symlink_chain(&mut steps, &files);
        self.build_symlink_loop(&mut steps, &dirs);
        // A little content under /var/tmp/<run-id> too.
        {
            let name = self.fresh_name();
            let canonical = join(&self.var_root.clone(), &name);
            steps.push(plain(
                Op::Mkdir {
                    path: canonical.clone(),
                    mode: 0o755,
                },
                Effect::AddNode(canonical, Kind::Dir),
            ));
        }
        if self.allow_escaping {
            self.build_escaping_links(&mut steps, &dirs);
        }
        steps
    }

    fn build_symlink_chain(&mut self, steps: &mut Vec<GenStep>, files: &[Vec<u8>]) {
        let Some(target_file) = self.pick(files) else {
            return;
        };
        let dir = parent_of(&target_file);
        let mut prev_name = basename(&target_file);
        let chain_len = 1 + self.rng.below(6);
        for _ in 0..chain_len {
            let name = self.fresh_name();
            let canonical = join(&dir, &name);
            steps.push(plain(
                Op::Symlink {
                    target: prev_name.clone(),
                    path: canonical.clone(),
                },
                Effect::AddNode(canonical.clone(), Kind::Symlink),
            ));
            prev_name = name;
        }
    }

    fn build_symlink_loop(&mut self, steps: &mut Vec<GenStep>, dirs: &[Vec<u8>]) {
        let dir = self.pick(dirs).unwrap_or_else(|| self.tmp_root.clone());
        let a = self.fresh_name();
        let b = self.fresh_name();
        if a == b {
            return;
        }
        let a_path = join(&dir, &a);
        let b_path = join(&dir, &b);
        steps.push(plain(
            Op::Symlink {
                target: b.clone(),
                path: a_path.clone(),
            },
            Effect::AddNode(a_path, Kind::Symlink),
        ));
        steps.push(plain(
            Op::Symlink {
                target: a,
                path: b_path.clone(),
            },
            Effect::AddNode(b_path, Kind::Symlink),
        ));
    }

    /// Relative symlinks whose target climbs (via `..`) enough levels to
    /// exit the private root in the *virtual* view -- a documented shim gap
    /// (see `docs/testing.md`). Only ever probed read-only (`Lstat`/
    /// `Readlink`, which never follow the link), so this can never actually
    /// redirect a real syscall anywhere outside the sandbox.
    fn build_escaping_links(&mut self, steps: &mut Vec<GenStep>, dirs: &[Vec<u8>]) {
        for _ in 0..2 {
            let dir = self.pick(dirs).unwrap_or_else(|| self.tmp_root.clone());
            let name = self.fresh_name();
            let path = join(&dir, &name);
            // Comfortably more `..` than any plausible sandbox depth.
            let target = b"../../../../../../../../../etc".to_vec();
            steps.push(plain(
                Op::Symlink {
                    target,
                    path: path.clone(),
                },
                Effect::AddNode(path.clone(), Kind::Symlink),
            ));
            self.escaping_links.push(path);
        }
    }

    // -------------------------------------------------------------
    // Main fuzzing phase.
    // -------------------------------------------------------------

    pub fn next_op(&mut self) -> GenStep {
        let step = self.next_op_inner();
        // The whole-path limits (PATH_MAX, the shim's own, macOS's combined
        // link length) are not modelled; stay far below them by construction.
        debug_assert!(
            step.op.path_operands().iter().all(|p| p.len() < 512),
            "generated path too long: {:?}",
            step.op
        );
        step
    }

    fn next_op_inner(&mut self) -> GenStep {
        // Occasionally probe a read-only op directly on an escaping link
        // (never as a path *component* of anything else -- see module docs
        // and `docs/testing.md`).
        if self.allow_escaping && !self.escaping_links.is_empty() && self.rng.chance(1, 12) {
            let links = self.escaping_links.clone();
            let path = self.pick(&links).unwrap();
            // Neither follows the link, so the documented gap (resolving
            // *through* an escaping link) cannot apply: any mismatch here is
            // a real finding and is reported like every other op.
            return if self.rng.chance(1, 2) {
                plain(Op::Lstat { path }, Effect::None)
            } else {
                plain(Op::Readlink { path }, Effect::None)
            };
        }
        match self.rng.below(23) {
            0 => self.gen_mkdir(),
            1 => self.gen_open_create(),
            2 => self.gen_open_existing(),
            3 => self.gen_write(),
            4 => self.gen_read(),
            5 => self.gen_close(),
            6 => self.gen_symlink(),
            7 => self.gen_readlink(),
            8 => self.gen_rename(),
            9 => self.gen_unlink(),
            10 => self.gen_rmdir(),
            11 => self.gen_chdir(),
            12 => plain(Op::Getcwd, Effect::None),
            13 => self.gen_realpath(),
            14 => self.gen_stat(true),
            15 => self.gen_stat(false),
            16 => self.gen_opendir(),
            17 => self.gen_openat(),
            18 => self.gen_mkdirat(),
            19 => self.gen_unlinkat(),
            20 => self.gen_bind(),
            21 => self.gen_connect(),
            _ => self.gen_list(),
        }
    }

    fn gen_mkdir(&mut self) -> GenStep {
        let dir = self.any_dir();
        let name = self.biased_name();
        let canonical = join(&dir, &name);
        let path = self.spell_for_mutation(&canonical);
        plain(
            Op::Mkdir { path, mode: 0o755 },
            Effect::AddNode(canonical, Kind::Dir),
        )
    }

    fn gen_open_create(&mut self) -> GenStep {
        let dir = self.any_dir();
        let name = self.biased_name();
        let canonical = join(&dir, &name);
        let path = self.spell_for_trailing(&canonical);
        // `biased_name` may pick an existing sibling name: never let a
        // writable/creating open *follow* an escaping link (the real side
        // would refuse it as outside the sandbox, aborting the run).
        let escaping = self.escaping_links.contains(&canonical);
        let flags = OpenFlags {
            create: true,
            excl: self.rng.chance(1, 3),
            trunc: self.rng.chance(1, 4),
            write: true,
            nofollow: escaping,
            ..Default::default()
        };
        plain(Op::Open { path, flags }, Effect::CreateFile(canonical))
    }

    /// A non-creating `open` of something that already exists: a file (for
    /// later `Write`/`Read`), a directory, or -- with `O_NOFOLLOW` -- a
    /// symlink (to exercise `ELOOP`).
    fn gen_open_existing(&mut self) -> GenStep {
        let target = self.any_existing();
        let is_symlink = self
            .nodes
            .iter()
            .any(|n| n.path == target && n.kind == Kind::Symlink);
        // An escaping link is never followed (see `exec.rs`'s open guard).
        let escaping = self.escaping_links.contains(&target);
        let spelled = self.spell(&target);
        let flags = OpenFlags {
            write: !is_symlink && self.rng.chance(1, 2),
            nofollow: escaping || (is_symlink && self.rng.chance(2, 3)),
            ..Default::default()
        };
        plain(
            Op::Open {
                path: spelled,
                flags,
            },
            Effect::RegisterFileFd,
        )
    }

    /// Any open fd, file or directory: read/write on a directory fd is
    /// real behavior (EISDIR / EBADF) the model must match.
    fn pick_any_fd(&mut self) -> Option<u32> {
        let n = self.open_files.len() + self.open_dirs.len();
        if n == 0 {
            return None;
        }
        let i = self.rng.below(n as u64) as usize;
        Some(if i < self.open_files.len() {
            self.open_files[i]
        } else {
            self.open_dirs[i - self.open_files.len()]
        })
    }

    fn gen_write(&mut self) -> GenStep {
        let Some(fd) = self.pick_any_fd() else {
            return plain(Op::Getcwd, Effect::None);
        };
        let len = self.rng.below(12) as usize;
        let data: Vec<u8> = (0..len).map(|i| b'a' + (i as u8 % 26)).collect();
        plain(Op::Write { fd, data }, Effect::None)
    }

    fn gen_read(&mut self) -> GenStep {
        let Some(fd) = self.pick_any_fd() else {
            return plain(Op::Getcwd, Effect::None);
        };
        plain(
            Op::Read {
                fd,
                len: self.rng.below(24) as usize,
            },
            Effect::None,
        )
    }

    fn gen_close(&mut self) -> GenStep {
        let mut all: Vec<u32> = self
            .open_files
            .iter()
            .chain(self.open_dirs.iter())
            .copied()
            .collect();
        if all.is_empty() {
            return plain(Op::Getcwd, Effect::None);
        }
        let fd = all.remove(self.rng.below(all.len() as u64) as usize);
        plain(Op::CloseFd { fd }, Effect::Close(fd))
    }

    fn gen_symlink(&mut self) -> GenStep {
        let dir = self.any_dir();
        let name = self.biased_name();
        let canonical = join(&dir, &name);
        let path = self.spell_for_trailing(&canonical);
        // Relative target (a bare or `../`-through-sibling spelling of an
        // existing node in the same directory) most of the time; an
        // absolute (possibly re-spelled) target otherwise.
        let target = if self.rng.chance(3, 4) {
            let candidates = self
                .direct_children_of(&dir, Kind::File)
                .into_iter()
                .chain(self.direct_children_of(&dir, Kind::Dir))
                .collect::<Vec<_>>();
            match self.pick(&candidates) {
                Some(t) => basename(&t),
                None => self.fresh_name(),
            }
        } else {
            let existing = self.any_followable();
            self.spell_absolute(&existing)
        };
        plain(
            Op::Symlink { target, path },
            Effect::AddNode(canonical, Kind::Symlink),
        )
    }

    fn gen_readlink(&mut self) -> GenStep {
        let links = self.nodes_of_kind(Kind::Symlink);
        let path = self.pick(&links).unwrap_or_else(|| self.tmp_root.clone());
        let path = self.spell(&path);
        plain(Op::Readlink { path }, Effect::None)
    }

    fn gen_rename(&mut self) -> GenStep {
        let from = self.any_existing();
        if from == self.tmp_root || from == self.var_root || self.moves_escaping_link(&from) {
            return plain(Op::Getcwd, Effect::None);
        }
        let to_dir = self.any_dir();
        // Renaming a directory into (a subdirectory of) itself is where the
        // model's `EINVAL` and the real kernel's own errno for the same
        // case (macOS gave `ENOTDIR` when this was checked by hand) can
        // part ways -- a narrow, pre-existing `world_fsmodel` simplification
        // outside this driver's owned files, avoided here by construction
        // rather than chased as a "finding" (see the fuzz_driver report).
        let mut from_prefix = from.clone();
        from_prefix.push(b'/');
        if to_dir == from || to_dir.starts_with(&from_prefix) {
            return plain(Op::Getcwd, Effect::None);
        }
        let to_name = self.biased_name();
        let to = join(&to_dir, &to_name);
        // Replacing (via rename onto it) the cwd or a directory a tracked fd
        // still holds open unlinks it from under that handle: a real kernel
        // then fails `getcwd`/further `*at` creates (ENOENT). The model now
        // tracks detached directories, but the generator still avoids the
        // case by construction (dead-directory behaviour is replay-only,
        // covered by the `seed-dead-cwd` corpus; see `open_dir_paths`).
        if to == self.cwd || self.open_dir_paths.values().any(|p| p == &to) {
            return plain(Op::Getcwd, Effect::None);
        }
        let from_spelled = self.spell_for_trailing(&from);
        let to_spelled = self.spell_for_trailing(&to);
        plain(
            Op::Rename {
                from: from_spelled,
                to: to_spelled,
            },
            Effect::Rename(from, to),
        )
    }

    fn gen_unlink(&mut self) -> GenStep {
        let candidates: Vec<Vec<u8>> = self
            .nodes_of_kind(Kind::File)
            .into_iter()
            .chain(self.nodes_of_kind(Kind::Symlink))
            .collect();
        let Some(path) = self.pick(&candidates) else {
            return plain(Op::Getcwd, Effect::None);
        };
        let spelled = self.spell_for_trailing(&path);
        plain(Op::Unlink { path: spelled }, Effect::Remove(path))
    }

    fn gen_rmdir(&mut self) -> GenStep {
        let dirs: Vec<Vec<u8>> = self
            .nodes_of_kind(Kind::Dir)
            .into_iter()
            .filter(|d| {
                self.direct_children_of(d, Kind::Dir).is_empty()
                    && self.direct_children_of(d, Kind::File).is_empty()
                    && self.direct_children_of(d, Kind::Symlink).is_empty()
                    // Never the cwd, and never a directory some tracked
                    // fd still has open: dead-directory behaviour is
                    // modelled (detached nodes) but kept replay-only, so
                    // the generator avoids it (see `open_dir_paths`'s doc
                    // comment).
                    && d != &self.cwd
                    && !self.open_dir_paths.values().any(|p| p == d)
                    // The two sandbox roots are permanent anchors that
                    // `any_dir`/`gen_chdir`/... offer unconditionally.
                    && d != &self.tmp_root
                    && d != &self.var_root
            })
            .collect();
        let Some(path) = self.pick(&dirs) else {
            return plain(Op::Getcwd, Effect::None);
        };
        let spelled = self.spell_for_trailing(&path);
        plain(Op::Rmdir { path: spelled }, Effect::Remove(path))
    }

    fn gen_chdir(&mut self) -> GenStep {
        let mut dirs = self.nodes_of_kind(Kind::Dir);
        dirs.push(self.tmp_root.clone());
        dirs.push(self.var_root.clone());
        let target = self.pick(&dirs).unwrap_or_else(|| self.tmp_root.clone());
        let spelled = self.spell(&target);
        plain(Op::Chdir { path: spelled }, Effect::Chdir(target))
    }

    fn gen_realpath(&mut self) -> GenStep {
        let target = self.any_followable();
        let spelled = self.spell(&target);
        plain(Op::Realpath { path: spelled }, Effect::None)
    }

    fn gen_stat(&mut self, follow: bool) -> GenStep {
        let target = if follow {
            self.any_followable()
        } else {
            self.any_existing()
        };
        let spelled = self.spell(&target);
        if follow {
            plain(Op::Stat { path: spelled }, Effect::None)
        } else {
            plain(Op::Lstat { path: spelled }, Effect::None)
        }
    }

    fn gen_opendir(&mut self) -> GenStep {
        let mut dirs = self.nodes_of_kind(Kind::Dir);
        dirs.push(self.tmp_root.clone());
        dirs.push(self.var_root.clone());
        let target = self.pick(&dirs).unwrap_or_else(|| self.tmp_root.clone());
        let spelled = self.spell(&target);
        plain(Op::OpenDir { path: spelled }, Effect::RegisterDirFd(target))
    }

    /// A dirfd operand: usually a currently-open directory fd, sometimes a
    /// clearly-unused number (to exercise `EBADF`). `OpenAt`/`MkdirAt`/
    /// `UnlinkAt` are only ever generated with a *relative*, single- or
    /// multi-component name (never absolute): with an absolute path the
    /// dirfd argument is ignored by a real kernel regardless of validity,
    /// which `world_fsmodel::Model::resolve` does not mirror for an invalid
    /// `Start::Fd` (see `exec.rs`'s module docs) -- avoided here rather than
    /// chased as a "finding".
    fn pick_dirfd(&mut self) -> u32 {
        if !self.open_dirs.is_empty() && self.rng.chance(3, 4) {
            self.open_dirs[self.rng.below(self.open_dirs.len() as u64) as usize]
        } else {
            9000 + self.rng.below(1000) as u32
        }
    }

    fn gen_openat(&mut self) -> GenStep {
        let dirfd = self.pick_dirfd();
        let name = self.fresh_name();
        let flags = OpenFlags {
            create: true,
            write: true,
            excl: self.rng.chance(1, 3),
            ..Default::default()
        };
        // A garbage `dirfd` just exercises `EBADF` (`record` no-ops on any
        // nonzero errno); a real one gives us a fresh open file fd to reuse
        // for later `Write`/`Read`/`CloseFd` -- the target directory itself
        // is not tracked as a node.
        plain(
            Op::OpenAt {
                dirfd,
                path: name,
                flags,
            },
            Effect::RegisterFileFd,
        )
    }

    fn gen_mkdirat(&mut self) -> GenStep {
        let dirfd = self.pick_dirfd();
        let name = self.fresh_name();
        let effect = if let Some(dir) = self.dir_for_open_fd(dirfd) {
            Effect::AddNode(join(&dir, &name), Kind::Dir)
        } else {
            Effect::None
        };
        plain(Op::MkdirAt { dirfd, path: name }, effect)
    }

    fn gen_unlinkat(&mut self) -> GenStep {
        let dirfd = self.pick_dirfd();
        let rmdir = self.rng.chance(1, 2);
        let dir = self.dir_for_open_fd(dirfd);
        let name = if let Some(dir) = &dir {
            let mut cands = if rmdir {
                // Never the cwd or a directory a tracked fd still has open:
                // the same replay-only case `gen_rmdir` avoids.
                let mut c = self.direct_children_of(dir, Kind::Dir);
                c.retain(|p| p != &self.cwd && !self.open_dir_paths.values().any(|o| o == p));
                c
            } else {
                let mut c = self.direct_children_of(dir, Kind::File);
                c.extend(self.direct_children_of(dir, Kind::Symlink));
                c
            };
            cands.sort();
            self.pick(&cands)
                .map(|p| basename(&p))
                .unwrap_or_else(|| self.fresh_name())
        } else {
            self.fresh_name()
        };
        let effect = match &dir {
            Some(dir) => {
                let target = join(dir, &name);
                // A fresh-name fallback can still collide with the cwd or an
                // open directory; never rmdir those.
                if rmdir
                    && (target == self.cwd || self.open_dir_paths.values().any(|o| o == &target))
                {
                    return plain(Op::Getcwd, Effect::None);
                }
                Effect::Remove(target)
            }
            None => Effect::None,
        };
        plain(
            Op::UnlinkAt {
                dirfd,
                path: name,
                rmdir,
            },
            effect,
        )
    }

    /// The canonical directory this *model* fd number is tracked as, if we
    /// know it: we only remember this for fds opened via `OpenDir`
    /// (`gen_opendir`), keyed by the directory chosen at that time.
    fn dir_for_open_fd(&self, fd: u32) -> Option<Vec<u8>> {
        self.open_dir_paths.get(&fd).cloned()
    }

    /// A name definitely not already a child of `dir` (checked against both
    /// `self.nodes` and `self.sockets`; `self.sockets` entries have no
    /// `Node`, so `nodes_of_kind`-based checks alone would miss them). Bind
    /// is the one op that always needs a name this fresh: unlike
    /// `Open{O_CREAT|O_EXCL}` (well-defined to never follow a final
    /// symlink), a real `bind` colliding with an *existing* looping
    /// symlink can surface `ELOOP` where the model's simpler "does this
    /// name already exist" check gives `EADDRINUSE` -- a real, but
    /// uninteresting (not shim-related) macOS VFS quirk, avoided here by
    /// construction rather than chased as a finding.
    fn fresh_unused_name(&mut self, dir: &[u8]) -> Vec<u8> {
        for _ in 0..10 {
            let name = self.fresh_name();
            let candidate = join(dir, &name);
            if !self.nodes.iter().any(|n| n.path == candidate) && !self.sockets.contains(&candidate)
            {
                return name;
            }
        }
        self.fresh_name()
    }

    fn gen_bind(&mut self) -> GenStep {
        let dir = self.any_dir();
        let name = self.fresh_unused_name(&dir);
        let canonical = join(&dir, &name);
        let path = self.spell_for_trailing(&canonical);
        // A trailing slash makes bind fail (nothing is created), and a
        // later connect must only target a path that was really bound.
        if !path.ends_with(b"/") {
            self.sockets.push(canonical);
        }
        plain(Op::Bind { path }, Effect::None)
    }

    fn gen_connect(&mut self) -> GenStep {
        // Only connect to a path this run has itself successfully bound, so
        // the common case succeeds. `Model::do_connect` does model the
        // failure errnos (ENOENT, ENOTDIR, ELOOP, ENOTSOCK/ECONNREFUSED,
        // ENAMETOOLONG); they are covered by the seed corpus rather than
        // generated here.
        let Some(path) = self.pick(&self.sockets.clone()) else {
            return plain(Op::Getcwd, Effect::None);
        };
        let spelled = self.spell_for_mutation(&path);
        plain(Op::Connect { path: spelled }, Effect::None)
    }

    fn gen_list(&mut self) -> GenStep {
        let mut dirs = self.nodes_of_kind(Kind::Dir);
        dirs.push(self.tmp_root.clone());
        dirs.push(self.var_root.clone());
        let target = self.pick(&dirs).unwrap_or_else(|| self.tmp_root.clone());
        let spelled = self.spell(&target);
        plain(Op::List { path: spelled }, Effect::None)
    }

    // -------------------------------------------------------------
    // Bookkeeping.
    // -------------------------------------------------------------

    /// Update bookkeeping after seeing the model's own outcome for the op
    /// that produced `effect`. `ret`/`errno` are the model's `Outcome`
    /// fields.
    pub fn record(&mut self, effect: &Effect, ret: i64, errno: i32) {
        if errno != 0 {
            return;
        }
        match effect {
            Effect::None => {}
            Effect::AddNode(path, kind) => self.nodes.push(Node {
                path: path.clone(),
                kind: *kind,
            }),
            Effect::CreateFile(path) => {
                self.nodes.push(Node {
                    path: path.clone(),
                    kind: Kind::File,
                });
                self.open_files.push(ret as u32);
            }
            Effect::Remove(path) => {
                self.nodes.retain(|n| &n.path != path);
                self.sockets.retain(|s| s != path);
                self.escaping_links.retain(|l| l != path);
            }
            Effect::Rename(from, to) => {
                // A rename moves `from`'s whole subtree (and, if `to`
                // already existed as an empty dir, replaces it): every
                // tracked node/socket path under `from` -- not just an
                // exact match -- must move with it, or later ops built from
                // stale bookkeeping would target a path that no longer
                // exists (a `Connect` there would legitimately be `ENOENT`
                // on both sides, but the generator wants it to succeed).
                let mut to_prefix = to.clone();
                to_prefix.push(b'/');
                self.nodes
                    .retain(|n| &n.path != to && !n.path.starts_with(&to_prefix));
                // A rename onto an existing non-directory (e.g. a socket
                // `bind`'s own dirent) replaces it in the model too: a
                // socket entry sitting exactly at `to` must be retired here
                // just like a `self.nodes` one, or a later `Connect` would
                // target a path this run no longer actually controls.
                self.sockets.retain(|s| s != to);
                // `gen_rename` never moves an escaping link, but one can be
                // replaced by a rename onto it.
                self.escaping_links.retain(|l| l != to);
                for n in &mut self.nodes {
                    rebase(&mut n.path, from, to);
                }
                for s in &mut self.sockets {
                    rebase(s, from, to);
                }
                for p in self.open_dir_paths.values_mut() {
                    rebase(p, from, to);
                }
                rebase(&mut self.cwd, from, to);
            }
            Effect::Chdir(path) => self.cwd = path.clone(),
            Effect::RegisterDirFd(path) => {
                self.open_dirs.push(ret as u32);
                self.open_dir_paths.insert(ret as u32, path.clone());
            }
            Effect::RegisterFileFd => self.open_files.push(ret as u32),
            Effect::Close(fd) => {
                self.open_dirs.retain(|&f| f != *fd);
                self.open_files.retain(|&f| f != *fd);
                self.open_dir_paths.remove(fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Pure generator-state tests: nothing here touches the filesystem.
    use super::*;

    const FD: u32 = 5;

    fn generator() -> Generator {
        let mut g = Generator::new(1, "fz-00000000", false, false);
        let root = g.tmp_root.clone();
        g.record(&Effect::RegisterDirFd(root), FD as i64, 0);
        g
    }

    fn has_node(g: &Generator, path: &[u8]) -> bool {
        g.nodes.iter().any(|n| n.path == path)
    }

    /// Generates `mkdirat` steps until one targets `FD`, records it, and
    /// returns the created name.
    fn make_child(g: &mut Generator) -> Vec<u8> {
        for _ in 0..200 {
            let step = g.gen_mkdirat();
            if let (Op::MkdirAt { dirfd, path }, Effect::AddNode(p, Kind::Dir)) =
                (&step.op, &step.on_success)
            {
                assert_eq!(*dirfd, FD);
                assert_eq!(p, &join(&g.tmp_root, path));
                let name = path.clone();
                g.record(&step.on_success, 0, 0);
                return name;
            }
        }
        panic!("gen_mkdirat never targeted the tracked dirfd");
    }

    #[test]
    fn mkdirat_through_tracked_dirfd_records_child() {
        let mut g = generator();
        let name = make_child(&mut g);
        assert!(has_node(&g, &join(&g.tmp_root, &name)));
    }

    #[test]
    fn unlinkat_selects_existing_child() {
        let mut g = generator();
        let name = make_child(&mut g);
        let want = join(&g.tmp_root, &name);
        for _ in 0..500 {
            let step = g.gen_unlinkat();
            if let (
                Op::UnlinkAt {
                    dirfd: FD,
                    rmdir: true,
                    path,
                },
                Effect::Remove(p),
            ) = (&step.op, &step.on_success)
                && path == &name
            {
                assert_eq!(p, &want);
                return;
            }
        }
        panic!("gen_unlinkat never selected the existing child");
    }

    #[test]
    fn unlinkat_never_rmdirs_cwd_or_open_dir() {
        for use_cwd in [false, true] {
            let mut g = generator();
            let a = join(&g.tmp_root, b"a");
            g.record(&Effect::AddNode(a.clone(), Kind::Dir), 0, 0);
            if use_cwd {
                g.record(&Effect::Chdir(a.clone()), 0, 0);
            } else {
                g.record(&Effect::RegisterDirFd(a.clone()), 6, 0);
            }
            for _ in 0..2000 {
                let step = g.gen_unlinkat();
                if let (
                    Op::UnlinkAt {
                        dirfd: FD,
                        rmdir: true,
                        ..
                    },
                    Effect::Remove(p),
                ) = (&step.op, &step.on_success)
                {
                    assert_ne!(p, &a, "rmdir of a protected directory");
                }
            }
        }
    }

    #[test]
    fn remove_retires_socket_and_escaping_link() {
        let mut g = generator();
        let s = join(&g.tmp_root, b"sock");
        let l = join(&g.tmp_root, b"lnk");
        g.sockets.push(s.clone());
        g.escaping_links.push(l.clone());
        g.record(&Effect::Remove(s), 0, 0);
        g.record(&Effect::Remove(l), 0, 0);
        assert!(g.sockets.is_empty());
        assert!(g.escaping_links.is_empty());
    }

    /// A generator whose only non-root nodes are a directory holding an
    /// escaping link and one plain file.
    fn with_escaping_link() -> (Generator, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut g = Generator::new(1, "fz-00000000", true, true);
        let dir = join(&g.tmp_root, b"d");
        let link = join(&dir, b"esc");
        let file = join(&g.tmp_root, b"f");
        g.record(&Effect::AddNode(dir.clone(), Kind::Dir), 0, 0);
        g.record(&Effect::AddNode(link.clone(), Kind::Symlink), 0, 0);
        g.record(&Effect::AddNode(file.clone(), Kind::File), 0, 0);
        g.escaping_links.push(link.clone());
        (g, dir, link, file)
    }

    /// Only `lstat`/`readlink` (never following) may name an escaping link:
    /// `stat`, `realpath` and a new absolute symlink target never do.
    #[test]
    fn following_ops_never_target_an_escaping_link() {
        let (mut g, _, link, _) = with_escaping_link();
        let names_link = |p: &[u8]| p.ends_with(b"/esc") || p == b"d/esc" || p == b"esc";
        let mut lstat_hit = false;
        for _ in 0..2000 {
            match g.gen_stat(true).op {
                Op::Stat { path } => assert!(!names_link(&path), "stat {path:?}"),
                op => panic!("{op:?}"),
            }
            match g.gen_realpath().op {
                Op::Realpath { path } => assert!(!names_link(&path), "realpath {path:?}"),
                op => panic!("{op:?}"),
            }
            if let Op::Symlink { target, .. } = g.gen_symlink().op {
                assert!(!names_link(&target), "symlink target {target:?}");
            }
            if let Op::Lstat { path } = g.gen_stat(false).op {
                lstat_hit |= names_link(&path);
            }
        }
        assert!(lstat_hit, "lstat should still probe {link:?}");
    }

    /// Neither an escaping link nor a directory above it is ever renamed,
    /// and a rename onto one retires it.
    #[test]
    fn escaping_links_never_move() {
        let (mut g, dir, link, file) = with_escaping_link();
        assert!(g.moves_escaping_link(&link));
        assert!(g.moves_escaping_link(&dir));
        assert!(!g.moves_escaping_link(&file));
        assert!(!g.moves_escaping_link(&join(&g.tmp_root, b"d2")));
        for _ in 0..2000 {
            if let Effect::Rename(from, _) = g.gen_rename().on_success {
                assert!(from != link && from != dir, "renamed {from:?}");
            }
        }
        g.record(&Effect::Rename(file, link), 0, 0);
        assert!(g.escaping_links.is_empty());
    }
}
