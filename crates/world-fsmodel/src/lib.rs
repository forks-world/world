//! A pure, in-memory filesystem model used as a differential oracle for
//! `world-tmp-path` (the macOS shim's lexical mapper) and for
//! `world-runtime`'s Linux bind-mount isolation.
//!
//! The model keeps a single physical tree of nodes (directories, files,
//! symlinks, sockets). Two *views* interpret that tree differently:
//!
//! - [`View::Physical`]: the real host filesystem, exactly as it exists on
//!   disk. `root/tmp` (the workspace's private temp root) is just an
//!   ordinary directory; the host's own `/tmp` (or `/private/tmp` on macOS)
//!   is a separate, [`NodeKind::Opaque`] directory.
//! - [`View::Virtual`]: what the managed process sees. The host temp
//!   directory node is replaced ("mounted over") by the workspace's private
//!   `root/tmp` node, and `..` from the top of that private tree lands on
//!   the *mountpoint's* parent (e.g. `/private` on macOS, `/` on Linux), not
//!   on `root/tmp`'s own physical parent.
//!
//! Nothing here talks to the real kernel; [`Model::apply`] and
//! [`Model::resolve`] are a from-scratch reimplementation of the relevant
//! POSIX semantics, checked against the real kernel only by
//! `tests/conformance.rs` (macOS locally, Linux in CI).
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;

/// An opaque handle into a [`Model`]'s node arena.
pub type NodeId = usize;
/// A POSIX errno value (e.g. `libc::ENOENT`).
pub type Errno = i32;

/// Longest a single path component may be, on every profile.
const NAME_MAX: usize = 255;

/// Which real backend a [`Model`] stands in for; only affects `PATH_MAX`,
/// `MAXSYMLINKS`, and where a fresh model's built-in temp directories live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// The macOS `silo-bind` interposer: `/tmp` and `/var` are themselves
    /// symlinks to `/private/tmp` and `/private/var`.
    MacShim { root: Vec<u8> },
    /// Linux kernel isolation: `root/tmp` and `root/var/tmp` are bind-mounted
    /// directly over `/tmp` and `/var/tmp`.
    LinuxMount { root: Vec<u8> },
}

/// Which interpretation of the tree a lookup uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// What the managed process sees: the host temp root is replaced by the
    /// workspace's private one.
    Virtual,
    /// The real, physical host filesystem.
    Physical,
}

/// What a node in the model represents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Dir,
    File(Vec<u8>),
    Symlink(Vec<u8>),
    Socket,
    /// Exists but its contents are unmodelled (e.g. the host's real `/tmp`):
    /// treated exactly like `Dir` for resolution, but signals that an
    /// unlisted child is merely *unknown*, not necessarily absent.
    Opaque,
}

/// Where a [`Model::resolve`] lookup begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// The model's current working directory.
    Cwd,
    /// A directory previously opened as a model file descriptor.
    Fd(u32),
    /// The filesystem root.
    Root,
}

/// The starting point for an `*at` call: an absolute path ignores `dirfd`
/// entirely (the kernel never looks at it), a relative one starts at it.
pub fn at_start(dirfd: u32, path: &[u8]) -> Start {
    if path.starts_with(b"/") {
        Start::Root
    } else {
        Start::Fd(dirfd)
    }
}

/// The result of [`Model::apply`]ing an [`Op`]: `ret`/`errno` mirror a libc
/// call's return value and `errno`; `data` carries any bytes the call would
/// also produce (a `read`'s bytes, a `readlink`'s target, `getcwd`'s string,
/// `realpath`'s string, `List`'s sorted, NUL-joined names, or a one-byte stat
/// "kind code": 0=dir, 1=file, 2=symlink, 3=socket, 4=opaque).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ret: i64,
    pub errno: Errno,
    pub data: Vec<u8>,
}

/// `open`/`openat` flags relevant to the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenFlags {
    pub create: bool,
    pub excl: bool,
    pub trunc: bool,
    pub write: bool,
    pub directory: bool,
    pub nofollow: bool,
}

/// A single filesystem operation, as a fuzz driver would generate and
/// [`Model::apply`] would execute it. Paths are raw bytes (not necessarily
/// UTF-8); file descriptors are small, model-assigned handles, never real
/// OS descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Mkdir {
        path: Vec<u8>,
        mode: u32,
    },
    Open {
        path: Vec<u8>,
        flags: OpenFlags,
    },
    Write {
        fd: u32,
        data: Vec<u8>,
    },
    Read {
        fd: u32,
        len: usize,
    },
    Symlink {
        target: Vec<u8>,
        path: Vec<u8>,
    },
    Readlink {
        path: Vec<u8>,
    },
    Rename {
        from: Vec<u8>,
        to: Vec<u8>,
    },
    Unlink {
        path: Vec<u8>,
    },
    Rmdir {
        path: Vec<u8>,
    },
    Chdir {
        path: Vec<u8>,
    },
    Getcwd,
    Realpath {
        path: Vec<u8>,
    },
    Stat {
        path: Vec<u8>,
    },
    Lstat {
        path: Vec<u8>,
    },
    OpenDir {
        path: Vec<u8>,
    },
    OpenAt {
        dirfd: u32,
        path: Vec<u8>,
        flags: OpenFlags,
    },
    MkdirAt {
        dirfd: u32,
        path: Vec<u8>,
    },
    UnlinkAt {
        dirfd: u32,
        path: Vec<u8>,
        rmdir: bool,
    },
    Bind {
        path: Vec<u8>,
    },
    Connect {
        path: Vec<u8>,
    },
    MkstempAdopt {
        name: Vec<u8>,
    },
    List {
        path: Vec<u8>,
    },
    CloseFd {
        fd: u32,
    },
}

/// One entry of a [`Model::tree`] listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Slash-separated, relative to the `at` path passed to `tree`.
    pub path: Vec<u8>,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File { len: usize },
    Symlink { target: Vec<u8> },
    Socket,
}

struct Node {
    kind: NodeKind,
    /// The node's real, physical parent (`None` only for the root).
    parent: Option<NodeId>,
    /// Physical children, keyed by (possibly case-folded) name.
    children: BTreeMap<Vec<u8>, NodeId>,
    /// Virtual-view only: when resolution reaches this node, continue at
    /// this node instead (this node is a *mountpoint*).
    mounted_by: Option<NodeId>,
    /// Virtual-view only: this node is a mount *target*; `..` from here (not
    /// from a node further down) uses this instead of `parent`.
    virtual_parent: Option<NodeId>,
    /// The name this node is reported under when reached via
    /// `virtual_parent` (its mountpoint's own name).
    mount_name: Option<Vec<u8>>,
}

enum FdEntry {
    File {
        node: NodeId,
        pos: usize,
        write: bool,
    },
    Dir {
        node: NodeId,
    },
}

/// The in-memory filesystem model itself.
pub struct Model {
    nodes: Vec<Node>,
    profile: Profile,
    root_node: NodeId,
    case_insensitive: bool,
    cwd: NodeId,
    fds: BTreeMap<u32, FdEntry>,
    next_fd: u32,
}

fn errout(e: Errno) -> Outcome {
    Outcome {
        ret: -1,
        errno: e,
        data: Vec::new(),
    }
}
fn okout(ret: i64) -> Outcome {
    Outcome {
        ret,
        errno: 0,
        data: Vec::new(),
    }
}
fn dataout(ret: i64, data: Vec<u8>) -> Outcome {
    Outcome {
        ret,
        errno: 0,
        data,
    }
}

/// Split an absolute or relative path into (parent-directory-text, final
/// component, trailing). The parent text is `"."` for a bare relative name
/// and `"/"` for a top-level absolute one. `trailing` is true when the path
/// ended in one or more `/` (all of them are trimmed, so `"a//"` names `a`,
/// never the empty string); each mutating operation decides what that means
/// (see `Model::trail_mac` and the `do_*` functions). `Err(ENOENT)` for `""`
/// (POSIX: an empty pathname never names anything), `Err(EINVAL)` for a path
/// of only slashes (nothing to name).
fn parent_and_name(path: &[u8]) -> Result<(&[u8], &[u8], bool), Errno> {
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
        Some(0) => Ok((b"/", &trimmed[1..], trailing)),
        Some(i) => Ok((&trimmed[..i], &trimmed[i + 1..], trailing)),
        None => Ok((b".", trimmed, trailing)),
    }
}

/// What a trailing-slash final component resolves to on macOS, where the
/// kernel looks the name up *following* a symlink and requiring a directory
/// (measured: `rmdir ld/` and `rename ld/ y` act on the link's target).
enum Trail {
    /// The name does not exist.
    Missing,
    /// A dangling symlink chain; a create-type operation lands at the chain's
    /// end (parent node, missing name).
    Dangling(NodeId, Vec<u8>),
    /// Exists (possibly through a link) but is not a directory.
    NonDir,
    /// Exists (possibly through a link) and is this directory.
    Dir(NodeId),
}

impl Model {
    /// A fresh model for `profile`: a host skeleton (`/`, temp root
    /// aliases/mounts) plus the workspace's own private temp directories.
    pub fn new(profile: Profile) -> Model {
        let mut m = Model {
            nodes: vec![Node {
                kind: NodeKind::Dir,
                parent: None,
                children: BTreeMap::new(),
                mounted_by: None,
                virtual_parent: None,
                mount_name: None,
            }],
            profile: profile.clone(),
            root_node: 0,
            case_insensitive: false,
            cwd: 0,
            fds: BTreeMap::new(),
            next_fd: 3,
        };
        let root = m.root_node;
        match &profile {
            Profile::MacShim { root: root_path } => {
                let private = m.mkchild(root, b"private", NodeKind::Dir);
                let var = m.mkchild(private, b"var", NodeKind::Dir);
                let priv_tmp = m.mkchild(private, b"tmp", NodeKind::Opaque);
                let priv_var_tmp = m.mkchild(var, b"tmp", NodeKind::Opaque);
                m.mkchild(root, b"tmp", NodeKind::Symlink(b"private/tmp".to_vec()));
                m.mkchild(root, b"var", NodeKind::Symlink(b"private/var".to_vec()));
                let anchor = m.mkdir_p(View::Physical, root_path, NodeKind::Dir);
                let root_tmp = m.mkchild(anchor, b"tmp", NodeKind::Dir);
                let root_var = m.mkchild(anchor, b"var", NodeKind::Dir);
                let root_var_tmp = m.mkchild(root_var, b"tmp", NodeKind::Dir);
                m.nodes[priv_tmp].mounted_by = Some(root_tmp);
                m.nodes[root_tmp].virtual_parent = Some(private);
                m.nodes[root_tmp].mount_name = Some(b"tmp".to_vec());
                m.nodes[priv_var_tmp].mounted_by = Some(root_var_tmp);
                m.nodes[root_var_tmp].virtual_parent = Some(var);
                m.nodes[root_var_tmp].mount_name = Some(b"tmp".to_vec());
            }
            Profile::LinuxMount { root: root_path } => {
                let tmp = m.mkchild(root, b"tmp", NodeKind::Dir);
                let var = m.mkchild(root, b"var", NodeKind::Dir);
                let var_tmp = m.mkchild(var, b"tmp", NodeKind::Dir);
                let anchor = m.mkdir_p(View::Physical, root_path, NodeKind::Dir);
                let root_tmp = m.mkchild(anchor, b"tmp", NodeKind::Dir);
                let root_var_scaffold = m.mkchild(anchor, b"var", NodeKind::Dir);
                let root_var_tmp = m.mkchild(root_var_scaffold, b"tmp", NodeKind::Dir);
                m.nodes[tmp].mounted_by = Some(root_tmp);
                m.nodes[root_tmp].virtual_parent = Some(root);
                m.nodes[root_tmp].mount_name = Some(b"tmp".to_vec());
                m.nodes[var_tmp].mounted_by = Some(root_var_tmp);
                m.nodes[root_var_tmp].virtual_parent = Some(var);
                m.nodes[root_var_tmp].mount_name = Some(b"tmp".to_vec());
            }
        }
        m.cwd = m.root_node;
        m
    }

    /// A model with no temp-root scaffolding at all: just `/` plus the
    /// ancestors of `anchor`, for exercising the resolver/`apply` against a
    /// real, plain subtree (see `tests/conformance.rs`). Not part of the
    /// frozen fuzz-driver API.
    pub fn new_plain(anchor: &[u8]) -> Model {
        let mut m = Model {
            nodes: vec![Node {
                kind: NodeKind::Dir,
                parent: None,
                children: BTreeMap::new(),
                mounted_by: None,
                virtual_parent: None,
                mount_name: None,
            }],
            profile: Profile::LinuxMount {
                root: anchor.to_vec(),
            },
            root_node: 0,
            case_insensitive: false,
            cwd: 0,
            fds: BTreeMap::new(),
            next_fd: 3,
        };
        let anchor_node = m.mkdir_p(View::Physical, anchor, NodeKind::Dir);
        m.cwd = anchor_node;
        m
    }

    /// mkdir -p (in the given view), creating any missing ancestors as
    /// [`NodeKind::Dir`]. Returns the leaf node.
    pub fn add_fixture_dir(&mut self, view: View, path: &[u8]) -> NodeId {
        self.mkdir_p(view, path, NodeKind::Dir)
    }

    /// Like [`Model::add_fixture_dir`], but creates (or overwrites) a file
    /// with `contents`.
    pub fn add_fixture_file(&mut self, view: View, path: &[u8], contents: Vec<u8>) -> NodeId {
        let (dir, name, _) = parent_and_name(path).expect("valid fixture path");
        let parent = self.mkdir_p(view, dir, NodeKind::Dir);
        self.set_child(parent, name, NodeKind::File(contents))
    }

    /// Like [`Model::add_fixture_dir`], but creates (or overwrites) a
    /// symlink with the given (unresolved, possibly dangling) target text.
    pub fn add_fixture_symlink(&mut self, view: View, path: &[u8], target: Vec<u8>) -> NodeId {
        let (dir, name, _) = parent_and_name(path).expect("valid fixture path");
        let parent = self.mkdir_p(view, dir, NodeKind::Dir);
        self.set_child(parent, name, NodeKind::Symlink(target))
    }

    /// Like [`Model::add_fixture_dir`], but creates (or overwrites) a socket
    /// node (as `bind` would).
    pub fn add_fixture_socket(&mut self, view: View, path: &[u8]) -> NodeId {
        let (dir, name, _) = parent_and_name(path).expect("valid fixture path");
        let parent = self.mkdir_p(view, dir, NodeKind::Dir);
        self.set_child(parent, name, NodeKind::Socket)
    }

    /// Ensure the *ancestors* of `path` exist (as [`NodeKind::Opaque`]
    /// directories), without creating `path` itself. Useful to give a
    /// symlink target somewhere plausible to dangle towards without fully
    /// modelling it.
    pub fn add_opaque_ancestors(&mut self, path: &[u8]) {
        if let Ok((dir, _name, _)) = parent_and_name(path) {
            self.mkdir_p(View::Physical, dir, NodeKind::Opaque);
        }
    }

    /// Enable case-insensitive (case-preserving-on-lookup) name comparison.
    /// Off by default; generators using this should stick to lowercase ASCII
    /// names so folding is lossless.
    pub fn set_case_insensitive(&mut self, on: bool) {
        self.case_insensitive = on;
    }

    /// Kernel-like path resolution: walk `path` component by component from
    /// `start`, in `view`. `follow_last` controls whether the final
    /// component is dereferenced if it is a symlink. A trailing slash forces
    /// dereferencing of a final symlink and requires a directory, as path
    /// *lookups* do on both kernels; the mutating operations (unlink, rmdir,
    /// rename, symlink, bind, mkdir, `open(O_CREAT)`) do not go through this
    /// rule and instead decide per operation and per profile (see the
    /// `do_*` functions).
    pub fn resolve(
        &self,
        view: View,
        start: Start,
        path: &[u8],
        follow_last: bool,
    ) -> Result<NodeId, Errno> {
        self.resolve_impl(view, start, path, follow_last, None)
    }

    /// [`Model::resolve`] that also records, in walk order, every symlink
    /// node followed (nested ones and those followed before an error
    /// included) in `crossed`.
    pub fn resolve_traced(
        &self,
        view: View,
        start: Start,
        path: &[u8],
        follow_last: bool,
        crossed: &mut Vec<NodeId>,
    ) -> Result<NodeId, Errno> {
        self.resolve_impl(view, start, path, follow_last, Some(crossed))
    }

    fn resolve_impl(
        &self,
        view: View,
        start: Start,
        path: &[u8],
        follow_last: bool,
        trace: Option<&mut Vec<NodeId>>,
    ) -> Result<NodeId, Errno> {
        let mut link_count = 0u32;
        let start_node = match start {
            Start::Root => self.root_node,
            Start::Cwd => self.cwd,
            Start::Fd(fd) => self.fd_dir(fd)?,
        };
        self.resolve_inner(view, start_node, path, follow_last, &mut link_count, trace)
    }

    fn resolve_inner(
        &self,
        view: View,
        mut cur: NodeId,
        path: &[u8],
        follow_last: bool,
        link_count: &mut u32,
        mut trace: Option<&mut Vec<NodeId>>,
    ) -> Result<NodeId, Errno> {
        if path.len() >= self.path_max() {
            return Err(libc::ENAMETOOLONG);
        }
        // POSIX: an empty pathname is ENOENT (Linux and macOS alike; only
        // `AT_EMPTY_PATH` / `*at` with an fd gives it a meaning, which this
        // model does not offer).
        if path.is_empty() {
            return Err(libc::ENOENT);
        }
        if path[0] == b'/' {
            cur = self.root_node;
        }
        cur = self.enter(view, cur);
        let trailing_slash = path.len() > 1 && path.ends_with(b"/");
        let real: Vec<&[u8]> = path
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
            .collect();
        if real.is_empty() {
            return Ok(cur);
        }
        let last_idx = real.len() - 1;
        for (i, &comp) in real.iter().enumerate() {
            let is_last = i == last_idx;
            if comp == b".." {
                cur = self.enter(view, self.node_parent(view, cur));
                continue;
            }
            if comp.len() > NAME_MAX {
                return Err(libc::ENAMETOOLONG);
            }
            match &self.nodes[cur].kind {
                NodeKind::Dir | NodeKind::Opaque => {}
                _ => return Err(libc::ENOTDIR),
            }
            let key = self.key(comp);
            let child = match self.nodes[cur].children.get(&key) {
                Some(&id) => id,
                None => return Err(libc::ENOENT),
            };
            let mut target = child;
            let must_follow = !is_last || follow_last || trailing_slash;
            if must_follow && matches!(self.nodes[target].kind, NodeKind::Symlink(_)) {
                target =
                    self.follow_symlink(view, cur, target, link_count, trace.as_deref_mut())?;
            }
            if !is_last || trailing_slash {
                match &self.nodes[target].kind {
                    NodeKind::Dir | NodeKind::Opaque => {}
                    _ => return Err(libc::ENOTDIR),
                }
            }
            cur = self.enter(view, target);
        }
        Ok(cur)
    }

    fn follow_symlink(
        &self,
        view: View,
        dir: NodeId,
        link_node: NodeId,
        link_count: &mut u32,
        mut trace: Option<&mut Vec<NodeId>>,
    ) -> Result<NodeId, Errno> {
        let target = match &self.nodes[link_node].kind {
            NodeKind::Symlink(t) => t.clone(),
            _ => return Ok(link_node),
        };
        if let Some(t) = trace.as_deref_mut() {
            t.push(link_node);
        }
        *link_count += 1;
        if *link_count > self.max_symlinks() {
            return Err(libc::ELOOP);
        }
        if target.is_empty() {
            return Err(libc::ENOENT);
        }
        let base = if target[0] == b'/' {
            self.root_node
        } else {
            dir
        };
        self.resolve_inner(view, base, &target, true, link_count, trace)
    }

    /// The canonical path of `node` in `view`: physical realpath-like for
    /// [`View::Physical`], the host name the managed process would see for
    /// [`View::Virtual`].
    pub fn full_path(&self, view: View, node: NodeId) -> Vec<u8> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut cur = node;
        while let Some((name, parent)) = self.node_name_and_parent(view, cur) {
            parts.push(name);
            cur = parent;
        }
        parts.reverse();
        let mut out = Vec::new();
        for p in parts {
            out.push(b'/');
            out.extend_from_slice(&p);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        out
    }

    fn node_name_and_parent(&self, view: View, node: NodeId) -> Option<(Vec<u8>, NodeId)> {
        if view == View::Virtual
            && let Some(vp) = self.nodes[node].virtual_parent
        {
            return Some((self.nodes[node].mount_name.clone().unwrap_or_default(), vp));
        }
        let parent = self.nodes[node].parent?;
        let name = self.nodes[parent]
            .children
            .iter()
            .find(|&(_, &id)| id == node)
            .map(|(k, _)| k.clone())?;
        Some((name, parent))
    }

    /// Sorted recursive listing of everything below `at` (resolved in
    /// `view`), relative to it.
    pub fn tree(&self, view: View, at: &[u8]) -> Vec<Entry> {
        let mut out = Vec::new();
        let Ok(start) = self.resolve(view, Start::Root, at, true) else {
            return out;
        };
        self.walk(view, start, &[], &mut out);
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    fn walk(&self, view: View, node: NodeId, prefix: &[u8], out: &mut Vec<Entry>) {
        // Collect first: `enter` may need `&self.nodes` while we mutate `prefix`.
        let children: Vec<(Vec<u8>, NodeId)> = self.nodes[node]
            .children
            .iter()
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        for (name, child) in children {
            let child = self.enter(view, child);
            let mut path = prefix.to_vec();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(&name);
            match &self.nodes[child].kind {
                NodeKind::Dir | NodeKind::Opaque => {
                    out.push(Entry {
                        path: path.clone(),
                        kind: EntryKind::Dir,
                    });
                    self.walk(view, child, &path, out);
                }
                NodeKind::File(data) => {
                    out.push(Entry {
                        path,
                        kind: EntryKind::File { len: data.len() },
                    });
                }
                NodeKind::Symlink(t) => {
                    out.push(Entry {
                        path,
                        kind: EntryKind::Symlink { target: t.clone() },
                    });
                }
                NodeKind::Socket => {
                    out.push(Entry {
                        path,
                        kind: EntryKind::Socket,
                    });
                }
            }
        }
    }

    /// [`Model::tree`], rendered as a small hand-written JSON array (no
    /// serde dependency): `[{"path":"...","kind":"dir"|{"file":{"len":N}}|
    /// {"symlink":{"target":"..."}}|"socket"}, ...]`. Bytes outside
    /// `[0x20,0x7e]` (and `"`/`\`) are escaped as `\u00XX`; this is a debug
    /// aid, not intended to round-trip through a JSON parser for arbitrary
    /// non-ASCII path bytes.
    pub fn tree_json(&self, view: View, at: &[u8]) -> String {
        let entries = self.tree(view, at);
        let mut s = String::from("[");
        for (i, e) in entries.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"path\":\"");
            json_escape(&e.path, &mut s);
            s.push_str("\",\"kind\":");
            match &e.kind {
                EntryKind::Dir => s.push_str("\"dir\""),
                EntryKind::File { len } => {
                    s.push_str(&format!("{{\"file\":{{\"len\":{len}}}}}"));
                }
                EntryKind::Symlink { target } => {
                    s.push_str("{\"symlink\":{\"target\":\"");
                    json_escape(target, &mut s);
                    s.push_str("\"}}");
                }
                EntryKind::Socket => s.push_str("\"socket\""),
            }
            s.push('}');
        }
        s.push(']');
        s
    }

    /// Apply a single operation with `View::Virtual` (managed-process)
    /// semantics, mutating the model and returning the POSIX-style result.
    pub fn apply(&mut self, op: &Op) -> Outcome {
        match op {
            Op::Mkdir { path, mode: _ } => self.do_mkdir(Start::Cwd, path),
            Op::MkdirAt { dirfd, path } => self.do_mkdir(at_start(*dirfd, path), path),
            Op::Open { path, flags } => self.do_open(Start::Cwd, path, flags),
            Op::OpenAt { dirfd, path, flags } => self.do_open(at_start(*dirfd, path), path, flags),
            Op::OpenDir { path } => self.do_opendir(Start::Cwd, path),
            Op::Write { fd, data } => self.do_write(*fd, data),
            Op::Read { fd, len } => self.do_read(*fd, *len),
            Op::Symlink { target, path } => self.do_symlink(target, path),
            Op::Readlink { path } => self.do_readlink(path),
            Op::Rename { from, to } => self.do_rename(from, to),
            Op::Unlink { path } => self.unlink_impl(Start::Cwd, path, false),
            Op::Rmdir { path } => self.unlink_impl(Start::Cwd, path, true),
            Op::UnlinkAt { dirfd, path, rmdir } => {
                self.unlink_impl(at_start(*dirfd, path), path, *rmdir)
            }
            Op::Chdir { path } => self.do_chdir(path),
            Op::Getcwd => self.do_getcwd(),
            Op::Realpath { path } => self.do_realpath(path),
            Op::Stat { path } => self.do_stat(path, true),
            Op::Lstat { path } => self.do_stat(path, false),
            Op::Bind { path } => self.do_bind(path),
            Op::Connect { path } => self.do_connect(path),
            Op::MkstempAdopt { name } => self.do_mkstemp(name),
            Op::List { path } => self.do_list(path),
            Op::CloseFd { fd } => self.do_close(*fd),
        }
    }

    fn is_mac(&self) -> bool {
        matches!(self.profile, Profile::MacShim { .. })
    }

    /// macOS trailing-slash lookup of `key` in `parent` (see [`Trail`]).
    /// `path` is the original path text, used to find where a dangling
    /// symlink chain would create its target.
    fn trail_mac(
        &self,
        start: Start,
        parent: NodeId,
        key: &[u8],
        path: &[u8],
    ) -> Result<Trail, Errno> {
        let Some(&id) = self.nodes[parent].children.get(key) else {
            return Ok(Trail::Missing);
        };
        let target = if matches!(self.nodes[id].kind, NodeKind::Symlink(_)) {
            let mut link_count = 0u32;
            match self.follow_symlink(View::Virtual, parent, id, &mut link_count, None) {
                Ok(t) => t,
                Err(libc::ENOENT) => {
                    let (p, n, _) = self.resolve_for_create(start, path)?;
                    return Ok(Trail::Dangling(p, n));
                }
                Err(e) => return Err(e),
            }
        } else {
            id
        };
        Ok(match self.nodes[target].kind {
            NodeKind::Dir | NodeKind::Opaque => Trail::Dir(target),
            _ => Trail::NonDir,
        })
    }

    /// The (parent, map key) that owns directory `t`, for operations that
    /// act on a symlink's target. `EBUSY` for a mount point or an orphan.
    fn owner_of(&self, t: NodeId) -> Result<(NodeId, Vec<u8>), Errno> {
        if self.nodes[t].virtual_parent.is_some() || self.nodes[t].mounted_by.is_some() {
            return Err(libc::EBUSY);
        }
        let p = self.nodes[t]
            .parent
            .filter(|&p| p != t)
            .ok_or(libc::EBUSY)?;
        self.nodes[p]
            .children
            .iter()
            .find(|(_, c)| **c == t)
            .map(|(k, _)| (p, k.clone()))
            .ok_or(libc::EBUSY)
    }

    /// errno for a trailing-slash `symlink`/`bind` whose final component
    /// `key` exists or not. Linux never follows the name: it is
    /// `exists_errno` if present, else ENOENT (the slash demands a
    /// directory that a create cannot make). macOS resolves it through
    /// links first: missing or dangling is ENOENT, a non-directory is
    /// ENOTDIR, a directory is `exists_errno`.
    fn trailing_create_errno(
        &self,
        start: Start,
        parent: NodeId,
        key: &[u8],
        path: &[u8],
        exists_errno: Errno,
    ) -> Errno {
        if !self.is_mac() {
            return if self.nodes[parent].children.contains_key(key) {
                exists_errno
            } else {
                libc::ENOENT
            };
        }
        match self.trail_mac(start, parent, key, path) {
            Err(e) => e,
            Ok(Trail::Missing | Trail::Dangling(..)) => libc::ENOENT,
            Ok(Trail::NonDir) => libc::ENOTDIR,
            Ok(Trail::Dir(_)) => exists_errno,
        }
    }

    fn do_mkdir(&mut self, start: Start, path: &[u8]) -> Outcome {
        match self.resolve_parent(start, path) {
            Ok((parent, name, trailing)) => {
                match &self.nodes[parent].kind {
                    NodeKind::Dir | NodeKind::Opaque => {}
                    _ => return errout(libc::ENOTDIR),
                }
                let key = self.key(&name);
                // Linux ignores a trailing slash for mkdir. macOS resolves
                // the name through links: an existing directory is EEXIST,
                // an existing non-directory ENOTDIR, and a dangling link
                // creates its target.
                let (parent, key) = if trailing && self.is_mac() {
                    match self.trail_mac(start, parent, &key, path) {
                        Err(e) => return errout(e),
                        Ok(Trail::Missing) => (parent, key),
                        Ok(Trail::Dangling(p, n)) => (p, self.key(&n)),
                        Ok(Trail::Dir(_)) => return errout(libc::EEXIST),
                        Ok(Trail::NonDir) => return errout(libc::ENOTDIR),
                    }
                } else {
                    (parent, key)
                };
                if self.nodes[parent].children.contains_key(&key) {
                    return errout(libc::EEXIST);
                }
                let id = self.push_node(NodeKind::Dir, Some(parent));
                self.nodes[parent].children.insert(key, id);
                okout(0)
            }
            Err(e) => errout(e),
        }
    }

    fn do_open(&mut self, start: Start, path: &[u8], flags: &OpenFlags) -> Outcome {
        if flags.create && path.len() > 1 && path.ends_with(b"/") {
            // O_CREAT with a trailing slash never creates. Linux: EISDIR
            // once the parent resolves. macOS looks the name up through
            // links: missing/dangling ENOENT, non-directory ENOTDIR, a
            // directory EISDIR (EEXIST with O_EXCL).
            match self.resolve_parent(start, path) {
                Ok((parent, name, _)) => {
                    match &self.nodes[parent].kind {
                        NodeKind::Dir | NodeKind::Opaque => {}
                        _ => return errout(libc::ENOTDIR),
                    }
                    if !self.is_mac() {
                        return errout(libc::EISDIR);
                    }
                    let key = self.key(&name);
                    return errout(match self.trail_mac(start, parent, &key, path) {
                        Err(e) => e,
                        Ok(Trail::Missing | Trail::Dangling(..)) => libc::ENOENT,
                        Ok(Trail::NonDir) => libc::ENOTDIR,
                        Ok(Trail::Dir(_)) if flags.excl => libc::EEXIST,
                        Ok(Trail::Dir(_)) => libc::EISDIR,
                    });
                }
                // A path naming "." or ".." falls through to plain lookup.
                Err(libc::EINVAL) => {}
                Err(e) => return errout(e),
            }
        }
        if flags.create && flags.excl {
            // POSIX: with O_CREAT|O_EXCL, existence is judged on the literal
            // final component (as `lstat` would see it) -- a symlink there
            // is EEXIST regardless of whether it dangles or even loops, and
            // is never dereferenced.
            return match self.resolve_parent(start, path) {
                Ok((parent, name, _)) => {
                    match &self.nodes[parent].kind {
                        NodeKind::Dir | NodeKind::Opaque => {}
                        _ => return errout(libc::ENOTDIR),
                    }
                    let key = self.key(&name);
                    if self.nodes[parent].children.contains_key(&key) {
                        return errout(libc::EEXIST);
                    }
                    if flags.directory {
                        return errout(libc::ENOTDIR);
                    }
                    let id = self.push_node(NodeKind::File(Vec::new()), Some(parent));
                    self.nodes[parent].children.insert(key, id);
                    let fd = self.alloc_fd(FdEntry::File {
                        node: id,
                        pos: 0,
                        write: flags.write,
                    });
                    okout(fd as i64)
                }
                Err(e) => errout(e),
            };
        }
        let lookup_follow = !flags.nofollow;
        match self.resolve(View::Virtual, start, path, lookup_follow) {
            Ok(node) => match &self.nodes[node].kind {
                NodeKind::Dir | NodeKind::Opaque => {
                    if flags.write {
                        return errout(libc::EISDIR);
                    }
                    let fd = self.alloc_fd(FdEntry::Dir { node });
                    okout(fd as i64)
                }
                NodeKind::Symlink(_) => errout(libc::ELOOP),
                // open(2) on a socket node: Linux ENXIO, macOS EOPNOTSUPP.
                NodeKind::Socket => errout(if self.is_mac() {
                    libc::EOPNOTSUPP
                } else {
                    libc::ENXIO
                }),
                NodeKind::File(_) => {
                    if flags.directory {
                        return errout(libc::ENOTDIR);
                    }
                    if flags.trunc
                        && flags.write
                        && let NodeKind::File(data) = &mut self.nodes[node].kind
                    {
                        data.clear();
                    }
                    let fd = self.alloc_fd(FdEntry::File {
                        node,
                        pos: 0,
                        write: flags.write,
                    });
                    okout(fd as i64)
                }
            },
            Err(libc::ENOENT) if flags.create => {
                if flags.directory {
                    return errout(libc::ENOTDIR);
                }
                // The full resolution above failed with ENOENT, which can
                // mean either an ordinary missing name/directory, or that
                // the literal final component exists but is a *dangling*
                // symlink: `open(..., O_CREAT)` without `O_EXCL` (already
                // handled above) follows such a link and creates the file at
                // its target instead of at the link's own name.
                match self.resolve_for_create(start, path) {
                    Ok((parent, name, _)) => {
                        match &self.nodes[parent].kind {
                            NodeKind::Dir | NodeKind::Opaque => {}
                            _ => return errout(libc::ENOTDIR),
                        }
                        let key = self.key(&name);
                        if self.nodes[parent].children.contains_key(&key) {
                            return errout(libc::EEXIST);
                        }
                        let id = self.push_node(NodeKind::File(Vec::new()), Some(parent));
                        self.nodes[parent].children.insert(key, id);
                        let fd = self.alloc_fd(FdEntry::File {
                            node: id,
                            pos: 0,
                            write: flags.write,
                        });
                        okout(fd as i64)
                    }
                    Err(e) => errout(e),
                }
            }
            Err(e) => errout(e),
        }
    }

    /// Like [`Model::resolve_parent`], but follows a chain of *dangling*
    /// symlinks at the final component instead of failing: `open(...,
    /// O_CREAT)` on a dangling symlink creates the file at the link's
    /// target, not at the link's own name.
    fn resolve_for_create(
        &self,
        start: Start,
        path: &[u8],
    ) -> Result<(NodeId, Vec<u8>, bool), Errno> {
        let trailing = path.len() > 1 && path.ends_with(b"/");
        let mut link_count = 0u32;
        let start_node = match start {
            Start::Root => self.root_node,
            Start::Cwd => self.cwd,
            Start::Fd(fd) => self.fd_dir(fd)?,
        };
        let (parent, name) = self.resolve_for_create_inner(start_node, path, &mut link_count)?;
        Ok((parent, name, trailing))
    }

    fn resolve_for_create_inner(
        &self,
        mut cur: NodeId,
        path: &[u8],
        link_count: &mut u32,
    ) -> Result<(NodeId, Vec<u8>), Errno> {
        let view = View::Virtual;
        if path.len() >= self.path_max() {
            return Err(libc::ENAMETOOLONG);
        }
        if path.is_empty() {
            return Err(libc::ENOENT);
        }
        if path[0] == b'/' {
            cur = self.root_node;
        }
        cur = self.enter(view, cur);
        let real: Vec<&[u8]> = path
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
            .collect();
        let Some((&last, init)) = real.split_last() else {
            // Path was "/", "." or similarly empty of real components: there
            // is no name left to create.
            return Err(libc::EEXIST);
        };
        for &comp in init {
            if comp == b".." {
                cur = self.enter(view, self.node_parent(view, cur));
                continue;
            }
            if comp.len() > NAME_MAX {
                return Err(libc::ENAMETOOLONG);
            }
            match &self.nodes[cur].kind {
                NodeKind::Dir | NodeKind::Opaque => {}
                _ => return Err(libc::ENOTDIR),
            }
            let key = self.key(comp);
            let mut target = match self.nodes[cur].children.get(&key) {
                Some(&id) => id,
                None => return Err(libc::ENOENT),
            };
            if matches!(self.nodes[target].kind, NodeKind::Symlink(_)) {
                target = self.follow_symlink(view, cur, target, link_count, None)?;
            }
            match &self.nodes[target].kind {
                NodeKind::Dir | NodeKind::Opaque => {}
                _ => return Err(libc::ENOTDIR),
            }
            cur = self.enter(view, target);
        }
        if last == b".." {
            // The name to create would be "..": never a legal target.
            return Err(libc::EINVAL);
        }
        if last.len() > NAME_MAX {
            return Err(libc::ENAMETOOLONG);
        }
        match &self.nodes[cur].kind {
            NodeKind::Dir | NodeKind::Opaque => {}
            _ => return Err(libc::ENOTDIR),
        }
        let key = self.key(last);
        match self.nodes[cur].children.get(&key).copied() {
            None => Ok((cur, last.to_vec())),
            Some(id) => match self.nodes[id].kind.clone() {
                NodeKind::Symlink(target) => {
                    *link_count += 1;
                    if *link_count > self.max_symlinks() {
                        return Err(libc::ELOOP);
                    }
                    if target.is_empty() {
                        return Err(libc::ENOENT);
                    }
                    let base = if target[0] == b'/' {
                        self.root_node
                    } else {
                        cur
                    };
                    self.resolve_for_create_inner(base, &target, link_count)
                }
                // Anything else existing at the literal name means the
                // caller's full resolve() should already have succeeded;
                // reaching this defensively means "already exists".
                _ => Err(libc::EEXIST),
            },
        }
    }

    fn do_opendir(&mut self, start: Start, path: &[u8]) -> Outcome {
        match self.resolve(View::Virtual, start, path, true) {
            Ok(node) => match &self.nodes[node].kind {
                NodeKind::Dir | NodeKind::Opaque => {
                    let fd = self.alloc_fd(FdEntry::Dir { node });
                    okout(fd as i64)
                }
                _ => errout(libc::ENOTDIR),
            },
            Err(e) => errout(e),
        }
    }

    fn do_write(&mut self, fd: u32, data: &[u8]) -> Outcome {
        let (node, pos) = match self.fds.get(&fd) {
            Some(&FdEntry::File {
                node,
                pos,
                write: true,
            }) => (node, pos),
            Some(_) => return errout(libc::EBADF),
            None => return errout(libc::EBADF),
        };
        let NodeKind::File(content) = &mut self.nodes[node].kind else {
            return errout(libc::EBADF);
        };
        if content.len() < pos {
            content.resize(pos, 0);
        }
        let end = pos + data.len();
        if content.len() < end {
            content.resize(end, 0);
        }
        content[pos..end].copy_from_slice(data);
        self.fds.insert(
            fd,
            FdEntry::File {
                node,
                pos: end,
                write: true,
            },
        );
        okout(data.len() as i64)
    }

    fn do_read(&mut self, fd: u32, len: usize) -> Outcome {
        let (node, pos, write) = match self.fds.get(&fd) {
            Some(&FdEntry::File { node, pos, write }) => (node, pos, write),
            Some(_) => return errout(libc::EBADF),
            None => return errout(libc::EBADF),
        };
        let NodeKind::File(content) = &self.nodes[node].kind else {
            return errout(libc::EBADF);
        };
        let start = pos.min(content.len());
        let end = start.saturating_add(len).min(content.len());
        let slice = content[start..end].to_vec();
        let n = slice.len();
        self.fds.insert(
            fd,
            FdEntry::File {
                node,
                pos: pos + n,
                write,
            },
        );
        dataout(n as i64, slice)
    }

    fn do_close(&mut self, fd: u32) -> Outcome {
        if self.fds.remove(&fd).is_some() {
            okout(0)
        } else {
            errout(libc::EBADF)
        }
    }

    fn do_symlink(&mut self, target: &[u8], path: &[u8]) -> Outcome {
        // Both kernels copy the target in first and reject one that does
        // not fit before looking at the link path at all.
        if target.len() >= self.path_max() {
            return errout(libc::ENAMETOOLONG);
        }
        match self.resolve_parent(Start::Cwd, path) {
            Ok((parent, name, trailing)) => {
                match &self.nodes[parent].kind {
                    NodeKind::Dir | NodeKind::Opaque => {}
                    _ => return errout(libc::ENOTDIR),
                }
                let key = self.key(&name);
                if trailing {
                    return errout(self.trailing_create_errno(
                        Start::Cwd,
                        parent,
                        &key,
                        path,
                        libc::EEXIST,
                    ));
                }
                if self.nodes[parent].children.contains_key(&key) {
                    return errout(libc::EEXIST);
                }
                let id = self.push_node(NodeKind::Symlink(target.to_vec()), Some(parent));
                self.nodes[parent].children.insert(key, id);
                okout(0)
            }
            Err(e) => errout(e),
        }
    }

    fn do_readlink(&self, path: &[u8]) -> Outcome {
        match self.resolve(View::Virtual, Start::Cwd, path, false) {
            Ok(node) => match &self.nodes[node].kind {
                NodeKind::Symlink(t) => dataout(t.len() as i64, t.clone()),
                _ => errout(libc::EINVAL),
            },
            Err(e) => errout(e),
        }
    }

    /// On Linux the private `/tmp` and `/var/tmp` are separate bind mounts:
    /// 0 = host filesystem, 1 = private tmp mount, 2 = private var/tmp mount.
    /// macOS redirects both into one filesystem, so everything is mount 0.
    fn mount_of(&self, mut node: NodeId) -> u8 {
        let Profile::LinuxMount { root } = &self.profile else {
            return 0;
        };
        let find = |suffix: &[u8]| {
            let mut path = root.clone();
            path.extend_from_slice(suffix);
            self.resolve(View::Physical, Start::Root, &path, true).ok()
        };
        let (tmp, var_tmp) = (find(b"/tmp"), find(b"/var/tmp"));
        loop {
            if Some(node) == tmp {
                return 1;
            }
            if Some(node) == var_tmp {
                return 2;
            }
            match self.nodes[node].parent {
                Some(parent) if parent != node => node = parent,
                _ => return 0,
            }
        }
    }

    fn do_rename(&mut self, from: &[u8], to: &[u8]) -> Outcome {
        let (from_parent, from_name, from_trailing) = match self.resolve_parent(Start::Cwd, from) {
            Ok(v) => v,
            Err(e) => return errout(e),
        };
        let mut from_parent = from_parent;
        let mut from_key = self.key(&from_name);
        let Some(&child) = self.nodes[from_parent].children.get(&from_key) else {
            return errout(libc::ENOENT);
        };
        let mut from_id = child;
        if from_trailing && self.is_mac() {
            // macOS follows a source symlink given with a trailing slash and
            // renames its target directory.
            match self.trail_mac(Start::Cwd, from_parent, &from_key, from) {
                Err(e) => return errout(e),
                Ok(Trail::Missing | Trail::Dangling(..)) => return errout(libc::ENOENT),
                Ok(Trail::NonDir) => return errout(libc::ENOTDIR),
                Ok(Trail::Dir(t)) => {
                    if t != child {
                        (from_parent, from_key) = match self.owner_of(t) {
                            Ok(v) => v,
                            Err(e) => return errout(e),
                        };
                        from_id = t;
                    }
                }
            }
        }
        let from_is_dir = matches!(self.nodes[from_id].kind, NodeKind::Dir | NodeKind::Opaque);
        let (mut to_parent, to_name, to_trailing) = match self.resolve_parent(Start::Cwd, to) {
            Ok(v) => v,
            Err(e) => return errout(e),
        };
        match &self.nodes[to_parent].kind {
            NodeKind::Dir | NodeKind::Opaque => {}
            _ => return errout(libc::ENOTDIR),
        }
        let mut to_key = self.key(&to_name);
        if to_trailing && self.is_mac() {
            // macOS resolves the destination through links too: a missing
            // (or dangling) name only accepts a directory source, a
            // non-directory is ENOTDIR, an existing directory (or a link to
            // one) is the replaced node itself.
            match self.trail_mac(Start::Cwd, to_parent, &to_key, to) {
                Err(e) => return errout(e),
                Ok(Trail::Missing) if from_is_dir => {}
                Ok(Trail::Dangling(p, n)) if from_is_dir => {
                    to_parent = p;
                    to_key = self.key(&n);
                }
                Ok(Trail::Missing | Trail::Dangling(..)) => return errout(libc::ENOENT),
                Ok(Trail::NonDir) => return errout(libc::ENOTDIR),
                Ok(Trail::Dir(t)) => {
                    if self.nodes[to_parent].children.get(&to_key) != Some(&t) {
                        (to_parent, to_key) = match self.owner_of(t) {
                            Ok(v) => v,
                            Err(e) => return errout(e),
                        };
                    }
                }
            }
        }
        // Linux checks mount boundaries before the other rename rules.
        if self.mount_of(from_parent) != self.mount_of(to_parent) {
            return errout(libc::EXDEV);
        }
        // Linux: a trailing slash on either side demands a directory source
        // (a symlink is never followed, so a link to a directory is not one).
        if !self.is_mac() && (from_trailing || to_trailing) && !from_is_dir {
            return errout(libc::ENOTDIR);
        }
        if to_parent == from_id || self.is_descendant(from_id, to_parent) {
            return errout(libc::EINVAL);
        }
        let existing = self.nodes[to_parent].children.get(&to_key).copied();
        if let Some(existing_id) = existing {
            if existing_id == from_id {
                return okout(0);
            }
            // Linux rejects a target that is an ancestor of the source
            // (lock_rename's trap) before any type check; macOS reports the
            // type mismatch instead.
            if matches!(self.profile, Profile::LinuxMount { .. })
                && self.is_descendant(existing_id, from_id)
            {
                return errout(libc::ENOTEMPTY);
            }
            let to_is_dir = matches!(
                self.nodes[existing_id].kind,
                NodeKind::Dir | NodeKind::Opaque
            );
            match (from_is_dir, to_is_dir) {
                (true, true) => {
                    if !self.nodes[existing_id].children.is_empty() {
                        return errout(libc::ENOTEMPTY);
                    }
                }
                (true, false) => return errout(libc::ENOTDIR),
                (false, true) => return errout(libc::EISDIR),
                (false, false) => {}
            }
        }
        self.nodes[from_parent].children.remove(&from_key);
        self.nodes[to_parent].children.insert(to_key, from_id);
        self.nodes[from_id].parent = Some(to_parent);
        okout(0)
    }

    fn unlink_impl(&mut self, start: Start, path: &[u8], is_rmdir: bool) -> Outcome {
        match self.resolve_parent(start, path) {
            Ok((parent, name, trailing)) => {
                let key = self.key(&name);
                let Some(&id) = self.nodes[parent].children.get(&key) else {
                    return errout(libc::ENOENT);
                };
                let (mut parent, mut key, mut id) = (parent, key, id);
                if trailing && self.is_mac() {
                    // macOS resolves the name through links first: anything
                    // but a directory is ENOTDIR (dangling: ENOENT); unlink
                    // of a directory is EPERM; rmdir of a link to a
                    // directory removes the target.
                    match self.trail_mac(start, parent, &key, path) {
                        Err(e) => return errout(e),
                        Ok(Trail::Missing | Trail::Dangling(..)) => return errout(libc::ENOENT),
                        Ok(Trail::NonDir) => return errout(libc::ENOTDIR),
                        Ok(Trail::Dir(_)) if !is_rmdir => return errout(libc::EPERM),
                        Ok(Trail::Dir(t)) => {
                            if t != id {
                                (parent, key) = match self.owner_of(t) {
                                    Ok(v) => v,
                                    Err(e) => return errout(e),
                                };
                                id = t;
                            }
                        }
                    }
                }
                let is_dir = matches!(self.nodes[id].kind, NodeKind::Dir | NodeKind::Opaque);
                if is_rmdir {
                    if !is_dir {
                        return errout(libc::ENOTDIR);
                    }
                    if !self.nodes[id].children.is_empty() {
                        return errout(libc::ENOTEMPTY);
                    }
                } else if is_dir {
                    return errout(libc::EISDIR);
                } else if trailing {
                    // Linux (fs/namei.c `slashes:`): a non-directory named
                    // with a trailing slash is ENOTDIR; a symlink is never
                    // followed. (macOS returned above.)
                    return errout(libc::ENOTDIR);
                }
                self.nodes[parent].children.remove(&key);
                okout(0)
            }
            Err(e) => errout(e),
        }
    }

    fn do_chdir(&mut self, path: &[u8]) -> Outcome {
        match self.resolve(View::Virtual, Start::Cwd, path, true) {
            Ok(node) => match &self.nodes[node].kind {
                NodeKind::Dir | NodeKind::Opaque => {
                    self.cwd = node;
                    okout(0)
                }
                _ => errout(libc::ENOTDIR),
            },
            Err(e) => errout(e),
        }
    }

    fn do_getcwd(&self) -> Outcome {
        let p = self.full_path(View::Virtual, self.cwd);
        dataout(p.len() as i64, p)
    }

    fn do_realpath(&self, path: &[u8]) -> Outcome {
        match self.resolve(View::Virtual, Start::Cwd, path, true) {
            Ok(node) => {
                let p = self.full_path(View::Virtual, node);
                dataout(p.len() as i64, p)
            }
            Err(e) => errout(e),
        }
    }

    fn do_stat(&self, path: &[u8], follow: bool) -> Outcome {
        match self.resolve(View::Virtual, Start::Cwd, path, follow) {
            Ok(node) => {
                let code: u8 = match self.nodes[node].kind {
                    NodeKind::Dir => 0,
                    NodeKind::File(_) => 1,
                    NodeKind::Symlink(_) => 2,
                    NodeKind::Socket => 3,
                    NodeKind::Opaque => 4,
                };
                dataout(0, vec![code])
            }
            Err(e) => errout(e),
        }
    }

    fn do_bind(&mut self, path: &[u8]) -> Outcome {
        match self.resolve_parent(Start::Cwd, path) {
            Ok((parent, name, trailing)) => {
                match &self.nodes[parent].kind {
                    NodeKind::Dir | NodeKind::Opaque => {}
                    _ => return errout(libc::ENOTDIR),
                }
                let key = self.key(&name);
                if trailing {
                    return errout(self.trailing_create_errno(
                        Start::Cwd,
                        parent,
                        &key,
                        path,
                        libc::EADDRINUSE,
                    ));
                }
                if self.nodes[parent].children.contains_key(&key) {
                    return errout(libc::EADDRINUSE);
                }
                let id = self.push_node(NodeKind::Socket, Some(parent));
                self.nodes[parent].children.insert(key, id);
                okout(0)
            }
            Err(e) => errout(e),
        }
    }

    fn do_connect(&mut self, path: &[u8]) -> Outcome {
        match self.resolve(View::Virtual, Start::Cwd, path, true) {
            Ok(node) => match &self.nodes[node].kind {
                NodeKind::Socket => okout(0),
                _ => errout(libc::ECONNREFUSED),
            },
            Err(_) => errout(libc::ECONNREFUSED),
        }
    }

    fn do_mkstemp(&mut self, name: &[u8]) -> Outcome {
        // The name is a single literal component of the cwd.
        if name.is_empty() || name.contains(&b'/') {
            return errout(libc::EINVAL);
        }
        match &self.nodes[self.cwd].kind {
            NodeKind::Dir | NodeKind::Opaque => {}
            _ => return errout(libc::ENOTDIR),
        }
        let key = self.key(name);
        if self.nodes[self.cwd].children.contains_key(&key) {
            return errout(libc::EEXIST);
        }
        let id = self.push_node(NodeKind::File(Vec::new()), Some(self.cwd));
        self.nodes[self.cwd].children.insert(key, id);
        let fd = self.alloc_fd(FdEntry::File {
            node: id,
            pos: 0,
            write: true,
        });
        okout(fd as i64)
    }

    fn do_list(&mut self, path: &[u8]) -> Outcome {
        match self.resolve(View::Virtual, Start::Cwd, path, true) {
            Ok(node) => match &self.nodes[node].kind {
                NodeKind::Dir | NodeKind::Opaque => {
                    let names: Vec<&Vec<u8>> = self.nodes[node].children.keys().collect();
                    let mut data = Vec::new();
                    for (i, n) in names.iter().enumerate() {
                        if i > 0 {
                            data.push(b'\n');
                        }
                        data.extend_from_slice(n);
                    }
                    dataout(names.len() as i64, data)
                }
                _ => errout(libc::ENOTDIR),
            },
            Err(e) => errout(e),
        }
    }

    // --- internal helpers ---

    fn is_descendant(&self, ancestor: NodeId, node: NodeId) -> bool {
        let mut cur = node;
        loop {
            if cur == ancestor {
                return true;
            }
            match self.nodes[cur].parent {
                Some(p) if p != cur => cur = p,
                _ => return false,
            }
        }
    }

    fn resolve_parent(&self, start: Start, path: &[u8]) -> Result<(NodeId, Vec<u8>, bool), Errno> {
        // The kernel sees the whole text, not just the directory part.
        if path.len() >= self.path_max() {
            return Err(libc::ENAMETOOLONG);
        }
        let (dir, name, trailing) = parent_and_name(path)?;
        if name == b"." || name == b".." {
            return Err(libc::EINVAL);
        }
        let parent = if dir == b"." {
            match start {
                Start::Cwd => self.cwd,
                Start::Fd(fd) => self.fd_dir(fd)?,
                Start::Root => self.root_node,
            }
        } else {
            self.resolve(View::Virtual, start, dir, true)?
        };
        Ok((parent, name.to_vec(), trailing))
    }

    fn fd_dir(&self, fd: u32) -> Result<NodeId, Errno> {
        match self.fds.get(&fd) {
            Some(FdEntry::Dir { node }) => Ok(*node),
            Some(FdEntry::File { .. }) => Err(libc::ENOTDIR),
            None => Err(libc::EBADF),
        }
    }

    fn alloc_fd(&mut self, entry: FdEntry) -> u32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, entry);
        fd
    }

    fn enter(&self, view: View, node: NodeId) -> NodeId {
        if view == View::Virtual
            && let Some(t) = self.nodes[node].mounted_by
        {
            return t;
        }
        node
    }

    fn node_parent(&self, view: View, node: NodeId) -> NodeId {
        if view == View::Virtual
            && let Some(vp) = self.nodes[node].virtual_parent
        {
            return vp;
        }
        self.nodes[node].parent.unwrap_or(node)
    }

    fn key(&self, name: &[u8]) -> Vec<u8> {
        if self.case_insensitive {
            name.to_ascii_lowercase()
        } else {
            name.to_vec()
        }
    }

    fn push_node(&mut self, kind: NodeKind, parent: Option<NodeId>) -> NodeId {
        self.nodes.push(Node {
            kind,
            parent,
            children: BTreeMap::new(),
            mounted_by: None,
            virtual_parent: None,
            mount_name: None,
        });
        self.nodes.len() - 1
    }

    /// Create-or-get a child of `parent` named `name`; does not touch
    /// `kind` if the child already exists.
    fn mkchild(&mut self, parent: NodeId, name: &[u8], kind: NodeKind) -> NodeId {
        let key = self.key(name);
        if let Some(&id) = self.nodes[parent].children.get(&key) {
            return id;
        }
        let id = self.push_node(kind, Some(parent));
        self.nodes[parent].children.insert(key, id);
        id
    }

    /// Create-or-overwrite a child of `parent` named `name` with `kind`.
    fn set_child(&mut self, parent: NodeId, name: &[u8], kind: NodeKind) -> NodeId {
        let key = self.key(name);
        if let Some(&id) = self.nodes[parent].children.get(&key) {
            self.nodes[id].kind = kind;
            return id;
        }
        let id = self.push_node(kind, Some(parent));
        self.nodes[parent].children.insert(key, id);
        id
    }

    /// mkdir -p `path` (in `view`), creating missing components with `kind`.
    /// Unlike a plain `mkchild` walk, this follows pre-existing symlinks and
    /// mount redirections along the way (e.g. macOS's built-in `/tmp` ->
    /// `private/tmp` -> the private root/tmp mount), so a fixture added
    /// under `/tmp/...` actually lands below the workspace's private temp
    /// root rather than as a bogus child of the `/tmp` symlink node itself.
    fn mkdir_p(&mut self, view: View, path: &[u8], kind: NodeKind) -> NodeId {
        let mut cur = self.enter(view, self.root_node);
        let comps: Vec<&[u8]> = path
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
            .collect();
        for comp in comps {
            if comp == b".." {
                cur = self.enter(view, self.node_parent(view, cur));
                continue;
            }
            let key = self.key(comp);
            let existing = self.nodes[cur].children.get(&key).copied();
            let child = match existing {
                Some(id) => match &self.nodes[id].kind {
                    NodeKind::Symlink(target) => {
                        let target = target.clone();
                        let base = if target.first() == Some(&b'/') {
                            self.root_node
                        } else {
                            cur
                        };
                        let mut link_count = 0u32;
                        self.resolve_inner(view, base, &target, true, &mut link_count, None)
                            .unwrap_or(id)
                    }
                    _ => id,
                },
                None => {
                    let id = self.push_node(kind.clone(), Some(cur));
                    self.nodes[cur].children.insert(key, id);
                    id
                }
            };
            cur = self.enter(view, child);
        }
        cur
    }

    fn max_symlinks(&self) -> u32 {
        match self.profile {
            Profile::MacShim { .. } => 32,
            Profile::LinuxMount { .. } => 40,
        }
    }

    fn path_max(&self) -> usize {
        match self.profile {
            Profile::MacShim { .. } => 1024,
            Profile::LinuxMount { .. } => 4096,
        }
    }
}

fn json_escape(bytes: &[u8], out: &mut String) {
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\u{b:04x}")),
        }
    }
}

/// A byte's worth of "plain" characters that survive [`escape`] unchanged.
fn is_plain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-')
}

/// Escape `bytes` for [`Op::to_line`]: anything outside `[A-Za-z0-9._/-]`
/// becomes `%XX` (hex).
fn escape(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if is_plain(b) {
            s.push(b as char);
        } else {
            s.push('%');
            s.push_str(&format!("{b:02x}"));
        }
    }
    s
}

/// Inverse of [`escape`].
fn unescape(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// [`unescape`] for a path-like operand: `None` if the decoded bytes contain
/// a NUL, which no real syscall can carry (the C string would be truncated).
fn unescape_path(s: &str) -> Option<Vec<u8>> {
    let v = unescape(s);
    if v.contains(&0) { None } else { Some(v) }
}

fn flag_char(v: bool) -> char {
    if v { '1' } else { '0' }
}

impl OpenFlags {
    fn to_flag_str(self) -> String {
        [
            self.create,
            self.excl,
            self.trunc,
            self.write,
            self.directory,
            self.nofollow,
        ]
        .into_iter()
        .map(flag_char)
        .collect()
    }

    fn from_flag_str(s: &str) -> Option<OpenFlags> {
        let chars: Vec<char> = s.chars().collect();
        if chars.len() != 6 {
            return None;
        }
        let f = |c: char| c == '1';
        Some(OpenFlags {
            create: f(chars[0]),
            excl: f(chars[1]),
            trunc: f(chars[2]),
            write: f(chars[3]),
            directory: f(chars[4]),
            nofollow: f(chars[5]),
        })
    }
}

impl Op {
    /// Every path-like byte string this op hands to a syscall (`write`
    /// data is not one).
    pub fn path_operands(&self) -> Vec<&[u8]> {
        match self {
            Op::Mkdir { path, .. }
            | Op::Open { path, .. }
            | Op::Readlink { path }
            | Op::Unlink { path }
            | Op::Rmdir { path }
            | Op::Chdir { path }
            | Op::Realpath { path }
            | Op::Stat { path }
            | Op::Lstat { path }
            | Op::OpenDir { path }
            | Op::OpenAt { path, .. }
            | Op::MkdirAt { path, .. }
            | Op::UnlinkAt { path, .. }
            | Op::Bind { path }
            | Op::Connect { path }
            | Op::List { path } => vec![path],
            Op::Symlink { target, path } => vec![target, path],
            Op::Rename { from, to } => vec![from, to],
            Op::MkstempAdopt { name } => vec![name],
            Op::Write { .. } | Op::Read { .. } | Op::Getcwd | Op::CloseFd { .. } => vec![],
        }
    }

    /// Render as a single stable, round-trippable text line (no embedded
    /// newlines: path/data bytes are hex-escaped).
    pub fn to_line(&self) -> String {
        match self {
            Op::Mkdir { path, mode } => format!("mkdir {} {mode:o}", escape(path)),
            Op::Open { path, flags } => format!("open {} {}", escape(path), flags.to_flag_str()),
            Op::Write { fd, data } => format!("write {fd} {}", escape(data)),
            Op::Read { fd, len } => format!("read {fd} {len}"),
            Op::Symlink { target, path } => {
                format!("symlink {} {}", escape(target), escape(path))
            }
            Op::Readlink { path } => format!("readlink {}", escape(path)),
            Op::Rename { from, to } => format!("rename {} {}", escape(from), escape(to)),
            Op::Unlink { path } => format!("unlink {}", escape(path)),
            Op::Rmdir { path } => format!("rmdir {}", escape(path)),
            Op::Chdir { path } => format!("chdir {}", escape(path)),
            Op::Getcwd => "getcwd".to_string(),
            Op::Realpath { path } => format!("realpath {}", escape(path)),
            Op::Stat { path } => format!("stat {}", escape(path)),
            Op::Lstat { path } => format!("lstat {}", escape(path)),
            Op::OpenDir { path } => format!("opendir {}", escape(path)),
            Op::OpenAt { dirfd, path, flags } => {
                format!("openat {dirfd} {} {}", escape(path), flags.to_flag_str())
            }
            Op::MkdirAt { dirfd, path } => format!("mkdirat {dirfd} {}", escape(path)),
            Op::UnlinkAt { dirfd, path, rmdir } => {
                format!("unlinkat {dirfd} {} {rmdir}", escape(path))
            }
            Op::Bind { path } => format!("bind {}", escape(path)),
            Op::Connect { path } => format!("connect {}", escape(path)),
            Op::MkstempAdopt { name } => format!("mkstemp {}", escape(name)),
            Op::List { path } => format!("list {}", escape(path)),
            Op::CloseFd { fd } => format!("close {fd}"),
        }
    }

    /// Parse a line produced by [`Op::to_line`]; `None` for anything else.
    pub fn from_line(s: &str) -> Option<Op> {
        let mut it = s.split(' ');
        let cmd = it.next()?;
        match cmd {
            "mkdir" => Some(Op::Mkdir {
                path: unescape_path(it.next()?)?,
                mode: u32::from_str_radix(it.next()?, 8).ok()?,
            }),
            "open" => Some(Op::Open {
                path: unescape_path(it.next()?)?,
                flags: OpenFlags::from_flag_str(it.next()?)?,
            }),
            "write" => Some(Op::Write {
                fd: it.next()?.parse().ok()?,
                data: unescape(it.next()?),
            }),
            "read" => Some(Op::Read {
                fd: it.next()?.parse().ok()?,
                len: it.next()?.parse().ok()?,
            }),
            "symlink" => Some(Op::Symlink {
                target: unescape_path(it.next()?)?,
                path: unescape_path(it.next()?)?,
            }),
            "readlink" => Some(Op::Readlink {
                path: unescape_path(it.next()?)?,
            }),
            "rename" => Some(Op::Rename {
                from: unescape_path(it.next()?)?,
                to: unescape_path(it.next()?)?,
            }),
            "unlink" => Some(Op::Unlink {
                path: unescape_path(it.next()?)?,
            }),
            "rmdir" => Some(Op::Rmdir {
                path: unescape_path(it.next()?)?,
            }),
            "chdir" => Some(Op::Chdir {
                path: unescape_path(it.next()?)?,
            }),
            "getcwd" => Some(Op::Getcwd),
            "realpath" => Some(Op::Realpath {
                path: unescape_path(it.next()?)?,
            }),
            "stat" => Some(Op::Stat {
                path: unescape_path(it.next()?)?,
            }),
            "lstat" => Some(Op::Lstat {
                path: unescape_path(it.next()?)?,
            }),
            "opendir" => Some(Op::OpenDir {
                path: unescape_path(it.next()?)?,
            }),
            "openat" => Some(Op::OpenAt {
                dirfd: it.next()?.parse().ok()?,
                path: unescape_path(it.next()?)?,
                flags: OpenFlags::from_flag_str(it.next()?)?,
            }),
            "mkdirat" => Some(Op::MkdirAt {
                dirfd: it.next()?.parse().ok()?,
                path: unescape_path(it.next()?)?,
            }),
            "unlinkat" => Some(Op::UnlinkAt {
                dirfd: it.next()?.parse().ok()?,
                path: unescape_path(it.next()?)?,
                rmdir: it.next()?.parse().ok()?,
            }),
            "bind" => Some(Op::Bind {
                path: unescape_path(it.next()?)?,
            }),
            "connect" => Some(Op::Connect {
                path: unescape_path(it.next()?)?,
            }),
            "mkstemp" => Some(Op::MkstempAdopt {
                name: unescape_path(it.next()?)?,
            }),
            "list" => Some(Op::List {
                path: unescape_path(it.next()?)?,
            }),
            "close" => Some(Op::CloseFd {
                fd: it.next()?.parse().ok()?,
            }),
            _ => None,
        }
    }
}

/// A small, dependency-free splitmix64 PRNG for deterministic test-case
/// generation.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform value in `0..n` (0 when `n == 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    /// True with probability `p_num / p_den`.
    pub fn chance(&mut self, p_num: u64, p_den: u64) -> bool {
        p_den != 0 && self.below(p_den) < p_num
    }
}

/// Whether `a` and `b` are the same errno, or a documented platform quirk
/// pair. Kept intentionally small: an unmatched divergence should usually be
/// investigated, not silently swallowed here.
pub fn errno_equiv(linux: bool, a: Errno, b: Errno) -> bool {
    if a == b {
        return true;
    }
    // ENOTEMPTY vs EEXIST: some historical Unixes (and BSD-derived kernels
    // in some paths) report EEXIST where Linux reports ENOTEMPTY for
    // rename()/rmdir() onto or of a non-empty directory.
    let pair = |x: i32, y: i32| (a == x && b == y) || (a == y && b == x);
    if pair(libc::ENOTEMPTY, libc::EEXIST) {
        return true;
    }
    // macOS/BSD: unlink(2) on a directory reports EPERM, not the Linux EISDIR.
    if !linux && pair(libc::EISDIR, libc::EPERM) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac_root() -> Vec<u8> {
        b"/Users/me/.world/tmp/127.77.0.1".to_vec()
    }
    fn linux_root() -> Vec<u8> {
        b"/home/me/.world/tmp/127.77.0.1".to_vec()
    }

    fn resolve_ok(m: &Model, view: View, path: &[u8]) -> NodeId {
        m.resolve(view, Start::Root, path, true)
            .unwrap_or_else(|e| panic!("resolve({path:?}) failed: {e}"))
    }

    #[test]
    fn resolve_traced_records_every_followed_symlink() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/d");
        let inner = m.add_fixture_symlink(View::Virtual, b"/tmp/inner", b"d".to_vec());
        let outer = m.add_fixture_symlink(View::Virtual, b"/tmp/outer", b"inner".to_vec());
        let dead = m.add_fixture_symlink(View::Virtual, b"/tmp/dead", b"nowhere".to_vec());
        let mut crossed = Vec::new();
        let n = m
            .resolve_traced(
                View::Virtual,
                Start::Root,
                b"/tmp/outer",
                true,
                &mut crossed,
            )
            .unwrap();
        assert_eq!(n, resolve_ok(&m, View::Virtual, b"/tmp/d"));
        // (`/tmp` itself is the first symlink followed on the macOS profile.)
        assert_eq!(crossed[crossed.len() - 2..], [outer, inner]);
        // Not followed when it is the final component and follow_last is off.
        crossed.clear();
        m.resolve_traced(
            View::Virtual,
            Start::Root,
            b"/tmp/outer",
            false,
            &mut crossed,
        )
        .unwrap();
        assert!(!crossed.contains(&outer));
        // A link followed before an error is still recorded.
        crossed.clear();
        let r = m.resolve_traced(View::Virtual, Start::Root, b"/tmp/dead", true, &mut crossed);
        assert_eq!(r, Err(libc::ENOENT));
        assert_eq!(crossed.last(), Some(&dead));
    }

    #[test]
    fn mac_tmp_alias_resolves_to_private_root_tmp() {
        let m = Model::new(Profile::MacShim { root: mac_root() });
        let via_tmp = resolve_ok(&m, View::Virtual, b"/tmp");
        let via_private = resolve_ok(&m, View::Virtual, b"/private/tmp");
        assert_eq!(via_tmp, via_private);
        // And it must be the private root/tmp node, not the host one.
        let physical_root_tmp =
            resolve_ok(&m, View::Physical, &[mac_root(), b"/tmp".to_vec()].concat());
        assert_eq!(via_tmp, physical_root_tmp);
    }

    #[test]
    fn mac_var_tmp_alias_resolves_to_private_root_var_tmp() {
        let m = Model::new(Profile::MacShim { root: mac_root() });
        let via_var_tmp = resolve_ok(&m, View::Virtual, b"/var/tmp");
        let physical = resolve_ok(
            &m,
            View::Physical,
            &[mac_root(), b"/var/tmp".to_vec()].concat(),
        );
        assert_eq!(via_var_tmp, physical);
    }

    #[test]
    fn mac_dotdot_at_private_root_goes_to_private_not_physical_parent() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/a");
        // cd into /tmp/a, then ".." twice: once back to the mounted /tmp
        // node, once more out of it -- which must land on /private, not on
        // root/tmp's own physical parent (root's ancestor directory).
        let node = resolve_ok(&m, View::Virtual, b"/tmp/a/../..");
        let private = resolve_ok(&m, View::Virtual, b"/private");
        assert_eq!(node, private);
    }

    #[test]
    fn linux_dotdot_at_tmp_mount_goes_to_slash() {
        let m = Model::new(Profile::LinuxMount { root: linux_root() });
        let node = resolve_ok(&m, View::Virtual, b"/tmp/..");
        let root = resolve_ok(&m, View::Virtual, b"/");
        assert_eq!(node, root);
    }

    /// POSIX: an empty pathname is ENOENT for every path-taking call, on
    /// both profiles (it used to resolve to the cwd / be EINVAL).
    #[test]
    fn empty_path_is_enoent() {
        for profile in [
            Profile::MacShim { root: mac_root() },
            Profile::LinuxMount { root: linux_root() },
        ] {
            let mut m = Model::new(profile);
            let e = |m: &mut Model, op: Op| m.apply(&op).errno;
            let empty = || Vec::new();
            let create = OpenFlags {
                create: true,
                write: true,
                ..Default::default()
            };
            let excl = OpenFlags {
                create: true,
                excl: true,
                write: true,
                ..Default::default()
            };
            let cases = vec![
                Op::Stat { path: empty() },
                Op::Lstat { path: empty() },
                Op::Chdir { path: empty() },
                Op::Realpath { path: empty() },
                Op::OpenDir { path: empty() },
                Op::List { path: empty() },
                Op::Readlink { path: empty() },
                Op::Open {
                    path: empty(),
                    flags: OpenFlags::default(),
                },
                Op::Open {
                    path: empty(),
                    flags: create,
                },
                Op::Open {
                    path: empty(),
                    flags: excl,
                },
                Op::Mkdir {
                    path: empty(),
                    mode: 0o755,
                },
                Op::Unlink { path: empty() },
                Op::Rename {
                    from: empty(),
                    to: b"/tmp/x".to_vec(),
                },
                Op::Symlink {
                    target: b"/tmp".to_vec(),
                    path: empty(),
                },
            ];
            for op in cases {
                let line = op.to_line();
                assert_eq!(e(&mut m, op), libc::ENOENT, "{line}");
            }
            // OpenAt with a real dirfd and an empty name.
            let out = m.apply(&Op::OpenDir {
                path: b"/tmp".to_vec(),
            });
            assert_eq!(out.errno, 0);
            let fd = out.ret as u32;
            let at = m.apply(&Op::OpenAt {
                dirfd: fd,
                path: Vec::new(),
                flags: OpenFlags::default(),
            });
            assert_eq!(at.errno, libc::ENOENT);
            // "/" is still EINVAL for a creating call.
            assert_eq!(
                e(
                    &mut m,
                    Op::Mkdir {
                        path: b"/".to_vec(),
                        mode: 0o755
                    }
                ),
                libc::EINVAL
            );
        }
    }

    #[test]
    fn mkstemp_rejects_empty_or_slashed_names() {
        let mut m = Model::new(Profile::LinuxMount { root: linux_root() });
        for name in [&b""[..], b"a/b", b"/x"] {
            let out = m.apply(&Op::MkstempAdopt {
                name: name.to_vec(),
            });
            assert_ne!(out.errno, 0, "{name:?}");
        }
        assert_eq!(
            m.apply(&Op::Chdir {
                path: b"/tmp".to_vec()
            })
            .errno,
            0
        );
        let ok = m.apply(&Op::MkstempAdopt {
            name: b"okname".to_vec(),
        });
        assert_eq!(ok.errno, 0);
    }

    #[test]
    fn linux_rename_across_private_mounts_is_exdev() {
        let mut m = Model::new(Profile::LinuxMount { root: linux_root() });
        for path in [&b"/tmp/a"[..], b"/var/tmp/d"] {
            let out = m.apply(&Op::Mkdir {
                path: path.to_vec(),
                mode: 0o755,
            });
            assert_eq!(out.errno, 0, "{}", String::from_utf8_lossy(path));
        }
        let cross = m.apply(&Op::Rename {
            from: b"/tmp/a".to_vec(),
            to: b"/var/tmp/d/a".to_vec(),
        });
        assert_eq!(cross.errno, libc::EXDEV);
        let within = m.apply(&Op::Rename {
            from: b"/tmp/a".to_vec(),
            to: b"/tmp/b".to_vec(),
        });
        assert_eq!(within.errno, 0);
    }

    #[test]
    fn rename_onto_an_ancestor_matches_each_kernel() {
        for (profile, expected) in [
            (Profile::LinuxMount { root: linux_root() }, libc::ENOTEMPTY),
            (Profile::MacShim { root: mac_root() }, libc::EISDIR),
        ] {
            let mut m = Model::new(profile);
            for op in [
                Op::Mkdir {
                    path: b"/tmp/vk".to_vec(),
                    mode: 0o755,
                },
                Op::Open {
                    path: b"/tmp/vk/u9".to_vec(),
                    flags: OpenFlags {
                        create: true,
                        write: true,
                        ..OpenFlags::default()
                    },
                },
            ] {
                assert_eq!(m.apply(&op).errno, 0);
            }
            let out = m.apply(&Op::Rename {
                from: b"/tmp/vk/u9".to_vec(),
                to: b"/tmp/vk".to_vec(),
            });
            assert_eq!(out.errno, expected);
        }
    }

    #[test]
    fn mac_rename_between_tmp_and_var_tmp_succeeds() {
        // The shim redirects both into one filesystem under the root.
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        for path in [&b"/tmp/a"[..], b"/var/tmp/d"] {
            let out = m.apply(&Op::Mkdir {
                path: path.to_vec(),
                mode: 0o755,
            });
            assert_eq!(out.errno, 0, "{}", String::from_utf8_lossy(path));
        }
        let out = m.apply(&Op::Rename {
            from: b"/tmp/a".to_vec(),
            to: b"/var/tmp/d/a".to_vec(),
        });
        assert_eq!(out.errno, 0);
    }

    #[test]
    fn physical_view_does_not_mount() {
        let m = Model::new(Profile::LinuxMount { root: linux_root() });
        // Physically, /tmp is just a plain host dir; its parent is "/".
        let tmp = resolve_ok(&m, View::Physical, b"/tmp");
        let parent = m.node_parent(View::Physical, tmp);
        let root = resolve_ok(&m, View::Physical, b"/");
        assert_eq!(parent, root);
        // But it must NOT equal the virtual /tmp (the mounted root/tmp).
        let virt = resolve_ok(&m, View::Virtual, b"/tmp");
        assert_ne!(tmp, virt);
    }

    #[test]
    fn relative_symlink_resolves_against_its_own_directory() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/a/b");
        m.add_fixture_symlink(View::Virtual, b"/tmp/link", b"a/b".to_vec());
        let via_link = resolve_ok(&m, View::Virtual, b"/tmp/link");
        let direct = resolve_ok(&m, View::Virtual, b"/tmp/a/b");
        assert_eq!(via_link, direct);
    }

    #[test]
    fn symlink_loop_yields_eloop() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_symlink(View::Virtual, b"/tmp/a", b"b".to_vec());
        m.add_fixture_symlink(View::Virtual, b"/tmp/b", b"a".to_vec());
        let err = m
            .resolve(View::Virtual, Start::Root, b"/tmp/a", true)
            .unwrap_err();
        assert_eq!(err, libc::ELOOP);
    }

    #[test]
    fn non_dir_in_middle_is_enotdir() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_file(View::Virtual, b"/tmp/f", b"hi".to_vec());
        let err = m
            .resolve(View::Virtual, Start::Root, b"/tmp/f/x", true)
            .unwrap_err();
        assert_eq!(err, libc::ENOTDIR);
    }

    #[test]
    fn trailing_slash_on_file_is_enotdir() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_file(View::Virtual, b"/tmp/f", b"hi".to_vec());
        let err = m
            .resolve(View::Virtual, Start::Root, b"/tmp/f/", true)
            .unwrap_err();
        assert_eq!(err, libc::ENOTDIR);
    }

    #[test]
    fn overlong_path_is_enametoolong() {
        let m = Model::new(Profile::MacShim { root: mac_root() });
        let long = format!("/tmp/{}", "a".repeat(2000));
        let err = m
            .resolve(View::Virtual, Start::Root, long.as_bytes(), true)
            .unwrap_err();
        assert_eq!(err, libc::ENAMETOOLONG);
    }

    #[test]
    fn overlong_component_is_enametoolong() {
        let m = Model::new(Profile::MacShim { root: mac_root() });
        let long = format!("/tmp/{}", "a".repeat(300));
        let err = m
            .resolve(View::Virtual, Start::Root, long.as_bytes(), true)
            .unwrap_err();
        assert_eq!(err, libc::ENAMETOOLONG);
    }

    #[test]
    fn missing_component_is_enoent() {
        let m = Model::new(Profile::MacShim { root: mac_root() });
        let err = m
            .resolve(View::Virtual, Start::Root, b"/tmp/nope", true)
            .unwrap_err();
        assert_eq!(err, libc::ENOENT);
    }

    #[test]
    fn mkdir_then_eexist() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        assert_eq!(
            m.apply(&Op::Mkdir {
                path: b"/tmp/d".to_vec(),
                mode: 0o755
            })
            .errno,
            0
        );
        let out = m.apply(&Op::Mkdir {
            path: b"/tmp/d".to_vec(),
            mode: 0o755,
        });
        assert_eq!(out.errno, libc::EEXIST);
    }

    #[test]
    fn open_create_write_read_roundtrip() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        let flags = OpenFlags {
            create: true,
            write: true,
            ..Default::default()
        };
        let open = m.apply(&Op::Open {
            path: b"/tmp/f".to_vec(),
            flags,
        });
        assert_eq!(open.errno, 0);
        let fd = open.ret as u32;
        let w = m.apply(&Op::Write {
            fd,
            data: b"hello".to_vec(),
        });
        assert_eq!(w.ret, 5);
        m.apply(&Op::CloseFd { fd });
        let open2 = m.apply(&Op::Open {
            path: b"/tmp/f".to_vec(),
            flags: OpenFlags::default(),
        });
        let fd2 = open2.ret as u32;
        let r = m.apply(&Op::Read { fd: fd2, len: 100 });
        assert_eq!(r.data, b"hello");
        assert_eq!(r.ret, 5);
    }

    #[test]
    fn open_excl_on_existing_is_eexist() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_file(View::Virtual, b"/tmp/f", vec![]);
        let flags = OpenFlags {
            create: true,
            excl: true,
            write: true,
            ..Default::default()
        };
        let out = m.apply(&Op::Open {
            path: b"/tmp/f".to_vec(),
            flags,
        });
        assert_eq!(out.errno, libc::EEXIST);
    }

    #[test]
    fn rename_dir_over_nonempty_dir_is_enotempty() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/a");
        m.add_fixture_dir(View::Virtual, b"/tmp/b/child");
        let out = m.apply(&Op::Rename {
            from: b"/tmp/a".to_vec(),
            to: b"/tmp/b".to_vec(),
        });
        assert_eq!(out.errno, libc::ENOTEMPTY);
    }

    #[test]
    fn rename_file_over_dir_is_eisdir() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_file(View::Virtual, b"/tmp/a", vec![]);
        m.add_fixture_dir(View::Virtual, b"/tmp/b");
        let out = m.apply(&Op::Rename {
            from: b"/tmp/a".to_vec(),
            to: b"/tmp/b".to_vec(),
        });
        assert_eq!(out.errno, libc::EISDIR);
    }

    #[test]
    fn rename_dir_over_file_is_enotdir() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/a");
        m.add_fixture_file(View::Virtual, b"/tmp/b", vec![]);
        let out = m.apply(&Op::Rename {
            from: b"/tmp/a".to_vec(),
            to: b"/tmp/b".to_vec(),
        });
        assert_eq!(out.errno, libc::ENOTDIR);
    }

    #[test]
    fn rename_into_own_subtree_is_einval() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/a/b");
        let out = m.apply(&Op::Rename {
            from: b"/tmp/a".to_vec(),
            to: b"/tmp/a/b/c".to_vec(),
        });
        assert_eq!(out.errno, libc::EINVAL);
    }

    #[test]
    fn unlink_dir_is_eisdir_rmdir_nonempty_is_enotempty() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/a/b");
        let out = m.apply(&Op::Unlink {
            path: b"/tmp/a".to_vec(),
        });
        assert_eq!(out.errno, libc::EISDIR);
        let out = m.apply(&Op::Rmdir {
            path: b"/tmp/a".to_vec(),
        });
        assert_eq!(out.errno, libc::ENOTEMPTY);
    }

    #[test]
    fn symlink_and_readlink_roundtrip() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.apply(&Op::Symlink {
            target: b"/etc/hosts".to_vec(),
            path: b"/tmp/l".to_vec(),
        });
        let out = m.apply(&Op::Readlink {
            path: b"/tmp/l".to_vec(),
        });
        assert_eq!(out.data, b"/etc/hosts");
    }

    #[test]
    fn readlink_on_non_symlink_is_einval() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_file(View::Virtual, b"/tmp/f", vec![]);
        let out = m.apply(&Op::Readlink {
            path: b"/tmp/f".to_vec(),
        });
        assert_eq!(out.errno, libc::EINVAL);
    }

    #[test]
    fn bind_twice_is_eaddrinuse_connect_to_non_socket_is_econnrefused() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        let out = m.apply(&Op::Bind {
            path: b"/tmp/s".to_vec(),
        });
        assert_eq!(out.errno, 0);
        let out = m.apply(&Op::Bind {
            path: b"/tmp/s".to_vec(),
        });
        assert_eq!(out.errno, libc::EADDRINUSE);
        let out = m.apply(&Op::Connect {
            path: b"/tmp/s".to_vec(),
        });
        assert_eq!(out.errno, 0);
        m.add_fixture_file(View::Virtual, b"/tmp/notasocket", vec![]);
        let out = m.apply(&Op::Connect {
            path: b"/tmp/notasocket".to_vec(),
        });
        assert_eq!(out.errno, libc::ECONNREFUSED);
    }

    #[test]
    fn chdir_getcwd_realpath() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/a/b");
        m.apply(&Op::Chdir {
            path: b"/tmp/a/b".to_vec(),
        });
        let out = m.apply(&Op::Getcwd);
        assert_eq!(out.data, b"/private/tmp/a/b");
        let out = m.apply(&Op::Realpath {
            path: b"..".to_vec(),
        });
        assert_eq!(out.data, b"/private/tmp/a");
    }

    #[test]
    fn list_is_sorted() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/b");
        m.add_fixture_dir(View::Virtual, b"/tmp/a");
        let out = m.apply(&Op::List {
            path: b"/tmp".to_vec(),
        });
        assert_eq!(out.data, b"a\nb");
        assert_eq!(out.ret, 2);
    }

    #[test]
    fn op_round_trips_through_to_line_from_line() {
        let ops = vec![
            Op::Mkdir {
                path: b"/tmp/a b".to_vec(),
                mode: 0o755,
            },
            Op::Open {
                path: b"/tmp/\xffweird".to_vec(),
                flags: OpenFlags {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            },
            Op::Write {
                fd: 3,
                data: b"hi there\n".to_vec(),
            },
            Op::Read { fd: 3, len: 10 },
            Op::Symlink {
                target: b"../x".to_vec(),
                path: b"/tmp/l".to_vec(),
            },
            Op::Rename {
                from: b"/tmp/a".to_vec(),
                to: b"/tmp/b".to_vec(),
            },
            Op::UnlinkAt {
                dirfd: 4,
                path: b"x".to_vec(),
                rmdir: true,
            },
            Op::Getcwd,
            Op::CloseFd { fd: 9 },
        ];
        for op in ops {
            let line = op.to_line();
            assert!(
                !line.contains('\n'),
                "line must not contain newline: {line:?}"
            );
            let back = Op::from_line(&line).unwrap_or_else(|| panic!("failed to parse {line:?}"));
            assert_eq!(back, op, "round trip for {line:?}");
        }
    }

    #[test]
    fn rng_is_deterministic_and_varies() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..10 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = Rng::new(1);
        let vals: Vec<u64> = (0..5).map(|_| c.below(1000)).collect();
        assert!(vals.iter().any(|&v| v != vals[0]));
    }

    #[test]
    fn errno_equiv_basic() {
        assert!(errno_equiv(true, libc::ENOENT, libc::ENOENT));
        assert!(!errno_equiv(true, libc::ENOENT, libc::EEXIST));
        assert!(errno_equiv(true, libc::ENOTEMPTY, libc::EEXIST));
        assert!(errno_equiv(false, libc::EISDIR, libc::EPERM));
        assert!(!errno_equiv(true, libc::EISDIR, libc::EPERM));
    }

    #[test]
    fn tree_and_tree_json_smoke_test() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.add_fixture_dir(View::Virtual, b"/tmp/a");
        m.add_fixture_file(View::Virtual, b"/tmp/a/f", b"xy".to_vec());
        m.add_fixture_symlink(View::Virtual, b"/tmp/l", b"a/f".to_vec());
        let entries = m.tree(View::Virtual, b"/tmp");
        assert_eq!(
            entries,
            vec![
                Entry {
                    path: b"a".to_vec(),
                    kind: EntryKind::Dir
                },
                Entry {
                    path: b"a/f".to_vec(),
                    kind: EntryKind::File { len: 2 }
                },
                Entry {
                    path: b"l".to_vec(),
                    kind: EntryKind::Symlink {
                        target: b"a/f".to_vec()
                    }
                },
            ]
        );
        let json = m.tree_json(View::Virtual, b"/tmp");
        assert!(json.contains("\"path\":\"a/f\""));
        assert!(json.contains("\"len\":2"));
    }

    #[test]
    fn case_insensitive_lookup() {
        let mut m = Model::new(Profile::MacShim { root: mac_root() });
        m.set_case_insensitive(true);
        m.add_fixture_dir(View::Virtual, b"/tmp/abc");
        let a = resolve_ok(&m, View::Virtual, b"/tmp/abc");
        let b = resolve_ok(&m, View::Virtual, b"/tmp/ABC");
        assert_eq!(a, b);
    }

    fn trailing_fixture(profile: Profile) -> Model {
        let mut m = Model::new(profile);
        m.add_fixture_file(View::Virtual, b"/tmp/f", vec![]);
        m.add_fixture_dir(View::Virtual, b"/tmp/d");
        m.add_fixture_dir(View::Virtual, b"/tmp/e");
        m.add_fixture_file(View::Virtual, b"/tmp/t/in", vec![]);
        m.add_fixture_symlink(View::Virtual, b"/tmp/ld", b"t".to_vec());
        m.add_fixture_symlink(View::Virtual, b"/tmp/le", b"e".to_vec());
        m.add_fixture_symlink(View::Virtual, b"/tmp/lf", b"f".to_vec());
        m.add_fixture_symlink(View::Virtual, b"/tmp/dl", b"nowhere".to_vec());
        m.add_fixture_socket(View::Virtual, b"/tmp/s");
        m
    }

    /// One trailing-slash case: `kind` is the syscall, `args` its path(s).
    fn trailing_op(kind: &str, args: &[&str]) -> Op {
        let b = |i: usize| format!("/tmp/{}", args[i]).into_bytes();
        let create = |excl: bool| OpenFlags {
            create: true,
            excl,
            write: true,
            ..OpenFlags::default()
        };
        match kind {
            "unlink" => Op::Unlink { path: b(0) },
            "rmdir" => Op::Rmdir { path: b(0) },
            "rename" => Op::Rename {
                from: b(0),
                to: b(1),
            },
            "symlink" => Op::Symlink {
                target: b"x".to_vec(),
                path: b(0),
            },
            "bind" => Op::Bind { path: b(0) },
            "mkdir" => Op::Mkdir {
                path: b(0),
                mode: 0o755,
            },
            "creat" => Op::Open {
                path: b(0),
                flags: create(false),
            },
            "creatx" => Op::Open {
                path: b(0),
                flags: create(true),
            },
            other => panic!("unknown kind {other}"),
        }
    }

    fn assert_trailing_table(profile: Profile, table: &[(&str, &[&str], Errno)]) {
        for (kind, args, expected) in table {
            let mut m = trailing_fixture(profile.clone());
            let out = m.apply(&trailing_op(kind, args));
            assert_eq!(
                out.errno, *expected,
                "{:?} {kind} {args:?}: got {} want {}",
                profile, out.errno, expected
            );
        }
    }

    fn exists(m: &mut Model, path: &str) -> bool {
        m.apply(&Op::Lstat {
            path: path.as_bytes().to_vec(),
        })
        .errno
            == 0
    }

    #[test]
    fn trailing_slash_semantics_per_profile() {
        let ok = 0;
        // Measured macOS (APFS): the final component is looked up through
        // symlinks and must be a directory.
        let mac: &[(&str, &[&str], Errno)] = &[
            ("unlink", &["f/"], libc::ENOTDIR),
            ("unlink", &["f//"], libc::ENOTDIR),
            ("unlink", &["s/"], libc::ENOTDIR),
            ("unlink", &["lf/"], libc::ENOTDIR),
            ("unlink", &["d/"], libc::EPERM),
            ("unlink", &["d//"], libc::EPERM),
            ("unlink", &["ld/"], libc::EPERM),
            ("unlink", &["missing/"], libc::ENOENT),
            ("unlink", &["dl/"], libc::ENOENT),
            ("rmdir", &["d/"], ok),
            ("rmdir", &["d//"], ok),
            ("rmdir", &["f/"], libc::ENOTDIR),
            ("rmdir", &["lf/"], libc::ENOTDIR),
            ("rmdir", &["s/"], libc::ENOTDIR),
            ("rmdir", &["ld/"], libc::ENOTEMPTY),
            ("rmdir", &["le/"], ok),
            ("rmdir", &["dl/"], libc::ENOENT),
            ("rmdir", &["missing/"], libc::ENOENT),
            ("rename", &["f/", "x"], libc::ENOTDIR),
            ("rename", &["f//", "x"], libc::ENOTDIR),
            ("rename", &["f", "x/"], libc::ENOENT),
            ("rename", &["f", "x//"], libc::ENOENT),
            ("rename", &["d", "x/"], ok),
            ("rename", &["d", "x//"], ok),
            ("rename", &["d/", "x"], ok),
            ("rename", &["d/", "d2/"], ok),
            ("rename", &["ld/", "y"], ok),
            ("rename", &["le/", "y"], ok),
            ("rename", &["lf/", "y"], libc::ENOTDIR),
            ("rename", &["dl/", "y"], libc::ENOENT),
            ("rename", &["f", "d/"], libc::EISDIR),
            ("rename", &["f", "ld/"], libc::EISDIR),
            ("rename", &["s", "e/"], libc::EISDIR),
            ("rename", &["s", "x/"], libc::ENOENT),
            ("rename", &["lf", "x/"], libc::ENOENT),
            ("rename", &["ld", "x/"], libc::ENOENT),
            ("rename", &["f", "lf/"], libc::ENOTDIR),
            ("rename", &["f", "f/"], libc::ENOTDIR),
            ("rename", &["d", "f/"], libc::ENOTDIR),
            ("rename", &["d", "lf/"], libc::ENOTDIR),
            ("rename", &["d", "ld/"], libc::ENOTEMPTY),
            ("rename", &["d", "le/"], ok),
            ("rename", &["d", "dl/"], ok),
            ("rename", &["d", "d/"], ok),
            ("symlink", &["l/"], libc::ENOENT),
            ("symlink", &["n//"], libc::ENOENT),
            ("symlink", &["dl/"], libc::ENOENT),
            ("symlink", &["f/"], libc::ENOTDIR),
            ("symlink", &["lf/"], libc::ENOTDIR),
            ("symlink", &["s/"], libc::ENOTDIR),
            ("symlink", &["d/"], libc::EEXIST),
            ("symlink", &["d//"], libc::EEXIST),
            ("symlink", &["ld/"], libc::EEXIST),
            ("creat", &["n2/"], libc::ENOENT),
            ("creat", &["n2//"], libc::ENOENT),
            ("creat", &["dl/"], libc::ENOENT),
            ("creat", &["f/"], libc::ENOTDIR),
            ("creat", &["lf/"], libc::ENOTDIR),
            ("creat", &["s/"], libc::ENOTDIR),
            ("creat", &["d/"], libc::EISDIR),
            ("creat", &["d//"], libc::EISDIR),
            ("creat", &["ld/"], libc::EISDIR),
            ("creatx", &["n3/"], libc::ENOENT),
            ("creatx", &["dl/"], libc::ENOENT),
            ("creatx", &["f/"], libc::ENOTDIR),
            ("creatx", &["lf/"], libc::ENOTDIR),
            ("creatx", &["d/"], libc::EEXIST),
            ("creatx", &["ld/"], libc::EEXIST),
            ("bind", &["s2/"], libc::ENOENT),
            ("bind", &["n//"], libc::ENOENT),
            ("bind", &["dl/"], libc::ENOENT),
            ("bind", &["s/"], libc::ENOTDIR),
            ("bind", &["f/"], libc::ENOTDIR),
            ("bind", &["lf/"], libc::ENOTDIR),
            ("bind", &["d/"], libc::EADDRINUSE),
            ("bind", &["ld/"], libc::EADDRINUSE),
            ("mkdir", &["n/"], ok),
            ("mkdir", &["n//"], ok),
            ("mkdir", &["dl/"], ok),
            ("mkdir", &["d/"], libc::EEXIST),
            ("mkdir", &["d//"], libc::EEXIST),
            ("mkdir", &["ld/"], libc::EEXIST),
            ("mkdir", &["f/"], libc::ENOTDIR),
            ("mkdir", &["f//"], libc::ENOTDIR),
            ("mkdir", &["lf/"], libc::ENOTDIR),
            ("mkdir", &["s/"], libc::ENOTDIR),
        ];
        assert_trailing_table(Profile::MacShim { root: mac_root() }, mac);

        // Linux (fs/namei.c): the final component is never followed by
        // unlink/rmdir/rename, and symlink/bind/O_CREAT never create.
        let linux: &[(&str, &[&str], Errno)] = &[
            ("unlink", &["missing/"], libc::ENOENT),
            ("unlink", &["d/"], libc::EISDIR),
            ("unlink", &["f/"], libc::ENOTDIR),
            ("unlink", &["f//"], libc::ENOTDIR),
            ("unlink", &["s/"], libc::ENOTDIR),
            ("unlink", &["lf/"], libc::ENOTDIR),
            ("unlink", &["ld/"], libc::ENOTDIR),
            ("unlink", &["dl/"], libc::ENOTDIR),
            ("rmdir", &["d/"], ok),
            ("rmdir", &["d//"], ok),
            ("rmdir", &["f/"], libc::ENOTDIR),
            ("rmdir", &["ld/"], libc::ENOTDIR),
            ("rmdir", &["missing/"], libc::ENOENT),
            ("rename", &["f/", "x"], libc::ENOTDIR),
            ("rename", &["f", "x/"], libc::ENOTDIR),
            ("rename", &["f", "x//"], libc::ENOTDIR),
            ("rename", &["f", "d/"], libc::ENOTDIR),
            ("rename", &["s", "x/"], libc::ENOTDIR),
            ("rename", &["lf", "x/"], libc::ENOTDIR),
            ("rename", &["ld/", "y"], libc::ENOTDIR),
            ("rename", &["ld", "y/"], libc::ENOTDIR),
            ("rename", &["d", "x/"], ok),
            ("rename", &["d", "x//"], ok),
            ("rename", &["d/", "x"], ok),
            ("rename", &["d/", "d2/"], ok),
            ("rename", &["d", "f/"], libc::ENOTDIR),
            ("rename", &["d", "ld/"], libc::ENOTDIR),
            ("rename", &["d", "e/"], ok),
            ("rename", &["f/", "../var/tmp/x"], libc::EXDEV),
            ("symlink", &["l/"], libc::ENOENT),
            ("symlink", &["n//"], libc::ENOENT),
            ("symlink", &["f/"], libc::EEXIST),
            ("symlink", &["d/"], libc::EEXIST),
            ("symlink", &["ld/"], libc::EEXIST),
            ("symlink", &["dl/"], libc::EEXIST),
            ("creat", &["n/"], libc::EISDIR),
            ("creat", &["d/"], libc::EISDIR),
            ("creat", &["f/"], libc::EISDIR),
            ("creat", &["d//"], libc::EISDIR),
            ("creatx", &["n/"], libc::EISDIR),
            ("creatx", &["d/"], libc::EISDIR),
            ("bind", &["s2/"], libc::ENOENT),
            ("bind", &["n//"], libc::ENOENT),
            ("bind", &["s/"], libc::EADDRINUSE),
            ("bind", &["d/"], libc::EADDRINUSE),
            ("mkdir", &["n/"], ok),
            ("mkdir", &["n//"], ok),
            ("mkdir", &["d/"], libc::EEXIST),
            ("mkdir", &["f/"], libc::EEXIST),
        ];
        assert_trailing_table(Profile::LinuxMount { root: linux_root() }, linux);
    }

    #[test]
    fn mac_trailing_slash_follows_links_like_the_kernel() {
        let mut m = trailing_fixture(Profile::MacShim { root: mac_root() });
        // rename ld/ y renames the link's *target* directory.
        assert_eq!(m.apply(&trailing_op("rename", &["ld/", "y"])).errno, 0);
        assert!(!exists(&mut m, "/tmp/t"));
        assert!(exists(&mut m, "/tmp/y/in"));
        assert!(exists(&mut m, "/tmp/ld"), "the link itself stays");

        // rmdir le/ removes the (empty) target, not the link.
        let mut m = trailing_fixture(Profile::MacShim { root: mac_root() });
        assert_eq!(m.apply(&trailing_op("rmdir", &["le/"])).errno, 0);
        assert!(!exists(&mut m, "/tmp/e"));
        assert!(exists(&mut m, "/tmp/le"));

        // rmdir ld/ on a non-empty target leaves everything intact.
        let mut m = trailing_fixture(Profile::MacShim { root: mac_root() });
        assert_eq!(
            m.apply(&trailing_op("rmdir", &["ld/"])).errno,
            libc::ENOTEMPTY
        );
        assert!(exists(&mut m, "/tmp/t/in"));

        // A dangling link with a trailing slash creates at its target.
        for (kind, args) in [("mkdir", ["dl/"; 1].as_slice()), ("rename", &["d", "dl/"])] {
            let mut m = trailing_fixture(Profile::MacShim { root: mac_root() });
            assert_eq!(m.apply(&trailing_op(kind, args)).errno, 0);
            assert!(exists(&mut m, "/tmp/nowhere"), "{kind}");
            assert!(exists(&mut m, "/tmp/dl"), "{kind}");
        }

        // A trailing slash never turns a link removal into a link-target
        // removal for unlink.
        let mut m = trailing_fixture(Profile::MacShim { root: mac_root() });
        m.apply(&trailing_op("unlink", &["ld/"]));
        assert!(exists(&mut m, "/tmp/ld") && exists(&mut m, "/tmp/t/in"));
    }

    #[test]
    fn trailing_slashes_are_all_trimmed_from_the_name() {
        assert_eq!(
            parent_and_name(b"/tmp/a//").unwrap(),
            (&b"/tmp"[..], &b"a"[..], true)
        );
        assert_eq!(
            parent_and_name(b"a//").unwrap(),
            (&b"."[..], &b"a"[..], true)
        );
        assert_eq!(
            parent_and_name(b"a").unwrap(),
            (&b"."[..], &b"a"[..], false)
        );
        assert_eq!(parent_and_name(b"//"), Err(libc::EINVAL));
        assert_eq!(parent_and_name(b""), Err(libc::ENOENT));
    }

    #[test]
    fn open_of_a_socket_node_differs_per_profile() {
        for (profile, want) in [
            (Profile::MacShim { root: mac_root() }, libc::EOPNOTSUPP),
            (Profile::LinuxMount { root: linux_root() }, libc::ENXIO),
        ] {
            let mut m = Model::new(profile);
            m.add_fixture_socket(View::Virtual, b"/tmp/s");
            let out = m.apply(&Op::Open {
                path: b"/tmp/s".to_vec(),
                flags: OpenFlags {
                    write: true,
                    ..OpenFlags::default()
                },
            });
            assert_eq!(out.errno, want);
        }
    }

    #[test]
    fn nul_in_a_path_operand_is_rejected_at_parse_time() {
        for line in [
            "mkdir a%00b 755",
            "open a%00b 0000",
            "symlink t%00x a",
            "symlink t a%00b",
            "readlink a%00b",
            "rename a%00b c",
            "rename a c%00d",
            "unlink a%00b",
            "rmdir a%00b",
            "chdir a%00b",
            "realpath a%00b",
            "stat a%00b",
            "lstat a%00b",
            "opendir a%00b",
            "openat 3 a%00b 0000",
            "mkdirat 3 a%00b",
            "unlinkat 3 a%00b false",
            "bind a%00b",
            "connect a%00b",
            "mkstemp a%00b",
            "list a%00b",
        ] {
            assert_eq!(Op::from_line(line), None, "{line}");
        }
        let w = Op::Write {
            fd: 3,
            data: b"a\0b".to_vec(),
        };
        assert_eq!(Op::from_line(&w.to_line()), Some(w));
    }

    #[test]
    fn absolute_at_paths_ignore_the_dirfd() {
        let create = OpenFlags {
            create: true,
            write: true,
            ..OpenFlags::default()
        };
        for profile in [
            Profile::MacShim { root: mac_root() },
            Profile::LinuxMount { root: linux_root() },
        ] {
            let mut m = Model::new(profile);
            // A bogus fd: relative fails, absolute does not care.
            let rel = m.apply(&Op::OpenAt {
                dirfd: 99,
                path: b"f".to_vec(),
                flags: create,
            });
            assert_eq!(rel.errno, libc::EBADF);
            let abs = m.apply(&Op::OpenAt {
                dirfd: 99,
                path: b"/tmp/f".to_vec(),
                flags: create,
            });
            assert_eq!(abs.errno, 0);
            // A file fd: relative is ENOTDIR, absolute still works.
            let fd = abs.ret as u32;
            let rel = m.apply(&Op::MkdirAt {
                dirfd: fd,
                path: b"n".to_vec(),
            });
            assert_eq!(rel.errno, libc::ENOTDIR);
            let out = m.apply(&Op::MkdirAt {
                dirfd: fd,
                path: b"/tmp/n".to_vec(),
            });
            assert_eq!(out.errno, 0);
            let out = m.apply(&Op::UnlinkAt {
                dirfd: 99,
                path: b"/tmp/n".to_vec(),
                rmdir: true,
            });
            assert_eq!(out.errno, 0);
            let out = m.apply(&Op::UnlinkAt {
                dirfd: 99,
                path: b"n".to_vec(),
                rmdir: true,
            });
            assert_eq!(out.errno, libc::EBADF);
        }
        assert_eq!(at_start(5, b"/x"), Start::Root);
        assert_eq!(at_start(5, b"x"), Start::Fd(5));
    }

    #[test]
    fn path_max_boundary_per_profile() {
        for (profile, max) in [
            (Profile::MacShim { root: mac_root() }, 1024usize),
            (Profile::LinuxMount { root: linux_root() }, 4096usize),
        ] {
            let mut m = Model::new(profile);
            let long = |n: usize| {
                // Components stay under NAME_MAX so only the total matters.
                let mut p = b"/tmp/".to_vec();
                while p.len() < n {
                    let i = p.len() - 4;
                    p.push(if i % 100 == 99 && p.len() + 1 < n {
                        b'/'
                    } else {
                        b'a'
                    });
                }
                p
            };
            for op in [
                Op::Stat { path: long(max) },
                Op::Mkdir {
                    path: long(max),
                    mode: 0o755,
                },
                Op::Rmdir { path: long(max) },
                Op::Unlink { path: long(max) },
            ] {
                assert_eq!(m.apply(&op).errno, libc::ENAMETOOLONG, "{op:?}");
            }
            // One byte shorter is a normal lookup miss, not ENAMETOOLONG.
            assert_eq!(
                m.apply(&Op::Stat {
                    path: long(max - 1)
                })
                .errno,
                libc::ENOENT
            );
            assert_eq!(
                m.apply(&Op::Unlink {
                    path: long(max - 1)
                })
                .errno,
                libc::ENOENT
            );
            // Symlink target of PATH_MAX bytes is rejected before anything
            // else; one shorter is fine.
            let out = m.apply(&Op::Symlink {
                target: vec![b'a'; max],
                path: b"/tmp/l".to_vec(),
            });
            assert_eq!(out.errno, libc::ENAMETOOLONG);
            let out = m.apply(&Op::Symlink {
                target: vec![b'a'; max - 1],
                path: b"/tmp/l".to_vec(),
            });
            assert_eq!(out.errno, 0);
        }
    }

    #[test]
    fn trailing_slash_on_a_symlink_loop_matches_each_kernel() {
        for (profile, want) in [
            (Profile::LinuxMount { root: linux_root() }, libc::ENOTDIR),
            (Profile::MacShim { root: mac_root() }, libc::ELOOP),
        ] {
            let mut m = Model::new(profile);
            m.add_fixture_symlink(View::Virtual, b"/tmp/la", b"/tmp/lb".to_vec());
            m.add_fixture_symlink(View::Virtual, b"/tmp/lb", b"/tmp/la".to_vec());
            let out = m.apply(&Op::Rename {
                from: b"/tmp/la/".to_vec(),
                to: b"/tmp/y".to_vec(),
            });
            assert_eq!(out.errno, want, "rename");
            let out = m.apply(&Op::Rmdir {
                path: b"/tmp/la/".to_vec(),
            });
            assert_eq!(out.errno, want, "rmdir");
        }
    }
}
