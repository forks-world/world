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
/// component). The parent text is `"."` for a bare relative name and `"/"`
/// for a top-level absolute one. `Err(EINVAL)` for `""` or `"/"` (nothing to
/// name).
fn parent_and_name(path: &[u8]) -> Result<(&[u8], &[u8]), Errno> {
    if path.is_empty() {
        return Err(libc::EINVAL);
    }
    let trimmed = if path.len() > 1 && path.ends_with(b"/") {
        &path[..path.len() - 1]
    } else {
        path
    };
    if trimmed == b"/" {
        return Err(libc::EINVAL);
    }
    match trimmed.iter().rposition(|&b| b == b'/') {
        Some(0) => Ok((b"/", &trimmed[1..])),
        Some(i) => Ok((&trimmed[..i], &trimmed[i + 1..])),
        None => Ok((b".", trimmed)),
    }
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
        let (dir, name) = parent_and_name(path).expect("valid fixture path");
        let parent = self.mkdir_p(view, dir, NodeKind::Dir);
        self.set_child(parent, name, NodeKind::File(contents))
    }

    /// Like [`Model::add_fixture_dir`], but creates (or overwrites) a
    /// symlink with the given (unresolved, possibly dangling) target text.
    pub fn add_fixture_symlink(&mut self, view: View, path: &[u8], target: Vec<u8>) -> NodeId {
        let (dir, name) = parent_and_name(path).expect("valid fixture path");
        let parent = self.mkdir_p(view, dir, NodeKind::Dir);
        self.set_child(parent, name, NodeKind::Symlink(target))
    }

    /// Like [`Model::add_fixture_dir`], but creates (or overwrites) a socket
    /// node (as `bind` would).
    pub fn add_fixture_socket(&mut self, view: View, path: &[u8]) -> NodeId {
        let (dir, name) = parent_and_name(path).expect("valid fixture path");
        let parent = self.mkdir_p(view, dir, NodeKind::Dir);
        self.set_child(parent, name, NodeKind::Socket)
    }

    /// Ensure the *ancestors* of `path` exist (as [`NodeKind::Opaque`]
    /// directories), without creating `path` itself. Useful to give a
    /// symlink target somewhere plausible to dangle towards without fully
    /// modelling it.
    pub fn add_opaque_ancestors(&mut self, path: &[u8]) {
        if let Ok((dir, _name)) = parent_and_name(path) {
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
    /// component is dereferenced if it is a symlink (a trailing slash always
    /// forces dereferencing, exactly as the kernel does).
    pub fn resolve(
        &self,
        view: View,
        start: Start,
        path: &[u8],
        follow_last: bool,
    ) -> Result<NodeId, Errno> {
        let mut link_count = 0u32;
        let start_node = match start {
            Start::Root => self.root_node,
            Start::Cwd => self.cwd,
            Start::Fd(fd) => self.fd_dir(fd)?,
        };
        self.resolve_inner(view, start_node, path, follow_last, &mut link_count)
    }

    fn resolve_inner(
        &self,
        view: View,
        mut cur: NodeId,
        path: &[u8],
        follow_last: bool,
        link_count: &mut u32,
    ) -> Result<NodeId, Errno> {
        if path.len() > self.path_max() {
            return Err(libc::ENAMETOOLONG);
        }
        if path.is_empty() {
            return Ok(self.enter(view, cur));
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
                target = self.follow_symlink(view, cur, target, link_count)?;
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
    ) -> Result<NodeId, Errno> {
        let target = match &self.nodes[link_node].kind {
            NodeKind::Symlink(t) => t.clone(),
            _ => return Ok(link_node),
        };
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
        self.resolve_inner(view, base, &target, true, link_count)
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
            Op::MkdirAt { dirfd, path } => self.do_mkdir(Start::Fd(*dirfd), path),
            Op::Open { path, flags } => self.do_open(Start::Cwd, path, flags),
            Op::OpenAt { dirfd, path, flags } => self.do_open(Start::Fd(*dirfd), path, flags),
            Op::OpenDir { path } => self.do_opendir(Start::Cwd, path),
            Op::Write { fd, data } => self.do_write(*fd, data),
            Op::Read { fd, len } => self.do_read(*fd, *len),
            Op::Symlink { target, path } => self.do_symlink(target, path),
            Op::Readlink { path } => self.do_readlink(path),
            Op::Rename { from, to } => self.do_rename(from, to),
            Op::Unlink { path } => self.unlink_impl(Start::Cwd, path, false),
            Op::Rmdir { path } => self.unlink_impl(Start::Cwd, path, true),
            Op::UnlinkAt { dirfd, path, rmdir } => {
                self.unlink_impl(Start::Fd(*dirfd), path, *rmdir)
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

    fn do_mkdir(&mut self, start: Start, path: &[u8]) -> Outcome {
        match self.resolve_parent(start, path) {
            Ok((parent, name)) => {
                match &self.nodes[parent].kind {
                    NodeKind::Dir | NodeKind::Opaque => {}
                    _ => return errout(libc::ENOTDIR),
                }
                let key = self.key(&name);
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
        if flags.create && flags.excl {
            // POSIX: with O_CREAT|O_EXCL, existence is judged on the literal
            // final component (as `lstat` would see it) -- a symlink there
            // is EEXIST regardless of whether it dangles or even loops, and
            // is never dereferenced.
            return match self.resolve_parent(start, path) {
                Ok((parent, name)) => {
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
                NodeKind::Socket => errout(libc::ENXIO),
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
                    Ok((parent, name)) => {
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
    fn resolve_for_create(&self, start: Start, path: &[u8]) -> Result<(NodeId, Vec<u8>), Errno> {
        let mut link_count = 0u32;
        let start_node = match start {
            Start::Root => self.root_node,
            Start::Cwd => self.cwd,
            Start::Fd(fd) => self.fd_dir(fd)?,
        };
        self.resolve_for_create_inner(start_node, path, &mut link_count)
    }

    fn resolve_for_create_inner(
        &self,
        mut cur: NodeId,
        path: &[u8],
        link_count: &mut u32,
    ) -> Result<(NodeId, Vec<u8>), Errno> {
        let view = View::Virtual;
        if path.len() > self.path_max() {
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
                target = self.follow_symlink(view, cur, target, link_count)?;
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
        match self.resolve_parent(Start::Cwd, path) {
            Ok((parent, name)) => {
                match &self.nodes[parent].kind {
                    NodeKind::Dir | NodeKind::Opaque => {}
                    _ => return errout(libc::ENOTDIR),
                }
                let key = self.key(&name);
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
        let (from_parent, from_name) = match self.resolve_parent(Start::Cwd, from) {
            Ok(v) => v,
            Err(e) => return errout(e),
        };
        let from_key = self.key(&from_name);
        let Some(&from_id) = self.nodes[from_parent].children.get(&from_key) else {
            return errout(libc::ENOENT);
        };
        let (to_parent, to_name) = match self.resolve_parent(Start::Cwd, to) {
            Ok(v) => v,
            Err(e) => return errout(e),
        };
        match &self.nodes[to_parent].kind {
            NodeKind::Dir | NodeKind::Opaque => {}
            _ => return errout(libc::ENOTDIR),
        }
        // Linux checks mount boundaries before the other rename rules.
        if self.mount_of(from_parent) != self.mount_of(to_parent) {
            return errout(libc::EXDEV);
        }
        let to_key = self.key(&to_name);
        if to_parent == from_id || self.is_descendant(from_id, to_parent) {
            return errout(libc::EINVAL);
        }
        let existing = self.nodes[to_parent].children.get(&to_key).copied();
        if let Some(existing_id) = existing {
            if existing_id == from_id {
                return okout(0);
            }
            let from_is_dir = matches!(self.nodes[from_id].kind, NodeKind::Dir | NodeKind::Opaque);
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
            Ok((parent, name)) => {
                let key = self.key(&name);
                let Some(&id) = self.nodes[parent].children.get(&key) else {
                    return errout(libc::ENOENT);
                };
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
            Ok((parent, name)) => {
                match &self.nodes[parent].kind {
                    NodeKind::Dir | NodeKind::Opaque => {}
                    _ => return errout(libc::ENOTDIR),
                }
                let key = self.key(&name);
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

    fn resolve_parent(&self, start: Start, path: &[u8]) -> Result<(NodeId, Vec<u8>), Errno> {
        let (dir, name) = parent_and_name(path)?;
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
        Ok((parent, name.to_vec()))
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
                        self.resolve_inner(view, base, &target, true, &mut link_count)
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
                path: unescape(it.next()?),
                mode: u32::from_str_radix(it.next()?, 8).ok()?,
            }),
            "open" => Some(Op::Open {
                path: unescape(it.next()?),
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
                target: unescape(it.next()?),
                path: unescape(it.next()?),
            }),
            "readlink" => Some(Op::Readlink {
                path: unescape(it.next()?),
            }),
            "rename" => Some(Op::Rename {
                from: unescape(it.next()?),
                to: unescape(it.next()?),
            }),
            "unlink" => Some(Op::Unlink {
                path: unescape(it.next()?),
            }),
            "rmdir" => Some(Op::Rmdir {
                path: unescape(it.next()?),
            }),
            "chdir" => Some(Op::Chdir {
                path: unescape(it.next()?),
            }),
            "getcwd" => Some(Op::Getcwd),
            "realpath" => Some(Op::Realpath {
                path: unescape(it.next()?),
            }),
            "stat" => Some(Op::Stat {
                path: unescape(it.next()?),
            }),
            "lstat" => Some(Op::Lstat {
                path: unescape(it.next()?),
            }),
            "opendir" => Some(Op::OpenDir {
                path: unescape(it.next()?),
            }),
            "openat" => Some(Op::OpenAt {
                dirfd: it.next()?.parse().ok()?,
                path: unescape(it.next()?),
                flags: OpenFlags::from_flag_str(it.next()?)?,
            }),
            "mkdirat" => Some(Op::MkdirAt {
                dirfd: it.next()?.parse().ok()?,
                path: unescape(it.next()?),
            }),
            "unlinkat" => Some(Op::UnlinkAt {
                dirfd: it.next()?.parse().ok()?,
                path: unescape(it.next()?),
                rmdir: it.next()?.parse().ok()?,
            }),
            "bind" => Some(Op::Bind {
                path: unescape(it.next()?),
            }),
            "connect" => Some(Op::Connect {
                path: unescape(it.next()?),
            }),
            "mkstemp" => Some(Op::MkstempAdopt {
                name: unescape(it.next()?),
            }),
            "list" => Some(Op::List {
                path: unescape(it.next()?),
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
}
