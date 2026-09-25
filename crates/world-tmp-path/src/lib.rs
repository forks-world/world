//! Pure, allocation-free mapping of host temp paths (`/tmp`, `/var/tmp` and
//! their `/private` forms) below a per-workspace root. Shared by silo-bind's
//! async-signal-safe interposers and by world-runtime's ordinary (allocating)
//! executable resolution, so neither links the other: silo-bind's rlib runs a
//! process-wide constructor and defines `#[no_mangle]` libc interposers that
//! must never be pulled into the supervisor.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use std::os::raw::c_int;

pub const PATH_MAX: usize = libc::PATH_MAX as usize;
/// Longest a workspace temp root may be: `valid_root` enforces it, and
/// world-runtime's registry rejects a root longer than this before it is
/// ever persisted (see `world-runtime::silo::check_root`).
pub const MAX_ROOT_LEN: usize = 512;

/// Host temp roots, longest first, and their location below the workspace root.
const HOST_ROOTS: [(&[u8], &[u8]); 4] = [
    (b"/private/var/tmp", b"/var/tmp"),
    (b"/private/tmp", b"/tmp"),
    (b"/var/tmp", b"/var/tmp"),
    (b"/tmp", b"/tmp"),
];
/// Names reported for mapped locations, matching host `realpath` output.
const CANONICAL: [(&[u8], &[u8]); 2] = [
    (b"/var/tmp", b"/private/var/tmp"),
    (b"/tmp", b"/private/tmp"),
];

/// An absolute, normalized directory outside every host temp root: libSystem
/// resolves physical paths component by component through the interposed
/// calls, so no prefix of the root may itself be redirected. The minimum
/// length keeps reported names no longer than physical ones, so results can
/// be rewritten in place.
pub fn valid_root(root: &[u8]) -> bool {
    root.len() >= 8
        && root.len() <= MAX_ROOT_LEN
        && root.starts_with(b"/")
        && !root.ends_with(b"/")
        && !root.contains(&0)
        && root[1..]
            .split(|&b| b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
        && HOST_ROOTS
            .iter()
            .all(|(host, _)| component_rest(root, host).is_none())
}

/// The remainder of `path` after `prefix`, when `prefix` names a whole
/// leading component sequence.
fn component_rest<'a>(path: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let rest = path.strip_prefix(prefix)?;
    (rest.is_empty() || rest[0] == b'/').then_some(rest)
}

/// Lexically normalize an absolute path: drop empty and `.` components and
/// resolve `..`. Returns None when the result does not fit. Test oracle only:
/// production mapping must not resolve `..` lexically (see `map`), since a
/// symlink earlier in the path can make that differ from kernel resolution.
#[cfg(test)]
fn normalize(path: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut len = 0;
    for component in path.split(|&b| b == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                while len > 0 {
                    len -= 1;
                    if out[len] == b'/' {
                        break;
                    }
                }
            }
            _ => {
                let end = len + 1 + component.len();
                if end >= out.len() {
                    return None;
                }
                out[len] = b'/';
                out[len + 1..end].copy_from_slice(component);
                len = end;
            }
        }
    }
    if len == 0 {
        out[0] = b'/';
        len = 1;
    }
    Some(len)
}

/// Where a leading path prefix currently stands, relative to the three
/// aliased directories that lead into a host temp root.
#[derive(Clone, Copy)]
enum Base {
    Root,
    Private,
    PrivVar,
}

impl Base {
    fn parent(self) -> Base {
        match self {
            Base::Root => Base::Root,
            Base::Private => Base::Root,
            Base::PrivVar => Base::Private,
        }
    }
}

/// Scan state while walking a path's components left to right. `Temp` tracks
/// how many real components have been pushed below the matched temp root
/// (`depth`) and where its remainder begins (`start`), so re-entering a temp
/// root later only keeps the suffix after the latest match. `named` is true
/// once a real component (not `..`) has been pushed below the root: only
/// then can a `..` that empties `depth` be crossing a symlink, so only then
/// does it need the kernel's help (see `map_with`).
#[derive(Clone, Copy)]
enum Scan {
    Base(Base),
    Other {
        base: Base,
        depth: u32,
    },
    Temp {
        sub: &'static [u8],
        parent: Base,
        start: usize,
        depth: u32,
        named: bool,
    },
}

/// The textual parent of an absolute, slash-separated path with no trailing
/// slash (as kernel-resolved paths are). The parent of `/` is `/`.
fn textual_parent(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) => &path[..1],
        Some(i) => &path[..i],
        None => b"/",
    }
}

/// True when some component of `path` is literally `tmp`. Used to decide
/// whether a `..` popping a named (`Other`) component could possibly reach a
/// temp root, so a plain rename like `/src/../include/x.h` never asks the
/// kernel anything.
fn has_tmp_component(path: &[u8]) -> bool {
    path.split(|&b| b == b'/').any(|c| c == b"tmp")
}

/// How many `..` components appear in `path`.
fn dotdot_count(path: &[u8]) -> usize {
    path.split(|&b| b == b'/').filter(|c| *c == b"..").count()
}

/// Write the World location for `path` into `out` as a NUL-terminated string.
/// Ok(None) means the path is used unchanged. Uses the real kernel to resolve
/// an escaping `..` that follows a named component (see `map_with`).
pub fn map(root: &[u8], path: &[u8], out: &mut [u8]) -> Result<Option<usize>, c_int> {
    let mut resolve = kernel_full_path;
    map_with(root, path, out, &mut resolve)
}

/// Map a symlink target: purely lexical. A target whose decision would need
/// the kernel (a `..` escaping a temp root, or popping a name before `tmp`)
/// is stored verbatim; it resolves at lookup time, possibly dangling.
pub fn map_target(root: &[u8], target: &[u8], out: &mut [u8]) -> Result<Option<usize>, c_int> {
    const UNRESOLVED: c_int = -1; // never a real errno
    match map_with(root, target, out, &mut |_, _| Err(UNRESOLVED)) {
        Err(UNRESOLVED) => Ok(None),
        r => r,
    }
}

/// Ask the kernel where a physical path (which may cross symlinks and may
/// still contain unresolved `..` components) really resolves, following
/// symlinks. `fd` is a directory to resolve `path` against, or `AT_FDCWD` to
/// resolve against the cwd (a non-directory `fd` reports `ENOTDIR`, as
/// `openat` itself would). Our own image's libc calls are not interposed, so
/// this reaches the real `getattrlistat` rather than looping back through
/// `map`.
#[cfg(target_os = "macos")]
fn kernel_full_path_at(fd: c_int, path: &[u8], out: &mut [u8]) -> Result<usize, c_int> {
    #[repr(C)]
    struct FullPathBuf {
        length: u32,
        name: libc::attrreference_t,
        data: [u8; PATH_MAX],
    }
    let mut list: libc::attrlist = unsafe { std::mem::zeroed() };
    list.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    list.commonattr = libc::ATTR_CMN_FULLPATH;
    let mut buf: FullPathBuf = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<FullPathBuf>();
    let ret = unsafe {
        libc::getattrlistat(
            fd,
            path.as_ptr().cast(),
            (&mut list as *mut libc::attrlist).cast(),
            (&mut buf as *mut FullPathBuf).cast(),
            size,
            0, // follow symlinks
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    // attr_dataoffset is relative to the address of the attrreference_t itself.
    let base = (&buf.name as *const libc::attrreference_t).cast::<u8>();
    let text_ptr = unsafe { base.offset(buf.name.attr_dataoffset as isize) };
    let text = unsafe { std::slice::from_raw_parts(text_ptr, buf.name.attr_length as usize) };
    let text = text.split(|&b| b == 0).next().unwrap_or(text);
    if text.len() >= out.len() {
        return Err(libc::ENAMETOOLONG);
    }
    out[..text.len()].copy_from_slice(text);
    Ok(text.len())
}

#[cfg(not(target_os = "macos"))]
fn kernel_full_path_at(_fd: c_int, _path: &[u8], _out: &mut [u8]) -> Result<usize, c_int> {
    Err(libc::ENOSYS)
}

/// Resolve an absolute (already NUL-terminated) path against the cwd.
fn kernel_full_path(path: &[u8], out: &mut [u8]) -> Result<usize, c_int> {
    kernel_full_path_at(libc::AT_FDCWD, path, out)
}

/// The physical, absolute name of `dirfd` (or the cwd, for `AT_FDCWD`) via
/// the kernel: `getattrlistat(dirfd, "./", ...)` reports the full path of the
/// directory `dirfd` itself names.
fn real_base(dirfd: c_int, out: &mut [u8]) -> Result<usize, c_int> {
    kernel_full_path_at(dirfd, b"./\0", out)
}

/// Write the World location for `path` into `out` as a NUL-terminated string.
/// Ok(None) means the path is used unchanged. Only the leading components
/// decide redirection, exactly as the kernel resolves them one at a time.
/// Below a temp root, the remainder is normally copied verbatim: a `..` that
/// crosses a symlink (e.g. `/tmp/a/link/../x`) is left for the kernel to
/// resolve rather than resolved lexically here. But a `..` that empties a
/// temp root's depth *after* a named component was pushed (e.g.
/// `/tmp/a/link/../../../etc/x`) would otherwise return to `Base`, and the
/// caller's literal text would then walk the *host's* temp root instead of
/// the redirected one. `resolve` (the real kernel for `map`, a fake one in
/// tests) is asked where the physical prefix up to that `..` really
/// resolves, so the escape can be rewritten and the scan restarted.
/// Terminates because each restart strictly reduces the number of `..`
/// components; a resolver whose answer contains `..` gets `ELOOP`.
pub(crate) fn map_with(
    root: &[u8],
    path: &[u8],
    out: &mut [u8],
    resolve: &mut impl FnMut(&[u8], &mut [u8]) -> Result<usize, c_int>,
) -> Result<Option<usize>, c_int> {
    // An overlong path is rejected by the kernel exactly as the caller wrote it.
    if !path.starts_with(b"/") || path.len() >= PATH_MAX {
        return Ok(None);
    }
    let mut cur = [0u8; PATH_MAX];
    cur[..path.len()].copy_from_slice(path);
    let mut cur_len = path.len();
    let mut rewritten = false;
    let mut dotdots = dotdot_count(path);

    loop {
        let mut state = Scan::Base(Base::Root);
        let mut pos = 0;
        let mut escape = None;
        for component in cur[..cur_len].split(|&b| b == b'/') {
            let comp_start = pos;
            let end = pos + component.len();
            pos = end + 1;
            state = match (state, component) {
                (s, b"" | b".") => s,
                (Scan::Base(b), b"..") => Scan::Base(b.parent()),
                (Scan::Base(Base::Root), b"private") => Scan::Base(Base::Private),
                (Scan::Base(Base::Root | Base::Private), b"var") => Scan::Base(Base::PrivVar),
                (Scan::Base(Base::Root | Base::Private), b"tmp") => Scan::Temp {
                    sub: b"/tmp",
                    parent: Base::Private,
                    start: end,
                    depth: 0,
                    named: false,
                },
                (Scan::Base(Base::PrivVar), b"tmp") => Scan::Temp {
                    sub: b"/var/tmp",
                    parent: Base::PrivVar,
                    start: end,
                    depth: 0,
                    named: false,
                },
                (Scan::Base(b), _) => Scan::Other { base: b, depth: 1 },
                // A `..` popping a named (non-temp) component is only worth
                // asking the kernel about when a `tmp` component still
                // follows: only then could the answer ever be redirected, so
                // a plain `/src/../include/x.h` stays lexical and syscall-free.
                (Scan::Other { .. }, b"..")
                    if has_tmp_component(&cur[pos.min(cur_len)..cur_len]) =>
                {
                    escape = Some((0, None, comp_start, end));
                    break;
                }
                (Scan::Other { base, depth: 1 }, b"..") => Scan::Base(base),
                (Scan::Other { base, depth }, b"..") => Scan::Other {
                    base,
                    depth: depth - 1,
                },
                (Scan::Other { base, depth }, _) => Scan::Other {
                    base,
                    depth: depth + 1,
                },
                (
                    Scan::Temp {
                        depth: 0,
                        named: false,
                        parent,
                        ..
                    },
                    b"..",
                ) => Scan::Base(parent),
                (
                    Scan::Temp {
                        sub,
                        start,
                        depth: 0,
                        named: true,
                        ..
                    },
                    b"..",
                ) => {
                    escape = Some((start, Some(sub), comp_start, end));
                    break;
                }
                (
                    Scan::Temp {
                        sub,
                        parent,
                        start,
                        depth,
                        named,
                    },
                    b"..",
                ) => Scan::Temp {
                    sub,
                    parent,
                    start,
                    depth: depth - 1,
                    named,
                },
                (
                    Scan::Temp {
                        sub,
                        parent,
                        start,
                        depth,
                        ..
                    },
                    _,
                ) => Scan::Temp {
                    sub,
                    parent,
                    start,
                    depth: depth + 1,
                    named: true,
                },
            };
        }

        let Some((start, sub, comp_start, dotdot_end)) = escape else {
            let Scan::Temp { sub, start, .. } = state else {
                if !rewritten {
                    return Ok(None);
                }
                // The rewritten text must be used: the original would walk
                // the host's temp root instead of the redirected one.
                if cur_len >= out.len() {
                    return Err(libc::ENAMETOOLONG);
                }
                out[..cur_len].copy_from_slice(&cur[..cur_len]);
                out[cur_len] = 0;
                return Ok(Some(cur_len));
            };
            let rest = &cur[start..cur_len];
            let total = root.len() + sub.len() + rest.len();
            if total >= out.len() {
                return Err(libc::ENAMETOOLONG);
            }
            out[..root.len()].copy_from_slice(root);
            out[root.len()..root.len() + sub.len()].copy_from_slice(sub);
            out[root.len() + sub.len()..total].copy_from_slice(rest);
            out[total] = 0;
            return Ok(Some(total));
        };

        // Build the physical path up to (not including) the escaping `..`,
        // using `out` as scratch, and ask where it really resolves. A `Temp`
        // escape's prefix is temp-root-relative and is placed below `root`
        // first; an `Other` escape's prefix is already the absolute text
        // being scanned. Either way a trailing "/" is appended so a named
        // component that is really a file fails with ENOTDIR, exactly as the
        // kernel would if asked to descend into it.
        let head_len = sub.map_or(0, |s| root.len() + s.len());
        let prefix = &cur[start..comp_start];
        let total = head_len + prefix.len();
        if total + 1 >= out.len() {
            return Err(libc::ENAMETOOLONG);
        }
        if let Some(sub) = sub {
            out[..root.len()].copy_from_slice(root);
            out[root.len()..head_len].copy_from_slice(sub);
        }
        out[head_len..total].copy_from_slice(prefix);
        out[total] = b'/';
        out[total + 1] = 0;

        let mut resolved = [0u8; PATH_MAX];
        let resolved_len = resolve(&out[..total + 2], &mut resolved)?;
        let host_len = unmap_in_place(root, &mut resolved, resolved_len).unwrap_or(resolved_len);
        let parent = textual_parent(&resolved[..host_len]);
        let remainder_start = if dotdot_end < cur_len {
            dotdot_end + 1
        } else {
            cur_len
        };
        let remainder = &cur[remainder_start..cur_len];

        let mut next = [0u8; PATH_MAX];
        let mut next_len = parent.len();
        if next_len >= next.len() {
            return Err(libc::ENAMETOOLONG);
        }
        next[..next_len].copy_from_slice(parent);
        if parent != b"/" {
            if next_len >= next.len() {
                return Err(libc::ENAMETOOLONG);
            }
            next[next_len] = b'/';
            next_len += 1;
        }
        if next_len + remainder.len() >= next.len() {
            return Err(libc::ENAMETOOLONG);
        }
        next[next_len..next_len + remainder.len()].copy_from_slice(remainder);
        next_len += remainder.len();

        // Termination: each rewrite must strictly reduce the `..` count. With a
        // canonical resolver this always holds; otherwise fail closed.
        let next_dotdots = dotdot_count(&next[..next_len]);
        if next_dotdots >= dotdots {
            return Err(libc::ELOOP);
        }
        dotdots = next_dotdots;

        cur[..next_len].copy_from_slice(&next[..next_len]);
        cur_len = next_len;
        // An `Other` escape's rewritten prefix is kernel-equivalent to the
        // original text (it only resolved symlinks along the way), so unless
        // the restarted scan lands in `Temp` there is nothing to force: the
        // original text remains fine to use unchanged.
        if sub.is_some() {
            rewritten = true;
        }
    }
}

/// The first non-empty, non-`.` component of a relative path, or `""` when
/// `path` has none (e.g. `"."`, `""`).
fn first_real_component(p: &[u8]) -> &[u8] {
    p.split(|&b| b == b'/')
        .find(|c| !c.is_empty() && *c != b".")
        .unwrap_or(b"")
}

/// Write the World location for a `dirfd`-relative `path` into `out`, exactly
/// as `map` does for an absolute one. Below a directory `fd` (or the cwd, for
/// `AT_FDCWD`), a relative path with a `..` component can reach a host temp
/// root, or, from a cwd already inside a workspace's private tree, escape it
/// physically without escaping it logically; so can a relative path with no
/// `..` at all, once its first real component is `tmp`, `private` or `var`
/// (see `map_at_with`). If `base` fails, the error is returned; the relative
/// path is never passed through unmapped.
pub fn map_at(
    root: &[u8],
    dirfd: c_int,
    path: &[u8],
    out: &mut [u8],
) -> Result<Option<usize>, c_int> {
    let mut resolve = kernel_full_path;
    map_at_with(root, path, out, |b| real_base(dirfd, b), &mut resolve)
}

/// Write the World location for `path`, resolved against `base` (the real,
/// physical directory a relative `path` starts from) into `out`. `resolve` is
/// the kernel (or a fake, in tests), used both by `base` (via `map_at`'s
/// `real_base`) and to finish mapping the joined absolute text.
///
/// An absolute `path` is handled exactly as `map_with` already does,
/// ignoring `base` entirely. A relative `path` with no `..` component whose
/// first real component is not `tmp`, `private` or `var` resolves through the
/// kernel exactly as written, so `base` is never even called for it (`base`
/// is a real syscall) -- it could not possibly land under a host temp root.
/// Otherwise `base` is joined with `path`,
/// popping `path`'s *leading* `.`/`..` components textually against `base`
/// (a `..` deeper in `path` is left for `map_with`'s own scan, exactly as for
/// any other absolute text). `base` itself is first rewritten to its
/// *canonical* (host) name when it lies under `root`: from a cwd already
/// inside the private tree, a `..` must land on the reported parent (e.g.
/// `/private/tmp`), not the tree's own physical parent, since the two
/// diverge right at the root. The joined, absolute text is then run back
/// through `map_with`; if that itself finds no redirect but `base` was under
/// `root`, the joined text must still be reported (never the original
/// relative one, which the kernel would instead resolve inside the private
/// tree). If `base` fails, the error is returned; the relative path is never
/// passed through unmapped.
pub(crate) fn map_at_with(
    root: &[u8],
    path: &[u8],
    out: &mut [u8],
    base: impl FnOnce(&mut [u8]) -> Result<usize, c_int>,
    resolve: &mut impl FnMut(&[u8], &mut [u8]) -> Result<usize, c_int>,
) -> Result<Option<usize>, c_int> {
    if path.starts_with(b"/") {
        return map_with(root, path, out, resolve);
    }
    let has_dotdot = path.split(|&b| b == b'/').any(|c| c == b"..");
    if !has_dotdot && !matches!(first_real_component(path), b"tmp" | b"private" | b"var") {
        return Ok(None);
    }
    let mut base_buf = [0u8; PATH_MAX];
    let base_len = match base(&mut base_buf) {
        Ok(n) if n < base_buf.len() => n,
        Ok(_) => return Err(libc::ENAMETOOLONG),
        Err(e) => return Err(e),
    };
    let under_root = unmap_in_place(root, &mut base_buf, base_len);
    let mut len = under_root.unwrap_or(base_len);

    let mut joined = [0u8; PATH_MAX];
    joined[..len].copy_from_slice(&base_buf[..len]);
    let mut rest = path;
    loop {
        rest = match rest {
            b"." => b"",
            b".." => {
                pop_component(&mut len, &joined);
                b""
            }
            _ if rest.starts_with(b"./") => &rest[2..],
            _ if rest.starts_with(b"../") => {
                pop_component(&mut len, &joined);
                &rest[3..]
            }
            _ => break,
        };
        if rest.is_empty() {
            break;
        }
    }
    if !rest.is_empty() {
        if &joined[..len] != b"/" {
            if len >= joined.len() {
                return Err(libc::ENAMETOOLONG);
            }
            joined[len] = b'/';
            len += 1;
        }
        if len + rest.len() >= joined.len() {
            return Err(libc::ENAMETOOLONG);
        }
        joined[len..len + rest.len()].copy_from_slice(rest);
        len += rest.len();
    }

    match map_with(root, &joined[..len], out, resolve)? {
        Some(n) => Ok(Some(n)),
        None if under_root.is_some() => {
            if len >= out.len() {
                return Err(libc::ENAMETOOLONG);
            }
            out[..len].copy_from_slice(&joined[..len]);
            out[len] = 0;
            Ok(Some(len))
        }
        None => Ok(None),
    }
}

/// Remove the last component of `joined[..*len]` textually, never crossing
/// the leading `/` itself.
fn pop_component(len: &mut usize, joined: &[u8; PATH_MAX]) {
    while *len > 1 && joined[*len - 1] != b'/' {
        *len -= 1;
    }
    if *len > 1 {
        *len -= 1;
    }
}

/// Rewrite a physical World location back to its host name in place.
/// Returns the new length, or None when `buf[..len]` is not mapped.
pub fn unmap_in_place(root: &[u8], buf: &mut [u8], len: usize) -> Option<usize> {
    let rest = component_rest(&buf[..len], root)?;
    let (canonical, start) = CANONICAL.iter().find_map(|(sub, canonical)| {
        component_rest(rest, sub).map(|r| (*canonical, len - r.len()))
    })?;
    let new_len = canonical.len() + len - start;
    buf.copy_within(start..len, canonical.len());
    buf[..canonical.len()].copy_from_slice(canonical);
    Some(new_len)
}

/// Copy a `getcwd` result into the caller's buffer, unmapping it first.
/// `local[..len]` holds the physical name (no NUL required); `dst` is the
/// caller's buffer. Errors (`ERANGE`) leave `dst` untouched, matching
/// `getcwd`'s contract.
pub fn copy_cwd(root: &[u8], local: &mut [u8], len: usize, dst: &mut [u8]) -> Result<usize, c_int> {
    let n = unmap_in_place(root, local, len).unwrap_or(len);
    if n + 1 > dst.len() {
        return Err(libc::ERANGE);
    }
    dst[..n].copy_from_slice(&local[..n]);
    dst[n] = 0;
    Ok(n)
}

/// Copy a `readlink` result into the caller's buffer, unmapping it first and
/// truncating to `dst`'s capacity exactly as the kernel would (no NUL, since
/// `readlink` does not add one).
pub fn copy_link(root: &[u8], local: &mut [u8], len: usize, dst: &mut [u8]) -> usize {
    let n = unmap_in_place(root, local, len).unwrap_or(len);
    let copied = n.min(dst.len());
    dst[..copied].copy_from_slice(&local[..copied]);
    copied
}

/// Offset of `sun_path` in `sockaddr_un`: the `sun_len` and `sun_family`
/// bytes precede it on macOS.
pub const SUN_PATH_OFFSET: usize = 2;
#[cfg(target_os = "macos")]
const _: () = assert!(SUN_PATH_OFFSET == std::mem::offset_of!(libc::sockaddr_un, sun_path));

/// Rewrite a physical `AF_UNIX` address to its host name in place. `sa` holds
/// raw `sockaddr_un` bytes in macOS layout (`sun_len`, `sun_family`, then
/// `sun_path`) and `reported` is the kernel's address length, which must fit
/// within `sa`. Returns the new total length; freed tail bytes are zeroed and
/// the `sun_len` byte is updated. Pure and allocation-free, so it is
/// unit-testable on any host without a live socket.
pub fn unmap_sockaddr(root: &[u8], sa: &mut [u8], reported: usize) -> Option<usize> {
    if reported <= SUN_PATH_OFFSET || reported > sa.len() || sa[1] as c_int != libc::AF_UNIX {
        return None;
    }
    let region = reported - SUN_PATH_OFFSET;
    let path_len = sa[SUN_PATH_OFFSET..reported]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(region);
    let new_len = unmap_in_place(root, &mut sa[SUN_PATH_OFFSET..], path_len)?;
    sa[SUN_PATH_OFFSET + new_len..reported].fill(0);
    let total = SUN_PATH_OFFSET + new_len + usize::from(new_len < region);
    sa[0] = total as u8;
    Some(total)
}

/// After a requery reports `storage[..reported]`, unmap it in place and copy
/// at most `cap` bytes into `dst`, leaving `dst[cap..]` untouched. Returns the
/// unmapped total length, which may exceed `cap` so callers can still detect
/// truncation the way the kernel reports it.
pub fn requeried_unix(
    root: &[u8],
    storage: &mut [u8],
    reported: usize,
    cap: usize,
    dst: &mut [u8],
) -> Option<usize> {
    let total = unmap_sockaddr(root, storage, reported)?;
    let n = cap.min(total).min(storage.len()).min(dst.len());
    dst[..n].copy_from_slice(&storage[..n]);
    Some(total)
}

/// Errors from mapping or resolving a PATH candidate that just mean "this
/// entry does not exist", so the search should move on to the next one,
/// rather than fail the whole lookup. Shared by silo-bind's PATH search and
/// world-runtime's `map_candidate` so both skip the same errors.
pub fn skippable(errno: c_int) -> bool {
    matches!(errno, libc::ENOENT | libc::ENOTDIR | libc::EACCES)
}

/// Allocating form for callers outside async-signal context, such as
/// world-runtime resolving an entry point's executable before `exec`.
/// `root` is the workspace's temp root (see `world-runtime::silo::temp_root`).
/// Returns `path` unchanged when it is not below a host temp root.
pub fn map_under(
    root: &std::path::Path,
    path: &std::path::Path,
) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let mut buf = [0u8; PATH_MAX];
    match map(
        root.as_os_str().as_bytes(),
        path.as_os_str().as_bytes(),
        &mut buf,
    ) {
        Ok(Some(len)) => Ok(std::ffi::OsString::from_vec(buf[..len].to_vec()).into()),
        Ok(None) => Ok(path.to_owned()),
        Err(errno) => Err(std::io::Error::from_raw_os_error(errno)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &[u8] = b"/Users/me/.local/share/world/workspaces/tmp/127.77.0.1";

    /// A resolver that stands in for the kernel: it follows `links` (physical
    /// path -> target, matched by whole leading components; relative targets
    /// resolve against the link's own parent, absolute targets as-is) --
    /// plus the two real symlinks every macOS host has at its root, `/var`
    /// and `/tmp` -- until none apply, then fails with `ENOENT` for any
    /// remaining path under `absent`, else lexically normalizes. This is
    /// oracle-consistent with the kernel exactly when no *other* symlink is
    /// involved, which is why the plain `mapped()` tests below (no links) can
    /// use it in place of a live `getattrlist`. The default `/var`/`/tmp`
    /// aliasing matters once `map_with` can ask about literal, non-root
    /// -anchored text (the `Other`-escape case): unlike a `Temp` escape's
    /// prefix, which is always below `root` and so never contains a literal
    /// leading "/var" or "/tmp" to misread lexically.
    fn fake_resolve<'a>(
        links: &'a [(&'a str, &'a str)],
        absent: &'a [&'a str],
    ) -> impl FnMut(&[u8], &mut [u8]) -> Result<usize, c_int> + 'a {
        const DEFAULT: [(&str, &str); 2] = [("/var", "/private/var"), ("/tmp", "/private/tmp")];
        move |path: &[u8], out: &mut [u8]| {
            let mut current = path.split(|&b| b == 0).next().unwrap_or(path).to_vec();
            for _ in 0..32 {
                let Some((link, target)) = links
                    .iter()
                    .chain(DEFAULT.iter())
                    .find(|(link, _)| component_rest(&current, link.as_bytes()).is_some())
                else {
                    break;
                };
                let rest = component_rest(&current, link.as_bytes()).unwrap().to_vec();
                let mut next = if let Some(abs) = target.strip_prefix('/') {
                    let mut v = vec![b'/'];
                    v.extend_from_slice(abs.as_bytes());
                    v
                } else {
                    let parent = textual_parent(link.as_bytes());
                    let mut v = parent.to_vec();
                    if parent != b"/" {
                        v.push(b'/');
                    }
                    v.extend_from_slice(target.as_bytes());
                    v
                };
                next.extend_from_slice(&rest);
                current = next;
            }
            if absent
                .iter()
                .any(|a| component_rest(&current, a.as_bytes()).is_some())
            {
                return Err(libc::ENOENT);
            }
            let mut buf = [0u8; PATH_MAX];
            let len = normalize(&current, &mut buf).ok_or(libc::ENAMETOOLONG)?;
            if len >= out.len() {
                return Err(libc::ENAMETOOLONG);
            }
            out[..len].copy_from_slice(&buf[..len]);
            Ok(len)
        }
    }

    fn mapped_with(path: &str, links: &[(&str, &str)]) -> Result<Option<String>, c_int> {
        mapped_with_absent(path, links, &[])
    }

    /// Like `mapped_with`, but also reports `ENOENT` for anything under
    /// `absent`.
    fn mapped_with_absent(
        path: &str,
        links: &[(&str, &str)],
        absent: &[&str],
    ) -> Result<Option<String>, c_int> {
        let mut out = [0u8; PATH_MAX];
        let mut resolve = fake_resolve(links, absent);
        let result = map_with(ROOT, path.as_bytes(), &mut out, &mut resolve)?;
        Ok(result.map(|n| String::from_utf8(out[..n].to_vec()).unwrap()))
    }

    /// Like `mapped_with`, but with a caller-supplied resolver (e.g. one that
    /// must never be called, or that reports a specific real-world errno).
    fn mapped_with_resolver(
        path: &str,
        resolve: &mut impl FnMut(&[u8], &mut [u8]) -> Result<usize, c_int>,
    ) -> Result<Option<String>, c_int> {
        let mut out = [0u8; PATH_MAX];
        let result = map_with(ROOT, path.as_bytes(), &mut out, resolve)?;
        Ok(result.map(|n| String::from_utf8(out[..n].to_vec()).unwrap()))
    }

    fn mapped(path: &str) -> Option<String> {
        mapped_with(path, &[]).unwrap()
    }

    /// A `map_at_with` base closure that reports a fixed physical path.
    fn fixed_base(s: String) -> impl FnOnce(&mut [u8]) -> Result<usize, c_int> {
        move |out: &mut [u8]| {
            out[..s.len()].copy_from_slice(s.as_bytes());
            Ok(s.len())
        }
    }

    fn mapped_at(
        base: impl FnOnce(&mut [u8]) -> Result<usize, c_int>,
        path: &str,
    ) -> Result<Option<String>, c_int> {
        let mut out = [0u8; PATH_MAX];
        let mut resolve = fake_resolve(&[], &[]);
        let result = map_at_with(ROOT, path.as_bytes(), &mut out, base, &mut resolve)?;
        Ok(result.map(|n| String::from_utf8(out[..n].to_vec()).unwrap()))
    }

    #[test]
    fn maps_host_temp_roots() {
        let root = std::str::from_utf8(ROOT).unwrap();
        for (path, expected) in [
            ("/tmp", "/tmp"),
            ("/tmp/", "/tmp/"),
            ("/tmp/a.lock", "/tmp/a.lock"),
            ("/private/tmp/.s.PGSQL.5432", "/tmp/.s.PGSQL.5432"),
            ("/var/tmp/x", "/var/tmp/x"),
            ("/private/var/tmp", "/var/tmp"),
            ("//tmp//a/./b/../c", "/tmp//a/./b/../c"),
            ("/private/./tmp/x", "/tmp/x"),
            // The remainder past the matched temp root is copied verbatim, so
            // a `..` that crosses a symlink is left for the kernel to resolve.
            ("/tmp/a/link/../x", "/tmp/a/link/../x"),
            ("/private/../tmp/x", "/tmp/x"),
            ("/var/../tmp/x", "/tmp/x"),
            ("/var/../var/tmp/y", "/var/tmp/y"),
            ("/tmp/a/../../tmp/x", "/tmp/x"),
            ("/Users/../tmp/x", "/tmp/x"),
        ] {
            assert_eq!(mapped(path), Some(format!("{root}{expected}")), "{path}");
        }
    }

    #[test]
    fn leaves_other_paths() {
        for path in [
            "relative/tmp",
            "tmp/x",
            "/tmpfoo",
            "/private/tmpx/y",
            "/var/tmpx",
            "/Users/me/tmp",
            "/private/var/folders/x",
            "/tmp/../etc/hosts",
            "/Users/me/.local/share/world/workspaces/tmp/127.77.0.1",
            "/Users/me/.local/share/world/workspaces/tmp/127.77.0.1/tmp/x",
            "/Users/me/.local/share/world/workspaces/tmp/../tmp/127.77.0.1/tmp/x",
            "/tmp/..",
            "/private/var/tmp/../../etc",
            "/private/var/folders/../tmpx",
            // /var and /tmp are themselves symlinks to their /private forms,
            // so backing out of them lexically lands on /private, not on /:
            // /var/../private/tmp/a/a is really /private/private/tmp/a/a,
            // which is not a temp root either way.
            "/var/../private/tmp/a/a",
            "/tmp/../private/tmp/x",
        ] {
            assert_eq!(mapped(path), None, "{path}");
        }
    }

    #[test]
    fn escaping_dotdot_after_a_named_component_asks_the_kernel() {
        let root = std::str::from_utf8(ROOT).unwrap();
        let link = format!("{root}/tmp/a/link");
        // A relative symlink, then enough ".." to leave the temp root
        // entirely: the kernel resolves "a/link" -> "a/b/c" first, so the
        // three ".." land on "a", then "tmp", then the private root -- not
        // on a lexical (and wrong) parent of "a/link".
        assert_eq!(
            mapped_with("/tmp/a/link/../../../etc/x", &[(&link, "b/c")]),
            Ok(Some(format!("{root}/tmp/etc/x")))
        );
        let abs_link = format!("{root}/tmp/a/abs");
        // An absolute symlink target is used as-is, ignoring the redirected
        // prefix it was found under.
        assert_eq!(
            mapped_with("/tmp/a/abs/../../../tmp/f", &[(&abs_link, "/usr/bin")]),
            Ok(Some(format!("{root}/tmp/f")))
        );
        // No symlink at all: the escape still needs the kernel's help
        // because a named component ("a") was pushed first, but the result
        // is the same as plain lexical resolution.
        assert_eq!(
            mapped_with("/tmp/a/../../etc/hosts", &[]),
            Ok(Some("/private/etc/hosts".to_string()))
        );
        // Escaping past the temp root with no named component in between
        // (e.g. "/tmp/..") never needs the kernel: it stays on the fast,
        // allocation-free path and is left unmapped.
        assert_eq!(mapped_with("/tmp/..", &[]), Ok(None));
    }

    #[test]
    fn map_with_propagates_resolver_errors() {
        let mut out = [0u8; PATH_MAX];
        let mut resolve = |_: &[u8], _: &mut [u8]| Err(libc::ENOENT);
        let result = map_with(ROOT, b"/tmp/a/../../etc", &mut out, &mut resolve);
        assert_eq!(result, Err(libc::ENOENT));
    }

    fn target_mapped(target: &str) -> Result<Option<String>, c_int> {
        let mut out = [0u8; PATH_MAX];
        let result = map_target(ROOT, target.as_bytes(), &mut out)?;
        Ok(result.map(|n| String::from_utf8(out[..n].to_vec()).unwrap()))
    }

    #[test]
    fn map_target_leaves_targets_that_would_need_the_kernel() {
        // Both need the kernel to decide whether the ".." escapes back out to
        // a temp root; `map_target` never asks it, so the target is stored
        // verbatim and resolves (possibly dangling) at lookup time.
        assert_eq!(target_mapped("/does-not-exist/../tmp/x"), Ok(None));
        assert_eq!(target_mapped("/tmp/a/../../etc/x"), Ok(None));
    }

    #[test]
    fn map_target_maps_purely_lexical_temp_targets() {
        let root = std::str::from_utf8(ROOT).unwrap();
        assert_eq!(target_mapped("/tmp/x"), Ok(Some(format!("{root}/tmp/x"))));
        assert_eq!(
            target_mapped("/private/var/tmp/y"),
            Ok(Some(format!("{root}/var/tmp/y")))
        );
        // A ".." that never leaves the temp root is copied verbatim, exactly
        // as `map`/`map_with` would with no symlinks in play -- no resolver
        // call needed.
        assert_eq!(
            target_mapped("/tmp/a/../b"),
            Ok(Some(format!("{root}/tmp/a/../b")))
        );
    }

    #[test]
    fn map_target_leaves_relative_targets() {
        assert_eq!(target_mapped("tmp/x"), Ok(None));
    }

    #[test]
    fn escaping_dotdot_past_a_named_other_component_asks_the_kernel() {
        let root = std::str::from_utf8(ROOT).unwrap();

        // A definitely-absent leading component: since "tmp" still follows,
        // the escape must ask the kernel, and its ENOENT must propagate
        // rather than the path silently mapping into the workspace.
        assert_eq!(
            mapped_with_absent("/definitely-absent/../tmp/x", &[], &["/definitely-absent"]),
            Err(libc::ENOENT)
        );

        // A symlinked leading component must be resolved by the kernel
        // before the escaping ".." is applied, exactly like a Temp escape.
        assert_eq!(
            mapped_with_absent("/l/../tmp/x", &[("/l", "/private/var/folders")], &[]),
            Ok(Some(format!("{root}/var/tmp/x")))
        );

        // Two ordinary (non-special) named components popped one at a time,
        // no symlinks involved: same result as plain lexical resolution,
        // reached via two escape-and-restart rounds.
        assert_eq!(
            mapped_with_absent("/a/b/../../tmp/x", &[], &[]),
            Ok(Some(format!("{root}/tmp/x")))
        );

        // Popping a named component out of the aliased "/var" prefix still
        // lands correctly on the var temp root.
        assert_eq!(
            mapped_with_absent("/var/x/../tmp/y", &[], &[]),
            Ok(Some(format!("{root}/var/tmp/y")))
        );

        // No "tmp" component anywhere past the "..": stays lexical and never
        // asks the kernel at all.
        assert_eq!(
            mapped_with_resolver("/Users/me/src/../include/x.h", &mut |_, _| {
                panic!("resolver should not be called")
            }),
            Ok(None)
        );

        // A named component that is really a file, not a directory: the
        // trailing "/" added to the resolve prefix makes the kernel (here,
        // the fake standing in for it) fail with ENOTDIR, exactly as trying
        // to `cd` into a file would.
        let file_prefix = format!("{root}/tmp/f/");
        assert_eq!(
            mapped_with_resolver("/tmp/f/../../etc", &mut |p: &[u8], _: &mut [u8]| {
                if p.starts_with(file_prefix.as_bytes()) {
                    Err(libc::ENOTDIR)
                } else {
                    panic!("unexpected resolve call: {p:?}")
                }
            }),
            Err(libc::ENOTDIR)
        );
    }

    // The restart loop used to be capped at a fixed 64 iterations; a valid
    // path needing one restart per named-component ".." could exceed that
    // and be wrongly rejected with ELOOP. The bound is now the strictly
    // decreasing ".." count instead, so these have no fixed limit.

    #[test]
    fn many_named_dotdots_before_tmp_still_map() {
        let root = std::str::from_utf8(ROOT).unwrap();
        // 65 "/a/.." pairs: one more than the old fixed cap of 64 restarts.
        let path = format!("{}/tmp/x", "/a/..".repeat(65));
        assert_eq!(
            mapped_with(&path, &[]),
            Ok(Some(format!("{root}/tmp/x"))),
            "{path}"
        );
    }

    #[test]
    fn two_hundred_named_dotdots_before_tmp_still_map() {
        let root = std::str::from_utf8(ROOT).unwrap();
        let path = format!("{}/tmp/x", "/a/..".repeat(200));
        assert!(path.len() < PATH_MAX, "test path must fit PATH_MAX");
        assert_eq!(
            mapped_with(&path, &[]),
            Ok(Some(format!("{root}/tmp/x"))),
            "{path}"
        );
    }

    #[test]
    fn many_temp_escapes_before_tmp_still_map() {
        let root = std::str::from_utf8(ROOT).unwrap();
        // Each "/a/../../tmp" unit, once already inside the temp root, pops
        // the named "a" (needing the kernel, since it might be a symlink)
        // and then the temp root itself, landing on its physical parent --
        // and immediately walks back down through a literal "tmp" text,
        // which restarts the scan right back at a fresh Temp entry. 65
        // rounds is one more than the old fixed cap of 64 restarts.
        let path = format!("/tmp{}/x", "/a/../../tmp".repeat(65));
        assert_eq!(
            mapped_with(&path, &[]),
            Ok(Some(format!("{root}/tmp/x"))),
            "{path}"
        );
    }

    #[test]
    fn misbehaving_resolver_cannot_loop() {
        // A resolver whose answer itself contains ".." can never make
        // progress; it must fail closed rather than loop forever.
        let mut calls = 0;
        let mut resolve = |_: &[u8], out: &mut [u8]| {
            calls += 1;
            let s: &[u8] = b"/a/../a";
            out[..s.len()].copy_from_slice(s);
            Ok(s.len())
        };
        assert_eq!(
            mapped_with_resolver("/a/../tmp/x", &mut resolve),
            Err(libc::ELOOP)
        );
        assert!(calls <= 1, "resolver called {calls} times");
    }

    #[test]
    fn map_at_with_joins_relative_dotdot_against_the_real_base() {
        let root = std::str::from_utf8(ROOT).unwrap();

        // No ".." at all, and the first real component isn't tmp/private/var:
        // resolved through the kernel exactly as written, without ever
        // calling `base` (a real syscall).
        assert_eq!(
            mapped_at(
                |_: &mut [u8]| -> Result<usize, c_int> {
                    panic!("base should not be called without ..")
                },
                "a/b",
            ),
            Ok(None)
        );

        // From an ordinary host cwd, enough ".." to reach a host temp root.
        assert_eq!(
            mapped_at(
                fixed_base("/Users/alice/project".to_string()),
                "../../../tmp/s.sock",
            ),
            Ok(Some(format!("{root}/tmp/s.sock")))
        );
        // Not enough ".." to reach anywhere redirected: left unmapped.
        assert_eq!(
            mapped_at(fixed_base("/Users/alice/project".to_string()), "../x"),
            Ok(None)
        );

        // From a cwd already inside the private tree, ".." must land on the
        // *reported* (host) parent, not the tree's own physical parent.
        let base_a = format!("{root}/tmp/a");
        assert_eq!(
            mapped_at(fixed_base(base_a.clone()), "../../etc/hosts"),
            Ok(Some("/private/etc/hosts".to_string()))
        );
        assert_eq!(
            mapped_at(fixed_base(base_a), "../b"),
            Ok(Some(format!("{root}/tmp/b")))
        );

        // A `base` failure (e.g. EBADF/ENOTDIR from a bad dirfd) is returned
        // directly: the relative path is never passed through unmapped.
        assert_eq!(
            mapped_at(|_: &mut [u8]| Err(libc::ENOENT), "../x"),
            Err(libc::ENOENT)
        );
        // Same for a path with no `..` whose first component forces `base`
        // to be called at all.
        assert_eq!(
            mapped_at(|_: &mut [u8]| Err(libc::EBADF), "tmp/x"),
            Err(libc::EBADF)
        );
        // A `base` that reports a length not strictly less than the buffer
        // (here, exactly `PATH_MAX`) leaves no room for a NUL and is treated
        // like any other overlong result.
        assert_eq!(
            mapped_at(|_: &mut [u8]| Ok(PATH_MAX), "../x"),
            Err(libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn map_at_with_joins_no_dotdot_paths_from_root_bases() {
        let root = std::str::from_utf8(ROOT).unwrap();

        // From "/" (or its "/private" aliases), a relative path with no ".."
        // still reaches a host temp root once joined with the base, exactly
        // as the kernel would resolve it component by component.
        for (base, path, expected) in [
            ("/", "tmp/x", "/tmp/x"),
            ("/private", "tmp/x", "/tmp/x"),
            ("/private/var", "tmp/x", "/var/tmp/x"),
            ("/", "var/tmp/x", "/var/tmp/x"),
            ("/", "private/var/tmp/x", "/var/tmp/x"),
            ("/", "./tmp/x", "/tmp/x"),
            ("/", ".//tmp/x", "/tmp/x"),
        ] {
            assert_eq!(
                mapped_at(fixed_base(base.to_string()), path),
                Ok(Some(format!("{root}{expected}"))),
                "{base} + {path}"
            );
        }

        // An ordinary host cwd: "tmp/x" joined onto it is just a host path
        // with no temp root anywhere in its resolved prefix, so it is left
        // unmapped exactly as the kernel would leave it.
        assert_eq!(
            mapped_at(fixed_base("/Users/me".to_string()), "tmp/x"),
            Ok(None)
        );

        // No ".." and a first real component that is never tmp/private/var:
        // `base` (a real syscall) is never even called.
        for path in ["src/main.rs", "a/b", "."] {
            assert_eq!(
                mapped_at(
                    |_: &mut [u8]| -> Result<usize, c_int> {
                        panic!("base should not be called for {path}")
                    },
                    path,
                ),
                Ok(None),
                "{path}"
            );
        }

        // A base already under the redirected root: the joined text lands
        // back inside it, and `map_with` reports that directly.
        let base_under_root = format!("{root}/tmp/a");
        assert_eq!(
            mapped_at(fixed_base(base_under_root), "tmp/x"),
            Ok(Some(format!("{root}/tmp/a/tmp/x")))
        );
    }

    #[test]
    fn copies_cwd_result_unmapping_first() {
        let physical = format!("{}/tmp/a", std::str::from_utf8(ROOT).unwrap());
        let host = "/private/tmp/a";
        let mut local = [0u8; PATH_MAX];
        local[..physical.len()].copy_from_slice(physical.as_bytes());

        // Exactly the host name plus NUL fits.
        let mut dst = [0u8; PATH_MAX];
        let n = copy_cwd(ROOT, &mut local, physical.len(), &mut dst).unwrap();
        assert_eq!(n, host.len());
        assert_eq!(&dst[..n], host.as_bytes());

        // A buffer that only fits the host name without its NUL is ERANGE,
        // even though the physical name would not have fit either.
        let mut local2 = local;
        let mut dst2 = [0xAAu8; PATH_MAX];
        let err = copy_cwd(ROOT, &mut local2, physical.len(), &mut dst2[..host.len()]).unwrap_err();
        assert_eq!(err, libc::ERANGE);
        assert!(dst2[..host.len()].iter().all(|&b| b == 0xAA));

        // An unmapped path is copied through as-is.
        let mut other = *b"/other\0\0\0\0\0\0\0\0\0\0";
        let mut dst3 = [0u8; PATH_MAX];
        let n = copy_cwd(ROOT, &mut other, 6, &mut dst3).unwrap();
        assert_eq!(&dst3[..n], b"/other");
    }

    #[test]
    fn copies_readlink_result_unmapping_first() {
        let physical = format!("{}/tmp/target", std::str::from_utf8(ROOT).unwrap());
        let host = "/private/tmp/target";
        let mut local = [0u8; PATH_MAX];
        local[..physical.len()].copy_from_slice(physical.as_bytes());

        // Truncation is measured against the (shorter) host name, not the
        // physical name.
        let mut local1 = local;
        let mut dst = [0xAAu8; 32];
        let n = copy_link(ROOT, &mut local1, physical.len(), &mut dst[..10]);
        assert_eq!(n, 10);
        assert_eq!(&dst[..10], &host.as_bytes()[..10]);

        // An exact fit is copied in full, with no NUL appended.
        let mut local2 = local;
        let mut dst2 = [0xAAu8; PATH_MAX];
        let n = copy_link(ROOT, &mut local2, physical.len(), &mut dst2[..host.len()]);
        assert_eq!(n, host.len());
        assert_eq!(&dst2[..host.len()], host.as_bytes());

        // An unmapped target is copied through as-is.
        let mut other = *b"/other\0\0\0\0\0\0\0\0\0\0";
        let mut dst3 = [0u8; 32];
        let n = copy_link(ROOT, &mut other, 6, &mut dst3);
        assert_eq!(&dst3[..n], b"/other");
    }

    #[test]
    fn rejects_results_beyond_path_max() {
        let path = format!("/tmp/{}", "a".repeat(PATH_MAX - 10));
        let mut out = [0u8; PATH_MAX];
        assert_eq!(
            map(ROOT, path.as_bytes(), &mut out),
            Err(libc::ENAMETOOLONG)
        );
        // Unmappable overlong input is left to the kernel.
        let path = format!("/tmp/{}", "a".repeat(PATH_MAX));
        assert_eq!(map(ROOT, path.as_bytes(), &mut out), Ok(None));
    }

    #[test]
    fn unmaps_physical_locations() {
        for (physical, expected) in [
            ("/tmp", Some("/private/tmp")),
            ("/tmp/a/b", Some("/private/tmp/a/b")),
            ("/var/tmp/x", Some("/private/var/tmp/x")),
            ("", None),
            ("/tmpfoo", None),
            ("/other", None),
        ] {
            let mut buf = [ROOT, physical.as_bytes()].concat();
            buf.resize(buf.len() + 1, 0);
            let len = buf.len() - 1;
            let result = unmap_in_place(ROOT, &mut buf, len)
                .map(|n| String::from_utf8(buf[..n].to_vec()).unwrap());
            assert_eq!(result.as_deref(), expected, "{physical}");
        }
        let mut other = b"/private/tmp/x".to_vec();
        assert_eq!(unmap_in_place(ROOT, &mut other, 14), None);
    }

    #[test]
    fn validates_roots() {
        assert!(valid_root(ROOT));
        for root in [
            &b""[..],
            b"/",
            b"/short",
            b"relative/path/root",
            b"/private/tmp/world/",
            b"/private//tmp/world",
            b"/private/tmp/../etc",
            b"/private/./tmp/world",
            b"/private/tmp/world-501/127.77.0.1",
            b"/tmp/world-501/127.77.0.1",
            b"/private/var/tmp/world/127.77.0.1",
        ] {
            assert!(!valid_root(root), "{}", String::from_utf8_lossy(root));
        }
    }

    #[test]
    fn unmap_sockaddr_rejects_oversized_report() {
        // The entry point only ever passes a slice at least as long as
        // `reported`; this guards misuse from overrunning `sa` instead.
        let mut sa = [0u8; 16];
        assert_eq!(unmap_sockaddr(ROOT, &mut sa, 80), None);
    }

    #[test]
    fn unmap_sockaddr_rewrites_host_name_and_zeroes_freed_tail() {
        let physical = format!("{}/tmp/a", std::str::from_utf8(ROOT).unwrap());
        let mut sa = [0xFFu8; 128];
        sa[1] = libc::AF_UNIX as u8;
        sa[2..2 + physical.len()].copy_from_slice(physical.as_bytes());
        sa[2 + physical.len()] = 0; // trailing NUL, as the kernel would report
        let reported = 2 + physical.len() + 1;
        let total = unmap_sockaddr(ROOT, &mut sa, reported).unwrap();
        let host = "/private/tmp/a";
        assert_eq!(total, 2 + host.len() + 1);
        assert_eq!(sa[0], total as u8);
        assert_eq!(&sa[2..2 + host.len()], host.as_bytes());
        // Freed tail bytes, including the old NUL slot, are zeroed rather
        // than left as stale physical-path bytes.
        assert!(sa[2 + host.len()..reported].iter().all(|&b| b == 0));
    }

    #[test]
    fn requeried_unix_copies_only_up_to_the_caller_capacity() {
        let physical = format!("{}/tmp/s.sock", std::str::from_utf8(ROOT).unwrap());
        let mut storage = [0u8; 128];
        storage[1] = libc::AF_UNIX as u8;
        storage[2..2 + physical.len()].copy_from_slice(physical.as_bytes());
        let reported = 2 + physical.len() + 1;

        // Reference: what an untruncated in-place unmap produces.
        let mut full = storage;
        let total = unmap_sockaddr(ROOT, &mut full, reported).unwrap();
        assert_eq!(total, 2 + "/private/tmp/s.sock".len() + 1);

        // A caller with only a 20-byte buffer gets that same content up to
        // its capacity and nothing written past it.
        let cap = 20;
        let mut dst = [0xAAu8; 32];
        let reported_len =
            requeried_unix(ROOT, &mut storage, reported, cap, &mut dst[..cap]).unwrap();
        assert_eq!(reported_len, total);
        assert_eq!(&dst[..cap], &full[..cap]);
        assert!(dst[cap..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn map_under_returns_input_when_unmapped() {
        let root = std::path::Path::new(std::str::from_utf8(ROOT).unwrap());
        let path = std::path::Path::new("/Users/me/project");
        assert_eq!(map_under(root, path).unwrap(), path);
    }

    #[test]
    fn map_under_redirects_below_root() {
        let root = std::path::Path::new(std::str::from_utf8(ROOT).unwrap());
        let path = std::path::Path::new("/tmp/a/b");
        let expected =
            std::path::PathBuf::from(format!("{}/tmp/a/b", std::str::from_utf8(ROOT).unwrap()));
        assert_eq!(map_under(root, path).unwrap(), expected);
    }

    /// Component-wise normalization plus the alias expansion the mapper
    /// itself models: `/var` and `/tmp` behave like symlinks to
    /// `/private/var` and `/private/tmp` respectively (nothing else is a
    /// symlink here). Test oracle only; unlike `normalize`, this is
    /// consistent with the real host, where `/var` and `/tmp` truly are
    /// symlinked to their `/private` forms.
    #[cfg(test)]
    fn normalize_host(path: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for component in path.split(|&b| b == b'/') {
            match component {
                b"" | b"." => {}
                b".." => {
                    if let Some(pos) = out.iter().rposition(|&b| b == b'/') {
                        out.truncate(pos);
                    }
                }
                b"tmp" | b"var" if out.is_empty() => {
                    out.extend_from_slice(b"/private");
                    out.push(b'/');
                    out.extend_from_slice(component);
                }
                _ => {
                    out.push(b'/');
                    out.extend_from_slice(component);
                }
            }
        }
        if out.is_empty() {
            out.push(b'/');
        }
        out
    }

    /// The host path `map_under`-equivalent redirection should produce,
    /// computed independently of the mapper: normalize first (with alias
    /// expansion), then relocate whatever lands under a real temp root.
    #[cfg(test)]
    fn expected_host(root: &[u8], path: &[u8]) -> Vec<u8> {
        let n = normalize_host(path);
        let under = |prefix: &[u8]| component_rest(&n, prefix).map(|rest| rest.to_vec());
        if let Some(rest) = under(b"/private/var/tmp") {
            let mut out = root.to_vec();
            out.extend_from_slice(b"/var/tmp");
            out.extend_from_slice(&rest);
            out
        } else if let Some(rest) = under(b"/private/tmp") {
            let mut out = root.to_vec();
            out.extend_from_slice(b"/tmp");
            out.extend_from_slice(&rest);
            out
        } else {
            n
        }
    }

    #[test]
    fn normalize_host_expands_var_and_tmp_aliases_only_at_root() {
        // The reported regression: /var and /tmp are symlinks to their
        // /private forms, so /var/.. is /private, not /. Alias expansion
        // only applies right at the root, so a second "private"/"tmp" deeper
        // in the path is not itself re-aliased: /private/private/tmp is not
        // a temp root.
        assert_eq!(
            normalize_host(b"/var/../private/tmp/a/a"),
            b"/private/private/tmp/a/a"
        );
        assert_eq!(
            normalize_host(b"/tmp/../private/tmp/x"),
            b"/private/private/tmp/x"
        );
        assert_eq!(normalize_host(b"/var/../tmp/x"), b"/private/tmp/x");
    }

    proptest::proptest! {
        #[test]
        fn map_then_unmap_names_the_host_path(rest in "(/[a-z][a-z.]{0,7}){0,6}") {
            let root = std::str::from_utf8(ROOT).unwrap();
            let mut out = [0u8; PATH_MAX];
            let path = format!("/tmp{rest}");
            if let Some(n) = map(ROOT, path.as_bytes(), &mut out).unwrap() {
                let world = format!("{root}/tmp{rest}");
                proptest::prop_assert_eq!(&out[..n], world.as_bytes());
                let new_len = unmap_in_place(ROOT, &mut out, n).unwrap();
                let host = format!("/private/tmp{rest}");
                proptest::prop_assert_eq!(&out[..new_len], host.as_bytes());
            }
        }

        #[test]
        fn map_agrees_with_normalized_oracle(components in proptest::collection::vec(
            proptest::prop_oneof![
                "[a-z]{1,4}",
                proptest::strategy::Just(".".to_string()),
                proptest::strategy::Just("..".to_string()),
                proptest::strategy::Just(String::new()),
                proptest::strategy::Just("tmp".to_string()),
                proptest::strategy::Just("private".to_string()),
                proptest::strategy::Just("var".to_string()),
            ],
            1..8,
        )) {
            let path = format!("/{}", components.join("/"));

            // No symlinks are in play here (fake_resolve with no links is
            // oracle-consistent with the real kernel), so the mapper's own
            // result -- normalized the same way the real host would resolve
            // it, with /var and /tmp treated as symlinks to their /private
            // forms -- must agree with an oracle built the same way.
            let mut mapped_buf = [0u8; PATH_MAX];
            let mapped = map_with(ROOT, path.as_bytes(), &mut mapped_buf, &mut fake_resolve(&[], &[])).unwrap();
            let effective: Vec<u8> = match mapped {
                Some(n) => mapped_buf[..n].to_vec(),
                None => path.as_bytes().to_vec(),
            };
            proptest::prop_assert_eq!(normalize_host(&effective), expected_host(ROOT, path.as_bytes()));
        }
    }
}
