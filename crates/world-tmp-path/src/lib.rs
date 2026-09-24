//! Pure, allocation-free mapping of host temp paths (`/tmp`, `/var/tmp` and
//! their `/private` forms) below a per-workspace root. Shared by silo-bind's
//! async-signal-safe interposers and by world-runtime's ordinary (allocating)
//! executable resolution, so neither links the other: silo-bind's rlib runs a
//! process-wide constructor and defines `#[no_mangle]` libc interposers that
//! must never be pulled into the supervisor.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use std::os::raw::c_int;

pub const PATH_MAX: usize = libc::PATH_MAX as usize;

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
        && root.len() <= 512
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

/// Write the World location for `path` into `out` as a NUL-terminated string.
/// Ok(None) means the path is used unchanged. Uses the real kernel to resolve
/// an escaping `..` that follows a named component (see `map_with`).
pub fn map(root: &[u8], path: &[u8], out: &mut [u8]) -> Result<Option<usize>, c_int> {
    let mut resolve = kernel_full_path;
    map_with(root, path, out, &mut resolve)
}

/// Ask the kernel where a physical path (which may cross symlinks and may
/// still contain unresolved `..` components) really resolves, following
/// symlinks. Our own image's libc calls are not interposed, so this reaches
/// the real `getattrlist` rather than looping back through `map`.
#[cfg(target_os = "macos")]
fn kernel_full_path(path: &[u8], out: &mut [u8]) -> Result<usize, c_int> {
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
        libc::getattrlist(
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
fn kernel_full_path(_path: &[u8], _out: &mut [u8]) -> Result<usize, c_int> {
    Err(libc::ENOSYS)
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

    for _ in 0..64 {
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
                    escape = Some((sub, start, comp_start, end));
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

        let Some((sub, start, comp_start, dotdot_end)) = escape else {
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
        // using `out` as scratch, and ask where it really resolves.
        let prefix = &cur[start..comp_start];
        let total = root.len() + sub.len() + prefix.len();
        if total >= out.len() {
            return Err(libc::ENAMETOOLONG);
        }
        out[..root.len()].copy_from_slice(root);
        out[root.len()..root.len() + sub.len()].copy_from_slice(sub);
        out[root.len() + sub.len()..total].copy_from_slice(prefix);
        out[total] = 0;

        let mut resolved = [0u8; PATH_MAX];
        let resolved_len = resolve(&out[..total + 1], &mut resolved)?;
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

        cur[..next_len].copy_from_slice(&next[..next_len]);
        cur_len = next_len;
        rewritten = true;
    }
    Err(libc::ELOOP)
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

    /// A resolver that stands in for the kernel: it follows `links`
    /// (physical path -> target, matched by whole leading components;
    /// relative targets resolve against the link's own parent, absolute
    /// targets as-is) until none apply, then lexically normalizes. This is
    /// oracle-consistent with the kernel exactly when no symlink is
    /// involved, which is why the plain `mapped()` tests below (no links)
    /// can use it in place of a live `getattrlist`.
    fn fake_resolve<'a>(
        links: &'a [(&'a str, &'a str)],
    ) -> impl FnMut(&[u8], &mut [u8]) -> Result<usize, c_int> + 'a {
        move |path: &[u8], out: &mut [u8]| {
            let mut current = path.split(|&b| b == 0).next().unwrap_or(path).to_vec();
            for _ in 0..32 {
                let Some((link, target)) = links
                    .iter()
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
        let mut out = [0u8; PATH_MAX];
        let mut resolve = fake_resolve(links);
        let result = map_with(ROOT, path.as_bytes(), &mut out, &mut resolve)?;
        Ok(result.map(|n| String::from_utf8(out[..n].to_vec()).unwrap()))
    }

    fn mapped(path: &str) -> Option<String> {
        mapped_with(path, &[]).unwrap()
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
            let mapped = map_with(ROOT, path.as_bytes(), &mut mapped_buf, &mut fake_resolve(&[])).unwrap();
            let effective: Vec<u8> = match mapped {
                Some(n) => mapped_buf[..n].to_vec(),
                None => path.as_bytes().to_vec(),
            };
            proptest::prop_assert_eq!(normalize_host(&effective), expected_host(ROOT, path.as_bytes()));
        }
    }
}
