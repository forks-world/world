//! World-private temporary directories. Paths below the shared host temp roots
//! are redirected below `WORLD_TMP`, so equal lock, socket and file names in
//! different workspaces stay distinct. Mapping is lexical, allocation-free and
//! async-signal-safe: interposed calls may run between fork and exec.
// Only the macOS interposers use the runtime entry points; Linux builds the
// pure mapping for its unit tests.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

pub const PATH_MAX: usize = libc::PATH_MAX as usize;

static ROOT: OnceLock<Option<Box<[u8]>>> = OnceLock::new();

/// Host temp roots, longest first, and their location below `WORLD_TMP`.
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

/// Read `WORLD_TMP` once, before any interposed call can observe it. Returns
/// false when a value is present but unusable.
pub fn init() -> bool {
    let value = std::env::var_os("WORLD_TMP");
    let valid = value.as_ref().is_none_or(|v| {
        use std::os::unix::ffi::OsStrExt;
        valid_root(v.as_bytes())
    });
    ROOT.get_or_init(|| {
        use std::os::unix::ffi::OsStrExt;
        value
            .filter(|_| valid)
            .map(|v| v.as_bytes().to_vec().into_boxed_slice())
    });
    valid
}

pub fn root() -> Option<&'static [u8]> {
    ROOT.get().and_then(Option::as_deref)
}

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
/// root later only keeps the suffix after the latest match.
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
    },
}

/// Write the World location for `path` into `out` as a NUL-terminated string.
/// Ok(None) means the path is used unchanged. Only the leading components
/// decide redirection, exactly as the kernel resolves them one at a time; the
/// remainder is then copied verbatim, so a `..` that crosses a symlink (e.g.
/// `/tmp/a/link/../x`) is left for the kernel to resolve rather than resolved
/// lexically here.
pub fn map(root: &[u8], path: &[u8], out: &mut [u8]) -> Result<Option<usize>, c_int> {
    // An overlong path is rejected by the kernel exactly as the caller wrote it.
    if !path.starts_with(b"/") || path.len() >= PATH_MAX {
        return Ok(None);
    }
    let mut state = Scan::Base(Base::Root);
    let mut pos = 0;
    for component in path.split(|&b| b == b'/') {
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
            },
            (Scan::Base(Base::PrivVar), b"tmp") => Scan::Temp {
                sub: b"/var/tmp",
                parent: Base::PrivVar,
                start: end,
                depth: 0,
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
                    parent, depth: 0, ..
                },
                b"..",
            ) => Scan::Base(parent),
            (
                Scan::Temp {
                    sub,
                    parent,
                    start,
                    depth,
                },
                b"..",
            ) => Scan::Temp {
                sub,
                parent,
                start,
                depth: depth - 1,
            },
            (
                Scan::Temp {
                    sub,
                    parent,
                    start,
                    depth,
                },
                _,
            ) => Scan::Temp {
                sub,
                parent,
                start,
                depth: depth + 1,
            },
        };
    }
    let Scan::Temp { sub, start, .. } = state else {
        return Ok(None);
    };
    let rest = &path[start..];
    let total = root.len() + sub.len() + rest.len();
    if total >= out.len() {
        return Err(libc::ENAMETOOLONG);
    }
    out[..root.len()].copy_from_slice(root);
    out[root.len()..root.len() + sub.len()].copy_from_slice(sub);
    out[root.len() + sub.len()..total].copy_from_slice(rest);
    out[total] = 0;
    Ok(Some(total))
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

/// Map a C path for an interposed call. The returned pointer is either `path`
/// or points into `buf`, which must outlive its use.
pub unsafe fn map_ptr(
    path: *const c_char,
    buf: &mut [u8; PATH_MAX],
) -> Result<*const c_char, c_int> {
    let Some(root) = root() else {
        return Ok(path);
    };
    if path.is_null() {
        return Ok(path);
    }
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    Ok(match map(root, bytes, buf)? {
        Some(_) => buf.as_ptr().cast(),
        None => path,
    })
}

/// Allocating form for code that already runs outside async-signal context.
pub fn map_path(path: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let mut buf = [0u8; PATH_MAX];
    match root().map(|root| map(root, path.as_os_str().as_bytes(), &mut buf)) {
        Some(Ok(Some(len))) => std::ffi::OsString::from_vec(buf[..len].to_vec()).into(),
        _ => path.to_owned(),
    }
}

/// Rewrite a NUL-terminated result string in place.
pub unsafe fn unmap_cstr(path: *mut c_char) {
    let Some(root) = root() else { return };
    if path.is_null() {
        return;
    }
    let len = unsafe { libc::strlen(path) };
    let buf = unsafe { std::slice::from_raw_parts_mut(path.cast::<u8>(), len + 1) };
    if let Some(new_len) = unmap_in_place(root, buf, len) {
        buf[new_len] = 0;
    }
}

/// Map an `AF_UNIX` address. Returns the address to use, possibly `storage`.
#[cfg(target_os = "macos")]
pub unsafe fn map_unix(
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
    storage: &mut std::mem::MaybeUninit<libc::sockaddr_un>,
) -> Result<(*const libc::sockaddr, libc::socklen_t), c_int> {
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let Some(root) = root() else {
        return Ok((addr, len));
    };
    if addr.is_null()
        || (len as usize) <= offset
        || unsafe { (*addr).sa_family } as c_int != libc::AF_UNIX
    {
        return Ok((addr, len));
    }
    let un = unsafe { &*(addr as *const libc::sockaddr_un) };
    let available = (len as usize - offset).min(un.sun_path.len());
    let raw = unsafe { std::slice::from_raw_parts(un.sun_path.as_ptr().cast::<u8>(), available) };
    let path = raw.split(|&b| b == 0).next().unwrap_or_default();
    let mut buf = [0u8; PATH_MAX];
    let Some(mapped) = map(root, path, &mut buf)? else {
        return Ok((addr, len));
    };
    let out = storage.write(unsafe { std::mem::zeroed() });
    if mapped >= out.sun_path.len() {
        return Err(libc::ENAMETOOLONG);
    }
    for (dst, src) in out.sun_path.iter_mut().zip(&buf[..mapped]) {
        *dst = *src as c_char;
    }
    let new_len = offset + mapped + 1;
    out.sun_family = libc::AF_UNIX as _;
    out.sun_len = new_len as u8;
    Ok((
        (out as *const libc::sockaddr_un).cast(),
        new_len as libc::socklen_t,
    ))
}

/// Offset of `sun_path` in `sockaddr_un`: the `sun_len` and `sun_family`
/// bytes precede it on macOS.
const SUN_PATH_OFFSET: usize = 2;
#[cfg(target_os = "macos")]
const _: () = assert!(SUN_PATH_OFFSET == std::mem::offset_of!(libc::sockaddr_un, sun_path));

/// Rewrite a physical `AF_UNIX` address to its host name in place. `sa` holds
/// raw `sockaddr_un` bytes in macOS layout (`sun_len`, `sun_family`, then
/// `sun_path`) and `reported` is the kernel's address length, which must fit
/// within `sa`. Returns the new total length; freed tail bytes are zeroed and
/// the `sun_len` byte is updated. Pure and allocation-free, so it is
/// unit-testable on any host without a live socket.
fn unmap_sockaddr(root: &[u8], sa: &mut [u8], reported: usize) -> Option<usize> {
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
fn requeried_unix(
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

/// Report a returned `AF_UNIX` address by its host name. `cap` is the
/// caller's original buffer capacity (`*len` before the real call, 0 when
/// `len` was null): the kernel copies at most `cap` bytes into `addr` but
/// still sets `*len` to the untruncated address length, so bytes at or past
/// `cap` in the caller's buffer must never be read or written. When
/// truncated, `real` (the same libSystem entry point, called again for `fd`)
/// requeries the untruncated address into a local buffer instead.
#[cfg(target_os = "macos")]
pub unsafe fn unmap_unix(
    fd: c_int,
    addr: *mut libc::sockaddr,
    cap: libc::socklen_t,
    len: *mut libc::socklen_t,
    real: unsafe extern "C" fn(c_int, *mut libc::sockaddr, *mut libc::socklen_t) -> c_int,
) {
    let Some(root) = root() else { return };
    if addr.is_null() || len.is_null() {
        return;
    }
    let reported = unsafe { *len } as usize;
    let cap = cap as usize;
    if reported <= SUN_PATH_OFFSET {
        return;
    }
    if reported <= cap {
        let sa = unsafe { std::slice::from_raw_parts_mut(addr.cast::<u8>(), reported) };
        if let Some(total) = unmap_sockaddr(root, sa, reported) {
            unsafe { *len = total as libc::socklen_t };
        }
        return;
    }
    // The kernel copied only `cap` bytes into `addr` but reported the
    // untruncated length: never touch `addr` past `cap`. Requery into a
    // buffer large enough for any AF_UNIX address instead.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut storage_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        real(
            fd,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut storage_len,
        )
    } != 0
    {
        return;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut storage as *mut libc::sockaddr_storage).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_storage>(),
        )
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(addr.cast::<u8>(), cap) };
    if let Some(total) = requeried_unix(root, bytes, storage_len as usize, cap, dst) {
        unsafe { *len = total as libc::socklen_t };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &[u8] = b"/Users/me/.local/share/world/workspaces/tmp/127.77.0.1";

    fn mapped(path: &str) -> Option<String> {
        let mut out = [0u8; PATH_MAX];
        map(ROOT, path.as_bytes(), &mut out)
            .unwrap()
            .map(|n| String::from_utf8(out[..n].to_vec()).unwrap())
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
        ] {
            assert_eq!(mapped(path), None, "{path}");
        }
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
            let mut normalized_buf = [0u8; PATH_MAX];
            let normalized_len = normalize(path.as_bytes(), &mut normalized_buf).unwrap();
            let normalized_path = normalized_buf[..normalized_len].to_vec();

            let mut mapped_buf = [0u8; PATH_MAX];
            let mapped = map(ROOT, path.as_bytes(), &mut mapped_buf).unwrap();
            let mut mapped_norm_buf = [0u8; PATH_MAX];
            let mapped_norm = map(ROOT, &normalized_path, &mut mapped_norm_buf).unwrap();

            proptest::prop_assert_eq!(mapped.is_some(), mapped_norm.is_some());
            if let (Some(a), Some(b)) = (mapped, mapped_norm) {
                let mut norm_a_buf = [0u8; PATH_MAX];
                let norm_a_len = normalize(&mapped_buf[..a], &mut norm_a_buf).unwrap();
                let mut norm_b_buf = [0u8; PATH_MAX];
                let norm_b_len = normalize(&mapped_norm_buf[..b], &mut norm_b_buf).unwrap();
                proptest::prop_assert_eq!(&norm_a_buf[..norm_a_len], &norm_b_buf[..norm_b_len]);
            }
        }
    }
}
