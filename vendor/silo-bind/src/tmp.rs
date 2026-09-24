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
/// resolve `..`. Returns None when the result does not fit.
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

/// Write the World location for `path` into `out` as a NUL-terminated string.
/// Ok(None) means the path is used unchanged.
pub fn map(root: &[u8], path: &[u8], out: &mut [u8]) -> Result<Option<usize>, c_int> {
    if !path.starts_with(b"/") {
        return Ok(None);
    }
    let mut scratch = [0u8; PATH_MAX];
    // An overlong path is rejected by the kernel exactly as the caller wrote it.
    let Some(len) = normalize(path, &mut scratch) else {
        return Ok(None);
    };
    let path = &scratch[..len];
    if component_rest(path, root).is_some() {
        return Ok(None);
    }
    for (host, sub) in HOST_ROOTS {
        let Some(rest) = component_rest(path, host) else {
            continue;
        };
        let total = root.len() + sub.len() + rest.len();
        if total >= out.len() {
            return Err(libc::ENAMETOOLONG);
        }
        out[..root.len()].copy_from_slice(root);
        out[root.len()..root.len() + sub.len()].copy_from_slice(sub);
        out[root.len() + sub.len()..total].copy_from_slice(rest);
        out[total] = 0;
        return Ok(Some(total));
    }
    Ok(None)
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

/// Report a returned `AF_UNIX` address by its host name.
#[cfg(target_os = "macos")]
pub unsafe fn unmap_unix(addr: *mut libc::sockaddr, len: *mut libc::socklen_t) {
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let Some(root) = root() else { return };
    if addr.is_null() || len.is_null() || (unsafe { *len } as usize) <= offset {
        return;
    }
    if unsafe { (*addr).sa_family } as c_int != libc::AF_UNIX {
        return;
    }
    let un = unsafe { &mut *(addr as *mut libc::sockaddr_un) };
    let available = (unsafe { *len } as usize - offset).min(un.sun_path.len());
    let buf =
        unsafe { std::slice::from_raw_parts_mut(un.sun_path.as_mut_ptr().cast::<u8>(), available) };
    let path_len = buf.iter().position(|&b| b == 0).unwrap_or(available);
    if let Some(new_len) = unmap_in_place(root, buf, path_len) {
        buf[new_len..path_len].fill(0);
        let total = offset + new_len + usize::from(new_len < available);
        un.sun_len = total as u8;
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
            ("/tmp/", "/tmp"),
            ("/tmp/a.lock", "/tmp/a.lock"),
            ("/private/tmp/.s.PGSQL.5432", "/tmp/.s.PGSQL.5432"),
            ("/var/tmp/x", "/var/tmp/x"),
            ("/private/var/tmp", "/var/tmp"),
            ("//tmp//a/./b/../c", "/tmp/a/c"),
            ("/private/./tmp/x", "/tmp/x"),
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

    proptest::proptest! {
        #[test]
        fn map_then_unmap_names_the_host_path(rest in "(/[a-z][a-z.]{0,7}){0,6}") {
            let mut out = [0u8; PATH_MAX];
            let path = format!("/tmp{rest}");
            if let Some(n) = map(ROOT, path.as_bytes(), &mut out).unwrap() {
                let new_len = unmap_in_place(ROOT, &mut out, n).unwrap();
                let mut normalized = [0u8; PATH_MAX];
                let len = normalize(format!("/private/tmp{rest}").as_bytes(), &mut normalized).unwrap();
                proptest::prop_assert_eq!(&out[..new_len], &normalized[..len]);
            }
        }
    }
}
