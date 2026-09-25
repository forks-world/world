//! World-specific restrictions on silo's cooperative address translation.
use std::{
    ffi::{CStr, OsStr},
    net::Ipv4Addr,
    os::raw::c_int,
    path::{Path, PathBuf},
};

/// The `DYLD_INSERT_LIBRARIES` and `SILO_IP` values this process was itself
/// launched with, as raw bytes (see `injection_matches`).
type Injection = (Box<[u8]>, Box<[u8]>);
static INJECTION: std::sync::OnceLock<Option<Injection>> = std::sync::OnceLock::new();

pub unsafe fn address_allowed(
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
    binding: bool,
) -> bool {
    if addr.is_null() {
        return true;
    }
    if (len as usize) < std::mem::size_of::<libc::sa_family_t>() + 1 {
        unsafe {
            *crate::errno_ptr() = libc::EINVAL;
        }
        return false;
    }
    let Some(own) = crate::get_silo_ip() else {
        unsafe {
            *crate::errno_ptr() = libc::EACCES;
        }
        return false;
    };
    let check = |ip: u32| {
        let v = Ipv4Addr::from(u32::from_be(ip));
        if v.is_loopback() {
            ip == own || v == Ipv4Addr::LOCALHOST
        } else {
            !binding || v.is_unspecified()
        }
    };
    let allowed = match unsafe { (*addr).sa_family as i32 } {
        libc::AF_INET if (len as usize) >= std::mem::size_of::<libc::sockaddr_in>() => {
            check(unsafe { (*(addr as *const libc::sockaddr_in)).sin_addr.s_addr })
        }
        libc::AF_INET6 if (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let bytes = unsafe { (*(addr as *const libc::sockaddr_in6)).sin6_addr.s6_addr };
            let ip = std::net::Ipv6Addr::from(bytes);
            if let Some(ip) = ip.to_ipv4_mapped() {
                check(u32::from(ip).to_be())
            } else {
                !binding || ip.is_loopback() || ip.is_unspecified()
            }
        }
        libc::AF_UNIX => true,
        libc::AF_UNSPEC if !binding => true,
        _ => false,
    };
    if !allowed {
        unsafe {
            *crate::errno_ptr() = libc::EACCES;
        }
    }
    allowed
}

fn executable_file(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    path.is_file()
        && std::ffi::CString::new(path.as_os_str().as_bytes())
            .is_ok_and(|path| unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 })
}

/// Walk `path_var` like `execvp`, joining each entry against `cwd` (an empty
/// entry means `cwd` itself, matching `posix_spawnp`) before asking `map` to
/// redirect the candidate below a temp root. A `map` error that just means
/// "this entry does not exist" (`skippable`) moves on to the next entry; any
/// other error aborts the whole search. An absolute entry needs no `cwd` and
/// is used as-is; a relative one (including the empty-entry "cwd itself"
/// case) is skipped without `cwd`, rather than handed to `map` bare -- see
/// `path_candidate`, whose own cwd lookup can fail once the caller's working
/// directory has been removed. Pure and allocation-only, so it is
/// unit-testable without touching the filesystem.
fn search_path(
    name: &OsStr,
    cwd: Option<&Path>,
    path_var: &OsStr,
    map: impl Fn(&Path) -> Result<PathBuf, c_int>,
    exec: impl Fn(&Path) -> bool,
) -> Result<PathBuf, c_int> {
    for entry in std::env::split_paths(path_var) {
        let candidate = if entry.is_absolute() {
            entry.join(name)
        } else if let Some(cwd) = cwd {
            cwd.join(&entry).join(name)
        } else {
            continue;
        };
        let mapped = match map(&candidate) {
            Ok(p) => p,
            Err(e) if world_tmp_path::skippable(e) => continue,
            Err(e) => return Err(e),
        };
        if exec(&mapped) {
            return Ok(mapped);
        }
    }
    Err(libc::EACCES)
}

/// Resolve a spawnp candidate once so policy checks, shebang inspection and
/// the actual spawn all refer to the same file. argv itself remains untouched.
/// The returned pathname (including a symlink) is absolute, since it is used
/// both as the exec target and, for a shebang script, as the script's own
/// argv entry (see `resolve_sip_exec`).
pub unsafe fn path_candidate(path: *const libc::c_char) -> Result<std::ffi::CString, c_int> {
    use std::os::unix::ffi::OsStrExt;
    if path.is_null() {
        return Err(libc::EACCES);
    }
    let name = std::ffi::OsStr::from_bytes(unsafe { CStr::from_ptr(path) }.to_bytes());
    if name.as_bytes().contains(&b'/') {
        return Ok(unsafe { CStr::from_ptr(path) }.to_owned());
    }
    // Our own image's calls are not interposed, so this is the physical cwd,
    // when one can still be determined at all (getcwd fails once the caller's
    // working directory has itself been removed). An absolute PATH entry
    // needs no cwd and is still redirected below; only a relative one is then
    // skipped, in `search_path`, rather than falling back to the host path.
    let cwd = std::env::current_dir().ok();
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let found = search_path(
        name,
        cwd.as_deref(),
        &path_var,
        crate::tmp::map_path,
        executable_file,
    )?;
    std::ffi::CString::new(found.as_os_str().as_bytes()).map_err(|_| libc::EACCES)
}

/// The final exec target must be a native binary, never an unresolved script.
/// Canonicalization also rejects PATH entries symlinked to a protected binary.
pub unsafe fn native_target(path: *const libc::c_char) -> bool {
    let valid = (|| {
        if path.is_null() {
            return false;
        }
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(
            unsafe { CStr::from_ptr(path) }.to_bytes(),
        ));
        if !executable_file(path) {
            return false;
        }
        let Ok(path) = path.canonicalize() else {
            return false;
        };
        if ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/System"]
            .iter()
            .any(|p| path.starts_with(Path::new(p)))
        {
            return false;
        }
        if !path.is_file() {
            return false;
        }
        use std::os::unix::fs::PermissionsExt;
        let Ok(metadata) = path.metadata() else {
            return false;
        };
        if metadata.permissions().mode() & 0o6000 != 0 {
            return false;
        }
        let Ok(mut file) = std::fs::File::open(path) else {
            return false;
        };
        let mut magic = [0; 4];
        if std::io::Read::read_exact(&mut file, &mut magic).is_err() {
            return false;
        }
        [0xfeedfacf, 0xfeedface, 0xbebafeca, 0xcafebabe].contains(&u32::from_le_bytes(magic))
    })();
    if !valid {
        unsafe {
            *crate::errno_ptr() = libc::EACCES;
        }
    }
    valid
}

/// True when every `DYLD_INSERT_LIBRARIES=`/`SILO_IP=`/`WORLD_TMP=` entry in
/// `entries` carries exactly the expected bytes (duplicates are all checked,
/// so a later, conflicting occurrence cannot slip past an earlier matching
/// one), `library`/`ip` were both seen and are non-empty, and `WORLD_TMP`
/// was seen exactly when `tmp` expects one. Comparison is byte-for-byte
/// rather than through any lossy text conversion: a replacement character
/// can make two different invalid byte sequences compare equal as strings,
/// which would let a forged value slip past a lossy comparison.
fn injection_matches<'a>(
    entries: impl IntoIterator<Item = &'a [u8]>,
    library: &[u8],
    ip: &[u8],
    tmp: Option<&[u8]>,
) -> bool {
    let mut has_library = false;
    let mut has_ip = false;
    let mut has_tmp = false;
    for entry in entries {
        if let Some(value) = entry.strip_prefix(b"DYLD_INSERT_LIBRARIES=") {
            if value != library {
                return false;
            }
            has_library = true;
        } else if let Some(value) = entry.strip_prefix(b"SILO_IP=") {
            if value != ip {
                return false;
            }
            has_ip = true;
        } else if let Some(value) = entry.strip_prefix(b"WORLD_TMP=") {
            let Some(expected) = tmp else {
                return false;
            };
            if value != expected {
                return false;
            }
            has_tmp = true;
        }
    }
    has_library && has_ip && (has_tmp == tmp.is_some()) && !library.is_empty() && !ip.is_empty()
}

/// Refuse child launches that would silently lose injection. This is a
/// compatibility check, not protection from a program using raw syscalls.
pub unsafe fn spawn_allowed(path: *const libc::c_char, envp: *const *const libc::c_char) -> bool {
    let valid = (|| {
        if path.is_null() || envp.is_null() {
            return false;
        }
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(
            unsafe { CStr::from_ptr(path) }.to_bytes(),
        ));
        if !executable_file(path) {
            return false;
        }
        let Ok(path) = path.canonicalize() else {
            return false;
        };
        if ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/System"]
            .iter()
            .any(|p| path.starts_with(Path::new(p)))
        {
            return false;
        }
        let Some((library, ip)) = INJECTION.get().and_then(Option::as_ref) else {
            return false;
        };
        // No allocation: each entry borrows straight from the child's envp.
        let entries = (0..65536)
            .map(|i| unsafe { *envp.add(i) })
            .take_while(|entry| !entry.is_null())
            .map(|entry| unsafe { CStr::from_ptr(entry) }.to_bytes());
        // A child without the same temp root would silently share host /tmp.
        injection_matches(entries, library, ip, crate::tmp::root())
    })();
    if !valid {
        unsafe {
            *crate::errno_ptr() = libc::EACCES;
        }
    }
    valid
}

pub fn acknowledge(tmp_valid: bool) {
    // Constructor-time values cannot be replaced by later setenv calls.
    INJECTION.get_or_init(|| {
        use std::os::unix::ffi::OsStrExt;
        let library = std::env::var_os("DYLD_INSERT_LIBRARIES")?;
        let ip = std::env::var_os("SILO_IP")?;
        Some((
            library.as_bytes().to_vec().into_boxed_slice(),
            ip.as_bytes().to_vec().into_boxed_slice(),
        ))
    });
    if std::env::var("WORLD_SILO_ACTIVE").as_deref() != Ok("1") {
        return;
    }
    if crate::get_silo_ip().is_none() || !tmp_valid || crate::tmp::root().is_none() {
        unsafe {
            libc::_exit(125);
        }
    }
    let Ok(path) = std::env::var("WORLD_SILO_ACK") else {
        unsafe {
            libc::_exit(125);
        }
    };
    let Ok(path) = std::ffi::CString::new(path) else {
        unsafe {
            libc::_exit(125);
        }
    };
    // SAFETY: path is a NUL-terminated CString; the fixed byte string is valid
    // for the duration of write. O_NOFOLLOW avoids following a replaced link.
    unsafe {
        // Descendants share this acknowledgement file. Never truncate a valid
        // acknowledgement while the supervisor or another constructor reads it.
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NOFOLLOW);
        if fd < 0 {
            libc::_exit(125);
        }
        let data = b"world-silo-v1";
        let n = libc::write(fd, data.as_ptr().cast(), data.len());
        libc::close(fd);
        if n != data.len() as isize {
            libc::_exit(125);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_path_maps_a_relative_entry_crossing_tmp_after_absolutizing() {
        // The entry itself never mentions /tmp; only joining it against cwd
        // does, so the map function only ever sees absolute candidates.
        let cwd = Path::new("/tmp/wt-x");
        let map = |p: &Path| -> Result<PathBuf, c_int> {
            let bytes = p.as_os_str().as_encoded_bytes();
            if let Some(rest) = bytes.strip_prefix(b"/tmp/") {
                Ok(PathBuf::from(format!(
                    "/root/tmp/{}",
                    std::str::from_utf8(rest).unwrap()
                )))
            } else {
                Ok(p.to_owned())
            }
        };
        let found = search_path(
            OsStr::new("probe"),
            Some(cwd),
            OsStr::new("probe-dir"),
            map,
            |_| true,
        )
        .unwrap();
        assert_eq!(found, Path::new("/root/tmp/wt-x/probe-dir/probe"));
    }

    #[test]
    fn search_path_skips_enoent_and_tries_the_next_entry() {
        let cwd = Path::new("/cwd");
        let map = |p: &Path| -> Result<PathBuf, c_int> {
            if p == Path::new("/cwd/a/probe") {
                Err(libc::ENOENT)
            } else {
                Ok(p.to_owned())
            }
        };
        let found = search_path(
            OsStr::new("probe"),
            Some(cwd),
            OsStr::new("a:b"),
            map,
            |_| true,
        )
        .unwrap();
        assert_eq!(found, Path::new("/cwd/b/probe"));
    }

    #[test]
    fn search_path_propagates_a_non_skippable_error() {
        let cwd = Path::new("/cwd");
        let map = |_: &Path| -> Result<PathBuf, c_int> { Err(libc::ELOOP) };
        let err = search_path(OsStr::new("probe"), Some(cwd), OsStr::new("a"), map, |_| {
            true
        })
        .unwrap_err();
        assert_eq!(err, libc::ELOOP);
    }

    #[test]
    fn search_path_fails_with_eacces_when_nothing_is_found() {
        let cwd = Path::new("/cwd");
        let map = |p: &Path| -> Result<PathBuf, c_int> { Ok(p.to_owned()) };
        let err = search_path(
            OsStr::new("probe"),
            Some(cwd),
            OsStr::new("a:b"),
            map,
            |_| false,
        )
        .unwrap_err();
        assert_eq!(err, libc::EACCES);
    }

    #[test]
    fn search_path_empty_entry_means_cwd() {
        let cwd = Path::new("/cwd");
        let map = |p: &Path| -> Result<PathBuf, c_int> { Ok(p.to_owned()) };
        let found = search_path(OsStr::new("probe"), Some(cwd), OsStr::new(""), map, |_| {
            true
        })
        .unwrap();
        assert_eq!(found, Path::new("/cwd/probe"));
    }

    #[test]
    fn search_path_absolute_entry_without_cwd_is_still_mapped() {
        // No cwd is needed for an absolute entry: it is joined and mapped
        // as-is, and `map` never has to see the (unavailable) name "a".
        let map = |p: &Path| -> Result<PathBuf, c_int> {
            assert_eq!(p, Path::new("/abs/probe"));
            Ok(p.to_owned())
        };
        let found = search_path(OsStr::new("probe"), None, OsStr::new("a:/abs"), map, |_| {
            true
        })
        .unwrap();
        assert_eq!(found, Path::new("/abs/probe"));
    }

    #[test]
    fn search_path_relative_entries_without_cwd_are_skipped() {
        let map = |p: &Path| -> Result<PathBuf, c_int> { Ok(p.to_owned()) };
        let err =
            search_path(OsStr::new("probe"), None, OsStr::new(""), map, |_| true).unwrap_err();
        assert_eq!(err, libc::EACCES);
        let err =
            search_path(OsStr::new("probe"), None, OsStr::new("a"), map, |_| true).unwrap_err();
        assert_eq!(err, libc::EACCES);
    }

    #[test]
    fn search_path_without_cwd_still_redirects_a_tmp_rooted_absolute_entry() {
        let map = |p: &Path| -> Result<PathBuf, c_int> {
            let bytes = p.as_os_str().as_encoded_bytes();
            if let Some(rest) = bytes.strip_prefix(b"/tmp/") {
                Ok(PathBuf::from(format!(
                    "/root/tmp/{}",
                    std::str::from_utf8(rest).unwrap()
                )))
            } else {
                Ok(p.to_owned())
            }
        };
        let found = search_path(OsStr::new("probe"), None, OsStr::new("/tmp/x"), map, |_| {
            true
        })
        .unwrap();
        assert_eq!(found, Path::new("/root/tmp/x/probe"));
    }

    #[test]
    fn injection_matches_non_utf8_tmp_root_exact_bytes() {
        let tmp: &[u8] = b"/U/\xff/w";
        let entries: Vec<&[u8]> = vec![
            b"WORLD_TMP=/U/\xff/w",
            b"DYLD_INSERT_LIBRARIES=lib",
            b"SILO_IP=1.2.3.4",
        ];
        assert!(injection_matches(entries, b"lib", b"1.2.3.4", Some(tmp)));
    }

    #[test]
    fn injection_matches_rejects_a_lossy_look_alike() {
        // The lossy decoding of b"/U/\xff/w" is "/U/\u{fffd}/w"; a *different*
        // invalid byte sequence that lossy-decodes the same way must not be
        // accepted as a byte-exact match.
        let tmp: &[u8] = b"/U/\xff/w";
        let look_alike: &[u8] = "/U/\u{fffd}/w".as_bytes();
        assert_ne!(tmp, look_alike);
        let mut world_tmp_entry = b"WORLD_TMP=".to_vec();
        world_tmp_entry.extend_from_slice(look_alike);
        let entries: Vec<&[u8]> = vec![
            b"DYLD_INSERT_LIBRARIES=lib",
            b"SILO_IP=1.2.3.4",
            &world_tmp_entry,
        ];
        assert!(!injection_matches(entries, b"lib", b"1.2.3.4", Some(tmp)));
    }

    #[test]
    fn injection_matches_rejects_a_conflicting_duplicate_world_tmp() {
        let entries: Vec<&[u8]> = vec![
            b"DYLD_INSERT_LIBRARIES=lib",
            b"SILO_IP=1.2.3.4",
            b"WORLD_TMP=/root/tmp/w",
            b"WORLD_TMP=/root/tmp/other",
        ];
        assert!(!injection_matches(
            entries,
            b"lib",
            b"1.2.3.4",
            Some(b"/root/tmp/w")
        ));
    }

    #[test]
    fn injection_matches_rejects_missing_world_tmp_when_expected() {
        let entries: Vec<&[u8]> = vec![b"DYLD_INSERT_LIBRARIES=lib", b"SILO_IP=1.2.3.4"];
        assert!(!injection_matches(
            entries,
            b"lib",
            b"1.2.3.4",
            Some(b"/root/tmp/w")
        ));
    }

    #[test]
    fn injection_matches_rejects_world_tmp_present_when_not_expected() {
        let entries: Vec<&[u8]> = vec![
            b"DYLD_INSERT_LIBRARIES=lib",
            b"SILO_IP=1.2.3.4",
            b"WORLD_TMP=/root/tmp/w",
        ];
        assert!(!injection_matches(entries, b"lib", b"1.2.3.4", None));
    }

    #[test]
    fn injection_matches_accepts_no_tmp_when_none_expected() {
        let entries: Vec<&[u8]> = vec![b"DYLD_INSERT_LIBRARIES=lib", b"SILO_IP=1.2.3.4"];
        assert!(injection_matches(entries, b"lib", b"1.2.3.4", None));
    }
}
