//! World-specific restrictions on silo's cooperative address translation.
use std::{ffi::CStr, net::Ipv4Addr, path::Path};

static INJECTION: std::sync::OnceLock<Option<(String, String)>> = std::sync::OnceLock::new();

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

/// Resolve a spawnp candidate once so policy checks, shebang inspection and
/// the actual spawn all refer to the same file. argv itself remains untouched.
pub unsafe fn path_candidate(path: *const libc::c_char) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    if path.is_null() {
        return None;
    }
    let name = std::ffi::OsStr::from_bytes(unsafe { CStr::from_ptr(path) }.to_bytes());
    if name.as_bytes().contains(&b'/') {
        return Some(unsafe { CStr::from_ptr(path) }.to_owned());
    }
    let candidate = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(name))
        .find(|p| executable_file(p))?;
    // Keep the selected pathname (including a symlink) as the script argv entry.
    let candidate = std::env::current_dir().ok()?.join(candidate);
    std::ffi::CString::new(candidate.as_os_str().as_bytes()).ok()
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
        let mut has_library = false;
        let mut has_ip = false;
        for i in 0..65536 {
            let entry = unsafe { *envp.add(i) };
            if entry.is_null() {
                break;
            }
            let value = unsafe { CStr::from_ptr(entry) }.to_string_lossy();
            if let Some(value) = value.strip_prefix("DYLD_INSERT_LIBRARIES=") {
                if value != library {
                    return false;
                }
                has_library = true;
            }
            if let Some(value) = value.strip_prefix("SILO_IP=") {
                if value != ip {
                    return false;
                }
                has_ip = true;
            }
        }
        has_library && has_ip && !library.is_empty() && !ip.is_empty()
    })();
    if !valid {
        unsafe {
            *crate::errno_ptr() = libc::EACCES;
        }
    }
    valid
}

pub fn acknowledge() {
    // Constructor-time values cannot be replaced by later setenv calls.
    INJECTION.get_or_init(|| {
        Some((
            std::env::var("DYLD_INSERT_LIBRARIES").ok()?,
            std::env::var("SILO_IP").ok()?,
        ))
    });
    if std::env::var("WORLD_SILO_ACTIVE").as_deref() != Ok("1") {
        return;
    }
    if crate::get_silo_ip().is_none() {
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
