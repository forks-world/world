//! World-specific restrictions on silo's cooperative address translation.
use std::{ffi::CStr, net::Ipv4Addr, path::Path};

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
        _ => false,
    };
    if !allowed {
        unsafe {
            *crate::errno_ptr() = libc::EACCES;
        }
    }
    allowed
}

/// Refuse child launches that would silently lose injection. This is a
/// compatibility check, not protection from a program using raw syscalls.
pub unsafe fn spawn_allowed(path: *const libc::c_char, envp: *const *const libc::c_char) -> bool {
    let valid = (|| {
        if path.is_null() || envp.is_null() {
            return false;
        }
        let name = unsafe { CStr::from_ptr(path) }.to_string_lossy();
        let path = if name.contains('/') {
            std::path::PathBuf::from(name.as_ref())
        } else {
            let Some(p) = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|p| p.join(name.as_ref()))
                .find(|p| p.is_file())
            else {
                return false;
            };
            p
        };
        let Ok(path) = path.canonicalize() else {
            return false;
        };
        if ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/System"]
            .iter()
            .any(|p| path.starts_with(Path::new(p)))
        {
            return false;
        }
        let library = std::env::var("DYLD_INSERT_LIBRARIES").unwrap_or_default();
        let ip = std::env::var("SILO_IP").unwrap_or_default();
        let mut has_library = false;
        let mut has_ip = false;
        for i in 0..65536 {
            let entry = unsafe { *envp.add(i) };
            if entry.is_null() {
                break;
            }
            let value = unsafe { CStr::from_ptr(entry) }.to_string_lossy();
            has_library |= value == format!("DYLD_INSERT_LIBRARIES={library}");
            has_ip |= value == format!("SILO_IP={ip}");
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
