//! World-private temporary directories. Paths below the shared host temp roots
//! are redirected below `WORLD_TMP`, so equal lock, socket and file names in
//! different workspaces stay distinct. Mapping is lexical, allocation-free and
//! async-signal-safe: interposed calls may run between fork and exec. The pure
//! mapper itself lives in `world-tmp-path`, shared with world-runtime's entry
//! point resolution (and tested there, unconditionally), so that crate stays
//! free of this crate's process-wide constructor and `#[no_mangle]` libc
//! interposers. This module is only the macOS libSystem-facing glue around
//! `WORLD_TMP` and is not compiled at all elsewhere (see `lib.rs`).
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

pub(crate) use world_tmp_path::{
    PATH_MAX, SUN_PATH_OFFSET, copy_cwd, copy_link, map, requeried_unix, unmap_in_place,
    unmap_sockaddr, valid_root,
};

static ROOT: OnceLock<Option<Box<[u8]>>> = OnceLock::new();

/// Read `WORLD_TMP` once, before any interposed call can observe it. Returns
/// false when a value is present but unusable. The root must be canonical: a
/// symlink in it would make the prefix check below observe a different
/// string than the kernel resolves, so escaping `..` handling could be fooled
/// by its own root.
pub fn init() -> bool {
    let value = std::env::var_os("WORLD_TMP");
    let valid = value.as_ref().is_none_or(|v| {
        use std::os::unix::ffi::OsStrExt;
        valid_root(v.as_bytes()) && std::fs::canonicalize(v).is_ok_and(|c| c.as_os_str() == v)
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

/// Allocating form for code that already runs outside async-signal context,
/// such as the `posix_spawnp`/`env` PATH search below. No root means `path`
/// is used unchanged; a mapping error is returned rather than silently
/// falling back to the (wrong, host) path.
pub fn map_path(path: &std::path::Path) -> Result<std::path::PathBuf, c_int> {
    use std::os::unix::ffi::OsStrExt;
    let Some(root) = root() else {
        return Ok(path.to_owned());
    };
    let root = std::path::Path::new(std::ffi::OsStr::from_bytes(root));
    world_tmp_path::map_under(root, path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
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
