//! Redirect shared host temp paths to the World temp root (see `crate::tmp`).
//! Path results (getcwd, realpath, readlink, AF_UNIX names) report host names.
//! Only libSystem entry points are covered: raw syscalls, pre-existing symlinks
//! into host temp roots and `fcntl(F_GETPATH)` still observe physical paths.
use crate::tmp::{PATH_MAX, copy_cwd, copy_link, map_ptr, root, unmap_cstr, unmap_unix};
use libc::{
    c_char, c_int, c_long, c_ulong, c_void, dev_t, gid_t, mode_t, off_t, size_t, sockaddr,
    socklen_t, ssize_t, uid_t,
};

macro_rules! redirect {
    ($module:ident, $symbol:literal, ($($arg:ident: $ty:ty),*) -> $ret:ty, [$($path:ident),+], $fail:expr) => {
        mod $module {
            #[allow(unused_imports)]
            use super::*;
            unsafe extern "C" {
                #[link_name = $symbol]
                fn real($($arg: $ty),*) -> $ret;
            }
            unsafe extern "C" fn entry($($arg: $ty),*) -> $ret {
                // Shadowed buffers stay alive until the real call returns.
                $(
                    let mut buf = [0u8; PATH_MAX];
                    let $path = match unsafe { map_ptr($path, &mut buf) } {
                        Ok(path) => path,
                        Err(error) => {
                            unsafe { *crate::errno_ptr() = error };
                            return $fail;
                        }
                    };
                )+
                unsafe { real($($arg),*) }
            }
            interpose!(INTERPOSE, entry, real);
        }
    };
}

type Path = *const c_char;

redirect!(stat, "stat", (path: Path, buf: *mut c_void) -> c_int, [path], -1);
redirect!(lstat, "lstat", (path: Path, buf: *mut c_void) -> c_int, [path], -1);
redirect!(stat64, "stat64", (path: Path, buf: *mut c_void) -> c_int, [path], -1);
redirect!(lstat64, "lstat64", (path: Path, buf: *mut c_void) -> c_int, [path], -1);
redirect!(fstatat, "fstatat", (fd: c_int, path: Path, buf: *mut c_void, flag: c_int) -> c_int, [path], -1);
redirect!(statfs, "statfs", (path: Path, buf: *mut c_void) -> c_int, [path], -1);
redirect!(statfs64, "statfs64", (path: Path, buf: *mut c_void) -> c_int, [path], -1);
redirect!(access, "access", (path: Path, mode: c_int) -> c_int, [path], -1);
redirect!(faccessat, "faccessat", (fd: c_int, path: Path, mode: c_int, flag: c_int) -> c_int, [path], -1);
redirect!(mkdir, "mkdir", (path: Path, mode: mode_t) -> c_int, [path], -1);
redirect!(mkdirat, "mkdirat", (fd: c_int, path: Path, mode: mode_t) -> c_int, [path], -1);
redirect!(mkfifo, "mkfifo", (path: Path, mode: mode_t) -> c_int, [path], -1);
redirect!(mkfifoat, "mkfifoat", (fd: c_int, path: Path, mode: mode_t) -> c_int, [path], -1);
redirect!(mknod, "mknod", (path: Path, mode: mode_t, dev: dev_t) -> c_int, [path], -1);
redirect!(mknodat, "mknodat", (fd: c_int, path: Path, mode: mode_t, dev: dev_t) -> c_int, [path], -1);
redirect!(rmdir, "rmdir", (path: Path) -> c_int, [path], -1);
redirect!(unlink, "unlink", (path: Path) -> c_int, [path], -1);
redirect!(unlinkat, "unlinkat", (fd: c_int, path: Path, flag: c_int) -> c_int, [path], -1);
redirect!(chdir, "chdir", (path: Path) -> c_int, [path], -1);
redirect!(chmod, "chmod", (path: Path, mode: mode_t) -> c_int, [path], -1);
redirect!(fchmodat, "fchmodat", (fd: c_int, path: Path, mode: mode_t, flag: c_int) -> c_int, [path], -1);
redirect!(chown, "chown", (path: Path, owner: uid_t, group: gid_t) -> c_int, [path], -1);
redirect!(lchown, "lchown", (path: Path, owner: uid_t, group: gid_t) -> c_int, [path], -1);
redirect!(fchownat, "fchownat", (fd: c_int, path: Path, owner: uid_t, group: gid_t, flag: c_int) -> c_int, [path], -1);
redirect!(truncate, "truncate", (path: Path, length: off_t) -> c_int, [path], -1);
redirect!(utimes, "utimes", (path: Path, times: *const c_void) -> c_int, [path], -1);
redirect!(lutimes, "lutimes", (path: Path, times: *const c_void) -> c_int, [path], -1);
redirect!(utimensat, "utimensat", (fd: c_int, path: Path, times: *const c_void, flag: c_int) -> c_int, [path], -1);
redirect!(chflags, "chflags", (path: Path, flags: u32) -> c_int, [path], -1);
redirect!(lchflags, "lchflags", (path: Path, flags: u32) -> c_int, [path], -1);
redirect!(pathconf, "pathconf", (path: Path, name: c_int) -> c_long, [path], -1);
redirect!(getxattr, "getxattr", (path: Path, name: Path, value: *mut c_void, size: size_t, position: u32, options: c_int) -> ssize_t, [path], -1);
redirect!(setxattr, "setxattr", (path: Path, name: Path, value: *const c_void, size: size_t, position: u32, options: c_int) -> c_int, [path], -1);
redirect!(removexattr, "removexattr", (path: Path, name: Path, options: c_int) -> c_int, [path], -1);
redirect!(listxattr, "listxattr", (path: Path, names: *mut c_char, size: size_t, options: c_int) -> ssize_t, [path], -1);
redirect!(getattrlist, "getattrlist", (path: Path, attrs: *mut c_void, buf: *mut c_void, size: size_t, options: u32) -> c_int, [path], -1);
redirect!(setattrlist, "setattrlist", (path: Path, attrs: *mut c_void, buf: *mut c_void, size: size_t, options: u32) -> c_int, [path], -1);
redirect!(getattrlistat, "getattrlistat", (fd: c_int, path: Path, attrs: *mut c_void, buf: *mut c_void, size: size_t, options: c_ulong) -> c_int, [path], -1);
redirect!(setattrlistat, "setattrlistat", (fd: c_int, path: Path, attrs: *mut c_void, buf: *mut c_void, size: size_t, options: u32) -> c_int, [path], -1);
redirect!(rename, "rename", (from: Path, to: Path) -> c_int, [from, to], -1);
redirect!(renameat, "renameat", (from_fd: c_int, from: Path, to_fd: c_int, to: Path) -> c_int, [from, to], -1);
redirect!(renamex_np, "renamex_np", (from: Path, to: Path, flags: u32) -> c_int, [from, to], -1);
redirect!(renameatx_np, "renameatx_np", (from_fd: c_int, from: Path, to_fd: c_int, to: Path, flags: u32) -> c_int, [from, to], -1);
redirect!(link, "link", (from: Path, to: Path) -> c_int, [from, to], -1);
redirect!(linkat, "linkat", (from_fd: c_int, from: Path, to_fd: c_int, to: Path, flag: c_int) -> c_int, [from, to], -1);
// A link target naming a host temp root is stored as its World location, so
// the kernel resolves it there; readlink reports the host name again.
redirect!(symlink, "symlink", (target: Path, path: Path) -> c_int, [target, path], -1);
redirect!(symlinkat, "symlinkat", (target: Path, fd: c_int, path: Path) -> c_int, [target, path], -1);
redirect!(clonefile, "clonefile", (from: Path, to: Path, flags: u32) -> c_int, [from, to], -1);
redirect!(clonefileat, "clonefileat", (from_fd: c_int, from: Path, to_fd: c_int, to: Path, flags: u32) -> c_int, [from, to], -1);
redirect!(fclonefileat, "fclonefileat", (from_fd: c_int, to_fd: c_int, to: Path, flags: u32) -> c_int, [to], -1);
redirect!(exchangedata, "exchangedata", (a: Path, b: Path, options: u32) -> c_int, [a, b], -1);

// open and openat take their optional mode as a C variadic argument.
unsafe extern "C" {
    #[link_name = "open"]
    fn real_open(path: Path, flags: c_int, ...) -> c_int;
    #[link_name = "open$NOCANCEL"]
    fn real_open_nocancel(path: Path, flags: c_int, ...) -> c_int;
    #[link_name = "openat"]
    fn real_openat(fd: c_int, path: Path, flags: c_int, ...) -> c_int;
    #[link_name = "openat$NOCANCEL"]
    fn real_openat_nocancel(fd: c_int, path: Path, flags: c_int, ...) -> c_int;
}

macro_rules! open_impl {
    ($impl:ident, $real:ident) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $impl(path: Path, flags: c_int, mode: c_int) -> c_int {
            let mut buf = [0u8; PATH_MAX];
            match unsafe { map_ptr(path, &mut buf) } {
                Ok(path) => unsafe { $real(path, flags, mode) },
                Err(error) => {
                    unsafe { *crate::errno_ptr() = error };
                    -1
                }
            }
        }
    };
    ($impl:ident, $real:ident, at) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $impl(fd: c_int, path: Path, flags: c_int, mode: c_int) -> c_int {
            let mut buf = [0u8; PATH_MAX];
            match unsafe { map_ptr(path, &mut buf) } {
                Ok(path) => unsafe { $real(fd, path, flags, mode) },
                Err(error) => {
                    unsafe { *crate::errno_ptr() = error };
                    -1
                }
            }
        }
    };
}
open_impl!(world_open_impl, real_open);
open_impl!(world_open_nocancel_impl, real_open_nocancel);
open_impl!(world_openat_impl, real_openat, at);
open_impl!(world_openat_nocancel_impl, real_openat_nocancel, at);

// Stable Rust cannot define C-variadic functions. Darwin arm64 passes variadic
// arguments on the stack, so load the (possibly absent) mode slot into the
// next argument register and continue in the fixed-argument implementation.
// Reading the caller's outgoing argument area is harmless when no mode exists.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".p2align 2",
    "_world_open_entry:",
    "ldr w2, [sp]",
    "b _world_open_impl",
    ".p2align 2",
    "_world_open_nocancel_entry:",
    "ldr w2, [sp]",
    "b _world_open_nocancel_impl",
    ".p2align 2",
    "_world_openat_entry:",
    "ldr w3, [sp]",
    "b _world_openat_impl",
    ".p2align 2",
    "_world_openat_nocancel_entry:",
    "ldr w3, [sp]",
    "b _world_openat_nocancel_impl",
);
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn world_open_entry();
    fn world_open_nocancel_entry();
    fn world_openat_entry();
    fn world_openat_nocancel_entry();
}
// x86_64 passes variadic arguments in the same registers as fixed ones.
#[cfg(not(target_arch = "aarch64"))]
use {
    world_open_impl as world_open_entry, world_open_nocancel_impl as world_open_nocancel_entry,
    world_openat_impl as world_openat_entry,
    world_openat_nocancel_impl as world_openat_nocancel_entry,
};
interpose!(OPEN, world_open_entry, real_open);
interpose!(OPEN_NOCANCEL, world_open_nocancel_entry, real_open_nocancel);
interpose!(OPENAT, world_openat_entry, real_openat);
interpose!(
    OPENAT_NOCANCEL,
    world_openat_nocancel_entry,
    real_openat_nocancel
);

unsafe extern "C" {
    #[link_name = "readlink"]
    fn real_readlink(path: Path, buf: *mut c_char, size: size_t) -> ssize_t;
    #[link_name = "readlinkat"]
    fn real_readlinkat(fd: c_int, path: Path, buf: *mut c_char, size: size_t) -> ssize_t;
    #[link_name = "realpath"]
    fn real_realpath(path: Path, resolved: *mut c_char) -> *mut c_char;
    #[link_name = "realpath$DARWIN_EXTSN"]
    fn real_realpath_extsn(path: Path, resolved: *mut c_char) -> *mut c_char;
    #[link_name = "getcwd"]
    fn real_getcwd(buf: *mut c_char, size: size_t) -> *mut c_char;
    #[link_name = "getsockname"]
    fn real_getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int;
    #[link_name = "getpeername"]
    fn real_getpeername(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int;
}

// A caller's buffer may fit the (shorter) host name but not the physical
// name: read the real link into a full-sized local buffer first, so
// truncation is judged against the host name rather than the physical one.
unsafe extern "C" fn readlink_entry(path: Path, buf: *mut c_char, size: size_t) -> ssize_t {
    let mut mapped = [0u8; PATH_MAX];
    let path = match unsafe { map_ptr(path, &mut mapped) } {
        Ok(path) => path,
        Err(error) => {
            unsafe { *crate::errno_ptr() = error };
            return -1;
        }
    };
    let Some(root) = root() else {
        return unsafe { real_readlink(path, buf, size) };
    };
    if buf.is_null() || size == 0 {
        return unsafe { real_readlink(path, buf, size) };
    }
    let mut local = [0u8; PATH_MAX];
    let n = unsafe { real_readlink(path, local.as_mut_ptr().cast(), PATH_MAX) };
    if n < 0 {
        return n;
    }
    if n as usize == PATH_MAX {
        // Our probe buffer may itself have truncated; let the real call
        // apply the caller's exact size instead of guessing.
        return unsafe { real_readlink(path, buf, size) };
    }
    let dst = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), size) };
    copy_link(root, &mut local, n as usize, dst) as ssize_t
}
unsafe extern "C" fn readlinkat_entry(
    fd: c_int,
    path: Path,
    buf: *mut c_char,
    size: size_t,
) -> ssize_t {
    let mut mapped = [0u8; PATH_MAX];
    let path = match unsafe { map_ptr(path, &mut mapped) } {
        Ok(path) => path,
        Err(error) => {
            unsafe { *crate::errno_ptr() = error };
            return -1;
        }
    };
    let Some(root) = root() else {
        return unsafe { real_readlinkat(fd, path, buf, size) };
    };
    if buf.is_null() || size == 0 {
        return unsafe { real_readlinkat(fd, path, buf, size) };
    }
    let mut local = [0u8; PATH_MAX];
    let n = unsafe { real_readlinkat(fd, path, local.as_mut_ptr().cast(), PATH_MAX) };
    if n < 0 {
        return n;
    }
    if n as usize == PATH_MAX {
        return unsafe { real_readlinkat(fd, path, buf, size) };
    }
    let dst = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), size) };
    copy_link(root, &mut local, n as usize, dst) as ssize_t
}
interpose!(READLINK, readlink_entry, real_readlink);
interpose!(READLINKAT, readlinkat_entry, real_readlinkat);

macro_rules! realpath_entry {
    ($entry:ident, $real:ident) => {
        unsafe extern "C" fn $entry(path: Path, resolved: *mut c_char) -> *mut c_char {
            let mut mapped = [0u8; PATH_MAX];
            match unsafe { map_ptr(path, &mut mapped) } {
                Ok(path) => {
                    let result = unsafe { $real(path, resolved) };
                    unsafe { unmap_cstr(result) };
                    result
                }
                Err(error) => {
                    unsafe { *crate::errno_ptr() = error };
                    std::ptr::null_mut()
                }
            }
        }
    };
}
realpath_entry!(realpath_entry, real_realpath);
realpath_entry!(realpath_extsn_entry, real_realpath_extsn);
interpose!(REALPATH, realpath_entry, real_realpath);
interpose!(REALPATH_EXTSN, realpath_extsn_entry, real_realpath_extsn);

// A caller's buffer may fit the (shorter) host name but not the physical
// one: probe the real cwd into a full-sized local buffer first, so ERANGE is
// judged against the host name rather than the physical name.
unsafe extern "C" fn getcwd_entry(buf: *mut c_char, size: size_t) -> *mut c_char {
    let Some(root) = root() else {
        return unsafe { real_getcwd(buf, size) };
    };
    if buf.is_null() {
        let result = unsafe { real_getcwd(std::ptr::null_mut(), 0) };
        if result.is_null() {
            return result;
        }
        unsafe { unmap_cstr(result) };
        if size > 0 {
            let len = unsafe { libc::strlen(result) };
            if len + 1 > size {
                unsafe { libc::free(result.cast()) };
                unsafe { *crate::errno_ptr() = libc::ERANGE };
                return std::ptr::null_mut();
            }
        }
        return result;
    }
    if size == 0 {
        unsafe { *crate::errno_ptr() = libc::EINVAL };
        return std::ptr::null_mut();
    }
    let mut local = [0u8; PATH_MAX];
    if unsafe { real_getcwd(local.as_mut_ptr().cast(), PATH_MAX) }.is_null() {
        // Preserve whatever errno this call sets.
        return unsafe { real_getcwd(buf, size) };
    }
    let len = unsafe { libc::strlen(local.as_ptr().cast()) };
    let dst = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), size) };
    match copy_cwd(root, &mut local, len, dst) {
        Ok(_) => buf,
        Err(error) => {
            unsafe { *crate::errno_ptr() = error };
            std::ptr::null_mut()
        }
    }
}
interpose!(GETCWD, getcwd_entry, real_getcwd);

unsafe extern "C" fn getsockname_entry(
    fd: c_int,
    addr: *mut sockaddr,
    len: *mut socklen_t,
) -> c_int {
    // The kernel copies at most the caller's original capacity into `addr`
    // but reports the untruncated length in `*len`; capture that capacity
    // before the real call so a small buffer is never read or written past it.
    let cap = if len.is_null() { 0 } else { unsafe { *len } };
    let result = unsafe { real_getsockname(fd, addr, len) };
    if result == 0 {
        unsafe { unmap_unix(fd, addr, cap, len, real_getsockname) };
    }
    result
}
unsafe extern "C" fn getpeername_entry(
    fd: c_int,
    addr: *mut sockaddr,
    len: *mut socklen_t,
) -> c_int {
    let cap = if len.is_null() { 0 } else { unsafe { *len } };
    let result = unsafe { real_getpeername(fd, addr, len) };
    if result == 0 {
        unsafe { unmap_unix(fd, addr, cap, len, real_getpeername) };
    }
    result
}
interpose!(GETSOCKNAME, getsockname_entry, real_getsockname);
interpose!(GETPEERNAME, getpeername_entry, real_getpeername);
