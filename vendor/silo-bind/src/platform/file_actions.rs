//! Track cwd-changing actions by their opaque handle, including handle moves and
//! reallocations by other add-action calls. No private macOS structure is parsed.
//! Lock-free storage also works in post-fork paths. Exhaustion fails before a
//! cwd action is added, rather than allowing an untracked directory change.
use libc::{c_char, c_int, mode_t, posix_spawn_file_actions_t};
use std::sync::atomic::{AtomicUsize, Ordering};

static CWD_ACTIONS: [AtomicUsize; 4096] = [const { AtomicUsize::new(0) }; 4096];

unsafe fn handle(actions: *const posix_spawn_file_actions_t) -> usize {
    if actions.is_null() {
        0
    } else {
        unsafe { *actions as usize }
    }
}
fn find(value: usize) -> Option<usize> {
    if value == 0 {
        return None;
    }
    CWD_ACTIONS
        .iter()
        .position(|slot| slot.load(Ordering::Acquire) == value)
}
pub unsafe fn changes_cwd(actions: *const libc::c_void) -> bool {
    find(unsafe { handle(actions.cast()) }).is_some()
}
fn clear(value: usize) {
    if let Some(slot) = find(value) {
        CWD_ACTIONS[slot].store(0, Ordering::Release);
    }
}
fn reserve(value: usize) -> Result<(usize, bool), c_int> {
    if value == 0 {
        return Err(libc::EINVAL);
    }
    if let Some(slot) = find(value) {
        return Ok((slot, false));
    }
    for (index, slot) in CWD_ACTIONS.iter().enumerate() {
        if slot
            .compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok((index, true));
        }
    }
    Err(libc::ENOMEM)
}

#[repr(C)]
struct Interpose {
    replacement: *const (),
    original: *const (),
}
// Immutable function addresses consumed by dyld; optional originals may be null.
unsafe impl Sync for Interpose {}
macro_rules! interpose {
    ($name:ident, $replacement:ident, $original:ident) => {
        #[used]
        #[unsafe(link_section = "__DATA,__interpose")]
        static $name: Interpose = Interpose {
            replacement: $replacement as *const (),
            original: $original as *const (),
        };
    };
}

unsafe extern "C" {
    #[link_name = "posix_spawn_file_actions_init"]
    fn real_init(actions: *mut posix_spawn_file_actions_t) -> c_int;
    #[link_name = "posix_spawn_file_actions_destroy"]
    fn real_destroy(actions: *mut posix_spawn_file_actions_t) -> c_int;
}
unsafe extern "C" fn init(actions: *mut posix_spawn_file_actions_t) -> c_int {
    let result = unsafe { real_init(actions) };
    if result == 0 {
        clear(unsafe { handle(actions) });
    }
    result
}
unsafe extern "C" fn destroy(actions: *mut posix_spawn_file_actions_t) -> c_int {
    let value = unsafe { handle(actions) };
    let result = unsafe { real_destroy(actions) };
    if result == 0 {
        clear(value);
    }
    result
}
interpose!(INIT, init, real_init);
interpose!(DESTROY, destroy, real_destroy);

// macOS 26 added POSIX names alongside the _np entry points. Weak imports keep
// this shim loadable on earlier macOS; dyld ignores null interpose originals.
core::arch::global_asm!(
    ".weak_reference _posix_spawn_file_actions_addchdir",
    ".weak_reference _posix_spawn_file_actions_addfchdir",
);

macro_rules! cwd_action {
    ($entry:ident, $wrapper:ident, $original:ident, $symbol:literal, $arg:ident: $ty:ty) => {
        unsafe extern "C" {
            #[link_name = $symbol]
            fn $original(actions: *mut posix_spawn_file_actions_t, $arg: $ty) -> c_int;
        }
        unsafe extern "C" fn $wrapper(
            actions: *mut posix_spawn_file_actions_t,
            $arg: $ty,
        ) -> c_int {
            let (slot, fresh) = match reserve(unsafe { handle(actions) }) {
                Ok(slot) => slot,
                Err(error) => return error,
            };
            let result = unsafe { $original(actions, $arg) };
            let value = if result != 0 && fresh {
                0
            } else {
                unsafe { handle(actions) }
            };
            CWD_ACTIONS[slot].store(value, Ordering::Release);
            result
        }
        interpose!($entry, $wrapper, $original);
    };
}
cwd_action!(CHDIR_NP, chdir_np, real_chdir_np, "posix_spawn_file_actions_addchdir_np", path: *const c_char);
cwd_action!(FCHDIR_NP, fchdir_np, real_fchdir_np, "posix_spawn_file_actions_addfchdir_np", fd: c_int);
cwd_action!(CHDIR, chdir, real_chdir, "posix_spawn_file_actions_addchdir", path: *const c_char);
cwd_action!(FCHDIR, fchdir, real_fchdir, "posix_spawn_file_actions_addfchdir", fd: c_int);

// Adding any other action can reallocate the opaque handle. Follow that move
// so a subsequent close/dup/open cannot erase knowledge of an earlier chdir.
macro_rules! other_action {
    ($entry:ident, $wrapper:ident, $original:ident, $symbol:literal, $($arg:ident: $ty:ty),+) => {
        unsafe extern "C" {
            #[link_name = $symbol]
            fn $original(actions: *mut posix_spawn_file_actions_t, $($arg: $ty),+) -> c_int;
        }
        unsafe extern "C" fn $wrapper(actions: *mut posix_spawn_file_actions_t, $($arg: $ty),+) -> c_int {
            let slot = find(unsafe { handle(actions) });
            let result = unsafe { $original(actions, $($arg),+) };
            if let Some(slot) = slot { CWD_ACTIONS[slot].store(unsafe { handle(actions) }, Ordering::Release); }
            result
        }
        interpose!($entry, $wrapper, $original);
    };
}
other_action!(CLOSE, close, real_close, "posix_spawn_file_actions_addclose", fd: c_int);
other_action!(DUP2, dup2, real_dup2, "posix_spawn_file_actions_adddup2", fd: c_int, newfd: c_int);
other_action!(OPEN, open, real_open, "posix_spawn_file_actions_addopen", fd: c_int, path: *const c_char, flags: c_int, mode: mode_t);
other_action!(INHERIT, inherit, real_inherit, "posix_spawn_file_actions_addinherit_np", fd: c_int);
