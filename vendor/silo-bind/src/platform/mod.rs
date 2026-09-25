#[cfg(target_os = "macos")]
#[repr(C)]
pub(crate) struct Interpose {
    pub replacement: *const (),
    pub original: *const (),
}
// Immutable function addresses consumed by dyld; optional originals may be null.
#[cfg(target_os = "macos")]
unsafe impl Sync for Interpose {}
#[cfg(target_os = "macos")]
macro_rules! interpose {
    ($name:ident, $replacement:ident, $original:ident) => {
        #[used]
        #[unsafe(link_section = "__DATA,__interpose")]
        static $name: $crate::platform::Interpose = $crate::platform::Interpose {
            replacement: $replacement as *const (),
            original: $original as *const (),
        };
    };
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod file_actions;

#[cfg(target_os = "macos")]
mod paths;
