fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // The socket probe exercises optional macOS 26 APIs on new systems,
        // but must still link against older SDKs and load on older systems.
        println!("cargo:rustc-link-arg-examples=-Wl,-weak_reference_mismatches,weak");
        for symbol in ["addchdir", "addfchdir"] {
            println!("cargo:rustc-link-arg-examples=-Wl,-U,_posix_spawn_file_actions_{symbol}");
        }
    }
}
