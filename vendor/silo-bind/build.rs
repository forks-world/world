fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // Older SDKs do not declare these macOS 26 symbols. Permit just these
        // optional imports, retaining the assembly weak-reference annotation
        // when Rust places references in separate codegen units.
        println!("cargo:rustc-link-arg=-Wl,-weak_reference_mismatches,weak");
        for symbol in ["addchdir", "addfchdir"] {
            println!("cargo:rustc-link-arg=-Wl,-U,_posix_spawn_file_actions_{symbol}");
        }
    }
}
