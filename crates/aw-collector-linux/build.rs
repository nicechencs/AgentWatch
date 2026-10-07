//! Build script for the Linux collector.
//!
//! P1-LNX-01 does not invoke clang, llvm, bpf-linker, or a nightly toolchain.
//! Those exist only on a Linux CI image, and only once SPIKE-01 has landed a
//! real program. Until then this script records that no object was embedded, so
//! a release build on any host still succeeds and the loader can see the absence
//! (`EmbeddedProgram::empty`) instead of a fake object.
//!
//! When a later task does embed bytecode, it should:
//! 1. run `cargo xtask build-ebpf` first (that is a separate crate, not a member);
//! 2. point `AW_EBPF_OBJECT` at the produced ELF;
//! 3. replace the `empty` marker below with `include_bytes!` of that file.

fn main() {
    println!("cargo:rerun-if-env-changed=AW_EBPF_OBJECT");
    println!("cargo:rerun-if-changed=build.rs");

    let object = std::env::var_os("AW_EBPF_OBJECT");
    if object.is_some() {
        // A path may be set by a future Linux job. This card does not read or
        // compile it: doing so would require the BPF toolchain on every build,
        // including Windows `cargo check`.
        println!("cargo:rustc-cfg=aw_ebpf_object_declared");
    }
    println!("cargo:rustc-env=AW_EBPF_EMBEDDED=0");
}
