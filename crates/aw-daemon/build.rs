//! Stamp whether `ui/dist` exists so `assets.rs` can compile without it.
//!
//! `include_dir` / `RustEmbed` fail the build when the folder is missing.
//! This script sets `aw_ui_dist` only when `ui/dist` is a directory. The HTTP
//! layer then serves an empty asset set instead of failing `cargo check`.

use std::path::Path;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(aw_ui_dist)");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dist = manifest.join("../../ui/dist");
    println!("cargo:rerun-if-changed=../../ui/dist");
    println!("cargo:rerun-if-env-changed=AW_UI_DEV_URL");
    if dist.is_dir() {
        println!("cargo:rustc-cfg=aw_ui_dist");
        println!("cargo:rustc-env=AW_UI_DIST_PRESENT=1");
    } else {
        println!("cargo:rustc-env=AW_UI_DIST_PRESENT=0");
    }
}
