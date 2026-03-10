//! Tests for the `main.rs` module-level doc comment — Finding E in WINDOWS.md.
//!
//! These tests verify that the module doc comment accurately reflects all
//! supported platforms, including Windows.

use std::fs;

/// Resolve the repository root via `CARGO_MANIFEST_DIR`.
fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

/// Read `src/main.rs` as a string, panicking if the file cannot be read.
fn read_main_rs() -> String {
    let path = repo_root().join("src").join("main.rs");
    fs::read_to_string(&path).expect("Failed to read src/main.rs")
}

// ---------------------------------------------------------------------------
// Cross-platform support doc comment
// ---------------------------------------------------------------------------

#[test]
fn main_rs_doc_mentions_windows() {
    let content = read_main_rs();
    // Verify that at least one module-level doc comment line (`//!`) mentions Windows.
    let doc_mentions_windows = content
        .lines()
        .filter(|line| line.starts_with("//!"))
        .any(|line| line.contains("Windows"));
    assert!(
        doc_mentions_windows,
        "src/main.rs module doc comment must mention Windows as a supported platform"
    );
}

#[test]
fn main_rs_doc_cross_platform_includes_windows_experimental() {
    let content = read_main_rs();
    assert!(
        content.contains("Cross-platform support (macOS, Linux, Windows (experimental))"),
        "src/main.rs module doc comment must list \
         'Cross-platform support (macOS, Linux, Windows (experimental))'"
    );
}

#[test]
fn main_rs_doc_cross_platform_does_not_omit_macos_linux() {
    let content = read_main_rs();
    // macOS and Linux must still appear in the same cross-platform line
    assert!(
        content.contains("macOS") && content.contains("Linux"),
        "src/main.rs module doc comment must still mention macOS and Linux"
    );
}
