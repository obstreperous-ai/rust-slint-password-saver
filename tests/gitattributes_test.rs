//! Tests for `.gitattributes` — line-ending hygiene (Finding B in WINDOWS.md).
//!
//! These tests verify that:
//! 1. The `.gitattributes` file exists at the repository root.
//! 2. It contains the required global `* text=auto eol=lf` rule.
//! 3. All critical source-file patterns have an explicit `eol=lf` rule.
//! 4. Binary file patterns are marked as `binary` (no line-ending conversion).
//! 5. Source files in the repository contain only LF line endings (no CRLF bytes).

use std::fs;
use std::path::Path;

/// Resolve the repository root by walking up from the manifest directory.
fn repo_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is set by Cargo when running tests and points to the
    // directory containing `Cargo.toml`, which is the repository root.
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

// ---------------------------------------------------------------------------
// Existence and basic structure
// ---------------------------------------------------------------------------

#[test]
fn gitattributes_file_exists() {
    let path = repo_root().join(".gitattributes");
    assert!(
        path.exists(),
        ".gitattributes must exist at the repository root to enforce LF line endings"
    );
}

#[test]
fn gitattributes_is_not_empty() {
    let path = repo_root().join(".gitattributes");
    let content = fs::read_to_string(&path).expect("Failed to read .gitattributes");
    assert!(
        !content.trim().is_empty(),
        ".gitattributes must not be empty"
    );
}

// ---------------------------------------------------------------------------
// Global catch-all rule
// ---------------------------------------------------------------------------

#[test]
fn gitattributes_has_global_eol_lf_rule() {
    let path = repo_root().join(".gitattributes");
    let content = fs::read_to_string(&path).expect("Failed to read .gitattributes");
    assert!(
        content.contains("* text=auto eol=lf"),
        ".gitattributes must contain '* text=auto eol=lf' as the global catch-all rule"
    );
}

// ---------------------------------------------------------------------------
// Per-extension LF rules
// ---------------------------------------------------------------------------

/// Helper: assert that a pattern with `eol=lf` is present for the given glob.
fn assert_eol_lf_rule(content: &str, extension: &str) {
    // Accept both "*.ext  text eol=lf" and "*.ext text eol=lf" (varying whitespace).
    let needle = format!("*{} ", extension);
    let has_rule = content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with(&needle) && trimmed.contains("eol=lf")
    });
    assert!(
        has_rule,
        ".gitattributes must contain an 'eol=lf' rule for '{extension}' files"
    );
}

#[test]
fn gitattributes_enforces_lf_for_rs() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_eol_lf_rule(&content, ".rs");
}

#[test]
fn gitattributes_enforces_lf_for_toml() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_eol_lf_rule(&content, ".toml");
}

#[test]
fn gitattributes_enforces_lf_for_md() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_eol_lf_rule(&content, ".md");
}

#[test]
fn gitattributes_enforces_lf_for_yml() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_eol_lf_rule(&content, ".yml");
}

#[test]
fn gitattributes_enforces_lf_for_slint() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_eol_lf_rule(&content, ".slint");
}

#[test]
fn gitattributes_enforces_lf_for_manifest() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_eol_lf_rule(&content, ".manifest");
}

#[test]
fn gitattributes_enforces_lf_for_json() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_eol_lf_rule(&content, ".json");
}

// ---------------------------------------------------------------------------
// Binary rules (must not undergo line-ending conversion)
// ---------------------------------------------------------------------------

/// Helper: assert that a pattern is marked as `binary`.
fn assert_binary_rule(content: &str, extension: &str) {
    let needle = format!("*{} ", extension);
    let has_rule = content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with(&needle) && trimmed.contains("binary")
    });
    assert!(
        has_rule,
        ".gitattributes must mark '{extension}' files as binary"
    );
}

#[test]
fn gitattributes_marks_exe_as_binary() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_binary_rule(&content, ".exe");
}

#[test]
fn gitattributes_marks_enc_as_binary() {
    let content = fs::read_to_string(repo_root().join(".gitattributes"))
        .expect("Failed to read .gitattributes");
    assert_binary_rule(&content, ".enc");
}

// ---------------------------------------------------------------------------
// Line-ending hygiene: no CRLF bytes in tracked source files
// ---------------------------------------------------------------------------

/// Read a file as raw bytes and return `true` if it contains a CRLF sequence.
fn has_crlf(path: &Path) -> bool {
    match fs::read(path) {
        Ok(bytes) => bytes.windows(2).any(|w| w == b"\r\n"),
        Err(_) => false, // Unreadable files are not our concern here
    }
}

#[test]
fn gitattributes_itself_has_no_crlf() {
    let path = repo_root().join(".gitattributes");
    assert!(
        !has_crlf(&path),
        ".gitattributes must use LF line endings, not CRLF"
    );
}

#[test]
fn app_manifest_has_no_crlf() {
    let path = repo_root().join("app.manifest");
    if path.exists() {
        assert!(
            !has_crlf(&path),
            "app.manifest must use LF line endings to avoid XML parser issues on Windows"
        );
    }
}

#[test]
fn cargo_toml_has_no_crlf() {
    let path = repo_root().join("Cargo.toml");
    assert!(
        !has_crlf(&path),
        "Cargo.toml must use LF line endings, not CRLF"
    );
}

#[test]
fn build_rs_has_no_crlf() {
    let path = repo_root().join("build.rs");
    if path.exists() {
        assert!(
            !has_crlf(&path),
            "build.rs must use LF line endings, not CRLF"
        );
    }
}

/// Spot-check that none of the Rust source files in `src/` contain CRLF bytes.
#[test]
fn src_rs_files_have_no_crlf() {
    let src_dir = repo_root().join("src");
    if !src_dir.exists() {
        return;
    }

    let mut crlf_files: Vec<String> = Vec::new();

    // Walk one level deep (src/*.rs) — sub-modules would need a recursive walk
    // but the project currently uses a flat src/ layout.
    if let Ok(entries) = fs::read_dir(&src_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("rs") && has_crlf(&p) {
                crlf_files.push(p.display().to_string());
            }
        }
    }

    assert!(
        crlf_files.is_empty(),
        "The following Rust source files contain CRLF line endings: {crlf_files:#?}"
    );
}
