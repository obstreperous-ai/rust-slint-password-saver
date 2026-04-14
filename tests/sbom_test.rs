//! Tests for SECURITY.md Issue 9 — SBOM generation in the release workflow.
//!
//! These tests verify that:
//! 1. `.github/workflows/release.yml` installs `cargo-sbom`.
//! 2. `.github/workflows/release.yml` contains a step that generates an SBOM file.
//! 3. The generated `sbom.spdx.json` file is included as a release asset.
//! 4. `SECURITY.md` marks Issue 9 as resolved.
//! 5. The SBOM/Provenance row in `SECURITY.md` is updated to reflect the implementation.

use std::fs;

/// Resolve the repository root via the `CARGO_MANIFEST_DIR` env variable that
/// Cargo sets automatically when running tests.
fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

// ---------------------------------------------------------------------------
// release.yml — cargo-sbom installation step
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_installs_cargo_sbom() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("cargo install cargo-sbom"),
        "release.yml must install cargo-sbom via 'cargo install cargo-sbom'"
    );
}

// ---------------------------------------------------------------------------
// release.yml — SBOM generation step
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_generates_sbom() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("cargo sbom --output-format spdx_json_2_3"),
        "release.yml must run 'cargo sbom --output-format spdx_json_2_3' to generate the SBOM"
    );
}

#[test]
fn release_workflow_sbom_uses_spdx_format() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("spdx_json_2_3"),
        "release.yml must use the 'spdx_json_2_3' output format for SBOM generation"
    );
}

#[test]
fn release_workflow_sbom_output_file_named() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("sbom.spdx.json"),
        "release.yml must reference sbom.spdx.json as the SBOM output file"
    );
}

// ---------------------------------------------------------------------------
// release.yml — SBOM uploaded as release asset
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_uploads_sbom_as_release_asset() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");

    // Find the softprops/action-gh-release step and verify sbom.spdx.json appears in its files block.
    let after_release_action = content
        .split("softprops/action-gh-release")
        .nth(1)
        .expect("release.yml must contain softprops/action-gh-release step");
    // Collect lines up to the next step definition.
    let files_block: String = after_release_action
        .lines()
        .take_while(|l| {
            let trimmed = l.trim_start();
            !(trimmed.starts_with("- name:") || trimmed.starts_with("- uses:"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        files_block.contains("sbom.spdx.json"),
        "release.yml must include sbom.spdx.json in the softprops/action-gh-release files list"
    );
}

// ---------------------------------------------------------------------------
// SECURITY.md — Issue 9 marked as resolved
// ---------------------------------------------------------------------------

#[test]
fn security_md_marks_issue_9_resolved() {
    let content =
        fs::read_to_string(repo_root().join("SECURITY.md")).expect("Failed to read SECURITY.md");
    assert!(
        content.contains("~~9. Generate SBOM in CI~~"),
        "SECURITY.md must mark Issue 9 'Generate SBOM in CI' as resolved with strikethrough"
    );
}

#[test]
fn security_md_sbom_row_updated() {
    let content =
        fs::read_to_string(repo_root().join("SECURITY.md")).expect("Failed to read SECURITY.md");

    // The SBOM / Provenance row must no longer say "Missing".
    let sbom_row = content
        .lines()
        .find(|l| l.contains("SBOM") && l.contains("Provenance"))
        .expect("SECURITY.md must contain an 'SBOM / Provenance' row");
    assert!(
        !sbom_row.contains("Missing") && !sbom_row.contains("missing"),
        "SECURITY.md SBOM/Provenance row must be updated to reflect that SBOM generation is implemented"
    );
}
