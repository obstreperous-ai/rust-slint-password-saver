//! Tests for SECURITY.md Issue 5 — SHA-256 checksum generation in the release workflow.
//!
//! These tests verify that:
//! 1. `.github/workflows/release.yml` contains a step that generates SHA-256 checksums.
//! 2. The generated `SHA256SUMS.txt` file is included as a release asset.
//! 3. The checksum step uses `sha256sum` on all artifact types (`.tar.gz`, `.zip`, `.msi`).
//! 4. `SECURITY.md` marks Issue 5 as resolved.

use std::fs;

/// Resolve the repository root via the `CARGO_MANIFEST_DIR` env variable that
/// Cargo sets automatically when running tests.
fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

// ---------------------------------------------------------------------------
// release.yml — SHA-256 checksum generation step
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_generates_sha256_checksums() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("sha256sum"),
        "release.yml must contain a step that runs sha256sum to generate checksums"
    );
}

#[test]
fn release_workflow_creates_sha256sums_file() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("SHA256SUMS.txt"),
        "release.yml must reference SHA256SUMS.txt for the checksum file"
    );
}

#[test]
fn release_workflow_uploads_sha256sums_as_release_asset() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");

    // Find the softprops/action-gh-release step and verify SHA256SUMS.txt appears before
    // the next top-level step definition (a line matching `    - name:`).
    let after_release_action = content
        .split("softprops/action-gh-release")
        .nth(1)
        .expect("release.yml must contain softprops/action-gh-release step");
    // Collect lines up to the next step (lines that start a new step with "    - name:" or "    - uses:")
    let files_block: String = after_release_action
        .lines()
        .take_while(|l| {
            let trimmed = l.trim_start();
            !(trimmed.starts_with("- name:") || trimmed.starts_with("- uses:"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        files_block.contains("SHA256SUMS.txt"),
        "release.yml must include SHA256SUMS.txt in the softprops/action-gh-release files list"
    );
}

#[test]
fn release_workflow_checksums_cover_tar_gz_artifacts() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("tar.gz"),
        "release.yml must reference .tar.gz artifacts in the checksum generation step"
    );
}

#[test]
fn release_workflow_checksums_cover_zip_artifacts() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains(".zip"),
        "release.yml must reference .zip artifacts in the checksum generation step"
    );
}

#[test]
fn release_workflow_checksums_cover_msi_artifacts() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains(".msi"),
        "release.yml must reference .msi artifacts in the checksum generation step"
    );
}

// ---------------------------------------------------------------------------
// SECURITY.md — Issue 5 marked as resolved
// ---------------------------------------------------------------------------

#[test]
fn security_md_marks_issue_5_resolved() {
    let content =
        fs::read_to_string(repo_root().join("SECURITY.md")).expect("Failed to read SECURITY.md");

    // Issue 5 heading should be struck-through (~~...~~) indicating it is resolved
    assert!(
        content.contains("~~5. Add SHA-256 Checksum Generation to Release Workflow~~"),
        "SECURITY.md must mark Issue 5 'Add SHA-256 Checksum Generation to Release Workflow' as resolved with strikethrough"
    );
}

#[test]
fn security_md_ci_table_updated_for_checksums() {
    let content =
        fs::read_to_string(repo_root().join("SECURITY.md")).expect("Failed to read SECURITY.md");

    // The CI/CD table row for release.yml must exist and must no longer say "No checksums"
    let release_yml_row = content
        .lines()
        .find(|l| l.contains("release.yml"))
        .expect("SECURITY.md CI/CD table must contain a row for release.yml");
    assert!(
        !release_yml_row.contains("No checksums") && !release_yml_row.contains("no checksums"),
        "SECURITY.md CI/CD table must be updated to reflect that checksum generation is now implemented"
    );
}
