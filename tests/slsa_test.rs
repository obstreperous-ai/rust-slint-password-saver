//! Tests for SECURITY.md Issue 10 — SLSA provenance attestation in the release workflow.
//!
//! These tests verify that:
//! 1. `.github/workflows/release.yml` has `attestations: write` permission in the `release` job.
//! 2. `.github/workflows/release.yml` has `id-token: write` permission in the `release` job.
//! 3. `.github/workflows/release.yml` contains an `actions/attest-build-provenance` step.
//! 4. The attestation step covers all release artifacts.
//! 5. `SECURITY.md` marks Issue 10 as resolved.
//! 6. The SBOM/Provenance row in `SECURITY.md` is updated to reflect SLSA attestation.

use std::fs;

/// Resolve the repository root via the `CARGO_MANIFEST_DIR` env variable that
/// Cargo sets automatically when running tests.
fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

// ---------------------------------------------------------------------------
// release.yml — attestations: write permission
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_has_attestations_write_permission() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("attestations: write"),
        "release.yml must grant 'attestations: write' permission in the release job"
    );
}

// ---------------------------------------------------------------------------
// release.yml — id-token: write permission
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_has_id_token_write_permission() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("id-token: write"),
        "release.yml must grant 'id-token: write' permission in the release job for OIDC signing"
    );
}

// ---------------------------------------------------------------------------
// release.yml — attest-build-provenance step present
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_uses_attest_build_provenance() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    let has_active_uses = content.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#')
            && trimmed.starts_with("uses:")
            && trimmed.contains("actions/attest-build-provenance")
    });
    assert!(
        has_active_uses,
        "release.yml must contain an active `uses: actions/attest-build-provenance` line"
    );
}

// ---------------------------------------------------------------------------
// release.yml — attestation covers archives
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_attestation_covers_archives() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");

    // Find the attest-build-provenance step and verify subject-path includes all artifact patterns.
    let after_attest = content
        .split("attest-build-provenance")
        .nth(1)
        .expect("release.yml must contain an attest-build-provenance step");
    let subject_block: String = after_attest
        .lines()
        .take_while(|l| {
            let trimmed = l.trim_start();
            !(trimmed.starts_with("- name:") || trimmed.starts_with("- uses:"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        subject_block.contains("subject-path:"),
        "release.yml attestation step must use 'subject-path:' to specify artifacts"
    );
    assert!(
        subject_block.contains("tar.gz"),
        "release.yml attestation step must cover .tar.gz archives"
    );
    assert!(
        subject_block.contains("zip"),
        "release.yml attestation step must cover .zip archives"
    );
    assert!(
        subject_block.contains("msi"),
        "release.yml attestation step must cover .msi installers"
    );
}

// ---------------------------------------------------------------------------
// SECURITY.md — Issue 10 marked as resolved
// ---------------------------------------------------------------------------

#[test]
fn security_md_marks_issue_10_resolved() {
    let content =
        fs::read_to_string(repo_root().join("SECURITY.md")).expect("Failed to read SECURITY.md");
    assert!(
        content.contains("~~10. Add SLSA Provenance Attestation~~"),
        "SECURITY.md must mark Issue 10 'Add SLSA Provenance Attestation' as resolved with strikethrough"
    );
}

// ---------------------------------------------------------------------------
// SECURITY.md — SBOM/Provenance row updated to include SLSA attestation
// ---------------------------------------------------------------------------

#[test]
fn security_md_sbom_provenance_row_reflects_slsa_attestation() {
    let content =
        fs::read_to_string(repo_root().join("SECURITY.md")).expect("Failed to read SECURITY.md");

    let sbom_row = content
        .lines()
        .find(|l| l.contains("SBOM") && l.contains("Provenance"))
        .expect("SECURITY.md must contain an 'SBOM / Provenance' row");
    assert!(
        sbom_row.to_lowercase().contains("slsa") || sbom_row.contains("attest"),
        "SECURITY.md SBOM/Provenance row must mention SLSA attestation"
    );
}
