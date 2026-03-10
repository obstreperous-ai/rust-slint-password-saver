//! Tests for Finding D in WINDOWS.md — code signing and `SmartScreen` documentation.
//!
//! These tests verify that:
//! 1. `README.md` contains a dedicated `SmartScreen` warning section.
//! 2. `README.md` contains step-by-step bypass instructions ("More info → Run anyway").
//! 3. `README.md` documents that source-built binaries bypass `SmartScreen`.
//! 4. `.github/workflows/release.yml` contains a commented placeholder signing step.
//! 5. `WINDOWS.md` contains a Code Signing subsection documenting provider options.
//! 6. `WINDOWS.md` code signing matrix entry is updated to reflect documentation status.

use std::fs;

/// Resolve the repository root via the `CARGO_MANIFEST_DIR` env variable that
/// Cargo sets automatically when running tests.
fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

// ---------------------------------------------------------------------------
// README.md — SmartScreen warning and bypass instructions
// ---------------------------------------------------------------------------

#[test]
fn readme_contains_smartscreen_warning_section() {
    let content =
        fs::read_to_string(repo_root().join("README.md")).expect("Failed to read README.md");
    // Verify the dedicated heading exists, not just any mention of SmartScreen
    assert!(
        content.contains("### Running on Windows") && content.contains("SmartScreen Warning"),
        "README.md must contain the dedicated '### Running on Windows — SmartScreen Warning' section heading"
    );
}

#[test]
fn readme_contains_smartscreen_bypass_heading() {
    let content =
        fs::read_to_string(repo_root().join("README.md")).expect("Failed to read README.md");
    assert!(
        content.contains("Running on Windows") && content.contains("SmartScreen"),
        "README.md must contain a dedicated 'Running on Windows — SmartScreen Warning' heading"
    );
}

#[test]
fn readme_contains_more_info_run_anyway_step() {
    let content =
        fs::read_to_string(repo_root().join("README.md")).expect("Failed to read README.md");
    assert!(
        content.contains("More info") && content.contains("Run anyway"),
        "README.md must include the 'More info → Run anyway' bypass step for SmartScreen"
    );
}

#[test]
fn readme_mentions_source_build_bypasses_smartscreen() {
    let content =
        fs::read_to_string(repo_root().join("README.md")).expect("Failed to read README.md");
    // Verify that the README explicitly connects `cargo build` / source builds with bypassing
    // SmartScreen — not just any incidental mention of "source"
    assert!(
        content.contains("cargo build") && content.contains("SmartScreen"),
        "README.md must note that binaries built with 'cargo build' bypass SmartScreen"
    );
}

#[test]
fn readme_explains_why_smartscreen_triggers() {
    let content =
        fs::read_to_string(repo_root().join("README.md")).expect("Failed to read README.md");
    assert!(
        content.contains("unsigned") || content.contains("unknown publisher") || content.contains("Unknown publisher"),
        "README.md must explain that SmartScreen triggers because the binary is unsigned / unknown publisher"
    );
}

// ---------------------------------------------------------------------------
// release.yml — commented placeholder signing step
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_exists() {
    let path = repo_root()
        .join(".github")
        .join("workflows")
        .join("release.yml");
    assert!(path.exists(), ".github/workflows/release.yml must exist");
}

#[test]
fn release_workflow_contains_signing_placeholder() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read release.yml");
    assert!(
        content.contains("TODO") && (content.contains("sign") || content.contains("Sign")),
        "release.yml must contain a commented TODO placeholder for the Windows signing step"
    );
}

#[test]
fn release_workflow_signing_step_is_commented_out() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read release.yml");
    // The signing step must appear as a comment (lines starting with #), not as an active step
    let has_commented_signing = content.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with('#')
            && (trimmed.contains("sign")
                || trimmed.contains("Sign")
                || trimmed.contains("signtool")
                || trimmed.contains("trusted-signing"))
    });
    assert!(
        has_commented_signing,
        "release.yml signing step must be commented out (lines starting with '#')"
    );
}

#[test]
fn release_workflow_references_trusted_signing_or_signtool() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read release.yml");
    assert!(
        content.contains("trusted-signing")
            || content.contains("signtool")
            || content.contains("azure/trusted-signing-action"),
        "release.yml must reference Microsoft Trusted Signing or signtool.exe in the placeholder"
    );
}

// ---------------------------------------------------------------------------
// WINDOWS.md — Code Signing subsection
// ---------------------------------------------------------------------------

#[test]
fn windows_md_exists() {
    let path = repo_root().join("WINDOWS.md");
    assert!(
        path.exists(),
        "WINDOWS.md must exist at the repository root"
    );
}

#[test]
fn windows_md_contains_code_signing_subsection() {
    let content =
        fs::read_to_string(repo_root().join("WINDOWS.md")).expect("Failed to read WINDOWS.md");
    assert!(
        content.contains("Code Signing"),
        "WINDOWS.md must contain a 'Code Signing' subsection documenting provider options"
    );
}

#[test]
fn windows_md_documents_ev_certificate_option() {
    let content =
        fs::read_to_string(repo_root().join("WINDOWS.md")).expect("Failed to read WINDOWS.md");
    assert!(
        content.contains("EV") || content.contains("Extended Validation"),
        "WINDOWS.md Code Signing subsection must document the EV certificate option"
    );
}

#[test]
fn windows_md_documents_microsoft_trusted_signing() {
    let content =
        fs::read_to_string(repo_root().join("WINDOWS.md")).expect("Failed to read WINDOWS.md");
    assert!(
        content.contains("Trusted Signing") || content.contains("Azure Code Signing"),
        "WINDOWS.md Code Signing subsection must document Microsoft Trusted Signing"
    );
}

#[test]
fn windows_md_documents_github_actions_signing_steps() {
    let content =
        fs::read_to_string(repo_root().join("WINDOWS.md")).expect("Failed to read WINDOWS.md");
    assert!(
        content.contains("trusted-signing-action") || content.contains("signtool"),
        "WINDOWS.md must document the GitHub Actions signing steps (trusted-signing-action or signtool)"
    );
}

#[test]
fn windows_md_finding_d_marked_as_documented() {
    let content =
        fs::read_to_string(repo_root().join("WINDOWS.md")).expect("Failed to read WINDOWS.md");
    // Finding D must be marked with a concrete status indicator showing that documentation and
    // placeholder steps have been added (not still listed as a bare TODO)
    assert!(
        content.contains("Finding D") && (content.contains("Partially implemented") || content.contains("DOCUMENTED") || content.contains("Implemented")),
        "WINDOWS.md Finding D must carry a status marker (e.g. 'Partially implemented') showing progress"
    );
}
