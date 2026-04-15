//! Tests for SECURITY.md Issue 11 — cargo-deny integration in CI.

use std::fs;

fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

#[test]
fn security_workflow_installs_cargo_deny() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("security.yml"),
    )
    .expect("Failed to read .github/workflows/security.yml");
    assert!(
        content.contains("cargo install cargo-deny"),
        "security.yml must install cargo-deny"
    );
}

#[test]
fn security_workflow_runs_cargo_deny_checks() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("security.yml"),
    )
    .expect("Failed to read .github/workflows/security.yml");
    assert!(
        content.contains("cargo deny check advisories bans licenses"),
        "security.yml must run cargo deny checks for advisories, bans, and licenses"
    );
}

#[test]
fn security_md_marks_issue_11_resolved() {
    let content =
        fs::read_to_string(repo_root().join("SECURITY.md")).expect("Failed to read SECURITY.md");
    assert!(
        content.contains("~~11. Add `cargo-deny` to CI~~"),
        "SECURITY.md must mark Issue 11 as resolved with strikethrough"
    );
}

#[test]
fn deny_toml_exists() {
    let deny_toml = repo_root().join("deny.toml");
    assert!(
        deny_toml.exists(),
        "Repository root must contain deny.toml for cargo-deny configuration"
    );
}
