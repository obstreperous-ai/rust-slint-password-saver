//! Tests for `app.manifest` — Windows application manifest (Finding C in WINDOWS.md).
//!
//! These tests verify that:
//! 1. The `app.manifest` file exists at the repository root.
//! 2. It contains a `<longPathAware>` element set to `true`.
//! 3. The `<longPathAware>` element uses the correct SMI/2016 namespace.
//! 4. The `<longPathAware>` element is nested inside `<asmv3:windowsSettings>`.
//! 5. The existing DPI-awareness declarations are still present and unmodified.

use std::fs;

/// Resolve the repository root via the `CARGO_MANIFEST_DIR` env variable that
/// Cargo sets automatically when running tests.
fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

// ---------------------------------------------------------------------------
// Existence and basic structure
// ---------------------------------------------------------------------------

#[test]
fn app_manifest_exists() {
    let path = repo_root().join("app.manifest");
    assert!(
        path.exists(),
        "app.manifest must exist at the repository root"
    );
}

#[test]
fn app_manifest_is_not_empty() {
    let path = repo_root().join("app.manifest");
    let content = fs::read_to_string(&path).expect("Failed to read app.manifest");
    assert!(!content.trim().is_empty(), "app.manifest must not be empty");
}

// ---------------------------------------------------------------------------
// longPathAware declaration
// ---------------------------------------------------------------------------

#[test]
fn app_manifest_contains_long_path_aware_element() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    assert!(
        content.contains("longPathAware"),
        "app.manifest must contain a <longPathAware> element to opt in to paths > 260 characters"
    );
}

#[test]
fn app_manifest_long_path_aware_is_true() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    // Check the full element string to avoid matching an unrelated element that happens
    // to contain the text ">true<".
    assert!(
        content.contains(
            r#"<longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>"#
        ),
        "app.manifest <longPathAware> must have the value 'true' to enable long-path support"
    );
}

#[test]
fn app_manifest_long_path_aware_uses_correct_namespace() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    // The namespace required for longPathAware is the SMI/2016/WindowsSettings namespace,
    // the same one used by dpiAwareness.  Using the wrong or missing namespace causes
    // Windows to silently ignore the element.
    assert!(
        content.contains(
            r#"longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings""#
        ),
        "app.manifest <longPathAware> must declare xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\""
    );
}

#[test]
fn app_manifest_long_path_aware_inside_windows_settings() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    // Verify that <longPathAware> appears after the opening <asmv3:windowsSettings> tag
    // and before the closing </asmv3:windowsSettings> tag, confirming proper nesting.
    let open_pos = content
        .find("<asmv3:windowsSettings>")
        .expect("app.manifest must contain opening <asmv3:windowsSettings>");
    let close_pos = content
        .find("</asmv3:windowsSettings>")
        .expect("app.manifest must contain closing </asmv3:windowsSettings>");
    let long_path_pos = content
        .find("longPathAware")
        .expect("app.manifest must contain <longPathAware>");
    assert!(
        long_path_pos > open_pos && long_path_pos < close_pos,
        "<longPathAware> must be nested inside <asmv3:windowsSettings>…</asmv3:windowsSettings> in app.manifest"
    );
}

// ---------------------------------------------------------------------------
// Existing DPI-awareness declarations must be preserved
// ---------------------------------------------------------------------------

#[test]
fn app_manifest_preserves_dpi_aware() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    assert!(
        content.contains("dpiAware"),
        "app.manifest must still contain the legacy <dpiAware> element after adding longPathAware"
    );
}

#[test]
fn app_manifest_preserves_dpi_awareness() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    assert!(
        content.contains("dpiAwareness"),
        "app.manifest must still contain the modern <dpiAwareness> element after adding longPathAware"
    );
}

#[test]
fn app_manifest_dpi_awareness_is_per_monitor_v2() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    assert!(
        content.contains("PerMonitorV2"),
        "app.manifest <dpiAwareness> must still be set to 'PerMonitorV2'"
    );
}

// ---------------------------------------------------------------------------
// Structural integrity checks
// ---------------------------------------------------------------------------

#[test]
fn app_manifest_has_assembly_root_element() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    assert!(
        content.contains("<assembly"),
        "app.manifest must have an <assembly> root element"
    );
}

#[test]
fn app_manifest_has_windows_compatibility_entry() {
    let content =
        fs::read_to_string(repo_root().join("app.manifest")).expect("Failed to read app.manifest");
    // Windows 10 GUID declared via <supportedOS>
    assert!(
        content.contains("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"),
        "app.manifest must declare the Windows 10/11 supportedOS GUID"
    );
}
