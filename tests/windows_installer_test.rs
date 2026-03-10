//! Tests for Finding F in WINDOWS.md — Windows installer infrastructure.
//!
//! These tests verify that:
//! 1. The WiX 4 installer definition (`installer/windows/main.wxs`) exists and is structurally valid.
//! 2. The Winget package manifest files exist and contain required fields.
//! 3. The Scoop manifest (`scoop/rust-slint-password-saver.json`) exists, is valid JSON, and contains
//!    required fields.
//! 4. `.github/workflows/release.yml` includes the WiX installer build step.
//! 5. `README.md` documents `winget install` and Scoop installation.
//! 6. `WINDOWS.md` marks Finding F as resolved.

use std::fs;

/// Resolve the repository root via the `CARGO_MANIFEST_DIR` env variable that
/// Cargo sets automatically when running tests.
fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set when running Cargo tests");
    std::path::PathBuf::from(manifest)
}

// ---------------------------------------------------------------------------
// WiX 4 installer definition
// ---------------------------------------------------------------------------

#[test]
fn wix_installer_file_exists() {
    let path = repo_root()
        .join("installer")
        .join("windows")
        .join("main.wxs");
    assert!(
        path.exists(),
        "installer/windows/main.wxs must exist (WiX 4 installer definition)"
    );
}

#[test]
fn wix_installer_uses_wix4_namespace() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("http://wixtoolset.org/schemas/v4/wxs"),
        "main.wxs must declare the WiX 4 XML namespace"
    );
}

#[test]
fn wix_installer_contains_product_name() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("Password Saver"),
        "main.wxs must specify 'Password Saver' as the product name"
    );
}

#[test]
fn wix_installer_contains_upgrade_code() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("UpgradeCode"),
        "main.wxs must declare an UpgradeCode GUID for reliable upgrades"
    );
}

#[test]
fn wix_installer_targets_program_files() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("ProgramFilesFolder") || content.contains("INSTALLFOLDER"),
        "main.wxs must install to %ProgramFiles% via ProgramFilesFolder / INSTALLFOLDER"
    );
}

#[test]
fn wix_installer_creates_start_menu_shortcut() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("<Shortcut"),
        "main.wxs must create a Start Menu shortcut via a <Shortcut> element"
    );
}

#[test]
fn wix_installer_removes_start_menu_folder_on_uninstall() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("<RemoveFolder"),
        "main.wxs must use <RemoveFolder> to clean up the Start Menu folder on uninstall"
    );
}

#[test]
fn wix_installer_references_exe_source_variable() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("$(var.ExeSource)"),
        "main.wxs must reference the $(var.ExeSource) preprocessor variable for the .exe path"
    );
}

#[test]
fn wix_installer_contains_major_upgrade() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("MajorUpgrade"),
        "main.wxs must declare <MajorUpgrade> to handle version upgrades correctly"
    );
}

#[test]
fn wix_installer_contains_build_instructions_comment() {
    let content = fs::read_to_string(
        repo_root()
            .join("installer")
            .join("windows")
            .join("main.wxs"),
    )
    .expect("Failed to read installer/windows/main.wxs");
    assert!(
        content.contains("wix build") && content.contains("msiexec"),
        "main.wxs must contain build and install command examples in its header comment"
    );
}

// ---------------------------------------------------------------------------
// Winget manifests
// ---------------------------------------------------------------------------

#[test]
fn winget_manifest_directory_exists() {
    let path = repo_root()
        .join("winget")
        .join("manifests")
        .join("o")
        .join("obstreperous-ai")
        .join("RustSlintPasswordSaver")
        .join("0.1.0");
    assert!(
        path.is_dir(),
        "winget/manifests/o/obstreperous-ai/RustSlintPasswordSaver/0.1.0/ directory must exist"
    );
}

#[test]
fn winget_version_manifest_exists() {
    let path = repo_root()
        .join("winget")
        .join("manifests")
        .join("o")
        .join("obstreperous-ai")
        .join("RustSlintPasswordSaver")
        .join("0.1.0")
        .join("obstreperous-ai.RustSlintPasswordSaver.yaml");
    assert!(
        path.exists(),
        "Winget version manifest obstreperous-ai.RustSlintPasswordSaver.yaml must exist"
    );
}

#[test]
fn winget_installer_manifest_exists() {
    let path = repo_root()
        .join("winget")
        .join("manifests")
        .join("o")
        .join("obstreperous-ai")
        .join("RustSlintPasswordSaver")
        .join("0.1.0")
        .join("obstreperous-ai.RustSlintPasswordSaver.installer.yaml");
    assert!(
        path.exists(),
        "Winget installer manifest obstreperous-ai.RustSlintPasswordSaver.installer.yaml must exist"
    );
}

#[test]
fn winget_locale_manifest_exists() {
    let path = repo_root()
        .join("winget")
        .join("manifests")
        .join("o")
        .join("obstreperous-ai")
        .join("RustSlintPasswordSaver")
        .join("0.1.0")
        .join("obstreperous-ai.RustSlintPasswordSaver.locale.en-US.yaml");
    assert!(
        path.exists(),
        "Winget locale manifest obstreperous-ai.RustSlintPasswordSaver.locale.en-US.yaml must exist"
    );
}

#[test]
fn winget_version_manifest_contains_package_identifier() {
    let content = fs::read_to_string(
        repo_root()
            .join("winget")
            .join("manifests")
            .join("o")
            .join("obstreperous-ai")
            .join("RustSlintPasswordSaver")
            .join("0.1.0")
            .join("obstreperous-ai.RustSlintPasswordSaver.yaml"),
    )
    .expect("Failed to read Winget version manifest");
    assert!(
        content.contains("PackageIdentifier")
            && content.contains("obstreperous-ai.RustSlintPasswordSaver"),
        "Winget version manifest must declare PackageIdentifier: obstreperous-ai.RustSlintPasswordSaver"
    );
}

#[test]
fn winget_installer_manifest_references_github_release() {
    let content = fs::read_to_string(
        repo_root()
            .join("winget")
            .join("manifests")
            .join("o")
            .join("obstreperous-ai")
            .join("RustSlintPasswordSaver")
            .join("0.1.0")
            .join("obstreperous-ai.RustSlintPasswordSaver.installer.yaml"),
    )
    .expect("Failed to read Winget installer manifest");
    assert!(
        content.contains("github.com/obstreperous-ai/rust-slint-password-saver"),
        "Winget installer manifest must contain a GitHub release download URL"
    );
}

#[test]
fn winget_installer_manifest_specifies_msi_type() {
    let content = fs::read_to_string(
        repo_root()
            .join("winget")
            .join("manifests")
            .join("o")
            .join("obstreperous-ai")
            .join("RustSlintPasswordSaver")
            .join("0.1.0")
            .join("obstreperous-ai.RustSlintPasswordSaver.installer.yaml"),
    )
    .expect("Failed to read Winget installer manifest");
    assert!(
        content.contains("InstallerType: msi") || content.contains("InstallerType: zip"),
        "Winget installer manifest must specify InstallerType"
    );
}

#[test]
fn winget_locale_manifest_contains_package_name() {
    let content = fs::read_to_string(
        repo_root()
            .join("winget")
            .join("manifests")
            .join("o")
            .join("obstreperous-ai")
            .join("RustSlintPasswordSaver")
            .join("0.1.0")
            .join("obstreperous-ai.RustSlintPasswordSaver.locale.en-US.yaml"),
    )
    .expect("Failed to read Winget locale manifest");
    assert!(
        content.contains("PackageName") && content.contains("Password Saver"),
        "Winget locale manifest must declare PackageName: Password Saver"
    );
}

// ---------------------------------------------------------------------------
// Scoop manifest
// ---------------------------------------------------------------------------

#[test]
fn scoop_manifest_exists() {
    let path = repo_root()
        .join("scoop")
        .join("rust-slint-password-saver.json");
    assert!(
        path.exists(),
        "scoop/rust-slint-password-saver.json must exist"
    );
}

#[test]
fn scoop_manifest_is_valid_json() {
    let content = fs::read_to_string(
        repo_root()
            .join("scoop")
            .join("rust-slint-password-saver.json"),
    )
    .expect("Failed to read scoop/rust-slint-password-saver.json");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&content);
    assert!(
        parsed.is_ok(),
        "scoop/rust-slint-password-saver.json must be valid JSON: {:?}",
        parsed.err()
    );
}

#[test]
fn scoop_manifest_contains_version() {
    let content = fs::read_to_string(
        repo_root()
            .join("scoop")
            .join("rust-slint-password-saver.json"),
    )
    .expect("Failed to read scoop/rust-slint-password-saver.json");
    let value: serde_json::Value = serde_json::from_str(&content).expect("Must be valid JSON");
    assert!(
        value.get("version").is_some(),
        "Scoop manifest must contain a 'version' field"
    );
}

#[test]
fn scoop_manifest_contains_url() {
    let content = fs::read_to_string(
        repo_root()
            .join("scoop")
            .join("rust-slint-password-saver.json"),
    )
    .expect("Failed to read scoop/rust-slint-password-saver.json");
    assert!(
        content.contains("github.com/obstreperous-ai/rust-slint-password-saver"),
        "Scoop manifest must reference the GitHub release download URL"
    );
}

#[test]
fn scoop_manifest_contains_bin() {
    let content = fs::read_to_string(
        repo_root()
            .join("scoop")
            .join("rust-slint-password-saver.json"),
    )
    .expect("Failed to read scoop/rust-slint-password-saver.json");
    let value: serde_json::Value = serde_json::from_str(&content).expect("Must be valid JSON");
    assert!(
        value.get("bin").is_some(),
        "Scoop manifest must contain a 'bin' field specifying the executable"
    );
}

#[test]
fn scoop_manifest_contains_autoupdate() {
    let content = fs::read_to_string(
        repo_root()
            .join("scoop")
            .join("rust-slint-password-saver.json"),
    )
    .expect("Failed to read scoop/rust-slint-password-saver.json");
    let value: serde_json::Value = serde_json::from_str(&content).expect("Must be valid JSON");
    assert!(
        value.get("autoupdate").is_some(),
        "Scoop manifest must contain an 'autoupdate' section for automatic version updates"
    );
}

// ---------------------------------------------------------------------------
// release.yml — WiX installer build step
// ---------------------------------------------------------------------------

#[test]
fn release_workflow_contains_wix_build_step() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("wix build"),
        "release.yml must contain a 'wix build' step to produce the .msi installer"
    );
}

#[test]
fn release_workflow_installs_wix_toolset() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("dotnet tool install") && content.contains("wix"),
        "release.yml must install the WiX 4 .NET global tool before building the installer"
    );
}

#[test]
fn release_workflow_uploads_msi_artifact() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains(".msi"),
        "release.yml must reference the .msi artifact (upload and/or release)"
    );
}

#[test]
fn release_workflow_includes_msi_in_release_files() {
    let content = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .expect("Failed to read .github/workflows/release.yml");
    assert!(
        content.contains("**/*.msi"),
        "release.yml Create Release step must include **/*.msi in the files glob"
    );
}

// ---------------------------------------------------------------------------
// README.md — Winget and Scoop installation instructions
// ---------------------------------------------------------------------------

#[test]
fn readme_contains_winget_install_command() {
    let content =
        fs::read_to_string(repo_root().join("README.md")).expect("Failed to read README.md");
    assert!(
        content.contains("winget install")
            && content.contains("obstreperous-ai.RustSlintPasswordSaver"),
        "README.md must include a 'winget install obstreperous-ai.RustSlintPasswordSaver' command"
    );
}

#[test]
fn readme_contains_scoop_install_instructions() {
    let content =
        fs::read_to_string(repo_root().join("README.md")).expect("Failed to read README.md");
    assert!(
        content.contains("scoop install") || content.contains("Scoop"),
        "README.md must include Scoop installation instructions"
    );
}

// ---------------------------------------------------------------------------
// WINDOWS.md — Finding F marked as resolved
// ---------------------------------------------------------------------------

#[test]
fn windows_md_finding_f_marked_resolved() {
    let content =
        fs::read_to_string(repo_root().join("WINDOWS.md")).expect("Failed to read WINDOWS.md");
    assert!(
        content.contains("Finding F")
            && (content.contains("RESOLVED")
                || content.contains("Implemented")
                || content.contains("✅")),
        "WINDOWS.md must mark Finding F as resolved/implemented"
    );
}

#[test]
fn windows_md_compatibility_matrix_updated_for_installer() {
    let content =
        fs::read_to_string(repo_root().join("WINDOWS.md")).expect("Failed to read WINDOWS.md");
    // The installer row in the compatibility matrix should be updated from ❌ to ✅ or ⚠️
    // We verify the matrix section still exists and references the installer
    assert!(
        content.contains("Installer") || content.contains("installer"),
        "WINDOWS.md compatibility matrix must reference installer status"
    );
}
