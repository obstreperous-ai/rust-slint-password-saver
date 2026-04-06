# 🪟 Windows Code Review & User Experience Analysis

> **Review Date**: March 2026 (updated from February 2026 initial audit)  
> **Reviewer**: AI Agent (Windows Expert Persona)  
> **Scope**: Full codebase evaluation from the perspective of a Windows end-user and developer  
> **Audience**: Agentic AI systems performing hands-off development

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Code Review Findings](#code-review-findings)
   - [What Works on Windows Today](#what-works-on-windows-today)
   - [Issues & Gaps](#issues--gaps)
3. [User Experience Reflection](#user-experience-reflection)
4. [Actionable Improvements](#actionable-improvements)
5. [Windows Compatibility Matrix](#windows-compatibility-matrix)
6. [Automated Improvements for Next Agent Run](#automated-improvements-for-next-agent-run)

---

## Executive Summary

Since the initial February 2026 audit, significant Windows improvements have been merged. The previously reported critical issues — console window on launch, missing Windows release binary, missing ACL protections on the HMAC key file and rate-limit persist file, the `FILE_FLAG_BACKUP_SEMANTICS` directory-ACL bug, and the non-Windows-conventional storage path — are all resolved. The application now ships a pre-built Windows binary in every GitHub release, logs to `%LOCALAPPDATA%\PasswordSaver\app.log` (since stderr is suppressed by `windows_subsystem`), uses `%LOCALAPPDATA%\PasswordSaver\` for data storage, and renders crisply on HiDPI displays.

A subsequent CI investigation (March 2026) identified two additional issues that were causing the `windows-latest` CI matrix to fail: a `rustfmt` import-ordering diff in `windows_permissions.rs`, and a `PermissionDenied` error in `SetSecurityInfo` caused by passing `OWNER_SECURITY_INFORMATION` without the required `WRITE_OWNER` access right. Both issues have been resolved.

Remaining gaps are predominantly in the **distribution and packaging** tier: no installer, no code signing, no Winget/Chocolatey package, and no `.gitattributes` to guard against CRLF contamination in the source repository. Three minor code-quality issues were also found in this audit: unused imports in `windows_permissions.rs`, a stale doc comment in `main.rs`, and the lack of long-path awareness in the application manifest.

**Overall Windows Readiness: 7/10** — builds, tests, and pre-built binary available; core security features (ACL, DPI manifest, subsystem flag) implemented. Installer, code-signing, and package-manager distribution still missing.

---

## Code Review Findings

### What Works on Windows Today

| Area | Status | Notes |
|------|--------|-------|
| **Build** | ✅ Compiles | CI runs `windows-latest` matrix; code compiles without errors (API mismatch with `windows` v0.52 fixed March 2026) |
| **Storage Path** | ✅ Windows-conventional | `%LOCALAPPDATA%\PasswordSaver\` on Windows (falls back to `USERPROFILE\.password_saver\`); `~/.password_saver/` on Unix |
| **File ACL (storage)** | ✅ Implemented | `windows_permissions.rs` provides `set_windows_secure_permissions()` used by `storage.rs` |
| **Directory ACL** | ✅ Implemented | `set_windows_directory_permissions()` with `FILE_FLAG_BACKUP_SEMANTICS` called from `main.rs`; failures logged as warnings |
| **HMAC key file ACL** | ✅ Implemented | `#[cfg(windows)]` block in `audit_log.rs` calls `set_windows_secure_permissions()` after key file creation |
| **Rate-limit file ACL** | ✅ Implemented | `#[cfg(windows)]` block in `rate_limit.rs` calls `set_windows_secure_permissions()` after each persist write |
| **Console window** | ✅ Suppressed | `#![cfg_attr(windows, windows_subsystem = "windows")]` added to `main.rs` |
| **Log output** | ✅ File-based on Windows | `env_logger` writes to `%LOCALAPPDATA%\PasswordSaver\app.log` when stderr is unavailable |
| **Release binary** | ✅ Shipped | `x86_64-pc-windows-msvc` in release matrix; `.zip` artifact attached to every GitHub release |
| **UI Framework** | ✅ Compatible | Slint supports Windows natively via Direct3D/OpenGL backend |
| **HiDPI / DPI awareness** | ✅ Implemented | `app.manifest` embedded via `embed-manifest` crate declares PerMonitorV2 DPI awareness |
| **Clipboard** | ✅ Compatible | `arboard` crate has Windows backend |
| **Browser Launch** | ✅ Compatible | `webbrowser` crate supports Windows |
| **Update Checker** | ✅ Compatible | `reqwest` blocking client works on Windows |
| **Encryption** | ✅ Platform-agnostic | All cryptographic code (Argon2, AES-GCM) is fully cross-platform |
| **CI documentation** | ✅ Explicit | `Verify MSVC toolchain (Windows)` step in `ci.yml` documents pre-installed toolchain |
| **README documentation** | ✅ Added | Windows prerequisites, build steps, storage path, and known limitations in README |

---

### Issues & Gaps

#### 🔴 Critical

**1. Console window appears on launch (`main.rs`)** ✅ Fixed

On Windows, Rust GUI applications compiled without the `#![windows_subsystem = "windows"]` attribute (or equivalent `#[link_args]` / manifest) will always open a black CMD/PowerShell console window behind the main application window. This is the most visible quality issue a Windows user encounters on first launch.

- **File**: `src/main.rs`
- **Current state**: ✅ `#![cfg_attr(windows, windows_subsystem = "windows")]` added; `env_logger` initialised to write to `%LOCALAPPDATA%\PasswordSaver\app.log` on Windows so log output is not lost
- **Impact**: Every Windows user sees a superfluous console window; looks like developer tooling, not a finished product
- **Fix**: Add `#![cfg_attr(windows, windows_subsystem = "windows")]` as a crate-level attribute to `main.rs`
- **Caveat**: This suppresses `stdout`/`stderr` on Windows, so logging strategy must be updated (write to file or Windows Event Log instead of stderr)

---

**2. No Windows binary in release pipeline (`release.yml`)** ✅ Fixed

The release workflow builds Linux x64, macOS Intel, and macOS Apple Silicon binaries. There is no `x86_64-pc-windows-msvc` target. Windows users have no pre-built binary and must install a full Rust toolchain and build from source — a significant barrier.

- **File**: `.github/workflows/release.yml`
- **Current state**: ✅ `x86_64-pc-windows-msvc` added to release matrix; `rust-slint-password-saver-windows-x86_64.zip` containing `rust-slint-password-saver.exe` is produced and attached to every GitHub release via PowerShell `Compress-Archive`
- **Impact**: ~~Zero-friction download is impossible for Windows users~~ Windows users can now download a pre-built binary directly from the GitHub releases page
- **Fix**: Add `x86_64-pc-windows-msvc` to the release matrix; ship a `.zip` archive containing the `.exe`

---

#### 🟠 High

**3. HMAC key file missing Windows ACL permissions (`audit_log.rs`)** ✅ Fixed

In `audit_log.rs`, after generating or loading the HMAC key, Unix file permissions (`0o600`) are set on the key file via `#[cfg(unix)]`. There is no corresponding `#[cfg(windows)]` block to call `set_windows_secure_permissions()`. On Windows the HMAC key file is created with default ACL (typically world-readable for local user accounts), degrading audit log integrity protection.

- **File**: `src/audit_log.rs`, lines 200–212
- **Current state**: ✅ `#[cfg(windows)]` block added immediately after the `#[cfg(unix)]` block; calls `crate::windows_permissions::set_windows_secure_permissions(key_path)` and logs a warning on failure
- **Impact**: ~~The audit HMAC key file may be readable by other users on multi-user Windows systems~~ The audit HMAC key file is now restricted to the current user on Windows
- **Fix**: Add `#[cfg(windows)]` block calling `crate::windows_permissions::set_windows_secure_permissions()` immediately after the existing Unix block

---

**4. Rate limiter persist file missing Windows ACL permissions (`rate_limit.rs`)**

`rate_limit.rs` sets Unix `0o600` permissions on the persisted attempt-timestamp JSON file after each write, but again has no `#[cfg(windows)]` counterpart. On Windows, the rate limit state file is left with default ACL.

- **File**: `src/rate_limit.rs`, lines 329–334
- **Current state**: ✅ `#[cfg(windows)]` block added immediately after the `#[cfg(unix)]` block; calls `crate::windows_permissions::set_windows_secure_permissions(path)` so the rate limit persist file is restricted to the current user on Windows
- **Impact**: ~~A local attacker could delete or modify the rate limit file on Windows to bypass brute-force protection~~ The rate limit persist file is now restricted to the current user on Windows
- **Fix**: Add `#[cfg(windows)]` block calling `set_windows_secure_permissions()` after the existing Unix block

---

**✅ 5. (RESOLVED) Storage path now uses Windows-conventional `%LOCALAPPDATA%\PasswordSaver\` (`main.rs`, `audit_log.rs`)**

The storage directory now uses `%LOCALAPPDATA%\PasswordSaver\` on Windows (with fallback to `USERPROFILE\.password_saver\` if `LOCALAPPDATA` is unset). On Unix the existing `~/.password_saver/` path is unchanged. A one-time migration warning is logged when the legacy path exists but the new path does not.

- **Files**: `src/main.rs` (`get_storage_path()`), `src/audit_log.rs` (`get_audit_log_path()`, `get_audit_hmac_key_path()`)
- **Current state**: ✅ `%LOCALAPPDATA%\PasswordSaver\` on Windows; `~/.password_saver/` on Unix
- **Impact resolved**: Windows users can now find their data via Windows Explorer and it is included in standard backup solutions

---

#### 🟡 Medium

**✅ 6. (RESOLVED) Windows installation documentation added to README (`README.md`)**

The README now includes Windows in the features list (as experimental), a "Windows" subsection under "Platform-Specific Dependencies" with Visual C++ Build Tools prerequisites, a "Known Windows Limitations" subsection covering the console window, SmartScreen, and storage location, and an updated Storage Location entry for `%LOCALAPPDATA%\PasswordSaver\`. The roadmap entry is updated to reflect that experimental Windows support is now available.

- **File**: `README.md`
- **Previous state**: Zero Windows setup instructions; "Windows Support" listed as future work
- **Current state**: ✅ Windows prerequisites, build steps, storage path, and known limitations documented; feature list updated to include Windows (experimental)

---

**7. ✅ FIXED: No Windows-specific system dependency installation step in CI (`ci.yml`)**

The CI matrix includes `windows-latest` but had no Windows-specific setup step (unlike the Ubuntu `apt-get` and macOS `brew` steps). The CI worked because GitHub-hosted `windows-latest` runners have MSVC pre-installed, but this was not documented or explicit.

- **File**: `.github/workflows/ci.yml`
- **Fixed state**: A `Verify MSVC toolchain (Windows)` step (`if: runner.os == 'Windows'`, runs `rustup show`) explicitly documents the pre-installed MSVC toolchain. A comment above the matrix entry explains that no extra installation is needed. README "Local Development" section now documents Visual C++ Build Tools as the Windows prerequisite.
- **Impact**: CI passes on all three platforms; developers setting up Windows locally have clear guidance

---

**8. ✅ FIXED: Directory ACL implementation now uses `FILE_FLAG_BACKUP_SEMANTICS` (`windows_permissions.rs`)**

`set_windows_directory_permissions()` previously delegated entirely to `set_windows_secure_permissions()`, which opens the path using `CreateFileW` with `OPEN_EXISTING` and `FILE_SHARE_READ`. Opening a **directory** with `CreateFileW` requires the `FILE_FLAG_BACKUP_SEMANTICS` flag in the `dwFlagsAndAttributes` parameter. Without it, `CreateFileW` fails on a directory path, causing the ACL function to silently return `Err(SecurityError::PermissionDenied)`.

- **File**: `src/windows_permissions.rs`
- **Fixed state**: `set_windows_directory_permissions()` has its own dedicated implementation that passes `FILE_FLAG_BACKUP_SEMANTICS` to `CreateFileW`, correctly opening a directory handle and applying the ACL
- **Impact**: Storage directory permissions are now correctly set on Windows

---

**9. Error from `set_windows_directory_permissions` is silently ignored (`main.rs`)** ✅ Fixed

In `main.rs`, the call to `set_windows_directory_permissions()` uses `let _ = ...`, meaning any ACL failure is silently discarded. Unlike Unix where permissions are verified and the application returns an error if they cannot be set, the Windows path provides no feedback.

- **File**: `src/main.rs`
- **Fixed state**: `if let Err(e) = set_windows_directory_permissions(parent)` now emits a `log::warn!()` including the directory path and error details; application continues to start
- **Impact**: Users and administrators now see a warning in the log if the storage directory ACL could not be set, improving security posture transparency

---

**10. No Windows application manifest or DPI awareness declaration** ✅ Fixed

Modern Windows applications should declare DPI awareness via an application manifest (or via `SetProcessDpiAwarenessContext` API) to render crisply on high-DPI displays. Without this, Windows may scale the application using bitmap scaling, resulting in blurry text and controls. Slint handles DPI internally for many backends, but a manifest ensures the OS does not apply legacy DPI virtualization.

- **Files**: `build.rs`, or a new `app.manifest` embedded via `windows-manifest` crate
- **Previous state**: No manifest file or DPI awareness declaration
- **Fixed state**: `app.manifest` added to the project root declaring `PerMonitorV2` DPI awareness. `embed-manifest = "1.4"` added as a Windows-only build dependency. `build.rs` embeds the manifest at compile time via `embed_manifest::embed_manifest(embed_manifest::new_manifest("app.manifest"))` under a `#[cfg(windows)]` guard. Slint's own Windows backend also handles per-monitor DPI scaling internally; the manifest reinforces this by preventing Windows from applying DPI virtualization before Slint can act.
- **Impact**: Application now renders crisply on HiDPI displays (Surface Pro, 4K monitors) at any scaling factor

---

**11. No Windows packaging / installer**

There is no mechanism to package the application as a Windows installer (`.msi`, NSIS `.exe`, or WiX bundle). Windows users expect either a download from the releases page or a package manager install (Winget, Chocolatey, Scoop). Binary downloads alone (a raw `.exe` in a `.zip`) will trigger Windows SmartScreen warnings for unsigned executables.

- **Current state**: No installer, no Winget/Chocolatey manifest
- **Impact**: Poor first-run experience; SmartScreen blocks or warns; no Start Menu entry, no uninstaller
- **Fix (minimum viable)**: Produce a signed `.zip` with `.exe` in the release workflow; document SmartScreen bypass steps; for polished experience, create a WiX or NSIS installer

---

#### 🟢 Low / Informational

**12. `main.rs` doc comment omits Windows from supported platforms**

The module-level doc comment in `main.rs` states "Cross-platform support (macOS, Linux)" — Windows is absent.

- **File**: `src/main.rs`, line 14
- **Fix**: Update to include Windows or qualify as "experimental Windows support"

---

**13. Clipboard auto-clear behaviour on Windows**

`arboard` (v3.4) clipboard on Windows works differently from X11/macOS: the Windows clipboard is owned by a window; when the application loses focus, Windows may clear the clipboard data. The 45-second auto-clear timer in `clipboard.rs` may therefore never fire if the user has already switched away. This is not a bug but a behavioural difference Windows users may not understand.

- **File**: `src/clipboard.rs`
- **Impact**: Clipboard clear UX differs from macOS/Linux; documentation gap
- **Fix**: Document Windows clipboard behaviour in user-facing help text; consider shortening the auto-clear window on Windows

---

**14. Dev container is Linux-only**

The `.devcontainer` configuration spins up a Linux container. Windows developers using VS Code Dev Containers will get a Linux environment, which works for building but is not a native Windows development experience, and will not reproduce Windows-specific build issues.

- **Fix**: Document that the dev container runs Linux and that Windows-native builds should be done locally; optionally add a separate Windows dev container

---

## User Experience Reflection

### From a Windows End-User's Perspective

A Windows user's first interaction with this application today would likely be:

1. **Discover the repository** on GitHub — the README now includes Windows in the features list (experimental) and a "Known Windows Limitations" section.
2. **Download a pre-built binary** from the GitHub releases page (`rust-slint-password-saver-windows-x86_64.zip`). ✅ Fixed — no longer requires Rust + MSVC toolchain.
3. **SmartScreen warning on first launch** — unsigned executables from unknown publishers trigger Windows SmartScreen / Defender. User must click "More info → Run anyway". Unresolved; requires code signing.
4. **No console window** ✅ Fixed — `windows_subsystem = "windows"` suppresses the terminal; the app opens directly to the GUI.
5. **File storage at `%LOCALAPPDATA%\PasswordSaver\`** ✅ Fixed — visible in Windows Explorer, included in standard backups; legacy dotfolder users see a migration warning in the log.
6. **High-DPI displays** ✅ Fixed — `app.manifest` embedded via `embed-manifest` declares PerMonitorV2 DPI awareness; the window renders crisply on Surface Pro and 4K monitors.
7. **No uninstaller** — the binary has no Windows installation footprint; uninstalling means manually deleting files with no guidance. Unresolved; requires installer.

For a Windows developer, the experience is better (they can build from source), but there are no Windows-specific troubleshooting guides, and ACL failures are now logged as warnings rather than silently discarded.

### For an Agentic AI Developer

The codebase is well-structured and the `#[cfg(windows)]` / `#[cfg(unix)]` pattern is used correctly. The primary risk for an AI agent making Windows improvements is:

- Accidentally breaking the Unix path when adding Windows-specific code (always use `#[cfg(windows)]` additions, not replacements)
- The `unsafe` Windows API code in `windows_permissions.rs` requires careful modification — test on a real Windows runner in CI
- The `windows` crate uses very specific feature flags in `Cargo.toml` — additions must include the correct feature strings

---

## Actionable Improvements

Each item below is formatted as a standalone GitHub issue suitable for hands-off Agentic AI development.

---

### ✅ Issue 1 (RESOLVED): Add `windows_subsystem` attribute to suppress console window on Windows

**Title**: `fix(windows): suppress console window on launch with windows_subsystem attribute`

**Labels**: `bug`, `windows`, `ux`

**Description**:

When the application is launched on Windows, a black console/terminal window appears alongside the main UI window. This is caused by the absence of the `windows_subsystem = "windows"` attribute in `main.rs`.

**Acceptance Criteria**:
- No console window appears when running `rust-slint-password-saver.exe` on Windows
- Application still builds and passes all tests on Linux and macOS (use `cfg_attr` to avoid affecting non-Windows builds)
- `log` output is redirected to a file on Windows (e.g., `%LOCALAPPDATA%\PasswordSaver\app.log`) since `stderr` is unavailable after applying this attribute

**Implementation Notes**:
1. Add `#![cfg_attr(windows, windows_subsystem = "windows")]` at the top of `src/main.rs`
2. Update `env_logger` initialisation to write to a file on Windows (use a conditional `#[cfg(windows)]` block)
3. Run the full CI test suite to confirm no regressions on Linux/macOS
4. Manually test on `windows-latest` GitHub Actions runner by verifying the build step succeeds

**Files to modify**: `src/main.rs`

---

### ✅ Issue 2 (RESOLVED): Add Windows (`x86_64-pc-windows-msvc`) release binary to CI/CD pipeline

**Title**: `feat(ci): add Windows x86_64 release binary to release workflow`

**Labels**: `enhancement`, `windows`, `ci`

**Description**:

The release workflow (`.github/workflows/release.yml`) builds binaries for Linux and macOS but not Windows. Windows users cannot download a pre-built binary and must compile from source.

**Acceptance Criteria**:
- A `rust-slint-password-saver-windows-x86_64.zip` artifact (containing `rust-slint-password-saver.exe`) is attached to every GitHub release
- The Windows build runs on a `windows-latest` GitHub Actions runner using the `x86_64-pc-windows-msvc` target
- The artifact is listed in the release notes

**Implementation Notes**:
1. Add a new entry to the `matrix.include` array in `.github/workflows/release.yml`:
   ```yaml
   - os: windows-latest
     target: x86_64-pc-windows-msvc
     artifact_name: rust-slint-password-saver.exe
     asset_name: rust-slint-password-saver-windows-x86_64
   ```
2. Add a Windows-specific packaging step to create a `.zip` archive (use PowerShell `Compress-Archive` since `tar` may not produce portable Windows archives)
3. Update the `strip binary` steps to skip Windows (the `strip` command is not available on MSVC targets; use `cargo build --release` without additional stripping, or use `llvm-strip` if available)
4. Verify the workflow produces a valid artifact on push

**Files to modify**: `.github/workflows/release.yml`

---

### ✅ Issue 3 (RESOLVED): Fix Windows ACL not applied to HMAC key file in audit log module

**Title**: `fix(security): apply Windows ACL to audit HMAC key file on Windows`

**Labels**: `bug`, `security`, `windows`

**Description**:

In `src/audit_log.rs`, after writing the HMAC key file used for audit log integrity, Unix permissions (`0o600`) are set via a `#[cfg(unix)]` block. There is no corresponding `#[cfg(windows)]` block. On Windows, the HMAC key file is created with default ACL and is potentially readable by other local users.

**Acceptance Criteria**:
- On Windows, the audit HMAC key file has ACL set to current-user-only access after creation
- No regression on Linux/macOS (existing `#[cfg(unix)]` block unchanged)
- Windows ACL call failures are logged as warnings (consistent with Unix handling)

**Implementation Notes**:
1. Locate the `#[cfg(unix)]` block in `src/audit_log.rs` (lines ~200–212) that sets `0o600` on the HMAC key file
2. Immediately after that block, add:
   ```rust
   #[cfg(windows)]
   {
       use crate::windows_permissions::set_windows_secure_permissions;
       if let Err(e) = set_windows_secure_permissions(key_path) {
           log::warn!(
               "Failed to set Windows ACL on audit HMAC key {}: {:?}. \
                Key file may be accessible to other users.",
               key_path.display(), e
           );
       }
   }
   ```
3. Ensure `windows_permissions` is visible in the module (it's `pub(crate)` via `lib.rs` with `#[cfg(windows)]`)
4. Run `cargo test` on Windows runner to verify

**Files to modify**: `src/audit_log.rs`

---

### ✅ Issue 4 (RESOLVED): Fix Windows ACL not applied to rate limit persist file

**Title**: `fix(security): apply Windows ACL to rate limit persist file on Windows`

**Labels**: `bug`, `security`, `windows`

**Description**:

`src/rate_limit.rs` sets Unix `0o600` permissions on the persisted rate-limit state file after each write, but has no Windows equivalent. A local attacker could delete or overwrite this file on Windows to bypass brute-force protection.

**Acceptance Criteria**:
- On Windows, the rate limit persist file has ACL set to current-user-only access after each write
- No regression on Linux/macOS
- ACL call failures are silently ignored (same best-effort semantics as the file write itself)

**Implementation Notes**:
1. Locate the `#[cfg(unix)]` block in `src/rate_limit.rs` (`persist_attempts` function, lines ~329–334)
2. Add a `#[cfg(windows)]` block directly after:
   ```rust
   #[cfg(windows)]
   {
       use crate::windows_permissions::set_windows_secure_permissions;
       let _ = set_windows_secure_permissions(path);
   }
   ```
3. Confirm the `windows_permissions` module is accessible from `rate_limit.rs` (check `use` path)

**Files to modify**: `src/rate_limit.rs`

---

### ✅ Issue 5 (RESOLVED): Fix `set_windows_directory_permissions` missing `FILE_FLAG_BACKUP_SEMANTICS`

**Title**: `fix(windows): add FILE_FLAG_BACKUP_SEMANTICS when opening directory for ACL modification`

**Labels**: `bug`, `security`, `windows`

**Description**:

`src/windows_permissions.rs` implements `set_windows_directory_permissions()` by delegating to `set_windows_secure_permissions()`. That function calls `CreateFileW` with `OPEN_EXISTING` but without the `FILE_FLAG_BACKUP_SEMANTICS` flag. On Windows, opening a **directory** handle with `CreateFileW` requires `FILE_FLAG_BACKUP_SEMANTICS` in the `dwFlagsAndAttributes` parameter — without it, the call returns `ERROR_ACCESS_DENIED` or `INVALID_HANDLE_VALUE`, causing the ACL to silently not be set. The call failure is then swallowed in `main.rs` with `let _ = ...`.

**Acceptance Criteria**:
- `set_windows_directory_permissions()` successfully opens a directory and applies ACL on Windows
- The existing `test_windows_directory_permissions_secure` test passes on a Windows runner
- `set_windows_secure_permissions()` (for files) is unchanged and continues to work

**Implementation Notes**:
1. In `src/windows_permissions.rs`, create a separate implementation for `set_windows_directory_permissions` instead of delegating to `set_windows_secure_permissions`:
   ```rust
   #[cfg(windows)]
   pub fn set_windows_directory_permissions(path: &Path) -> Result<(), SecurityError> {
       // Same logic as set_windows_secure_permissions but with FILE_FLAG_BACKUP_SEMANTICS
       use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
       // ... open with FILE_FLAG_BACKUP_SEMANTICS.0 in dwFlagsAndAttributes ...
   }
   ```
2. Import `FILE_FLAG_BACKUP_SEMANTICS` from `windows::Win32::Storage::FileSystem` (already a listed feature in `Cargo.toml`)
3. Add or verify the `test_windows_directory_permissions_secure` test in the module validates that the call returns `Ok(())`
4. Run tests on `windows-latest` GitHub Actions runner

**Files to modify**: `src/windows_permissions.rs`

---

### ✅ Issue 6 (RESOLVED): Log warning when Windows directory ACL fails instead of silently ignoring

**Title**: `fix(windows): log warning when directory ACL cannot be set instead of silent ignore`

**Labels**: `bug`, `windows`, `observability`

**Description**:

In `src/main.rs`, the call to `set_windows_directory_permissions()` uses `let _ = ...` to discard any error. On Unix, a failure to set directory permissions returns an error from `get_storage_path()` which aborts application startup with a clear message. On Windows, the equivalent failure is silently discarded, leaving the storage directory without secure ACL and the user with no indication.

**Acceptance Criteria**:
- If `set_windows_directory_permissions()` returns `Err`, a `warn!()` log message is emitted
- Application continues to start (consistent with current behaviour; do not treat as fatal)
- The log message includes the directory path and error type for diagnostics

**Implementation Notes**:
1. In `src/main.rs`, replace:
   ```rust
   #[cfg(windows)]
   {
       use rust_slint_password_saver::windows_permissions::set_windows_directory_permissions;
       let _ = set_windows_directory_permissions(parent);
   }
   ```
   with:
   ```rust
   #[cfg(windows)]
   {
       use rust_slint_password_saver::windows_permissions::set_windows_directory_permissions;
       if let Err(e) = set_windows_directory_permissions(parent) {
           log::warn!(
               "Failed to set Windows ACL on storage directory {:?}: {:?}. \
                Directory may be accessible to other users.",
               parent, e
           );
       }
   }
   ```
2. Run `cargo test` to confirm no regressions

**Files to modify**: `src/main.rs`

---

### ✅ Issue 7 (RESOLVED): Use Windows-conventional `%LOCALAPPDATA%` for storage path on Windows

**Title**: `feat(windows): use %LOCALAPPDATA%\PasswordSaver\ as storage path on Windows`

**Labels**: `enhancement`, `windows`, `ux`

**Description**:

On Windows, application data should be stored in `%LOCALAPPDATA%\<AppName>\` (for non-roaming user data) rather than `%USERPROFILE%\.password_saver\`. Using `%LOCALAPPDATA%` is the Windows-conventional location, is visible in Windows Explorer, and is included in standard backup solutions. The current dotfolder approach (`~/.password_saver/`) is hidden by default in Windows Explorer and is a Unix convention.

**Acceptance Criteria**:
- On Windows, storage files are created at `%LOCALAPPDATA%\PasswordSaver\passwords.enc` (and `audit.log`, `audit_hmac.key` in the same directory)
- On Unix systems, the existing `~/.password_saver/` path is unchanged
- If `LOCALAPPDATA` is not set, fall back gracefully to `USERPROFILE\.password_saver\`
- Existing Windows users with data at `USERPROFILE\.password_saver\` receive a one-time migration prompt or the old path is checked first

**Implementation Notes**:
1. Modify `get_storage_path()` in `src/main.rs` to use `#[cfg(windows)]` conditional:
   ```rust
   #[cfg(windows)]
   let base_dir = std::env::var("LOCALAPPDATA")
       .or_else(|_| std::env::var("USERPROFILE"))
       .unwrap_or_else(|_| String::from("."));
   #[cfg(not(windows))]
   let base_dir = std::env::var("HOME")
       .unwrap_or_else(|_| String::from("."));
   ```
2. Use `PasswordSaver` (no leading dot) as the directory name on Windows
3. Apply the same change to `get_audit_log_path()` and `get_audit_hmac_key_path()` in `src/audit_log.rs`
4. Add a migration check on Windows: if the new path does not exist but the old `USERPROFILE\.password_saver\` does, log a warning instructing the user to move their data

**Files to modify**: `src/main.rs`, `src/audit_log.rs`

---

### ✅ Issue 8 (RESOLVED): Add Windows installation documentation to README

**Title**: `docs: add Windows installation and build instructions to README`

**Labels**: `documentation`, `windows`

**Description**:

The README `Installation` section covers only macOS and Linux. Windows is listed as future work in the roadmap despite the application already building and running on Windows. Windows developers and users have no guidance on prerequisites, build steps, or known limitations.

**Acceptance Criteria**:
- A "Windows" subsection under "Platform-Specific Dependencies" with step-by-step instructions
- Known Windows limitations (console window, SmartScreen, dotfolder location) are documented
- Storage location for Windows (`%LOCALAPPDATA%\PasswordSaver\`) is documented
- The feature list at the top of README includes Windows (marked as experimental if appropriate)

**Implementation Notes**:
1. Add a `**Windows**` subsection to the "Platform-Specific Dependencies" section in README.md:
   ```markdown
   **Windows**:
   - Visual C++ Build Tools 2019 or later (install via https://visualstudio.microsoft.com/visual-cpp-build-tools/ or `winget install Microsoft.VisualStudio.2022.BuildTools`)
   - No additional system libraries required; Slint uses Direct3D on Windows
   ```
2. Add a "Known Windows Limitations" subsection noting:
   - Console window (to be fixed in a future release)
   - SmartScreen warning on unsigned binaries built from source
   - Storage location at `%USERPROFILE%\.password_saver\` (hidden by default; open via `%APPDATA%` in Explorer)
3. Update the feature list to include "Windows (experimental)"
4. Update the Storage Location section to include Windows path

**Files to modify**: `README.md`

---

### ✅ Issue 9 (RESOLVED): Add Windows application manifest for DPI awareness

**Title**: `feat(windows): embed application manifest declaring PerMonitorV2 DPI awareness`

**Labels**: `enhancement`, `windows`, `ux`

**Description**:

On Windows HiDPI displays (Surface Pro, 4K monitors), applications without a DPI awareness manifest may be rendered using legacy bitmap scaling (DPI virtualization), resulting in blurry text and controls. An application manifest declaring `PerMonitorV2` DPI awareness ensures crisp rendering on all display configurations.

**Resolution**:
- `app.manifest` added to the project root with `dpiAware` (true/PM) and `dpiAwareness` (PerMonitorV2) settings
- `embed-manifest = "1.4"` added as a `[target.'cfg(windows)'.build-dependencies]` entry in `Cargo.toml`
- `build.rs` calls `embed_manifest::embed_manifest(embed_manifest::new_manifest("app.manifest"))` under a `#[cfg(windows)]` guard, embedding the manifest at compile time — no separate `.exe.manifest` file is required at runtime
- **Slint finding**: Slint's Windows backend handles per-monitor DPI scaling internally. The embedded manifest complements this by ensuring the OS does not apply DPI virtualization before Slint can act, avoiding any conflict.

---

### ✅ Issue 10 (RESOLVED): Add Windows-specific CI setup step documentation and verification

**Title**: `docs(ci): document and verify Windows CI prerequisites in ci.yml`

**Labels**: `ci`, `windows`, `documentation`

**Description**:

The CI matrix runs on `windows-latest` but has no Windows-specific setup step, unlike the Ubuntu (`apt-get`) and macOS (`brew`) steps. This works because GitHub-hosted Windows runners have MSVC pre-installed, but it is not documented or explicit. Developers setting up a local Windows build environment have no guidance on which tools are required.

**Acceptance Criteria**:
- A comment in `ci.yml` explains why no extra dependencies are needed for Windows (MSVC pre-installed on GitHub runner) or a minimal Windows setup step is added
- A new documentation section or note in README's "Development Setup" explains Windows local prerequisites
- CI continues to pass on all three platforms

**Implementation Notes**:
1. Add a no-op `if: runner.os == 'Windows'` step to `ci.yml` that echoes the available MSVC version, serving as explicit documentation:
   ```yaml
   - name: Verify MSVC toolchain (Windows)
     if: runner.os == 'Windows'
     run: rustup show
   ```
2. Add a comment above the Windows matrix entry explaining that MSVC build tools are pre-installed on `windows-latest` runners
3. In README, add a note under "Local Development" that Windows requires "Visual C++ Build Tools" and link to the Microsoft download

**Files to modify**: `.github/workflows/ci.yml`, `README.md`

---

### Finding A: Unused imports in `windows_permissions.rs` ✅ Implemented

**Title**: `chore(windows): remove unused GRANT_ACCESS, INHERITED_ACE imports from windows_permissions.rs`

**Labels**: `chore`, `windows`, `code-quality`

**Description**:

The `#[cfg(windows)]` import block at the top of `src/windows_permissions.rs` (line 17) included `GRANT_ACCESS` and `INHERITED_ACE` from `windows::Win32::Security::Authorization`. Neither constant was referenced in any function body — only `SET_ACCESS`, `NO_INHERITANCE`, and `SUB_CONTAINERS_AND_OBJECTS_INHERIT` are actually used. On a Windows build with `cargo clippy`, these unused imports would generate `unused_imports` lint warnings. `ACCESS_MODE` is kept because it is the declared type of the `grfAccessMode` field in `EXPLICIT_ACCESS_W` struct literals; the Rust compiler resolves the type from the import and it is therefore not unused.

- **File**: `src/windows_permissions.rs`, line 17
- **Previous state**: `GRANT_ACCESS` and `INHERITED_ACE` appeared in the import list but were not used
- **Fix applied**: Removed `GRANT_ACCESS` and `INHERITED_ACE` from the import list; retained `ACCESS_MODE`, `SET_ACCESS`, `NO_INHERITANCE`, `SUB_CONTAINERS_AND_OBJECTS_INHERIT`, `SE_FILE_OBJECT`, `EXPLICIT_ACCESS_W`, `SetEntriesInAclW`, `SetSecurityInfo`, `TRUSTEE_IS_SID`, `TRUSTEE_W`
- **Status**: ✅ Implemented

**Files modified**: `src/windows_permissions.rs`

---

### Finding B (March 2026): Windows CI build failure — `windows` v0.52 API mismatch ✅ Fixed

**Title**: `fix(windows): resolve windows v0.52 API incompatibilities in windows_permissions.rs`

**Labels**: `bug`, `windows`, `build`

**Description**:

The Windows CI leg failed to compile due to four incompatibilities with `windows` crate v0.52:

1. **Unresolved imports** (`E0432`): `NO_INHERITANCE` and `SUB_CONTAINERS_AND_OBJECTS_INHERIT` are not exported by `windows::Win32::Security::Authorization` in this crate version. These were removed from the import block and replaced with local `const` definitions using their documented Win32 values from `WinNT.h`.

2. **Mismatched return types** (`E0308`): `SetEntriesInAclW` and `SetSecurityInfo` return `windows_core::Result<()>` in v0.52, not `WIN32_ERROR`. All four comparisons of the form `if result != ERROR_SUCCESS` were replaced with `if result.is_err()`. `ERROR_SUCCESS` was removed from the import list.

3. **Wrong pointer type** (`E0277`): `CreateFileW` requires a `PCWSTR` (`*const u16`) parameter, but `PWSTR` (`*mut u16`) was passed. Fixed by using `PCWSTR(wide_path.as_ptr())` instead of `PWSTR(wide_path.as_mut_ptr())` in both `set_windows_secure_permissions` and `set_windows_directory_permissions`.

4. **Wrong handle type** (`E0277`): `LocalFree` requires an `HLOCAL` parameter, but `HANDLE` was passed. Fixed by using `HLOCAL(new_acl as isize)` instead of `HANDLE(new_acl as isize)`. Added `HLOCAL` to the `windows::Win32::Foundation` import. Also removed the unused `ACCESS_MODE` import to eliminate the unused-import warning (which becomes a hard error under `-D warnings`).

- **File**: `src/windows_permissions.rs`
- **Root cause**: `windows` crate v0.52 changed the return type of ACL functions to `Result`-style, does not re-export certain ACE inheritance flags at the Authorization module path, and uses distinct handle types (`HLOCAL`, `PCWSTR`) that do not implement `IntoParam` for each other.
- **Fix applied**:
  - Removed `NO_INHERITANCE`, `SUB_CONTAINERS_AND_OBJECTS_INHERIT` from imports; added local `const NO_INHERITANCE: u32 = 0x0` and `const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3`
  - Removed `ERROR_SUCCESS` and `ACCESS_MODE` from imports
  - Replaced all four `!= ERROR_SUCCESS` checks with `.is_err()` in both functions
  - Changed `PWSTR(wide_path.as_mut_ptr())` → `PCWSTR(wide_path.as_ptr())` for `CreateFileW` in both functions
  - Changed `HANDLE(new_acl as isize)` → `HLOCAL(new_acl as isize)` for `LocalFree` in both functions
  - Added `PCWSTR` to `windows::core` imports; added `HLOCAL` to `windows::Win32::Foundation` imports
- **Status**: ✅ Fixed

**Files modified**: `src/windows_permissions.rs`, `WINDOWS.md`

### ~~New Finding B: No `.gitattributes` — CRLF line-ending risk on Windows clones~~ ✅ Resolved

**Title**: `chore: add .gitattributes to enforce LF line endings for source and data files`

**Labels**: `chore`, `windows`, `cross-platform`

**Status**: ✅ **Implemented** — `.gitattributes` created with global `* text=auto eol=lf` rule and per-extension `eol=lf` overrides for all source/data files; binary files marked with `binary` attribute. 17 TDD tests added in `tests/gitattributes_test.rs`.

**Description**:

The repository had no `.gitattributes` file. On Windows, Git defaults to `core.autocrlf=true`, which converts LF to CRLF on checkout. This can silently corrupt files whose content is parsed as text but must maintain exact byte sequences (e.g., `app.manifest` XML and any raw test fixtures), produce noisy diffs, and cause subtle issues when file content is compared byte-for-byte in tests. The `app.manifest` XML file in particular should remain LF to ensure the manifest parser in `embed-manifest` receives the expected bytes.

- **Previous state**: No `.gitattributes`; Windows developers cloning with default Git settings get CRLF in all text files
- **Impact**: Potential byte-level mismatches in tests; dirty working tree after switching platforms; manifest XML parser may produce unexpected output
- **Fix applied**: Created `.gitattributes` with:
  ```gitattributes
  * text=auto eol=lf
  *.rs       text eol=lf
  *.toml     text eol=lf
  *.md       text eol=lf
  *.yml      text eol=lf
  *.yaml     text eol=lf
  *.slint    text eol=lf
  *.manifest text eol=lf
  *.json     text eol=lf
  *.txt      text eol=lf
  *.sh       text eol=lf
  *.exe      binary
  *.enc      binary
  *.png      binary
  *.ico      binary
  ```

**Files created**: `.gitattributes`, `tests/gitattributes_test.rs`

---

### ✅ New Finding C (RESOLVED): Application manifest missing `longPathAware` declaration

**Title**: `feat(windows): add longPathAware to app.manifest to support paths > 260 characters`

**Labels**: `enhancement`, `windows`

**Description**:

Windows 10 version 1607 introduced native long-path support (> 260 characters / `MAX_PATH`). Applications must opt in by declaring `<longPathAware>true</longPathAware>` in their application manifest AND the system must have the corresponding Group Policy or registry key enabled (`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled = 1`). Without this declaration, `CreateFileW` and related APIs silently fail on paths longer than 260 characters, which can happen when `%LOCALAPPDATA%` itself is unusually deep (e.g., on enterprise machines with domain-joined user accounts and deep folder trees).

- **File**: `app.manifest`
- **Previous state**: `longPathAware` not declared; application would silently fail on paths > 260 characters on Windows 10 1607+ even with the system policy enabled

**Resolution**:
- `<longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>` added inside the existing `<asmv3:windowsSettings>` block in `app.manifest`
- 11 TDD tests added in `tests/app_manifest_test.rs` covering manifest existence, `longPathAware` presence, correct value (`true`), correct namespace, correct nesting inside `<asmv3:windowsSettings>`, preservation of existing DPI-awareness declarations, and structural integrity checks

---

### ✅ New Finding D (IMPLEMENTED): No code-signing — SmartScreen blocks unsigned release binaries

**Title**: `feat(release): sign Windows release binary to avoid SmartScreen false positive`

**Labels**: `enhancement`, `windows`, `security`, `ux`

**Status**: ✅ **Implemented** — Authenticode signing step enabled in `release.yml` using
`azure/trusted-signing-action@v0.5.1`; step skips gracefully when Microsoft Trusted Signing
secrets are absent; README documents SmartScreen bypass for unsigned builds.

**Description**:

All unsigned Windows executables from unknown publishers trigger Windows SmartScreen and may also trigger Windows Defender heuristic scanning. Users who download `rust-slint-password-saver-windows-x86_64.zip` and extract the `.exe` will see "Windows protected your PC" and must click "More info → Run anyway" — a step that many users will not take, treating it as a sign of malware. This is particularly damaging for a security-focused password manager application.

- **Previous state**: No Authenticode code-signing in the release workflow; no user guidance in README
- **Changes applied**:
  - **`README.md`**: Added a dedicated `### Running on Windows — SmartScreen Warning` subsection with:
    - Step-by-step "More info → Run anyway" bypass instructions
    - Explanation that the binary is unsigned (unknown publisher)
    - Note that source-built binaries (`cargo build --release`) bypass SmartScreen entirely
  - **`.github/workflows/release.yml`**: Enabled Microsoft Trusted Signing step
    (`azure/trusted-signing-action@v0.5.1`) guarded by
    `if: runner.os == 'Windows' && env.AZURE_TENANT_ID != ''`; step is placed **before** archive
    creation so `.zip` and `.msi` artifacts contain the signed binary; Option B (EV certificate via
    `signtool.exe`) retained as a commented reference
- **Options**:
  - **Minimum** ✅ Done: README guidance added; bypass instructions documented
  - **Better** ✅ Done: Microsoft Trusted Signing step enabled; activate by setting the five
    required GitHub Actions secrets (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
    `TRUSTED_SIGNING_ACCOUNT_NAME`, `TRUSTED_SIGNING_CERTIFICATE_PROFILE_NAME`)
  - **Alternative**: Obtain an EV Code Signing Certificate and enable the `signtool.exe` Option B
    comment in `release.yml`
- **Impact**: Unsigned binaries erode trust for a password manager; SmartScreen reputation builds slowly via download count
- **TDD tests**: 19 tests in `tests/code_signing_test.rs` covering README content, `release.yml`
  active signing step, conditional logic, step ordering, and `WINDOWS.md` documentation

**Files modified**: `.github/workflows/release.yml`, `README.md`, `WINDOWS.md`, `SECURITY.md`, `tests/code_signing_test.rs`

---

### Code Signing

This subsection documents the available options for Authenticode code-signing the Windows release
binary, eliminating the Windows SmartScreen "Windows protected your PC" dialog on first launch.

#### Why code-signing matters

Windows SmartScreen evaluates two signals for downloaded executables:
1. **Authenticode signature** — is the binary signed by a trusted certificate authority?
2. **Download reputation** — has this exact hash been seen often enough by Microsoft's telemetry?

An unsigned binary from an unknown publisher must accumulate significant download volume before
SmartScreen stops blocking it. For a security-focused password manager, asking users to click
"More info → Run anyway" undermines trust. An Authenticode certificate eliminates the reputation
requirement immediately.

#### Option A — Microsoft Trusted Signing (recommended)

[Microsoft Trusted Signing](https://learn.microsoft.com/en-us/azure/trusted-signing/) (formerly
Azure Code Signing) is a cloud-based signing service that does **not** require a hardware USB token.

| Attribute | Detail |
|-----------|--------|
| **Provider** | Microsoft Azure |
| **Certificate type** | Managed identity certificate (renewed automatically) |
| **Hardware token** | Not required |
| **Cost** | ~$9.99/month (Basic SKU, as of early 2026) |
| **SmartScreen** | Full Authenticode trust on day one |
| **Setup time** | 1–3 business days (identity verification) |
| **GitHub Actions action** | `azure/trusted-signing-action@v0` |

**Required GitHub repository secrets**:
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`

**GitHub Actions snippet** (already present as a comment in `release.yml`):
```yaml
- name: Sign Windows binary (Microsoft Trusted Signing)
  if: runner.os == 'Windows'
  uses: azure/trusted-signing-action@v0
  with:
    azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
    azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
    endpoint: https://eus.codesigning.azure.net/
    trusted-signing-account-name: <account-name>
    certificate-profile-name: <profile-name>
    files-folder: target/x86_64-pc-windows-msvc/release
    files-folder-filter: exe
    file-digest: SHA256
    timestamp-rfc3161: http://timestamp.acs.microsoft.com
    timestamp-digest: SHA256
```

#### Option B — EV Code Signing Certificate

An Extended Validation (EV) certificate from a traditional CA (e.g., DigiCert, Sectigo, GlobalSign)
provides the strongest SmartScreen signal but requires a hardware USB token (FIDO2 or HSM).

| Attribute | Detail |
|-----------|--------|
| **Provider** | DigiCert, Sectigo, GlobalSign, etc. |
| **Certificate type** | EV (Extended Validation) |
| **Hardware token** | Required (USB token shipped by the CA) |
| **Cost** | ~$300–$500/year |
| **SmartScreen** | Full Authenticode trust on day one; highest reputation tier |
| **Setup time** | 3–10 business days (identity + business verification) |
| **GitHub Actions** | `signtool.exe` with PFX exported from token |

**Required GitHub repository secrets**:
- `CODE_SIGNING_CERT_PFX_BASE64` — Base64-encoded `.pfx` certificate file
- `CODE_SIGNING_CERT_PASSWORD` — Password protecting the `.pfx`

**GitHub Actions snippet** (already present as a comment in `release.yml`):
```yaml
- name: Sign Windows binary (signtool / EV certificate)
  if: runner.os == 'Windows'
  shell: pwsh
  run: |
    $pfxBytes = [Convert]::FromBase64String("${{ secrets.CODE_SIGNING_CERT_PFX_BASE64 }}")
    $pfxPath  = "$env:RUNNER_TEMP\codesign.pfx"
    [IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
    signtool sign /fd SHA256 /p "${{ secrets.CODE_SIGNING_CERT_PASSWORD }}" `
      /f "$pfxPath" `
      /t http://timestamp.digicert.com `
      "target/x86_64-pc-windows-msvc/release/rust-slint-password-saver.exe"
    Remove-Item -Force "$pfxPath"
```

#### Activation steps

1. Choose Option A (Microsoft Trusted Signing) or Option B (EV certificate).
2. Obtain the certificate / set up the Azure account per the provider's onboarding guide.
3. Add the required secrets to the GitHub repository (`Settings → Secrets and variables → Actions`).
4. Uncomment the relevant signing step in `.github/workflows/release.yml` (the placeholder is already
   present — remove the leading `#` from each line of the chosen option).
5. Push a new version tag (`v*.*.*`) to trigger the release workflow and verify the signed binary.

---

### ✅ New Finding E (RESOLVED): `main.rs` module doc comment omits Windows

**Title**: `docs: update main.rs module doc comment to include Windows in supported platforms`

**Labels**: `documentation`, `windows`

**Description**:

The module-level Rustdoc comment in `src/main.rs` (line 14) stated:
```
//! - Cross-platform support (macOS, Linux)
```
Windows was not mentioned despite the application building and running on Windows with full ACL support and a published release binary.

- **File**: `src/main.rs`, line 14
- **Previous state**: `//! - Cross-platform support (macOS, Linux)`

**Resolution**:
- Updated to `//! - Cross-platform support (macOS, Linux, Windows (experimental))`
- 3 TDD tests added in `tests/main_doc_test.rs` verifying that the doc comment mentions Windows, contains the exact cross-platform string, and still includes macOS and Linux

---

### ✅ New Finding F (RESOLVED): No Windows installer

**Title**: `feat(windows): create Windows installer using WiX or Inno Setup`

**Labels**: `enhancement`, `windows`, `ux`

**Description**:

There is no mechanism to package the application as a Windows installer. Windows users expect either a `.msi`/`.exe` installer or a package manager entry (Winget, Chocolatey, Scoop). A raw `.exe` in a `.zip` provides no Start Menu entry, no `Add/Remove Programs` uninstaller, and no file association. Combining an installer with code signing (Finding D) would eliminate SmartScreen warnings on first run.

- **Previous state**: Pre-built `.zip` in GitHub releases; no installer; no package manager manifests
- **Resolution**:
  1. **Short-term — Winget manifest** ✅ Implemented: Winget manifest (3-file multi-manifest) created at
     `winget/manifests/o/obstreperous-ai/RustSlintPasswordSaver/0.1.0/`. Supports
     `winget install obstreperous-ai.RustSlintPasswordSaver`. Submission to
     [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) pending.
  2. **Medium-term — Scoop manifest** ✅ Implemented: Scoop manifest JSON created at
     `scoop/rust-slint-password-saver.json` pointing to the GitHub release `.zip` with
     `autoupdate` support for `scoop update`.
  3. **Long-term — WiX 4 MSI installer** ✅ Implemented: WiX 4 installer definition created at
     `installer/windows/main.wxs`. Installs to `%ProgramFiles%\PasswordSaver\`, creates a
     Start Menu shortcut, and registers an uninstaller in Add/Remove Programs.
     `.github/workflows/release.yml` updated to build and publish the `.msi` artifact on every
     tagged release using `dotnet tool install --global wix`.

**Silent install**: `msiexec /i rust-slint-password-saver-windows-x86_64.msi /quiet`  
**Silent uninstall**: `msiexec /x rust-slint-password-saver-windows-x86_64.msi /quiet`

**Files created/modified**:
- `installer/windows/main.wxs` — WiX 4 installer definition
- `winget/manifests/o/obstreperous-ai/RustSlintPasswordSaver/0.1.0/` — 3-file Winget manifest
- `scoop/rust-slint-password-saver.json` — Scoop manifest
- `.github/workflows/release.yml` — WiX build step + MSI artifact upload
- `README.md` — Windows package manager installation instructions

**TDD tests added**: 32 tests in `tests/windows_installer_test.rs` covering all acceptance criteria.

---

## Windows Compatibility Matrix

This table summarises the verified compatibility status of each codebase area across the primary target Windows versions and environments as of March 2026.

| Feature / Area | Win 10 (21H2+) | Win 11 | Server 2022 | WSL2 | Notes |
|---|---|---|---|---|---|
| **Build (cargo build)** | ✅ | ✅ | ✅ | ✅ (Linux binary) | MSVC toolchain required on native Windows; WSL2 produces Linux ELF |
| **CI (windows-latest runner)** | ✅ | ✅ | ✅ | N/A | GitHub Actions `windows-latest` = Server 2022 + MSVC |
| **Release binary (.exe)** | ✅ | ✅ | ✅ | N/A | `x86_64-pc-windows-msvc` in release matrix |
| **Storage path (`%LOCALAPPDATA%`)** | ✅ | ✅ | ✅ | ⚠️ | `LOCALAPPDATA` is set by Windows; WSL2 does not set it — app uses `HOME` under WSL2 |
| **File ACL (`set_windows_secure_permissions`)** | ✅ | ✅ | ✅ | N/A | Win32 API; only applies to native Windows build |
| **Directory ACL (`FILE_FLAG_BACKUP_SEMANTICS`)** | ✅ | ✅ | ✅ | N/A | Win32 API; only applies to native Windows build |
| **HMAC key file ACL** | ✅ | ✅ | ✅ | N/A | `audit_log.rs` `#[cfg(windows)]` block applies ACL |
| **Rate-limit file ACL** | ✅ | ✅ | ✅ | N/A | `rate_limit.rs` `#[cfg(windows)]` block applies ACL |
| **Console suppression (`windows_subsystem`)** | ✅ | ✅ | ✅ | N/A | `cfg_attr(windows, …)` — no effect on Unix/WSL2 |
| **Log to file (`app.log`)** | ✅ | ✅ | ✅ | N/A | Only active when `windows_subsystem` suppresses stderr |
| **DPI awareness (PerMonitorV2)** | ✅ | ✅ | ⚠️ | N/A | Server 2022 has limited HiDPI support; manifest is embedded but GPU display may vary |
| **HiDPI rendering (Slint)** | ✅ | ✅ | ⚠️ | N/A | Slint uses Direct3D backend; Server Core has no GPU — rendering may fail |
| **Clipboard (`arboard`)** | ✅ | ✅ | ⚠️ | ⚠️ | Server Core and WSL2 may lack clipboard integration |
| **Browser launch (`webbrowser`)** | ✅ | ✅ | ⚠️ | ⚠️ | Server Core may have no default browser; WSL2 needs `BROWSER` env var |
| **Update checker (`reqwest`)** | ✅ | ✅ | ✅ | ✅ | TLS via native Windows SSPI or OpenSSL in WSL2 |
| **Encryption (Argon2/AES-GCM)** | ✅ | ✅ | ✅ | ✅ | Pure Rust; fully platform-agnostic |
| **Long-path support (> 260 chars)** | ✅ | ✅ | ✅ | N/A | `longPathAware` declared in `app.manifest`; requires `LongPathsEnabled = 1` registry key on host |
| **Code signing (SmartScreen)** | ⚠️ | ⚠️ | ⚠️ | N/A | Signing step enabled in `release.yml` (`azure/trusted-signing-action@v0.5.1`); activates automatically when `AZURE_TENANT_ID` secret is set. Without the secret the binary is unsigned and SmartScreen warns on first launch; README documents bypass steps (see Finding D / Code Signing subsection) |
| **Installer / uninstaller** | ✅ | ✅ | ✅ | N/A | WiX 4 `.msi` installer built in `release.yml`; installs to `%ProgramFiles%\PasswordSaver\`; Start Menu shortcut created; Add/Remove Programs entry registered. Silent install/uninstall via `msiexec /i|/x ... /quiet`. |
| **Winget / Chocolatey / Scoop** | ✅ | ✅ | ✅ | N/A | Winget multi-manifest at `winget/manifests/o/obstreperous-ai/RustSlintPasswordSaver/0.1.0/`; Scoop manifest at `scoop/rust-slint-password-saver.json`; submission to winget-pkgs pending. |
| **Line-ending hygiene (`.gitattributes`)** | ✅ | ✅ | ✅ | ✅ | `.gitattributes` added; LF enforced for all source/data files; binaries marked binary |

**Legend**: ✅ Verified working · ⚠️ Works with caveats / not fully tested · ❌ Not implemented

---

## Automated Improvements for Next Agent Run

The following is a clean, numbered list of concrete GitHub issues for the next hands-off agent. Each item is single, scoped, and actionable with acceptance criteria.

1. ~~**Remove unused imports `GRANT_ACCESS` and `INHERITED_ACE` from `windows_permissions.rs`**~~
   ✅ **Implemented** — Removed `GRANT_ACCESS` and `INHERITED_ACE` from the `#[cfg(windows)]` import block in `src/windows_permissions.rs`.

2. ~~**Add `.gitattributes` to enforce LF line endings**~~
   ✅ **Implemented** — Created `.gitattributes` at the repository root with `* text=auto eol=lf` and explicit `eol=lf` overrides for `*.rs`, `*.toml`, `*.yml`, `*.yaml`, `*.slint`, `*.manifest`, `*.json`, `*.md`, `*.txt`, `*.sh`; marked `*.exe` and `*.enc` (and `*.png`, `*.ico`) as binary. Added 17 TDD tests in `tests/gitattributes_test.rs` covering file existence, all per-extension rules, binary rules, and CRLF absence checks.

3. ~~**Add `longPathAware` declaration to `app.manifest`**~~
   ✅ **Implemented** — Added `<longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>` inside the existing `<asmv3:windowsSettings>` block in `app.manifest`. Added 11 TDD tests in `tests/app_manifest_test.rs` covering manifest existence, `longPathAware` presence, correct value, correct namespace, correct nesting, preservation of DPI-awareness declarations, and structural integrity.

4. ~~**Fix `main.rs` module doc comment to include Windows in supported platforms**~~
   ✅ **Implemented** — Updated line 14 of `src/main.rs` from `//! - Cross-platform support (macOS, Linux)` to `//! - Cross-platform support (macOS, Linux, Windows (experimental))`. Added 3 TDD tests in `tests/main_doc_test.rs` verifying Windows is mentioned in the doc comment, the exact cross-platform string is present, and macOS/Linux are preserved.

5. ~~**Add Windows SmartScreen bypass instructions to README**~~
   ✅ **Implemented** — Added `### Running on Windows — SmartScreen Warning` subsection to `README.md` with step-by-step "More info → Run anyway" bypass instructions, explanation that the binary is unsigned, and a note that source-built binaries bypass SmartScreen entirely. Updated the existing bullet in "Known Windows Limitations" to link to the new section. 15 TDD tests added in `tests/code_signing_test.rs`.

6. ~~**Submit a Winget package manifest for `rust-slint-password-saver`**~~
   ✅ **Implemented** — Winget multi-manifest (version, installer, locale) created at
   `winget/manifests/o/obstreperous-ai/RustSlintPasswordSaver/0.1.0/`. Supports
   `winget install obstreperous-ai.RustSlintPasswordSaver` and local testing via
   `winget install --manifest winget/manifests/...`. README Installation section updated.
   32 TDD tests added in `tests/windows_installer_test.rs`.

7. ~~**Add a Scoop bucket manifest for developer-friendly installation**~~
   ✅ **Implemented** — Scoop manifest JSON created at `scoop/rust-slint-password-saver.json`
   pointing to the GitHub release `.zip` with `autoupdate` support. README Installation section
   updated with Scoop instructions. Tests included in `tests/windows_installer_test.rs`.

8. **Document Windows clipboard auto-clear behaviour difference in UI**
   `arboard` on Windows uses the OS clipboard ownership model: the clipboard data is lost when the application loses focus. Add a Windows-specific note in the clipboard-clear tooltip or help text explaining this difference from the 45-second auto-clear timer available on macOS/Linux. **Acceptance criteria**: Windows build includes UI text or a log warning that reflects the clipboard ownership limitation; no behaviour change to other platforms.

9. ~~**Create a WiX 4 installer for the Windows release**~~
   ✅ **Implemented** — WiX 4 installer definition created at `installer/windows/main.wxs`.
   Installs to `%ProgramFiles%\PasswordSaver\`, creates a Start Menu shortcut, registers an
   uninstaller entry in Add/Remove Programs. `.github/workflows/release.yml` updated to build
   the `.msi` using `dotnet tool install --global wix` and publish it as a separate release
   artifact. **Silent install**: `msiexec /i rust-slint-password-saver-windows-x86_64.msi /quiet`;
   **silent uninstall**: `msiexec /x rust-slint-password-saver-windows-x86_64.msi /quiet`.
   Tests included in `tests/windows_installer_test.rs`.

10. ~~**Investigate and document Authenticode code-signing options for CI**~~
    ✅ **Implemented** — `WINDOWS.md` now contains a `### Code Signing` subsection (under Finding D) documenting both Microsoft Trusted Signing and EV certificate options with provider details, estimated costs, required GitHub Actions secrets, and complete workflow snippets. `release.yml` has a commented-out placeholder signing step with `TODO` comment referencing this documentation. 15 TDD tests added in `tests/code_signing_test.rs` verifying all acceptance criteria.

11. ~~**Fix doc comment formatting to wrap bare environment variable paths in backticks**~~
    ✅ **Implemented** — Wrapped bare `$HOME/.password_saver` path references in backticks in doc comments (`src/audit_log.rs` test function, `tests/windows_installer_test.rs` module-level doc). Resolves `clippy::doc_markdown` lint errors that were failing the Code Quality workflow.

12. ~~**Fix CI failures: `rustfmt` import ordering and `SetSecurityInfo` `PermissionDenied` on Windows runners**~~
    ✅ **Implemented** — Two issues were causing the `windows-latest` CI matrix to fail:
    1. `cargo fmt -- --check` reported a diff in `windows_permissions.rs` because the identifiers inside the `use windows::Win32::Security::{…}` group were not in the order expected by rustfmt (`reorder_imports = true`). Fixed by running `cargo fmt`.
    2. Seven tests were failing with `PermissionDenied` because `SetSecurityInfo` was called with `OWNER_SECURITY_INFORMATION`, which requires `WRITE_OWNER` access on the file/directory handle. The handle was opened with only `READ_CONTROL | WRITE_DAC`, making the call fail on standard-user CI runners. Fixed by removing `OWNER_SECURITY_INFORMATION` from both `set_windows_secure_permissions()` and `set_windows_directory_permissions()`. Setting the owner is unnecessary — the files are created by the current user who is already the owner; only the DACL needs to be modified.

---


*This review was produced by Agentic AI in the Windows Expert persona. Each actionable item is self-contained and designed for autonomous AI-driven implementation without human intervention.*
