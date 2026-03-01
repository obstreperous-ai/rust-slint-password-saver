# 🪟 Windows Code Review & User Experience Analysis

> **Review Date**: February 2026  
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

---

## Executive Summary

The codebase shows a **partially complete Windows port**. Foundational work exists (Windows ACL permissions, `USERPROFILE` path fallback, `windows-latest` CI runner), but several gaps prevent a polished, first-class Windows experience. The most impactful missing piece is a **console window that appears when launching the app** (no `windows_subsystem` attribute), combined with the absence of **pre-built Windows binaries** in the release pipeline, which together create a very poor out-of-box experience for Windows users.

The application will **build and run** on Windows but requires the user to compile from source, shows a developer-style console terminal, and has no Windows-native installation story. README documentation entirely omits Windows, and several security features (HMAC key file ACL, rate limit file ACL) are silently skipped on Windows due to missing `#[cfg(windows)]` counterparts.

**Overall Windows Readiness: 4/10** — builds and functions, but is not ready for Windows end-users.

---

## Code Review Findings

### What Works on Windows Today

| Area | Status | Notes |
|------|--------|-------|
| **Build** | ✅ Compiles | CI runs `windows-latest` matrix; code compiles without errors |
| **Storage Path** | ✅ Functional | `USERPROFILE` env var fallback in `main.rs`, `audit_log.rs` |
| **File ACL (storage)** | ✅ Implemented | `windows_permissions.rs` provides `set_windows_secure_permissions()` used by `storage.rs` |
| **Directory ACL** | ✅ Implemented | `set_windows_directory_permissions()` called from `main.rs` on `~/.password_saver/` |
| **UI Framework** | ✅ Compatible | Slint supports Windows natively via Direct3D/OpenGL backend |
| **Clipboard** | ✅ Compatible | `arboard` crate has Windows backend |
| **Browser Launch** | ✅ Compatible | `webbrowser` crate supports Windows |
| **Update Checker** | ✅ Compatible | `reqwest` blocking client works on Windows |
| **Encryption** | ✅ Platform-agnostic | All cryptographic code (Argon2, AES-GCM) is fully cross-platform |

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

**2. No Windows binary in release pipeline (`release.yml`)**

The release workflow builds Linux x64, macOS Intel, and macOS Apple Silicon binaries. There is no `x86_64-pc-windows-msvc` target. Windows users have no pre-built binary and must install a full Rust toolchain and build from source — a significant barrier.

- **File**: `.github/workflows/release.yml`
- **Current state**: Three release targets, none for Windows
- **Impact**: Zero-friction download is impossible for Windows users
- **Fix**: Add `x86_64-pc-windows-msvc` to the release matrix; ship a `.zip` archive containing the `.exe`

---

#### 🟠 High

**3. HMAC key file missing Windows ACL permissions (`audit_log.rs`)**

In `audit_log.rs`, after generating or loading the HMAC key, Unix file permissions (`0o600`) are set on the key file via `#[cfg(unix)]`. There is no corresponding `#[cfg(windows)]` block to call `set_windows_secure_permissions()`. On Windows the HMAC key file is created with default ACL (typically world-readable for local user accounts), degrading audit log integrity protection.

- **File**: `src/audit_log.rs`, lines 200–212
- **Current state**: `#[cfg(unix)]` permission block only; no `#[cfg(windows)]` equivalent
- **Impact**: The audit HMAC key file may be readable by other users on multi-user Windows systems
- **Fix**: Add `#[cfg(windows)]` block calling `crate::windows_permissions::set_windows_secure_permissions()` immediately after the existing Unix block

---

**4. Rate limiter persist file missing Windows ACL permissions (`rate_limit.rs`)**

`rate_limit.rs` sets Unix `0o600` permissions on the persisted attempt-timestamp JSON file after each write, but again has no `#[cfg(windows)]` counterpart. On Windows, the rate limit state file is left with default ACL.

- **File**: `src/rate_limit.rs`, lines 329–334
- **Current state**: `#[cfg(unix)]` permission block only
- **Impact**: A local attacker could delete or modify the rate limit file on Windows to bypass brute-force protection
- **Fix**: Add `#[cfg(windows)]` block calling `set_windows_secure_permissions()` after the existing Unix block

---

**5. Storage path uses `~/.password_saver/` not Windows-conventional `%APPDATA%` (`main.rs`)**

The storage directory is resolved as `$HOME/.password_saver/` (Unix convention) with a `USERPROFILE` fallback. On Windows the conventional path for application data is `%APPDATA%\PasswordSaver\` (roaming) or `%LOCALAPPDATA%\PasswordSaver\` (local, preferred for encrypted data that should not roam). Using the dotfile convention at `USERPROFILE` works but is unusual, unexpected, and invisible to Windows users who look for app data in `AppData\Roaming` or `AppData\Local`.

- **Files**: `src/main.rs` (`get_storage_path()`), `src/audit_log.rs` (`get_audit_log_path()`, `get_audit_hmac_key_path()`)
- **Current state**: `$HOME/.password_saver/` with `USERPROFILE` fallback
- **Impact**: Violates Windows application data conventions; confuses users trying to backup or find their data; the `.password_saver` dotfolder does not appear in Windows Explorer by default (hidden)
- **Fix**: Use `LOCALAPPDATA` env var on Windows (e.g., `%LOCALAPPDATA%\PasswordSaver\`) via `#[cfg(windows)]`; keep `$HOME/.password_saver/` on Unix

---

#### 🟡 Medium

**6. No Windows installation documentation in README (`README.md`)**

The README explicitly states the app targets "macOS and Linux systems". The Installation section has subsections for macOS and Linux only. Windows is mentioned only once in the roadmap as a future item, despite the application already building and running on Windows.

- **File**: `README.md`
- **Current state**: Zero Windows setup instructions; "Windows Support" listed as future work
- **Impact**: Windows developers who clone the repo have no guidance on dependencies, build process, or known limitations
- **Fix**: Add a Windows prerequisites and build section to README; update the features list to include Windows (even as "experimental")

---

**7. No Windows-specific system dependency installation step in CI (`ci.yml`)**

The CI matrix includes `windows-latest` but has no Windows-specific setup step (unlike the Ubuntu `apt-get` and macOS `brew` steps). On Windows, Slint may require the Visual C++ Redistributable or specific MSVC build tools. The CI may work purely because GitHub-hosted `windows-latest` runners have MSVC pre-installed, but this is not documented or explicit.

- **File**: `.github/workflows/ci.yml`
- **Current state**: No `if: runner.os == 'Windows'` step
- **Impact**: CI passes by coincidence; developers setting up Windows locally have no guidance
- **Fix**: Add explicit Windows setup step (document required Visual C++ Build Tools, note that no additional packages are needed via winget/choco, or add a step to verify MSVC toolchain)

---

**8. Directory ACL implementation may not work correctly for directories (`windows_permissions.rs`)**

`set_windows_directory_permissions()` delegates entirely to `set_windows_secure_permissions()`, which opens the path using `CreateFileW` with `OPEN_EXISTING` and `FILE_SHARE_READ`. Opening a **directory** with `CreateFileW` requires the `FILE_FLAG_BACKUP_SEMANTICS` flag in the `dwFlagsAndAttributes` parameter. Without it, `CreateFileW` will fail on a directory path, causing the ACL function to silently return `Err(SecurityError::PermissionDenied)` — which is then swallowed by the `let _ =` in `main.rs`.

- **File**: `src/windows_permissions.rs`, lines 197–200
- **Current state**: Directory delegates to file ACL function; `FILE_FLAG_BACKUP_SEMANTICS` flag missing
- **Impact**: Storage directory permissions are silently not set on Windows; the security guarantee documented in comments is not met
- **Fix**: Add `FILE_FLAG_BACKUP_SEMANTICS` to `dwFlagsAndAttributes` when opening a directory, or create a dedicated `set_windows_directory_permissions` implementation

---

**9. Error from `set_windows_directory_permissions` is silently ignored (`main.rs`)**

In `main.rs`, the call to `set_windows_directory_permissions()` uses `let _ = ...`, meaning any ACL failure is silently discarded. Unlike Unix where permissions are verified and the application returns an error if they cannot be set, the Windows path provides no feedback.

- **File**: `src/main.rs`, lines 103–107
- **Current state**: `let _ = set_windows_directory_permissions(parent);`
- **Impact**: Users have no indication if the storage directory is not secured; reduces security posture transparency
- **Fix**: Log a `warn!()` if the ACL call fails, consistent with Unix error handling; optionally treat it as an error

---

**10. No Windows application manifest or DPI awareness declaration**

Modern Windows applications should declare DPI awareness via an application manifest (or via `SetProcessDpiAwarenessContext` API) to render crisply on high-DPI displays. Without this, Windows may scale the application using bitmap scaling, resulting in blurry text and controls. Slint handles DPI internally for many backends, but a manifest ensures the OS does not apply legacy DPI virtualization.

- **Files**: `build.rs`, or a new `app.manifest` embedded via `windows-manifest` crate
- **Current state**: No manifest file or DPI awareness declaration
- **Impact**: Blurry UI on Windows HiDPI screens (Surface Pro, 4K monitors)
- **Fix**: Add a Windows application manifest that declares `dpiAware` and `dpiAwareness` (PerMonitorV2), either as a `.manifest` file embedded via the `embed-manifest` crate in `build.rs`, or using `slint`'s own manifest embedding

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

1. **Discover the repository** on GitHub — the README says "macOS and Linux" so they may already feel unwelcome.
2. **No release binary available for Windows** — they are told to `cargo build --release`, which requires installing Rust, Visual C++ Build Tools, and 15+ minutes of compilation time. Many non-developer users will stop here.
3. **Launch the `.exe`** — a black console window pops up alongside the main window. This immediately signals "developer tool", not "polished application".
4. **File storage at `C:\Users\Alice\.password_saver\`** — Windows Explorer hides dotfolders by default. The user cannot easily find their data for backup.
5. **Windows Defender / SmartScreen** — if the user runs the binary directly (not built from source), SmartScreen may block it as an "unknown publisher" executable.
6. **High-DPI displays** — on a Surface Pro or 4K monitor, the window may appear blurry if the DPI manifest is absent.
7. **No uninstaller** — the binary has no Windows installation footprint; uninstalling means manually deleting files with no guidance.

For a Windows developer, the experience is better (they can build from source), but there are no Windows-specific troubleshooting guides, and any ACL issues are silently ignored.

### For an Agentic AI Developer

The codebase is well-structured and the `#[cfg(windows)]` / `#[cfg(unix)]` pattern is used correctly. The primary risk for an AI agent making Windows improvements is:

- Accidentally breaking the Unix path when adding Windows-specific code (always use `#[cfg(windows)]` additions, not replacements)
- The `unsafe` Windows API code in `windows_permissions.rs` requires careful modification — test on a real Windows runner in CI
- The `windows` crate uses very specific feature flags in `Cargo.toml` — additions must include the correct feature strings

---

## Actionable Improvements

Each item below is formatted as a standalone GitHub issue suitable for hands-off Agentic AI development.

---

### Issue 1: Add `windows_subsystem` attribute to suppress console window on Windows

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

### Issue 2: Add Windows (`x86_64-pc-windows-msvc`) release binary to CI/CD pipeline

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

### Issue 3: Fix Windows ACL not applied to HMAC key file in audit log module

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

### Issue 4: Fix Windows ACL not applied to rate limit persist file

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

### Issue 5: Fix `set_windows_directory_permissions` missing `FILE_FLAG_BACKUP_SEMANTICS`

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

### Issue 6: Log warning when Windows directory ACL fails instead of silently ignoring

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

### Issue 7: Use Windows-conventional `%LOCALAPPDATA%` for storage path on Windows

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

### Issue 8: Add Windows installation documentation to README

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

### Issue 9: Add Windows application manifest for DPI awareness

**Title**: `feat(windows): embed application manifest declaring PerMonitorV2 DPI awareness`

**Labels**: `enhancement`, `windows`, `ux`

**Description**:

On Windows HiDPI displays (Surface Pro, 4K monitors), applications without a DPI awareness manifest may be rendered using legacy bitmap scaling (DPI virtualization), resulting in blurry text and controls. An application manifest declaring `PerMonitorV2` DPI awareness ensures crisp rendering on all display configurations.

**Acceptance Criteria**:
- Application renders crisply on a simulated HiDPI environment (e.g., Windows display set to 150% or 200% scaling)
- No regression on standard DPI (100%) configurations
- Manifest is embedded at compile time via `build.rs` (no separate `.exe.manifest` file required at runtime)

**Implementation Notes**:
1. Add the `embed-manifest` crate as a Windows-only build dependency:
   ```toml
   [target.'cfg(windows)'.build-dependencies]
   embed-manifest = "1.4"
   ```
2. Create `app.manifest` in the project root with `dpiAware` and `dpiAwareness` settings
3. Call `embed_manifest::embed_manifest(embed_manifest::new_manifest("app.manifest"))` in `build.rs` under a `#[cfg(windows)]` guard
4. Check whether Slint's own Windows backend already handles DPI awareness; if it does, document this finding and skip the manifest approach to avoid conflicts

**Files to modify**: `build.rs`, `Cargo.toml` (build-dependencies), new file `app.manifest`

---

### Issue 10: Add Windows-specific CI setup step documentation and verification

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

*This review was produced by Agentic AI in the Windows Expert persona. Each actionable item is self-contained and designed for autonomous AI-driven implementation without human intervention.*
