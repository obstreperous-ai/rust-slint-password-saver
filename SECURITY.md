# Security Policy

## Overview

This document outlines the security architecture, current security status, identified vulnerabilities, and recommended improvements for the Rust Slint Password Saver project. This is a password manager application that uses Argon2 + AES-256-GCM encryption to protect user credentials.

**Scope note (v0.1):** Two-factor authentication methods (TOTP, hardware security keys, biometrics) are out of scope for v0.1 because the app is currently designed as a local-only, single-user password vault. 2FA is planned for future consideration.

## Table of Contents

- [Current Security Status](#current-security-status)
- [Security Posture Summary](#security-posture-summary)
- [Security Architecture](#security-architecture)
- [Resolved Security Findings](#resolved-security-findings)
- [Open Issues and Future Work](#open-issues-and-future-work)
- [OWASP Top 10 Coverage](#owasp-top-10-2021--2023-coverage)
- [CI/CD Pipeline Security](#cicd-pipeline-security-review)
- [Supply-Chain Security](#supply-chain-security-analysis)
- [Cryptography and Key Management Review](#cryptography-and-key-management-review)
- [Threat Model](THREAT_MODEL.md) *(separate document)*
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
- [Security Best Practices for Contributors](#security-best-practices-for-contributors)
- [Changelog](#changelog)

---

## Current Security Status

### ✅ Security Audit Status: **PASSING** (2026-04-25)

All previously identified critical and high-severity code-level findings have been resolved. The project demonstrates solid security engineering with proper use of cryptographic primitives, appropriate key derivation, secure randomness, and thoughtful error handling.

```
✅ Direct dependencies: No known vulnerabilities
✅ Transitive dependencies: No critical vulnerabilities
⚠️ Warnings: 2 unmaintained transitive dependencies (non-critical, Slint framework)
✅ Code-level findings: All 5 findings from 2026-02-22 audit resolved
✅ CI/CD pipeline: Properly configured with least-privilege permissions
✅ Build: Compiles cleanly, all tests pass
✅ Formatting: cargo fmt passes
✅ Pre-commit hooks: cargo-audit, clippy, fmt all configured
```

**Dependency Warnings (Non-Critical):**
- `bincode` 2.0.1 — Unmaintained (RUSTSEC-2025-0141). Transitive dependency via Slint. No known vulnerability; monitoring for Slint updates.
- `paste` 1.0.15 — Unmaintained (RUSTSEC-2024-0436). Transitive dependency via Slint. Procedural macro crate with minimal security exposure.

---

## Security Architecture

### Encryption Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  • User interface (Slint UI)                                 │
│  • Input validation (src/validation.rs)                      │
│  • Session management (src/session.rs)                       │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                Storage Encryption Layer                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Argon2id Key Derivation                               │ │
│  │  • Algorithm: Argon2id (hybrid mode)                  │ │
│  │  • Memory: 64 MiB (OWASP recommended)                  │ │
│  │  • Iterations: 2                                       │ │
│  │  • Parallelism: 4 threads                             │ │
│  │  • Version: V0x13 (latest)                            │ │
│  │  • Random salt (generated per save via OsRng)         │ │
│  │  • Output: 256-bit encryption key                     │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ AES-256-GCM Encryption                                 │ │
│  │  • 256-bit key size                                    │ │
│  │  • Galois/Counter Mode (authenticated)                 │ │
│  │  • 96-bit random nonce (generated per save via OsRng) │ │
│  │  • AEAD: Provides confidentiality + authenticity       │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                 File System Storage                          │
│  • Location: ~/.password_saver/passwords.enc                 │
│  • Format: JSON with encrypted data                          │
│  • Fields: salt, nonce, encrypted_data (all base64)          │
│  • Permissions: 0600 (Unix) / ACL current-user-only (Windows)│
└──────────────────────────────────────────────────────────────┘
```

### Security Properties

The following security properties have been verified against the source code as of 2026-04-05:

| Property | Status | Implementation |
|---|---|---|
| Confidentiality | ✅ | AES-256-GCM encryption (`src/storage.rs`) |
| Authenticity | ✅ | GCM authentication tag (AEAD) |
| Integrity verification | ✅ | SHA-256 checksums (`src/integrity.rs`) + GCM tamper detection |
| Zero-knowledge | ✅ | Master password never stored; derived via Argon2id per operation |
| Forward secrecy | ✅ | New random salt + nonce per save via `OsRng` |
| Memory safety | ✅ | Rust ownership + `ZeroizeOnDrop` on `PasswordEntry` (`src/storage.rs`) |
| Master password zeroization | ✅ | Wrapped in `Zeroizing<String>` in UI handlers (`src/ui_handlers.rs`) |
| Input validation | ✅ | Length limits + control char rejection (`src/validation.rs`) |
| Audit logging | ✅ | HMAC-SHA256 integrity with persistent random key (`src/audit_log.rs`) |
| Password strength enforcement | ✅ | 12-char min + uppercase/lowercase/digit/special + zxcvbn entropy (`src/password_strength.rs`) |
| Rate limiting | ✅ | 5 attempts per 5-min window, 1-min lockout, persistent to disk (`src/rate_limit.rs`) |
| Session timeout | ✅ | Auto-lock after 5 minutes of inactivity (`src/session.rs`) |
| Clipboard security | ✅ | Auto-clear after 30 seconds; only clears own content (`src/clipboard.rs`) |
| Secure file permissions | ✅ | 0600/0700 on Unix; ACL-based on Windows (`src/storage.rs`, `src/windows_permissions.rs`) |
| Secure deletion | ✅ | 3-pass overwrite before file removal (`src/secure_delete.rs`) |
| Password generator | ✅ | Cryptographically secure via `OsRng`/`thread_rng()` (`src/password_generator.rs`) |
| Emergency recovery codes | ✅ | 3 codes (~77-bit entropy), Argon2id-derived key, SHA-256 hashed storage (`src/recovery.rs`) |
| Encrypted backups | ✅ | Same Argon2id + AES-256-GCM as main storage (`src/backup.rs`) |
| Timing attack protection | ✅ | `subtle::ConstantTimeEq` + random jitter on auth paths (`src/storage.rs`) |
| Error message sanitization | ✅ | Generic user messages; detailed debug logs only (`src/errors.rs`) |
| Update notifications | ✅ | Privacy-preserving GitHub API check; no telemetry (`src/update_checker.rs`) |
| Master password change | ✅ | Secure re-encryption with strength validation (`src/storage.rs`) |

---

## Security Posture Summary

This table reflects the verified state of the project as of 2026-04-05, cross-referenced against the source code.

| Category | Status | Notes |
|---|---|---|
| Encryption Algorithm | ✅ Strong | AES-256-GCM with 96-bit random nonce per save, AEAD |
| Key Derivation | ✅ Strong | Argon2id (64 MiB, 2 iter, 4 parallelism, V0x13). Meets OWASP ≥64 MiB recommendation. Backward-compatible 32 MiB fallback for legacy files |
| Nonce/Salt Generation | ✅ Strong | `OsRng` (CSPRNG) for all nonces and salts; fresh per operation; no reuse |
| Memory Safety | ✅ Strong | Rust ownership, `ZeroizeOnDrop` for `PasswordEntry`, `Zeroizing<String>` for master passwords in `ui_handlers.rs` |
| File Permissions | ✅ Strong | 0600/0700 on Unix, Windows ACL (current user only) |
| Input Validation | ✅ Strong | Length limits, control char rejection, consistent 12-char min for master password |
| Rate Limiting | ✅ Strong | Persistent to disk (survives restart), 5 attempts/5 min, 1 min lockout, 0600 permissions |
| Audit Logging | ✅ Good | HMAC-SHA256 integrity, log rotation, persistent random key via `load_or_create_hmac_key()` |
| Session Management | ✅ Good | Auto-lock after 5 min inactivity, mutex poison recovery, thread-safe |
| Clipboard Security | ✅ Good | Auto-clear 30s, smart clear (only clears own content) |
| Recovery Mechanism | ✅ Good | Argon2id-based key derivation (same params as main), rate-limited, hashed code storage |
| Error Handling | ✅ Strong | Sanitized user messages, detailed debug logs, no crypto detail leakage |
| Timing Attack Protection | ✅ Good | Constant-time comparison via `subtle`, timing jitter on auth paths |
| Secure Deletion | ✅ Good | 3-pass overwrite, atomic updates with backup/restore, SSD limitations documented |
| Password Strength | ✅ Strong | zxcvbn entropy analysis, 12-char min, uppercase/lowercase/digit/special required |
| Password Generator | ✅ Strong | `OsRng` via `thread_rng()`, configurable, excludes ambiguous chars |
| Dependency Security | ✅ Good | `cargo-audit` passing, 0 critical; 2 non-critical unmaintained transitive deps (Slint) |
| CI/CD Security | ✅ Good | Least-privilege permissions, pinned action versions, scheduled audits, multi-OS matrix |
| Update Checker | ✅ Good | Privacy-preserving (GitHub API GET only), 10s timeout, hardcoded URL (no SSRF) |
| Database Integrity | ✅ Good | SHA-256 checksums, JSON validation, corruption detection, startup checks |
| Backup/Export | ✅ Good | Encrypted with Argon2+AES-256-GCM (same as main), import with duplicate detection |
| Windows Platform | ✅ Good | ACL-based permissions, app manifest, MSVC build, WiX installer in CI |
| Threat Model | ✅ Good | `THREAT_MODEL.md` documents 5 threat actors, 19 controls, 12 out-of-scope threats, and 6 residual risks |
| Binary Signing | ✅ Conditional | Release workflow signs the Windows binary via Microsoft Trusted Signing when `AZURE_TENANT_ID` secret is configured; step skips gracefully when credentials are absent |
| SBOM / Provenance | ✅ Strong | SPDX SBOM (`sbom.spdx.json`) generated via `cargo-sbom` and uploaded as a release asset; SLSA provenance attestations generated via `actions/attest-build-provenance@v2` and attached to each release |

---

## Resolved Security Findings

### Dependency Vulnerabilities

| Advisory | Component | Severity | Status |
|---|---|---|---|
| RUSTSEC-2026-0007 | `bytes` 1.11.0 → 1.11.1 | Critical | ✅ Fixed |
| RUSTSEC-2025-0141 | `bincode` 2.0.1 (via Slint) | Low (unmaintained) | ⚠️ Monitoring |
| RUSTSEC-2024-0436 | `paste` 1.0.15 (via Slint) | Low (unmaintained) | ⚠️ Monitoring |

### 2026-02-22 Code Audit Findings

Five code-level security findings were identified on 2026-02-22. All have been resolved:

| # | Finding | Severity | Resolution | Issue |
|---|---|---|---|---|
| 1 | Predictable HMAC key in audit log (hostname-derived) | HIGH | Replaced with cryptographically random persistent key via `load_or_create_hmac_key()` using `OsRng`. Key stored at `~/.password_saver/audit_hmac.key` with 0600 permissions. | #22 / #216 |
| 2 | Password validation inconsistency (8-char vs 12-char min) | MEDIUM | Removed weaker validation from `storage.rs`; all paths now use `password_strength::validate_password_strength()` with 12-char minimum. | #23 / #144 |
| 3 | Rate limiting not persistent across restarts | MEDIUM | `RateLimiter::with_persistence()` persists timestamps to `~/.password_saver/rate_limit.json` with 0600 permissions. Corrupted files handled gracefully. | #24 / #145 |
| 4 | Recovery key derived with SHA-256 instead of Argon2 | LOW-MEDIUM | `derive_recovery_key()` now uses Argon2id with same parameters as main KDF (32 MiB, 2 iter, 4 threads). Random salt stored in `StorageData`. | #25 / #146 |
| 5 | Master password not zeroized at UI layer | LOW | Master password wrapped in `Zeroizing<String>` immediately in all `ui_handlers.rs` callbacks (`handle_save_password`, `handle_load_passwords`, `handle_unlock`). | #26 / #147 |

### CodeQL False Positive: Hardcoded Nonce

Static analysis tools flag `let mut nonce_bytes = [0u8; 12];` as a hardcoded nonce. This is a **false positive** — the zero-initialized buffer is immediately overwritten by `OsRng.fill_bytes(&mut nonce_bytes)` before any use. Suppression annotations have been added to the three affected sites in `src/storage.rs`.

### Original Security Issues (Issues 1–21)

All 21 security features identified in the initial security review have been implemented:

1. ✅ `bytes` dependency vulnerability fix
2. ✅ Secure memory clearing (`zeroize`)
3. ✅ Secure file permissions (0600/0700)
4. ✅ Strengthened Argon2id parameters (64 MiB, OWASP recommended; backward-compatible 32 MiB fallback)
5. ✅ Password strength validation (zxcvbn + requirements)
6. ✅ Decryption rate limiting (persistent)
7. ✅ Security audit logging (HMAC-protected)
8. ✅ Master password change
9. ✅ Input validation and sanitization
10. ✅ Error message sanitization
11. ✅ Timing attack protection (`subtle` + jitter)
12. ✅ Windows file permissions (ACL)
13. ✅ Secure file deletion (3-pass overwrite)
14. ✅ Session timeout and auto-lock (5 min)
15. ✅ Clipboard security and auto-clear (30s)
16. ✅ Secure password generator
17. ✅ Encrypted backup and export
18. ✅ Database integrity verification (SHA-256)
19. ✅ Password search and filtering
20. ✅ Security update notifications
21. ✅ Emergency access and recovery codes

---

## Open Issues and Future Work

The following items have been identified through security review but are **not yet addressed**. Each is a candidate for a standalone GitHub issue.

### 🔴 High Priority

#### ~~1. Create a Formal Threat Model (`THREAT_MODEL.md`)~~ ✅ Resolved

`THREAT_MODEL.md` has been created at the repository root. It documents five threat actors
(TA-1 through TA-5) using STRIDE methodology, maps 19 security controls (SC-01 through SC-19)
to the threats they mitigate, and explicitly enumerates 12 out-of-scope threats and 6 residual
risks. See [THREAT_MODEL.md](THREAT_MODEL.md).

#### ~~2. Increase Argon2id Memory to 64 MiB (OWASP Recommendation)~~ ✅ Resolved

`src/storage.rs` now uses 64 MiB (65536 KiB) for Argon2id key derivation, meeting the OWASP
recommended minimum for password managers. A backward-compatible fallback to 32 MiB is applied
automatically when loading files encrypted before this upgrade, ensuring no data loss for
existing users. New saves always use 64 MiB parameters. Tests updated accordingly.

### 🟡 Medium Priority

#### ~~3. Add Explicit `permissions: contents: read` to CI Workflows~~ ✅ Resolved

Both `ci.yml` and `quality.yml` now have an explicit `permissions: contents: read` block at the workflow level, enforcing least privilege and preventing unexpected token scope escalation.

#### ~~4. Pin `dtolnay/rust-toolchain` to `@stable` in `security.yml`~~ ✅ Resolved

`security.yml` now uses `dtolnay/rust-toolchain@stable` instead of `@master`, ensuring reproducible and predictable toolchain installations in the security audit workflow.

#### ~~5. Add SHA-256 Checksum Generation to Release Workflow~~ ✅ Resolved

The `release.yml` workflow now generates a `SHA256SUMS.txt` file in the `release` job after all platform artifacts are downloaded. A `sha256sum` step hashes every `.tar.gz`, `.zip`, and `.msi` artifact and appends the results to `SHA256SUMS.txt`, which is then uploaded alongside the other release assets via `softprops/action-gh-release`.

#### ~~6. Enable Windows Authenticode Code Signing~~ ✅ Resolved

The `release.yml` build job now contains an active Microsoft Trusted Signing step that runs before
the archive and installer are packaged. The step is guarded by
`if: runner.os == 'Windows' && env.AZURE_TENANT_ID != ''`, so it skips automatically when the
five required GitHub Actions secrets (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
`TRUSTED_SIGNING_ACCOUNT_NAME`, `TRUSTED_SIGNING_CERTIFICATE_PROFILE_NAME`) are not configured.
Once a Microsoft Trusted Signing subscription is set up and the secrets are populated the Windows
binary (and consequently the `.zip` and `.msi` artifacts) will be Authenticode-signed on every
release, eliminating the SmartScreen "Windows protected your PC" warning for end users. An
Option B (EV certificate via `signtool.exe`) comment is retained in `release.yml` for reference.
See WINDOWS.md "Code Signing" subsection for provider options, costs, and activation steps.

#### ~~7. Full End-to-End Recovery Workflow Test~~ ✅ Resolved

`src/storage.rs` now stores the database encryption key encrypted with the recovery master key
(`encrypted_db_key_for_recovery` field in `StorageData`). The new
`PasswordStorage::load_entries_with_recovery_key` method enables complete password-less database
decryption: once a valid recovery code is presented to `EmergencyRecovery::recover_access`, the
resulting recovery key can be passed directly to `load_entries_with_recovery_key` to decrypt the
full entry list — no master password is required. The new integration test module
`tests/integration/recovery_workflow_test.rs` covers the complete scenario with six tests:
full password-less recovery, each code independently unlocking the database, wrong-key rejection,
graceful failure for databases without recovery data, multi-entry preservation, and parity between
the master-password path and the recovery-key path.

#### ~~8. Corrupt Backup Graceful Failure Test~~ ✅ Resolved

Five integration tests in `tests/integration/backup_recovery_test.rs` now verify that
`import_from_file()` returns a proper `Err` (never panics) when given corrupted backup files:
garbage data, empty file, non-existent file, truncated backup, and byte-flipped backup.

### 🔵 Low Priority

#### ~~9. Generate SBOM in CI~~ ✅ Resolved

The `release.yml` workflow now installs `cargo-sbom` and generates an SPDX 2.3 JSON Software
Bill of Materials (`sbom.spdx.json`) in the `release` job before the GitHub Release is created.
The file is uploaded alongside the platform archives, checksums, and installer as a named release
asset, giving downstream users and auditors a machine-readable inventory of all Rust crate
dependencies included in each release.

#### ~~10. Add SLSA Provenance Attestation~~ ✅ Resolved

The `release.yml` workflow's `release` job now has `attestations: write` and `id-token: write`
permissions and includes an `actions/attest-build-provenance@v2` step that generates SLSA
provenance attestations for all release artifacts (platform archives, checksums file, and SBOM).
The attestations are signed via GitHub's OIDC-based signing infrastructure and stored in the
repository's attestations API, allowing users to verify supply-chain integrity with
`gh attestation verify`.

#### ~~11. Add `cargo-deny` to CI~~ ✅ Resolved

The `security.yml` workflow now installs `cargo-deny` and runs
`cargo deny check advisories bans licenses` alongside `cargo audit`, adding license
compatibility checking, duplicate dependency detection, and advisory cross-referencing in CI.
The repository now includes `deny.toml` for policy configuration (allowed licenses and advisory
tracking/ignores for currently monitored transitive issues).

#### ~~12. Add Clipboard Manager Risk Warning~~ ✅ Resolved

README now explicitly warns that clipboard managers/history tools (for example KDE Klipper,
Clipman, and macOS clipboard history) may retain copied passwords beyond the app's 30-second
auto-clear window.

#### ~~13. Document Two-Factor Authentication as Future Enhancement~~ ✅ Resolved

README and SECURITY.md now explicitly state that 2FA (TOTP, hardware security keys, biometrics)
is out of scope for v0.1 and planned for future consideration because the current architecture is
local-only and single-user.

#### ~~14. Dedicated Windows ACL Permission Test~~ ✅ Resolved

Added `test_windows_file_acl_is_protected_and_single_ace` in
`src/windows_permissions.rs` to verify Windows ACLs are both protected from inheritance
and reduced to a single explicit ACE after applying secure permissions, ensuring access is
restricted to the current user as intended.

---

## OWASP Top 10 2021 & 2023 Coverage

| # | OWASP 2021 Category | Applicability | Status | Notes |
|---|---|---|---|---|
| A01 | Broken Access Control | ✅ Applicable | ✅ Mitigated | File permissions (0600/0700 Unix, ACL Windows), session auto-lock, rate limiting |
| A02 | Cryptographic Failures | ✅ Applicable | ✅ Strong | AES-256-GCM, Argon2id, OsRng, no hardcoded keys, proper nonce generation |
| A03 | Injection | ✅ Applicable | ✅ Mitigated | Input validation (control char rejection, length limits), no SQL/OS command execution |
| A04 | Insecure Design | ✅ Applicable | ✅ Good | Zero-knowledge architecture, defense-in-depth, secure defaults |
| A05 | Security Misconfiguration | ✅ Applicable | ✅ Good | Secure file permissions enforced by default, no debug modes in production |
| A06 | Vulnerable Components | ✅ Applicable | ✅ Good | cargo-audit + cargo-deny in CI + pre-commit, scheduled daily scans, 0 critical vulnerabilities |
| A07 | Auth Failures | ✅ Applicable | ✅ Strong | Persistent rate limiting, timing attack protection, strong password requirements |
| A08 | Data Integrity Failures | ✅ Applicable | ✅ Good | AES-GCM authentication tag, SHA-256 checksums, HMAC-protected audit logs |
| A09 | Logging & Monitoring | ✅ Applicable | ✅ Good | Comprehensive audit logging with HMAC integrity, rotation, secure permissions |
| A10 | SSRF | ⚠️ Limited | ✅ Mitigated | Update checker uses hardcoded GitHub URL only, 10s timeout, no user-controlled URLs |

### OWASP 2023 Additions

| Category | Applicability | Status | Notes |
|---|---|---|---|
| Insecure Output Handling | ✅ Applicable | ✅ Good | Error message sanitization, no sensitive data in user-facing messages |
| Excessive Agency | 🔵 N/A | — | Desktop app, no autonomous API calls |
| Overreliance | 🔵 N/A | — | No AI/ML components |

---

## CI/CD Pipeline Security Review

### Workflow Analysis

The repository has 5 GitHub Actions workflows:

| Workflow | Trigger | Permissions | Notes |
|---|---|---|---|
| `ci.yml` | Push/PR to `main` | `contents: read` ✅ | Multi-OS matrix (Linux, macOS, Windows). |
| `security.yml` | Push/PR on `Cargo.toml`/`Cargo.lock` + daily cron | `contents: read` ✅ | Uses `dtolnay/rust-toolchain@stable` ✅. Runs `cargo audit` + `cargo deny check advisories bans licenses` ✅ |
| `quality.yml` | Push/PR to `main` | `contents: read` ✅ | Clippy with `-D warnings`. |
| `codeql.yml` | Push/PR to `main` + weekly cron | `security-events: write`, `contents: read` ✅ | Rust CodeQL static analysis using `.github/codeql/codeql-config.yml` (`tests/` excluded to reduce fixture false positives). |
| `release.yml` | Tag push (`v*.*.*`) | `contents: write`, `attestations: write`, `id-token: write` ✅ | Multi-arch (Linux, macOS, Windows). ✅ SHA-256 checksums generated. ✅ Authenticode signing enabled (conditional on secrets). ✅ SLSA provenance attestations generated via `actions/attest-build-provenance@v2`. |

### CI/CD Open Items

- ~~Pin `dtolnay/rust-toolchain` to `@stable` in `security.yml`~~ ✅ Resolved
- ~~Add SHA-256 checksum generation to release artifacts~~ ✅ Resolved
- ~~Enable Windows Authenticode code signing~~ ✅ Resolved (conditional on secrets)
- ~~Generate SBOM and SLSA provenance attestation~~ ✅ Resolved

---

## Supply-Chain Security Analysis

### Lockfile and Reproducibility

- ✅ `Cargo.lock` is committed — ensures reproducible builds
- ✅ Build dependencies are separate from runtime (`[build-dependencies]`)
- ✅ `cargo audit` and `cargo deny check advisories bans licenses` run daily in CI and on dependency changes
- ✅ Pre-commit hook includes `cargo-audit`

### Direct Dependencies (16 runtime + 1 dev + 2 build)

| Crate | Version | Purpose | Risk |
|---|---|---|---|
| `slint` | 1.14 | UI framework | Low — well-maintained |
| `argon2` | 0.5.3 | KDF | Low — RustCrypto |
| `aes-gcm` | 0.10.3 | Encryption | Low — RustCrypto |
| `serde` / `serde_json` | 1.0 | Serialization | Low — ecosystem standard |
| `zxcvbn` | 3.1 | Password strength | Low — Dropbox-originated |
| `log` / `env_logger` | 0.4 / 0.11 | Logging | Low — ecosystem standard |
| `hmac` / `sha2` | 0.12 / 0.10 | HMAC / Hashing | Low — RustCrypto |
| `hex` | 0.4 | Hex encoding | Low |
| `zeroize` | 1.8 | Memory clearing | Low — RustCrypto |
| `subtle` | 2.6 | Constant-time ops | Low — RustCrypto |
| `rand` | 0.8 | CSPRNG | Low — Rust project |
| `bitflags` | 2.4 | Bit flags | Low |
| `arboard` | 3.4 | Clipboard | Medium — less audited |
| `reqwest` | 0.12 | HTTP client | Medium — large dependency tree |
| `semver` | 1.0 | Version parsing | Low |
| `webbrowser` | 1.0 | Open URLs | Low |

All cryptographic dependencies (`argon2`, `aes-gcm`, `hmac`, `sha2`, `subtle`, `rand`, `zeroize`) are from the [RustCrypto](https://github.com/RustCrypto) project.

---

## Cryptography and Key Management Review

### Algorithm Choices

| Operation | Algorithm | Parameters | Assessment |
|---|---|---|---|
| Key Derivation | Argon2id V0x13 | 64 MiB, 2 iter, 4 parallel, 32-byte output | ✅ Strong (meets OWASP ≥64 MiB recommendation) |
| Encryption | AES-256-GCM | 256-bit key, 96-bit nonce | ✅ Industry standard AEAD |
| Nonce Generation | OsRng | 12 bytes per operation | ✅ Cryptographically secure |
| Salt Generation | OsRng via SaltString | Random per save | ✅ Proper salt management |
| Recovery Key | Argon2id V0x13 | Same as main KDF | ✅ Consistent with main path |
| Audit Log Integrity | HMAC-SHA256 | 256-bit random key | ✅ Persistent key |
| Database Integrity | SHA-256 | Full file hash | ✅ Detects corruption |
| Timing Protection | `subtle::ConstantTimeEq` | + random jitter | ✅ Side-channel resistant |

### Key Management

| Key/Secret | Generation | Storage | Lifecycle |
|---|---|---|---|
| AES-256 encryption key | Derived via Argon2id | Never stored; derived on demand | Created per operation, zeroized after use |
| Master password | User-provided | Never stored | Wrapped in `Zeroizing<String>` at UI layer |
| Salt | OsRng (per save) | In encrypted JSON file | Regenerated per save |
| Nonce | OsRng (per save) | In encrypted JSON file | Regenerated per save |
| HMAC key (audit log) | OsRng (32 bytes) | `~/.password_saver/audit_hmac.key` (0600) | Persistent, created on first launch |
| Recovery codes | OsRng (16 chars from 30-char set, ~77-bit entropy) | SHA-256 hash stored; plaintext shown once | Generated on first setup |
| Recovery key salt | OsRng | In `StorageData` | Generated per recovery setup |

### Nonce Reuse Risk

AES-GCM is catastrophically vulnerable to nonce reuse. This is mitigated because each `save_entries()` generates a fresh random salt (→ new derived key) AND a fresh random nonce. Even with the same master password, the derived key changes. `OsRng` panics on failure, preventing silent non-random output.

---

## Reporting Security Vulnerabilities

### Responsible Disclosure

If you discover a security vulnerability in this project:

1. **DO NOT** open a public GitHub issue
2. **DO NOT** disclose the vulnerability publicly until it has been addressed
3. **DO** report via GitHub's private vulnerability reporting: navigate to the repository's **Security** tab → **Report a vulnerability**. Alternatively, contact the maintainer (`@obstreperous-ai`)
4. **DO** provide detailed information about the vulnerability
5. **DO** allow reasonable time for the maintainers to address the issue

### What to Include in Your Report

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact of the vulnerability
- Suggested remediation (if any)
- Your contact information for follow-up

### Response Timeline

- Acknowledge receipt: within 48 hours
- Initial assessment: within 7 days
- Target fix for critical issues: within 30 days
- Reporter kept informed of progress

---

## Security Best Practices for Contributors

### When Contributing Code

1. **Never commit secrets or credentials** — use `.gitignore` and environment variables
2. **Follow secure coding practices** — validate inputs, use constant-time comparisons, clear sensitive data, set secure file permissions
3. **Use safe dependencies** — run `cargo audit` before committing, keep dependencies updated
4. **Write security tests** — test auth failures, input edge cases, crypto operations, permissions
5. **Document security considerations** — comment on security-critical code, explain crypto choices

### Code Review Checklist

- [ ] No hardcoded secrets or credentials
- [ ] Input validation is comprehensive
- [ ] Error messages don't leak sensitive information
- [ ] Sensitive data is cleared from memory
- [ ] File permissions are set correctly
- [ ] Cryptographic operations use approved algorithms
- [ ] Dependencies have no known vulnerabilities
- [ ] Tests cover security edge cases

---

## Security Maintenance Schedule

**Weekly:** Review dependency advisories, monitor GitHub security alerts

**Monthly:** Run `cargo audit`, review and update dependencies

**Quarterly:** Full security audit of codebase, review cryptographic implementations, update SECURITY.md

**Annually:** Comprehensive security review, evaluate external audit, review policies

---

## Changelog

### 2026-04-25 — Fix Security Audit: upgrade `rustls-webpki` to 0.103.13 (RUSTSEC-2026-0104)

- Resolved `cargo audit` failure in the Security Audit workflow caused by
  `rustls-webpki 0.103.12`:
  - RUSTSEC-2026-0104: Reachable panic in certificate revocation list parsing
- Updated transitive dependency to `rustls-webpki 0.103.13` via `cargo update -p rustls-webpki`
  (Cargo.lock only, no direct-dependency or API changes required)
- `core2 0.4.0` remains as a yanked warning only; `deny.toml` has `yanked = "warn"` so
  this does not fail CI. No newer `^0.4` release exists upstream; tracked via `bitstream-io`
  → `rav1e` → `ravif` → `image` → `arboard` chain.
- Verified: `cargo build`, `cargo test` (78 passing), `cargo fmt -- --check`, and
  `cargo clippy --all-targets -- -D warnings` all succeed
- No `audit.toml` / advisory ignores were added; the fix is a genuine dependency upgrade

### 2026-04-20 — Fix Security Audit: upgrade `rustls-webpki` to 0.103.12

- Resolved two `cargo audit` failures in the Security Audit workflow caused by
  `rustls-webpki 0.103.10`:
  - RUSTSEC-2026-0098: name constraints for URI names were incorrectly accepted
  - RUSTSEC-2026-0099: name constraints were accepted for certificates asserting
    a wildcard name
- Updated transitive dependency to `rustls-webpki 0.103.12` via `cargo update -p rustls-webpki`
  (Cargo.lock only, no direct-dependency or API changes required)
- Verified: `cargo audit` exits 0, `cargo deny check advisories bans licenses` passes,
  `cargo build`, `cargo test` (78 passing), `cargo fmt -- --check`, and
  `cargo clippy --all-targets -- -D warnings` all succeed
- No `audit.toml` / advisory ignores were added for these advisories; the fix is
  a genuine dependency upgrade per the issue requirements

### 2026-04-18 — Final Code Quality and Documentation Consistency Review (Issue #256)

- Updated CI/CD workflow inventory to include `codeql.yml` (5 workflows total)
- Added explicit CodeQL workflow row (permissions, trigger, and test-fixture exclusion config)
- Re-verified security guidance alignment with current CI workflows and documentation
- Confirmed quality gates in the final review run: `cargo build`, `cargo test`,
  `cargo fmt -- --check`, and `cargo clippy --all-targets -- -D warnings`

### 2026-04-17 — Dedicated Windows ACL Permission Test (Issue #14)

- Added a dedicated Windows ACL test in `src/windows_permissions.rs`:
  `test_windows_file_acl_is_protected_and_single_ace`
- The test verifies ACL inheritance is disabled (`AreAccessRulesProtected == True`) and that
  exactly one explicit ACE remains after applying secure permissions
- Marked Issue #14 as resolved in "Open Issues and Future Work"

### 2026-04-16 — Document 2FA as Future Enhancement (Issue #13)

- Updated `README.md` and `SECURITY.md` to explicitly state that 2FA methods (TOTP, hardware
  security keys, biometrics) are out of scope for v0.1
- Added rationale that the current product scope is local-only and single-user
- Marked Issue #13 as resolved in "Open Issues and Future Work"

### 2026-04-15 — Add Clipboard Manager Retention Warning (Issue #12)

- Updated `README.md` security notes with an explicit warning that clipboard managers/history
  tools may retain copied passwords longer than the 30-second auto-clear timeout
- Marked Issue #12 as resolved in "Open Issues and Future Work"

### 2026-04-14 — Add SLSA Provenance Attestation (Issue #10)

- Added `attestations: write` and `id-token: write` permissions to the `release` job in
  `.github/workflows/release.yml`
- Added `actions/attest-build-provenance@v2` step in the `release` job, running after checksum
  generation and before the GitHub Release creation; the step attests all release artifacts
  (platform archives, `SHA256SUMS.txt`, and `sbom.spdx.json`) using GitHub's OIDC-based
  Sigstore signing infrastructure
- Users can verify artifact provenance with:
  `gh attestation verify <artifact> --repo <owner>/<repo>`
- Added `tests/slsa_test.rs` with six tests verifying the workflow configuration and SECURITY.md
  documentation are correct
- Updated SECURITY.md: Open Issue #10 marked as resolved; SBOM/Provenance row upgraded from
  ✅ Good to ✅ Strong; CI/CD Open Items updated; `release.yml` permissions row updated

### 2026-04-13 — Corrupt Backup Graceful Failure Test (Issue #8)

- Added five integration tests to `tests/integration/backup_recovery_test.rs` verifying that
  `import_from_file()` returns a proper `Err` (never panics) when given corrupted backup files:
  - `test_import_fails_gracefully_with_garbage_data`: completely random bytes
  - `test_import_fails_gracefully_with_empty_file`: zero-length file
  - `test_import_fails_gracefully_with_nonexistent_file`: missing file path
  - `test_import_fails_gracefully_with_truncated_backup`: valid backup truncated to half size
  - `test_import_fails_gracefully_with_byte_flipped_backup`: valid backup with flipped bytes
- Updated SECURITY.md: Open Issue #8 marked as resolved

### 2026-04-06 — Full End-to-End Recovery Workflow (Issue #7)

- Added `encrypted_db_key_for_recovery` field to `StorageData` in `src/storage.rs`:
  stores the database encryption key encrypted with the recovery master key
  (`nonce (12 B) || AES-256-GCM ciphertext`), enabling password-less database
  decryption without any master-password involvement
- Added `PasswordStorage::load_entries_with_recovery_key(&self, recovery_key: &[u8])`
  method: decrypts `encrypted_db_key_for_recovery` with the supplied recovery key,
  then uses the recovered database key to decrypt password entries — complete
  password-less recovery flow
- Updated `save_entries_with_recovery` to also generate and store the new
  `encrypted_db_key_for_recovery` blob on every recovery-enabled save
- Added `tests/integration/recovery_workflow_test.rs` with six end-to-end tests
  covering: password-less recovery, all three codes independently unlocking the
  database, wrong-key rejection, graceful failure without recovery data, multi-entry
  preservation, and parity between the master-password and recovery-key decryption paths
- Updated SECURITY.md: Open Issue #7 marked as resolved

### 2026-04-06 — Enable Windows Authenticode Code Signing (Issue #6)

- Added job-level `env` block to the `build` job in `.github/workflows/release.yml` exposing the
  five Microsoft Trusted Signing secrets (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
  `AZURE_CLIENT_SECRET`, `TRUSTED_SIGNING_ACCOUNT_NAME`,
  `TRUSTED_SIGNING_CERTIFICATE_PROFILE_NAME`) as environment variables
- Added an active `Sign Windows binary (Microsoft Trusted Signing)` step using
  `azure/trusted-signing-action@v0.5.1` guarded by
  `if: runner.os == 'Windows' && env.AZURE_TENANT_ID != ''`; the step is skipped
  automatically when the secrets are not configured and runs automatically once they are
- Moved the signing step **before** archive creation (`Create zip` / WiX installer build) so
  the `.zip` and `.msi` artifacts both contain the Authenticode-signed binary
- Retained Option B (EV certificate via `signtool.exe`) as a commented reference in `release.yml`
- Updated `tests/code_signing_test.rs`: renamed the "signed step is commented out" test to
  `release_workflow_option_b_remains_commented_out`; added four new tests verifying the active
  signing step, `azure/trusted-signing-action` usage, `AZURE_TENANT_ID` conditional, and correct
  step ordering
- Updated SECURITY.md: Open Issue #6 marked as resolved; Binary Signing row updated to
  ✅ Conditional; CI/CD workflow table and Open Items updated

### 2026-04-06 — Add Explicit `permissions: contents: read` to CI Workflows (Issue #3)

- Added `permissions: contents: read` block to `.github/workflows/ci.yml` at the workflow level
- Added `permissions: contents: read` block to `.github/workflows/quality.yml` at the workflow level
- Both workflows now explicitly enforce least privilege; no implicit token scope escalation
- Updated SECURITY.md: Open Issue #3 marked as resolved; CI/CD Workflow Analysis table updated

### 2026-04-05 — Increase Argon2id Memory to 64 MiB (Issue #2)

- Upgraded `Params::new(65536, ...)` in `src/storage.rs` (64 MiB, OWASP recommended minimum for password managers)
- Added backward-compatible migration: `load_entries()` and `verify_recovery_code()` now try 64 MiB first, then transparently fall back to 32 MiB for files encrypted before this upgrade
- Added `ARGON2_MEMORY_KIB` (65536) and `ARGON2_MEMORY_KIB_LEGACY` (32768) named constants
- Refactored `derive_key` to delegate to a shared private `derive_key_with_memory_cost` helper
- Updated `test_key_derivation_time` upper bound to 5 s (64 MiB requires more memory bandwidth on CI)
- Added `test_legacy_32mib_key_differs_from_64mib_key` test verifying the fallback is meaningful
- Updated SECURITY.md: Open Issue #2 marked as resolved; KDF memory updated to 64 MiB in all tables

### 2026-04-05 — Created Formal Threat Model (Issue #1)

- Created `THREAT_MODEL.md` at the repository root
- Documented five threat actors (TA-1 through TA-5): local unprivileged user, attacker with
  read access to the storage directory, offline attacker with a copy of the encrypted database,
  malicious same-user application, and forensic investigator with memory/disk artifacts
- Applied STRIDE methodology to enumerate 20+ individual threat scenarios
- Mapped 19 security controls (SC-01 through SC-19) to the threats each mitigates
- Documented 12 out-of-scope threats and 6 residual risks
- Updated SECURITY.md: Open Issue #1 marked as resolved; Security Posture Summary updated

### 2026-04-05 — SECURITY.md Review and Update (Issue #220)

- Reviewed SECURITY.md against source code and commit history
- **Fixed contradictory Issue #22 status**: was marked both open and resolved in different sections; code confirms `derive_hmac_key()` is fully removed and `load_or_create_hmac_key()` is in use — marked as resolved throughout
- **Corrected rate limiting lockout duration**: was listed as "15 minutes" in some sections; actual value is 1 minute (60 seconds per `LOCKOUT_DURATION_SECONDS` in `src/rate_limit.rs`)
- **Corrected Issue #6 acceptance criteria**: persistent rate limiting IS implemented per Issue #24 (was incorrectly shown as not implemented)
- **Removed ~3500 lines of redundant content**: implementation code snippets, proposed implementations, and issue-template-style details that duplicated GitHub issues
- **Consolidated two conflicting Security Posture Summary tables** (2026-02-22 and 2026-03-20) into a single accurate table verified against current source
- **Removed outdated "Security Recommendations" section**: all 12 items listed as "to do" were already implemented
- **Created clear "Open Issues and Future Work" section** with 14 prioritized items
- Added concise "Resolved Security Findings" summary tables
- Verified all security claims against actual source code

### 2026-03-20 — Final Production-Grade Security Audit (Issue #201)

- Comprehensive security audit covering all source files, CI/CD, dependencies
- Added OWASP Top 10, CI/CD review, supply-chain analysis, crypto review sections
- Verified all 5 findings from 2026-02-22 audit
- Updated security status to PASSING

### 2026-02-25 — Zeroize Master Password at UI Layer (Issue #26)

- Wrapped master password in `Zeroizing<String>` in all UI handler callbacks in `src/ui_handlers.rs`

### 2026-02-24 — Use Argon2 for Recovery Key Derivation (Issue #25)

- Replaced SHA-256 with Argon2id in `derive_recovery_key()` in `src/recovery.rs`

### 2026-02-23 — Implement Persistent Rate Limiting (Issue #24)

- Added `with_persistence()` constructor to `RateLimiter`; state persisted to `rate_limit.json`

### 2026-02-22 — Comprehensive Security Code Audit

- Identified 5 code-level findings (#22–#26)
- Conducted code coverage assessment and holistic security review
- Fixed password validation inconsistency (Issue #23)

### 2026-02-10 — Security Properties Expansion

- Added Issues #11–#21 covering timing attacks, Windows permissions, secure deletion, session timeout, clipboard, password generator, backup, integrity, search, updates, recovery

### 2026-02-08 — Initial Security Review

- Identified `bytes` dependency vulnerability (RUSTSEC-2026-0007) and fixed
- Implemented Issues #1–#10 (memory clearing, permissions, Argon2 params, password strength, rate limiting, audit logging, master password change, input validation, error sanitization)

---

**Last Updated:** 2026-04-17
**Security Audit Status:** ✅ PASSING (All code-level findings resolved. 0 critical dependency issues. 2 non-critical dependency warnings.)
**Next Review Date:** 2026-07-05
