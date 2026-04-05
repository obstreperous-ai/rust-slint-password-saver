# Threat Model — Rust Slint Password Saver

## Table of Contents

- [Overview](#overview)
- [Scope and Assumptions](#scope-and-assumptions)
- [Protected Assets](#protected-assets)
- [Trust Boundaries](#trust-boundaries)
- [Threat Actors](#threat-actors)
- [Threat Scenarios (STRIDE Analysis)](#threat-scenarios-stride-analysis)
  - [TA-1: Local Unprivileged User on a Shared System](#ta-1-local-unprivileged-user-on-a-shared-system)
  - [TA-2: Attacker with Read Access to the Storage Directory](#ta-2-attacker-with-read-access-to-the-storage-directory)
  - [TA-3: Attacker with a Copy of the Encrypted Database (Offline Attack)](#ta-3-attacker-with-a-copy-of-the-encrypted-database-offline-attack)
  - [TA-4: Malicious Application with User Privileges](#ta-4-malicious-application-with-user-privileges)
  - [TA-5: Forensic Investigator with Memory or Disk Artifacts](#ta-5-forensic-investigator-with-memory-or-disk-artifacts)
- [Security Controls to Threat Mapping](#security-controls-to-threat-mapping)
- [Out-of-Scope Threats](#out-of-scope-threats)
- [Residual Risks](#residual-risks)
- [Changelog](#changelog)

---

## Overview

This document is the formal threat model for the Rust Slint Password Saver. It enumerates the threat actors, attack scenarios, and security controls that address each scenario. Threats that are outside the application's defense boundary are explicitly documented as out of scope.

This model uses the [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) framework
(**S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege) to categorize each threat scenario.

---

## Scope and Assumptions

### In Scope

- The application binary and its runtime behaviour
- All data files managed by the application under `~/.password_saver/`
- The encryption and key derivation pipeline (`src/storage.rs`, `src/recovery.rs`)
- Authentication and session management (`src/rate_limit.rs`, `src/session.rs`)
- Clipboard handling (`src/clipboard.rs`)
- In-memory handling of the master password and decrypted entries

### Out of Scope

- Vulnerabilities in the host operating system or kernel
- Hardware attacks (cold-boot, DMA attacks, hardware keyloggers)
- Compromise of the Rust toolchain or RustCrypto crates at build time
- Network attacks (the application is local-only; the update checker makes a single read-only
  GET request to a hardcoded GitHub API URL and is not an attack surface for data exfiltration)
- Two-factor authentication (not implemented; identified as a future enhancement)
- Binary signing and SBOM provenance (open items tracked separately)

### Assumptions

1. The operating system's user isolation is intact and functioning correctly.
2. The host filesystem correctly enforces the Unix permission bits (0600/0700) or Windows ACLs
   that the application sets.
3. The Argon2id, AES-256-GCM, HMAC-SHA256, and other cryptographic primitives (all from
   [RustCrypto](https://github.com/RustCrypto)) are correctly implemented.
4. `OsRng` (the OS-provided CSPRNG) produces cryptographically unpredictable output.
5. The user chooses a strong master password that meets the enforced minimum requirements.

---

## Protected Assets

| Asset | Sensitivity | Storage |
|---|---|---|
| Plaintext password entries (service name, username, password) | **Critical** | In memory only while unlocked; never written to disk in plaintext |
| Master password | **Critical** | Never stored; derived via Argon2id per operation; held in `Zeroizing<String>` |
| Derived AES-256 encryption key | **Critical** | Never stored; derived per operation; zeroized after use |
| Encrypted database file (`passwords.enc`) | High | `~/.password_saver/passwords.enc` (0600 / ACL) |
| Recovery codes | High | Plaintext shown once at generation; only SHA-256 hash stored on disk |
| Recovery key salt | Medium | Inside `passwords.enc` |
| HMAC key for audit log | Medium | `~/.password_saver/audit_hmac.key` (0600 / ACL) |
| Audit log (`audit.log`) | Medium | `~/.password_saver/audit.log` (0600 / ACL) |
| Rate-limit state (`rate_limit.json`) | Low | `~/.password_saver/rate_limit.json` (0600 / ACL) |
| Database integrity checksum | Low | Embedded in `passwords.enc` |

---

## Trust Boundaries

```
┌──────────────────────────────────────────────────────────────────────┐
│ Operating System User Account (trust boundary: OS user isolation)    │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Application Process (trust boundary: process memory)           │  │
│  │                                                                 │  │
│  │  UI Layer  ──► Session Manager ──► Storage Layer               │  │
│  │  (Slint)       (auto-lock/timeout)  (Argon2id + AES-256-GCM)   │  │
│  │                                        │                        │  │
│  └────────────────────────────────────────┼────────────────────────┘  │
│                                           │ filesystem I/O            │
│  ┌────────────────────────────────────────▼────────────────────────┐  │
│  │ ~/.password_saver/ (trust boundary: filesystem permissions)      │  │
│  │  • passwords.enc  (0600)                                         │  │
│  │  • audit_hmac.key (0600)                                         │  │
│  │  • audit.log      (0600)                                         │  │
│  │  • rate_limit.json(0600)                                         │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
            │ clipboard
            ▼
  OS clipboard (trust boundary: OS clipboard isolation — NOT guaranteed)
```

---

## Threat Actors

| ID | Actor | Capability | Motivation |
|---|---|---|---|
| TA-1 | Local unprivileged user on a shared system | Access to own user account; can observe the screen while legitimate user is present | Steal another user's stored passwords |
| TA-2 | Attacker with read access to `~/.password_saver/` | Can read all files in the storage directory (e.g., due to misconfigured permissions, ACL bypass, or brief physical access) | Extract credentials without knowing the master password |
| TA-3 | Attacker with a copy of the encrypted database file | Offline access to `passwords.enc`; unlimited computation | Brute-force or dictionary-attack the master password |
| TA-4 | Malicious application with user privileges | Running as the same OS user; can hook input events, read clipboard, capture the screen | Intercept credentials as the user types or copies them |
| TA-5 | Forensic investigator / insider with memory or disk artifacts | Access to a memory dump, swap/pagefile, or hibernation image from the target machine | Recover decrypted passwords or the master password from volatile/non-volatile memory |

---

## Threat Scenarios (STRIDE Analysis)

### TA-1: Local Unprivileged User on a Shared System

**Profile:** A different OS user account on the same host. Shares disk storage and hardware but has no elevated privileges and cannot read files owned by the target user when permissions are correctly set.

| # | STRIDE Category | Threat | Mitigating Controls | Residual Risk |
|---|---|---|---|---|
| T-1.1 | Information Disclosure | Read the encrypted database or key files by accessing `~/.password_saver/` | **SC-05** File permissions 0700 on directory + 0600 on files prevent other OS users from reading any file in the directory | Low — residual risk if OS or filesystem has a permission-bypass vulnerability |
| T-1.2 | Information Disclosure | Shoulder-surf the screen while the application is unlocked and passwords are visible | **SC-10** Session auto-lock after 5 minutes of inactivity minimises the exposure window | Medium — no technical control prevents shoulder-surfing; physical/procedural controls are the mitigation |
| T-1.3 | Tampering | Replace or corrupt the database file by writing to `~/.password_saver/` | **SC-05** 0700 directory permissions deny write access to other users | Low |
| T-1.4 | Denial of Service | Fill the filesystem to prevent the application from saving | OS-level disk quotas (not an application responsibility) | Low — disk exhaustion affects all user applications equally |

---

### TA-2: Attacker with Read Access to the Storage Directory

**Profile:** The attacker has bypassed or been granted read access to all files under `~/.password_saver/` (e.g., through a permission misconfiguration, a privilege escalation bug in another application, or brief unattended physical access). Read-only; no write access assumed unless noted.

| # | STRIDE Category | Threat | Mitigating Controls | Residual Risk |
|---|---|---|---|---|
| T-2.1 | Information Disclosure | Read `passwords.enc` and extract plaintext entries | **SC-01** AES-256-GCM + **SC-02** Argon2id key derivation — ciphertext is unreadable without the master password | Low — file contents are still protected by strong encryption |
| T-2.2 | Information Disclosure | Read `audit_hmac.key` and forge or verify audit log entries | **SC-05** 0600 permissions are the only access control on this key; if bypassed, HMAC integrity of the audit log is lost | Medium — audit log integrity is compromised if this key is leaked; confidentiality of stored passwords is unaffected |
| T-2.3 | Tampering | Read `rate_limit.json`, manipulate the copy (requires write access), and restore it to bypass rate limiting | **SC-05** 0600 permissions prevent writes; if write access is obtained, rate limiting can be reset | Medium (write access required) — HMAC verification on the rate-limit file would harden this further and is a known improvement |
| T-2.4 | Repudiation | Delete or corrupt `audit.log` to erase evidence of authentication attempts | **SC-07** HMAC-SHA256 signatures detect tampering; deletion is not detectable by the application | Medium — audit log deletion is out of scope for a local application; OS-level immutable logging is the recommended control |
| T-2.5 | Information Disclosure | Read `audit.log` to learn when the application is in use and establish usage patterns | **SC-05** 0600 permissions; audit log entries do not record the master password or plaintext credentials | Low — timing metadata only; no credential leakage |

---

### TA-3: Attacker with a Copy of the Encrypted Database (Offline Attack)

**Profile:** The attacker possesses a copy of `passwords.enc` (e.g., found on a backup, recovered from a deleted file, or exfiltrated). They have unlimited offline compute and time. This is the most technically demanding attack surface.

| # | STRIDE Category | Threat | Mitigating Controls | Residual Risk |
|---|---|---|---|---|
| T-3.1 | Information Disclosure | Brute-force the master password against `passwords.enc` | **SC-02** Argon2id (32 MiB / 2 iter / 4 parallel) makes each attempt slow and memory-intensive (~100 ms on commodity hardware at 32 MiB). **SC-01** AES-256-GCM authentication tag provides immediate pass/fail feedback per attempt without any decryption oracle. **SC-09** Minimum 12-character master password with required character classes narrows the feasible search space. | Medium — Argon2id at 32 MiB is below the OWASP ≥64 MiB recommendation; a very weak master password remains vulnerable to targeted dictionary attacks |
| T-3.2 | Information Disclosure | Dictionary attack using known-password lists | **SC-02** + **SC-09** — same as T-3.1; zxcvbn entropy check rejects common passwords at creation time | Low–Medium — residual risk for passwords that score above the threshold but appear in specialised wordlists |
| T-3.3 | Tampering | Modify `passwords.enc` to inject malicious entries | **SC-01** AES-256-GCM authentication tag invalidates any modified ciphertext; **SC-11** SHA-256 database integrity check detects file corruption | Low |
| T-3.4 | Information Disclosure | Recover a previous version of the database from backups or version control | **SC-03** Each save generates a fresh random salt (new derived key) and fresh random nonce — previous backups do not share key material | Low |

---

### TA-4: Malicious Application with User Privileges

**Profile:** A malicious or compromised application running as the same OS user. It can monitor the clipboard, hook keyboard input, capture the screen, and interact with the application window using OS accessibility APIs. This actor operates within the same OS security boundary as the legitimate user.

| # | STRIDE Category | Threat | Mitigating Controls | Residual Risk |
|---|---|---|---|---|
| T-4.1 | Information Disclosure | Clipboard sniffing — read copied passwords from the clipboard before the 30-second timer fires | **SC-08** Auto-clear after 30 seconds limits the exposure window; smart clear only removes the application's own entry | **High (out of scope for user-space app)** — any application running as the same user can read the clipboard at any time; OS-level clipboard isolation (e.g., Wayland, Windows UWP isolation) is required for full mitigation |
| T-4.2 | Information Disclosure | Keylogging — capture the master password and all typed passwords | No in-scope application control; the Slint UI framework uses standard OS input APIs | **High (out of scope for user-space app)** — hardware security keys or OS-level secure input are required; documented as a known limitation |
| T-4.3 | Information Disclosure | Screen scraping / screenshot — capture displayed plaintext passwords | **SC-10** Session auto-lock after 5 minutes reduces the time window passwords are visible | **High (out of scope for user-space app)** — user-space applications cannot prevent other same-user processes from taking screenshots |
| T-4.4 | Tampering | Inject events into the application's input queue to perform actions on behalf of the user | No dedicated control; relies on OS-level input isolation | Medium — limited in practice because authentication with the master password still protects read access to stored credentials |
| T-4.5 | Information Disclosure | Accessibility API scraping — enumerate UI elements to extract visible passwords | No dedicated control; Slint UI accessibility APIs may expose visible labels | Medium (out of scope for user-space app) — depends on platform accessibility model; passwords should be masked by default in UI |

---

### TA-5: Forensic Investigator with Memory or Disk Artifacts

**Profile:** The investigator has access to a memory dump (live or post-mortem), the swap/pagefile, or a hibernation image from a machine that was running the application. They can search for patterns, strings, and binary data at rest.

| # | STRIDE Category | Threat | Mitigating Controls | Residual Risk |
|---|---|---|---|---|
| T-5.1 | Information Disclosure | Extract the master password from process memory | **SC-04** Master password wrapped in `Zeroizing<String>` in all UI handler callbacks (`src/ui_handlers.rs`); memory is zeroed when the `Zeroizing` wrapper is dropped | Medium — the Slint UI framework may retain a copy of the typed string before it reaches the application callback; compiler optimisations may also eliminate zeroization of short-lived stack values |
| T-5.2 | Information Disclosure | Extract decrypted password entries from the heap | **SC-04** `ZeroizeOnDrop` derived on `PasswordEntry` struct; entries are zeroed when the session lock or application exit triggers a drop | Medium — the garbage collector / heap allocator may retain freed pages; Slint UI string copies of displayed passwords are outside application control |
| T-5.3 | Information Disclosure | Recover decrypted data from the swap file or pagefile | **SC-04** Zeroization reduces the residency time of secrets in heap pages; **SC-10** Session auto-lock reduces the window during which decrypted data exists in memory | **High (out of scope for user-space app)** — user-space applications cannot prevent the OS from paging memory to disk; mlock/VirtualLock are OS-level controls not currently employed |
| T-5.4 | Information Disclosure | Extract decrypted data from a hibernation image | Same as T-5.3 | **High (out of scope for user-space app)** — hibernation captures the full RAM state regardless of in-process zeroization |
| T-5.5 | Information Disclosure | Recover the master password or session key from a core dump | **SC-04** Zeroization; application does not call `std::process::abort()` and does not explicitly enable core dumps | Medium — OS or container policies may enable core dumps; adding `prctl(PR_SET_DUMPABLE, 0)` on Linux is a future improvement |

---

## Security Controls to Threat Mapping

The table below is the reverse mapping: given a security control, which threat scenarios does it mitigate?

| Control ID | Control Name | Implementation | Threats Mitigated |
|---|---|---|---|
| SC-01 | AES-256-GCM authenticated encryption | `src/storage.rs` | T-2.1, T-3.1, T-3.2, T-3.3 |
| SC-02 | Argon2id key derivation (32 MiB / 2 iter / 4 parallel) | `src/storage.rs` `derive_key()` | T-3.1, T-3.2 |
| SC-03 | Fresh random salt and nonce per save (`OsRng`) | `src/storage.rs` | T-3.4 |
| SC-04 | Memory zeroization (`Zeroizing<String>`, `ZeroizeOnDrop`) | `src/ui_handlers.rs`, `src/storage.rs` | T-5.1, T-5.2, T-5.3 |
| SC-05 | Secure file permissions (0600/0700 Unix; ACL Windows) | `src/storage.rs`, `src/windows_permissions.rs` | T-1.1, T-1.3, T-2.1, T-2.2, T-2.3, T-2.5 |
| SC-06 | Secure deletion (3-pass overwrite before file removal) | `src/secure_delete.rs` | T-2.1 (residual copies after delete) |
| SC-07 | Audit log HMAC-SHA256 integrity | `src/audit_log.rs` | T-2.4 |
| SC-08 | Clipboard auto-clear (30 seconds) | `src/clipboard.rs` | T-4.1 |
| SC-09 | Password strength enforcement (zxcvbn + 12-char min + complexity) | `src/password_strength.rs`, `src/validation.rs` | T-3.1, T-3.2 |
| SC-10 | Session auto-lock after 5 minutes of inactivity | `src/session.rs` | T-1.2, T-4.3, T-5.1, T-5.2 |
| SC-11 | Database integrity check (SHA-256 checksum) | `src/integrity.rs` | T-3.3 |
| SC-12 | Rate limiting (5 attempts / 5-min window, 1-min lockout, persistent) | `src/rate_limit.rs` | T-3.1 (online guessing), T-3.2 |
| SC-13 | Timing attack protection (`subtle::ConstantTimeEq` + random jitter) | `src/storage.rs` | T-3.1 (timing side-channel) |
| SC-14 | Error message sanitisation | `src/errors.rs` | T-3.1 (no oracle feedback), T-2.1 |
| SC-15 | Input validation (length limits, control character rejection) | `src/validation.rs` | Injection attempts (indirect) |
| SC-16 | Encrypted backups (Argon2id + AES-256-GCM) | `src/backup.rs` | T-3.4 (backup copies) |
| SC-17 | Emergency recovery codes (~77-bit entropy, SHA-256 hashed) | `src/recovery.rs` | Recovery path availability |
| SC-18 | Cryptographically secure password generator (`OsRng`) | `src/password_generator.rs` | T-3.2 (generated passwords are high-entropy) |
| SC-19 | Privacy-preserving update checker (hardcoded URL, no telemetry) | `src/update_checker.rs` | Prevents SSRF; no data exfiltration |

---

## Out-of-Scope Threats

The following threat categories are **not mitigated by this application** and are explicitly acknowledged as out of scope. Users who require protection against these threats should apply appropriate OS-level, hardware-level, or procedural controls.

| # | Threat | Reason Out of Scope | Recommended Mitigation |
|---|---|---|---|
| OOS-1 | Keylogging by a same-user malicious process | User-space applications cannot prevent other user-space processes from hooking OS input APIs | Use a hardware security key, virtual keyboard, or OS-provided secure input mode |
| OOS-2 | Screen capture / screenshot by a same-user process | Same OS trust boundary; no API prevents same-user screen capture in standard desktop environments | Ensure display server policies (e.g., Wayland compositor restrictions) are enabled |
| OOS-3 | Clipboard sniffing before auto-clear | Clipboard is a shared OS resource readable by any process with the same user identity | Use a Wayland compositor or OS that enforces clipboard isolation; disable clipboard history tools |
| OOS-4 | OS swap / pagefile capture | User-space code cannot prevent the kernel from paging memory to disk | Enable full-disk encryption (e.g., LUKS, BitLocker, FileVault); disable swap; use `mlock` (future improvement) |
| OOS-5 | Hibernation image capture | Full RAM is written to disk by the OS during hibernation, regardless of in-process zeroization | Enable full-disk encryption; disable hibernation; ensure the system is powered off before the machine is taken |
| OOS-6 | Cold-boot attack | DRAM retains content for seconds to minutes after power loss, depending on temperature | Enable full-disk encryption; use a system without easily removable DRAM |
| OOS-7 | Hardware keylogger | Operates below the OS input stack | Physical access controls; inspect hardware regularly |
| OOS-8 | OS or kernel vulnerability exploitation | Privilege escalation vulnerabilities in the host OS are outside the application's trust boundary | Keep the OS and kernel fully patched |
| OOS-9 | Compromised Rust toolchain or supply chain | The binary is trusted as produced by an uncompromised toolchain; no SLSA provenance attestation currently available | Build from source with a verified toolchain; use reproducible builds (future enhancement) |
| OOS-10 | Two-factor authentication bypass | 2FA is not implemented (identified as a future enhancement for v0.2+) | Users requiring 2FA should await a future release or use an alternative tool |
| OOS-11 | Physical shoulder-surfing | No technical control prevents a person from reading the screen | Procedural: use the application in a private environment; rely on session auto-lock (SC-10) when stepping away |
| OOS-12 | Clipboard manager history retention | Third-party clipboard managers (KDE Klipper, macOS clipboard history, etc.) intercept clipboard writes before the 30-second timer fires | Disable clipboard history in any clipboard manager tool |

---

## Residual Risks

The following residual risks are **within scope** but not fully mitigated by existing controls:

| # | Risk | Severity | Notes |
|---|---|---|---|
| RR-1 | Argon2id at 32 MiB is below the OWASP ≥64 MiB recommendation | Medium | Deliberate trade-off for usability; tracked as Open Issue #2 in SECURITY.md |
| RR-2 | HMAC key for audit log stored in the same directory as the encrypted database | Medium | If read access to `~/.password_saver/` is gained (TA-2), the audit log's tamper-evidence is lost; confidentiality of stored passwords is unaffected |
| RR-3 | Rate-limit state file is not HMAC-protected | Low | An attacker with write access can reset rate limiting by deleting `rate_limit.json`; write access to 0600 files is already a significant privilege escalation |
| RR-4 | Slint UI framework retains string copies of displayed/typed values | Medium | Outside application control; affects TA-5 scenarios; upgrading Slint or switching to a secure input widget is the long-term mitigation |
| RR-5 | No `mlock`/`VirtualLock` to prevent sensitive pages from being swapped | High (out of scope) | Standard practice for high-security password managers; tracked for future consideration |
| RR-6 | Recovery code hash uses SHA-256 (single iteration) rather than a slow KDF | Low | Recovery codes have ~77 bits of entropy, making brute force impractical regardless of hash speed; Argon2id is used for the recovery *key* derivation |

---

## Changelog

### 2026-04-05 — Initial Threat Model Created (Issue #1)

- Created THREAT_MODEL.md at the repository root
- Documented five required threat actors (TA-1 through TA-5) using STRIDE methodology
- Mapped all 19 security controls (SC-01 through SC-19) to the threats they mitigate
- Documented 12 out-of-scope threats and 6 residual risks
- Updated SECURITY.md to reflect Open Issue #1 as resolved
