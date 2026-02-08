# Security Policy

## Overview

This document outlines the security architecture, current security status, identified vulnerabilities, and recommended improvements for the Rust Slint Password Saver project. This is a password manager application that uses military-grade encryption (Argon2 + AES-256-GCM) to protect user credentials.

## Table of Contents

- [Current Security Status](#current-security-status)
- [Security Architecture](#security-architecture)
- [Identified Security Issues](#identified-security-issues)
- [Security Recommendations](#security-recommendations)
- [Action Items](#action-items)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
- [Security Best Practices for Contributors](#security-best-practices-for-contributors)

---

## Current Security Status

### ⚠️ Security Audit Status: **FAILING**

The automated security audit (cargo-audit) is currently failing due to known vulnerabilities in transitive dependencies. See [Identified Security Issues](#identified-security-issues) for details.

### Security Audit Results (as of 2026-02-08)

```
✅ Direct dependencies: No known vulnerabilities
⚠️ Transitive dependencies: 1 critical vulnerability, 2 warnings
🔍 Total dependencies scanned: 618 crates
```

**Critical Issues:**
- `bytes` 1.11.0 - Integer overflow in `BytesMut::reserve` (RUSTSEC-2026-0007)

**Warnings:**
- `bincode` 2.0.1 - Unmaintained (RUSTSEC-2025-0141)
- `paste` 1.0.15 - Unmaintained (RUSTSEC-2024-0436)

---

## Security Architecture

### Encryption Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  • User interface (Slint UI)                                 │
│  • Input validation                                          │
│  • Session management                                        │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                Storage Encryption Layer                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Argon2 Key Derivation                                  │ │
│  │  • Memory-hard function                                │ │
│  │  • Default parameters (19 MiB memory, 2 iterations)    │ │
│  │  • Random salt (generated per save)                    │ │
│  │  • Output: 256-bit encryption key                      │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ AES-256-GCM Encryption                                 │ │
│  │  • 256-bit key size                                    │ │
│  │  • Galois/Counter Mode (authenticated)                 │ │
│  │  • 96-bit random nonce (generated per save)            │ │
│  │  • AEAD: Provides confidentiality + authenticity       │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                 File System Storage                          │
│  • Location: ~/.password_saver/passwords.enc                 │
│  • Format: JSON with encrypted data                          │
│  • Fields: salt, nonce, encrypted_data (all base64)          │
└──────────────────────────────────────────────────────────────┘
```

### Security Properties

✅ **Implemented:**
- Confidentiality via AES-256-GCM
- Authenticity via GCM authentication tag
- Integrity verification (tamper detection)
- Zero-knowledge (master password never stored)
- Forward secrecy (new salt/nonce per save)
- Memory safety via Rust's ownership system
- Input validation (checks for empty fields)

❌ **Missing:**
- Memory clearing for sensitive data (passwords in memory)
- Secure file permissions for encrypted storage file
- Rate limiting for decryption attempts
- Key stretching parameters tuning (Argon2 defaults may be too weak)
- Protection against timing attacks in password verification
- Secure deletion of old encrypted data
- Audit logging for security events
- Master password change functionality
- Backup and recovery mechanisms

✅ **Recently Added:**
- Password strength requirements/validation (v0.1.0) - Enforces strong master passwords on first use

---

## Identified Security Issues

### 🔴 Critical: Transitive Dependency Vulnerability

**Issue:** Integer overflow in `bytes` crate v1.11.0

```
Advisory:     RUSTSEC-2026-0007
Severity:     Critical
Component:    bytes 1.11.0 (transitive via slint → winit → combine)
Description:  Integer overflow in BytesMut::reserve can lead to buffer 
              overflows and potential memory corruption
Impact:       Potential for memory safety violations, though impact is
              limited as this crate is only used in UI rendering, not
              in cryptographic operations
Solution:     Upgrade to bytes >= 1.11.1
```

**Mitigation Strategy:**
1. Update `Cargo.lock` to use patched version of bytes
2. Wait for Slint framework to update its dependencies
3. Consider using `cargo update -p bytes` to force update

**Priority:** 🔴 **CRITICAL** - Must be resolved immediately

### 🟡 Warning: Unmaintained Dependencies

**Issue 1:** `bincode` 2.0.1 is unmaintained

```
Advisory:     RUSTSEC-2025-0141
Component:    bincode 2.0.1 (transitive via slint-compiler)
Impact:       No immediate security risk, but no future security patches
Mitigation:   Monitor for Slint framework migration to maintained alternatives
Priority:     🟡 MEDIUM - Monitor but not blocking
```

**Issue 2:** `paste` 1.0.15 is unmaintained

```
Advisory:     RUSTSEC-2024-0436  
Component:    paste 1.0.15 (transitive via slint → image → rav1e)
Impact:       Procedural macro crate, limited security exposure
Mitigation:   Monitor for Slint framework updates
Priority:     🟡 LOW - Monitor only
```

### 🔵 Code-Level Security Issues

#### 1. Memory Exposure of Sensitive Data

**Location:** `src/storage.rs`, `src/main.rs`

**Issue:** Passwords and master passwords are stored as `String` types in memory without secure erasure. When these strings are dropped, the memory may not be immediately overwritten, leaving sensitive data in memory longer than necessary.

```rust
// Current implementation in main.rs
pub fn save_entries(&self, entries: &[PasswordEntry], master_password: &str)

// PasswordEntry struct
pub struct PasswordEntry {
    pub title: String,
    pub username: String,
    pub password: String,  // ⚠️ Not securely cleared from memory
    pub created_at: u64,
}
```

**Impact:** 🟡 **MEDIUM** - Memory dumps could expose passwords
**Recommendation:** Use `zeroize` crate for secure memory clearing

#### 2. Insufficient File Permissions

**Location:** `src/storage.rs:369`, `src/main.rs:64`

**Issue:** Encrypted password file (`~/.password_saver/passwords.enc`) is created with default permissions, potentially allowing other users on the system to read it.

```rust
// Current implementation
fs::write(&self.storage_path, storage_json)
    .map_err(|e| format!("Failed to write to disk: {}", e))?;
```

**Impact:** 🟡 **MEDIUM** - Other system users could access encrypted data
**Recommendation:** Set file permissions to 0600 (owner read/write only)

#### 3. Weak Argon2 Parameters

**Location:** `src/storage.rs:163`

**Issue:** Using `Argon2::default()` which may use conservative parameters. For a password manager, stronger parameters should be used.

```rust
let argon2 = Argon2::default();  // ⚠️ Default parameters may be too weak
```

**Current Defaults:** ~19 MiB memory, 2 iterations, 4 parallelism
**Recommendation:** 64-256 MiB memory, 3-4 iterations for better security

**Impact:** 🟡 **MEDIUM** - Weaker protection against brute-force attacks
**Recommendation:** Use custom Argon2 parameters optimized for password managers

#### 4. No Rate Limiting on Decryption

**Location:** `src/storage.rs:422`, `src/main.rs:139`

**Issue:** No protection against brute-force attempts to guess master password. An attacker with access to the encrypted file can attempt unlimited decryption attempts.

**Impact:** 🟡 **MEDIUM** - Enables offline brute-force attacks
**Recommendation:** Implement attempt tracking and delays

#### 5. No Secure Deletion of Old Data

**Location:** `src/storage.rs:332`

**Issue:** When saving updated password entries, old encrypted file is replaced without secure deletion. On some file systems, old data may remain recoverable.

**Impact:** 🔵 **LOW** - Old encrypted data may be forensically recoverable
**Recommendation:** Implement secure file overwriting before deletion

#### 6. Cryptographic Randomness Source

**Location:** `src/storage.rs:343`, `src/storage.rs:349`

**Issue:** Using `OsRng` from `aes_gcm::aead::rand_core`, which is correct, but not explicitly documented.

```rust
let salt = SaltString::generate(&mut OsRng);
OsRng.fill_bytes(&mut nonce_bytes);
```

**Impact:** ✅ **GOOD** - Already using cryptographically secure RNG
**Recommendation:** Add comments documenting the security properties

#### 7. Missing Input Sanitization

**Location:** `src/main.rs:84-92`

**Issue:** Basic validation exists but no length limits or sanitization of inputs. Very long inputs could cause memory issues.

```rust
if master_password.is_empty() {
    // Only checks for empty, not length or content
}
```

**Impact:** 🔵 **LOW** - Potential for denial of service with extreme inputs
**Recommendation:** Add maximum length limits and input sanitization

#### 8. Error Messages Leak Information

**Location:** `src/storage.rs:276`, `src/main.rs:178-184`

**Issue:** Error messages from decryption failures could leak information about the system state or cryptographic operations.

```rust
Err(e) => format!("Decryption failed: {}", e)  // ⚠️ May leak crypto details
```

**Impact:** 🔵 **LOW** - Information leakage via error messages
**Recommendation:** Use generic error messages for crypto failures

---

## Security Recommendations

### Immediate Actions (Critical Priority)

1. **Fix bytes Dependency Vulnerability**
   - Run `cargo update -p bytes` to update to patched version
   - Verify security audit passes after update
   - Monitor Slint framework for official dependency updates

2. **Implement Secure Memory Handling**
   - Add `zeroize` crate dependency
   - Use `Zeroizing<String>` for passwords and master passwords
   - Implement `Drop` trait for `PasswordEntry` to clear sensitive data

3. **Set Secure File Permissions**
   - Set encrypted file permissions to 0600 (owner read/write only)
   - Create parent directory with 0700 permissions
   - Verify permissions on every file write

### High Priority

4. **Strengthen Argon2 Parameters**
   - Configure custom Argon2 parameters optimized for password managers
   - Use at least 64 MiB memory, 3 iterations
   - Make parameters configurable for different hardware capabilities

5. **Add Password Strength Requirements**
   - Implement minimum password length (12+ characters recommended)
   - Check against common passwords list
   - Provide password strength meter in UI

6. **Implement Rate Limiting**
   - Track failed decryption attempts
   - Add increasing delays after failed attempts
   - Lock out after threshold (e.g., 5 failed attempts)

### Medium Priority

7. **Add Security Audit Logging**
   - Log successful/failed decryption attempts with timestamps
   - Log file access events
   - Store logs separately with integrity protection

8. **Implement Master Password Change**
   - Allow users to change master password
   - Re-encrypt all data with new key derived from new password
   - Maintain password history to prevent reuse

9. **Add Secure Backup/Export**
   - Implement encrypted backup functionality
   - Add import/export with key derivation
   - Verify integrity of imported data

### Low Priority

10. **Enhance Error Handling**
    - Use generic error messages for cryptographic failures
    - Implement structured error types
    - Avoid leaking system information in errors

11. **Add Timing Attack Protection**
    - Use constant-time comparison for authentication operations
    - Ensure consistent execution time for password verification

12. **Implement Secure Deletion**
    - Overwrite file contents before deletion
    - Use platform-specific secure deletion APIs
    - Clear temporary buffers containing sensitive data

---

## Action Items

The following tasks are formatted as GitHub issues ready to be picked up by Copilot or developers. Each task is self-contained and includes implementation guidance.

### Issue 1: 🔴 Fix bytes Crate Vulnerability (CRITICAL)

**Title:** Fix critical security vulnerability in bytes crate dependency

**Description:**
The security audit is failing due to a critical vulnerability in the `bytes` crate v1.11.0 (RUSTSEC-2026-0007). This is a transitive dependency via the Slint UI framework.

**Vulnerability Details:**
- Advisory: RUSTSEC-2026-0007
- Component: bytes 1.11.0
- Issue: Integer overflow in `BytesMut::reserve`
- Severity: Critical
- Solution: Upgrade to bytes >= 1.11.1

**Tasks:**
1. Run `cargo update -p bytes` to update the bytes crate
2. Verify the update by running `cargo audit`
3. Ensure all tests still pass: `cargo test`
4. Verify the application builds and runs: `cargo run`
5. Document the fix in commit message

**Files to Check:**
- `Cargo.lock` - Should show bytes >= 1.11.1 after update

**Acceptance Criteria:**
- [ ] `cargo audit` passes without errors
- [ ] All tests pass
- [ ] Application builds and runs successfully
- [ ] Cargo.lock updated with patched bytes version

**Priority:** 🔴 CRITICAL
**Estimated Effort:** 30 minutes
**Labels:** security, critical, dependencies

---

### Issue 2: 🔴 Implement Secure Memory Clearing for Passwords

**Title:** Add secure memory clearing for sensitive data using zeroize crate

**Description:**
Passwords and master passwords are currently stored as regular `String` types. When these strings are dropped, Rust does not guarantee the memory is immediately cleared, potentially leaving sensitive data in memory accessible via memory dumps or swap files.

**Security Impact:**
- Medium severity
- Memory dumps could expose passwords
- Swap files could contain unencrypted passwords
- Forensic recovery of passwords from RAM

**Solution:**
Implement the `zeroize` crate to securely clear sensitive data from memory.

**Implementation Steps:**

1. Add dependency to `Cargo.toml`:
```toml
[dependencies]
zeroize = { version = "1.8", features = ["derive"] }
```

2. Update `PasswordEntry` struct in `src/storage.rs`:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    pub title: String,
    #[zeroize(skip)]  // Username is less sensitive
    pub username: String,
    pub password: String,  // Will be zeroized on drop
    #[zeroize(skip)]
    pub created_at: u64,
}
```

3. Update function signatures to accept `Zeroizing<String>` for master passwords in:
   - `src/storage.rs`: `save_entries()`, `load_entries()`, `derive_key()`
   - `src/main.rs`: UI callback handlers

4. Update UI callback handlers in `src/main.rs` to zeroize master password inputs

5. Add tests to verify zeroization behavior in `tests/storage_test.rs`

**Files to Modify:**
- `Cargo.toml` - Add zeroize dependency
- `src/storage.rs` - Update PasswordEntry struct and functions
- `src/main.rs` - Update UI handlers to use Zeroizing types
- `tests/storage_test.rs` - Add zeroization tests

**Testing:**
- Verify all existing tests pass
- Add new test to confirm sensitive data is cleared
- Use memory inspection tools to validate (optional)

**Acceptance Criteria:**
- [ ] zeroize crate added to dependencies
- [ ] PasswordEntry derives Zeroize and ZeroizeOnDrop
- [ ] Master password parameters use Zeroizing wrapper
- [ ] All tests pass
- [ ] Documentation updated with security guarantees

**Priority:** 🔴 HIGH
**Estimated Effort:** 2-3 hours
**Labels:** security, enhancement, cryptography

---

### Issue 3: 🟡 Set Secure File Permissions for Encrypted Storage

**Title:** Implement secure file permissions (0600) for password storage file

**Description:**
The encrypted password file (`~/.password_saver/passwords.enc`) is currently created with default file permissions, which may allow other users on the system to read it. While the data is encrypted, defense-in-depth principles dictate we should also protect the file at the OS level.

**Security Impact:**
- Medium severity  
- Other system users could access encrypted data
- Reduces attack surface (defense in depth)
- Protects against future encryption vulnerabilities

**Solution:**
Set file permissions to 0600 (owner read/write only) for the encrypted storage file and 0700 for the parent directory.

**Implementation Steps:**

1. Add platform-specific file permission handling to `src/storage.rs`:

```rust
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::fs::{self, Permissions};

// After writing the file
fn set_secure_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let permissions = Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .map_err(|e| format!("Failed to set file permissions: {}", e))?;
    }
    Ok(())
}
```

2. Update `save_entries()` in `src/storage.rs` to set permissions after write:
```rust
fs::write(&self.storage_path, storage_json)
    .map_err(|e| format!("Failed to write to disk: {}", e))?;

// Set secure permissions immediately after creation
self.set_secure_permissions(&self.storage_path)?;
```

3. Update `get_storage_path()` in `src/main.rs` to set directory permissions:
```rust
if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)?;
    
    #[cfg(unix)]
    {
        let permissions = Permissions::from_mode(0o700);
        std::fs::set_permissions(parent, permissions)?;
    }
}
```

4. Add tests to verify permissions are set correctly

**Files to Modify:**
- `src/storage.rs` - Add permission setting after file write
- `src/main.rs` - Set directory permissions in get_storage_path()
- `tests/storage_test.rs` - Add permission verification tests

**Testing:**
- Verify file permissions are 0600 after save on Unix systems
- Verify directory permissions are 0700 on Unix systems
- Verify functionality on Windows (no-op for permissions)
- All existing tests pass

**Acceptance Criteria:**
- [ ] File permissions set to 0600 on Unix systems after write
- [ ] Directory permissions set to 0700 on Unix systems
- [ ] No change in behavior on Windows
- [ ] Tests verify correct permissions are set
- [ ] All tests pass

**Priority:** 🟡 HIGH
**Estimated Effort:** 1-2 hours
**Labels:** security, enhancement, unix

---

### Issue 4: 🟡 Strengthen Argon2 Key Derivation Parameters

**Title:** Configure stronger Argon2 parameters for password manager use case

**Description:**
The application currently uses `Argon2::default()` which provides conservative parameters suitable for general use. For a password manager storing highly sensitive data, we should use stronger parameters to better protect against brute-force attacks.

**Security Impact:**
- Medium severity
- Default parameters may be too weak for password manager use case
- Stronger parameters increase resistance to brute-force attacks
- Configurable parameters allow optimization for different hardware

**Current Parameters:**
- Memory: ~19 MiB
- Iterations: 2
- Parallelism: 4

**Recommended Parameters:**
- Memory: 64 MiB (minimum), 256 MiB (recommended)
- Iterations: 3-4
- Parallelism: 4 (match CPU cores)

**Implementation Steps:**

1. Update `derive_key()` in `src/storage.rs` to use custom parameters:

```rust
use argon2::{Argon2, Algorithm, Version, Params};

pub fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    // Configure Argon2id with stronger parameters
    // Memory: 64 MiB, Iterations: 3, Parallelism: 4
    let params = Params::new(
        65536,  // 64 MiB memory cost (in KiB)
        3,      // 3 iterations
        4,      // 4 parallel threads
        Some(32) // 32 byte output length
    ).map_err(|e| format!("Failed to create Argon2 params: {}", e))?;
    
    let argon2 = Argon2::new(
        Algorithm::Argon2id,  // Argon2id (hybrid mode)
        Version::V0x13,       // Latest version
        params
    );
    
    // Rest of implementation...
}
```

2. Add configuration option for tuning parameters based on hardware:
   - Add optional config file: `~/.password_saver/config.json`
   - Allow users to adjust parameters for their hardware
   - Provide sensible defaults

3. Add documentation explaining the security trade-offs

4. Consider adding a parameter tuning utility that benchmarks the system

**Files to Modify:**
- `src/storage.rs` - Update derive_key() with custom parameters
- `Cargo.toml` - Ensure argon2 version supports custom parameters
- `README.md` - Document the security improvement
- `tests/storage_test.rs` - Update tests to handle new parameters

**Testing:**
- Verify key derivation still works correctly
- Measure key derivation time (should be 100ms-500ms for good security)
- Verify encrypted files from old version can still be read
- Benchmark on various hardware

**Acceptance Criteria:**
- [ ] Custom Argon2 parameters configured (64 MiB memory, 3 iterations)
- [ ] Key derivation time is reasonable (100ms-500ms)
- [ ] Backward compatibility maintained (can read old files)
- [ ] Documentation updated with security rationale
- [ ] All tests pass

**Priority:** 🟡 HIGH  
**Estimated Effort:** 2-3 hours
**Labels:** security, enhancement, cryptography

---

### Issue 5: ✅ Add Password Strength Validation (RESOLVED)

**Status:** ✅ **RESOLVED** - Implemented in v0.1.0

**Title:** Implement password strength requirements and validation

**Description:**
Currently, the application accepts any non-empty password without checking strength. This allows users to create weak master passwords that could be easily brute-forced, undermining the cryptographic security of the system.

**Security Impact:**
- Medium severity
- Weak passwords can be brute-forced even with strong encryption
- User education and enforcement of strong passwords is critical
- Password manager master password should be extremely strong

**Solution:**
Implement password strength validation with clear feedback to users.

**Implementation Steps:**

1. Add password strength checking crate to `Cargo.toml`:
```toml
[dependencies]
zxcvbn = "3.1"  # Password strength estimator
```

2. Create new module `src/password_strength.rs`:
```rust
use zxcvbn::zxcvbn;

pub struct PasswordRequirements {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
}

impl Default for PasswordRequirements {
    fn default() -> Self {
        Self {
            min_length: 12,  // NIST recommends at least 8, we use 12
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
        }
    }
}

pub fn validate_password_strength(
    password: &str,
    requirements: &PasswordRequirements
) -> Result<PasswordStrength, String> {
    // Implementation...
}

pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong,
}
```

3. Update `src/main.rs` to validate master password before first use:
```rust
ui.on_save_password(move |master_password, title, username, password| {
    // Validate master password strength on first use
    if !storage.exists() {
        match validate_password_strength(&master_password, &Default::default()) {
            Ok(strength) if strength < PasswordStrength::Strong => {
                ui.set_status_message(
                    "Master password is too weak. Please use a stronger password.".into()
                );
                return;
            }
            Err(e) => {
                ui.set_status_message(format!("Password validation error: {}", e).into());
                return;
            }
            _ => {}
        }
    }
    // Continue with save...
});
```

4. Add UI feedback for password strength (optional enhancement):
   - Add visual strength meter in UI
   - Show real-time feedback as user types
   - Provide suggestions for improving password

**Files to Create:**
- `src/password_strength.rs` - Password validation logic

**Files to Modify:**
- `Cargo.toml` - Add zxcvbn dependency
- `src/lib.rs` - Add password_strength module
- `src/main.rs` - Add validation in save_password callback
- `README.md` - Document password requirements

**Testing:**
- Test weak passwords are rejected
- Test strong passwords are accepted
- Test edge cases (empty, very long, special characters)
- Verify user-friendly error messages

**Acceptance Criteria:**
- [x] Password strength validation implemented
- [x] Minimum 12 character requirement enforced for master password
- [x] Clear error messages guide users to create strong passwords
- [x] Tests cover various password strengths
- [x] Documentation updated with password requirements

**Implementation Details:**
- ✅ Added `zxcvbn` crate (v3.1) for password strength analysis
- ✅ Created `src/password_strength.rs` module with comprehensive validation
- ✅ Enforces requirements: 12+ chars, uppercase, lowercase, digit, special character
- ✅ Uses zxcvbn entropy analysis to detect weak patterns and common passwords
- ✅ Validation only applied on first use (creating new password database)
- ✅ Provides user-friendly error messages with specific improvement suggestions
- ✅ Added 17 unit tests covering various password scenarios
- ✅ Updated README.md with password requirements and examples
- ✅ All tests pass, no clippy warnings

**Priority:** 🟡 MEDIUM
**Estimated Effort:** 3-4 hours  
**Labels:** security, enhancement, ux

---

### Issue 6: 🔵 Implement Decryption Rate Limiting

**Title:** Add rate limiting to prevent brute-force attacks on master password

**Description:**
Currently, there is no protection against an attacker making unlimited attempts to guess the master password. If an attacker gains access to the encrypted file, they can attempt brute-force attacks offline without rate limiting.

**Security Impact:**
- Medium severity
- Enables offline brute-force attacks
- No penalty for incorrect password attempts
- Combined with weak passwords, could allow unauthorized access

**Solution:**
Implement rate limiting with exponential backoff for failed decryption attempts.

**Implementation Steps:**

1. Create new module `src/rate_limit.rs`:
```rust
use std::time::{Duration, Instant};
use std::sync::Mutex;

pub struct RateLimiter {
    attempts: Mutex<Vec<Instant>>,
    max_attempts: usize,
    window: Duration,
    lockout_duration: Duration,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(Vec::new()),
            max_attempts: 5,
            window: Duration::from_secs(300),  // 5 minutes
            lockout_duration: Duration::from_secs(60),  // 1 minute lockout
        }
    }
    
    pub fn check_and_record_attempt(&self) -> Result<(), String> {
        // Implementation to track attempts and enforce delays
    }
    
    pub fn record_success(&self) {
        // Clear attempts on successful authentication
    }
}
```

2. Integrate into `src/main.rs`:
```rust
lazy_static! {
    static ref RATE_LIMITER: RateLimiter = RateLimiter::new();
}

ui.on_load_passwords(move |master_password| {
    // Check rate limit before attempting decryption
    if let Err(e) = RATE_LIMITER.check_and_record_attempt() {
        ui.set_status_message(e.into());
        return;
    }
    
    match storage.load_entries(&master_password) {
        Ok(entries) => {
            RATE_LIMITER.record_success();
            // Display entries...
        }
        Err(e) => {
            ui.set_status_message(
                "Incorrect master password. Please try again.".into()
            );
        }
    }
});
```

3. Implement persistent tracking of failed attempts:
   - Store attempt timestamps in separate file
   - Encrypt the tracking file
   - Prevent tampering by using HMAC

4. Add configuration for rate limit parameters

**Files to Create:**
- `src/rate_limit.rs` - Rate limiting logic

**Files to Modify:**
- `Cargo.toml` - Add lazy_static dependency
- `src/lib.rs` - Add rate_limit module  
- `src/main.rs` - Integrate rate limiting
- `tests/` - Add rate limit tests

**Testing:**
- Test rate limiting triggers after threshold
- Test successful authentication clears attempts
- Test persistent attempt tracking across restarts
- Verify user-friendly error messages

**Acceptance Criteria:**
- [ ] Rate limiting implemented with 5 attempts per 5 minutes
- [ ] Exponential backoff for repeated failures
- [ ] Persistent tracking of attempts (survives restarts)
- [ ] Clear user feedback about lockout status
- [ ] Tests verify rate limiting behavior

**Priority:** 🔵 MEDIUM
**Estimated Effort:** 4-5 hours
**Labels:** security, enhancement

---

### Issue 7: 🔵 Add Security Audit Logging

**Title:** Implement audit logging for security-relevant events

**Description:**
Currently, no audit trail exists for security events like successful/failed authentication attempts, file access, or data modifications. Audit logs are essential for detecting unauthorized access attempts and forensic analysis.

**Security Impact:**
- Low-Medium severity
- No forensic trail for security incidents
- Cannot detect unauthorized access attempts
- Lack of accountability for sensitive operations

**Solution:**
Implement structured audit logging with integrity protection.

**Implementation Steps:**

1. Add logging dependencies to `Cargo.toml`:
```toml
[dependencies]
log = "0.4"
env_logger = "0.11"
serde = { version = "1.0", features = ["derive"] }
```

2. Create new module `src/audit_log.rs`:
```rust
use std::fs::OpenOptions;
use std::io::Write;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct AuditEntry {
    timestamp: u64,
    event_type: AuditEventType,
    success: bool,
    details: Option<String>,
}

pub enum AuditEventType {
    MasterPasswordCheck,
    PasswordsSaved,
    PasswordsLoaded,
    FileAccess,
    RateLimitTriggered,
}

pub struct AuditLogger {
    log_path: PathBuf,
}

impl AuditLogger {
    pub fn log_event(&self, event: AuditEntry) -> Result<(), String> {
        // Implementation...
    }
}
```

3. Integrate logging into security operations:
   - Log all decryption attempts (success/failure)
   - Log file read/write operations
   - Log rate limit triggers
   - Log application start/stop

4. Protect log integrity:
   - Use append-only file
   - Add HMAC to each log entry
   - Store logs separately from encrypted data

5. Add log rotation and cleanup:
   - Rotate logs after size threshold
   - Keep last N days of logs
   - Compress old logs

**Files to Create:**
- `src/audit_log.rs` - Audit logging implementation

**Files to Modify:**
- `Cargo.toml` - Add logging dependencies
- `src/lib.rs` - Add audit_log module
- `src/main.rs` - Add logging to security operations
- `src/storage.rs` - Add logging to encryption/decryption

**Testing:**
- Verify events are logged correctly
- Test log file creation and permissions
- Verify log integrity protection
- Test log rotation

**Acceptance Criteria:**
- [ ] Audit logging implemented for security events
- [ ] Logs stored in `~/.password_saver/audit.log`
- [ ] Log entries include timestamp, event type, and result
- [ ] Log integrity protected with HMAC
- [ ] Log rotation implemented
- [ ] Documentation added for audit log format

**Priority:** 🔵 MEDIUM
**Estimated Effort:** 3-4 hours
**Labels:** security, enhancement, observability

---

### Issue 8: 🔵 Implement Master Password Change Functionality

**Title:** Add ability to change master password

**Description:**
Users currently have no way to change their master password after initial setup. This is a critical feature for password managers, as users may need to change passwords due to compromise, sharing, or routine security practices.

**Security Impact:**
- Medium severity (missing feature)
- Users cannot recover from password compromise
- No way to rotate credentials
- Limits security best practices

**Solution:**
Implement master password change functionality that re-encrypts all data with new key.

**Implementation Steps:**

1. Add `change_master_password()` method to `src/storage.rs`:
```rust
pub fn change_master_password(
    &self,
    old_password: &str,
    new_password: &str,
) -> Result<(), String> {
    // 1. Load entries with old password
    let entries = self.load_entries(old_password)?;
    
    // 2. Validate new password strength
    validate_password_strength(new_password)?;
    
    // 3. Ensure new password is different
    if old_password == new_password {
        return Err("New password must be different from old password".into());
    }
    
    // 4. Save entries with new password
    self.save_entries(&entries, new_password)?;
    
    // 5. Securely overwrite old encrypted file (optional)
    
    Ok(())
}
```

2. Add UI for password change in `src/ui/main.slint`:
   - Add "Change Master Password" dialog
   - Fields for: current password, new password, confirm new password
   - Add callback handler in main.rs

3. Add master password confirmation dialog:
   - Require typing new password twice
   - Show password strength indicator
   - Validate passwords match

4. Consider adding password history:
   - Prevent reuse of recent passwords
   - Store hashed history (not encrypted passwords)

**Files to Modify:**
- `src/storage.rs` - Add change_master_password() method
- `src/ui/main.slint` - Add password change dialog
- `src/main.rs` - Add password change callback
- `tests/storage_test.rs` - Add tests for password change

**Testing:**
- Test successful password change
- Test old password verification fails with wrong password
- Test new password strength validation
- Test entries are accessible with new password only
- Verify old password no longer works

**Acceptance Criteria:**
- [ ] Master password change functionality implemented
- [ ] UI dialog for password change added
- [ ] Password strength validation enforced
- [ ] Old password verified before change
- [ ] All data successfully re-encrypted
- [ ] Comprehensive tests for edge cases
- [ ] Documentation updated with password change instructions

**Priority:** 🔵 MEDIUM
**Estimated Effort:** 4-6 hours
**Labels:** security, enhancement, feature

---

### Issue 9: 🔵 Add Input Validation and Sanitization

**Title:** Implement comprehensive input validation and sanitization

**Description:**
Current input validation only checks for empty fields. There are no length limits, content validation, or sanitization, which could lead to issues with extremely long inputs or malicious content.

**Security Impact:**
- Low severity
- Potential for denial of service with extreme inputs
- No protection against injection attacks (low risk in this context)
- Missing best practice validation

**Solution:**
Implement comprehensive input validation with reasonable limits.

**Implementation Steps:**

1. Define constants for input limits in `src/storage.rs`:
```rust
pub const MAX_TITLE_LENGTH: usize = 200;
pub const MAX_USERNAME_LENGTH: usize = 500;
pub const MAX_PASSWORD_LENGTH: usize = 1000;
pub const MAX_MASTER_PASSWORD_LENGTH: usize = 500;
pub const MIN_MASTER_PASSWORD_LENGTH: usize = 12;
```

2. Create validation module `src/validation.rs`:
```rust
pub fn validate_title(title: &str) -> Result<(), String> {
    if title.is_empty() {
        return Err("Title cannot be empty".into());
    }
    if title.len() > MAX_TITLE_LENGTH {
        return Err(format!("Title too long (max {} chars)", MAX_TITLE_LENGTH).into());
    }
    // Check for control characters
    if title.chars().any(|c| c.is_control()) {
        return Err("Title contains invalid characters".into());
    }
    Ok(())
}

// Similar for username, password, master_password
```

3. Update `src/main.rs` to validate inputs before save:
```rust
ui.on_save_password(move |master_password, title, username, password| {
    // Validate all inputs
    if let Err(e) = validate_master_password(&master_password) {
        ui.set_status_message(format!("Invalid master password: {}", e).into());
        return;
    }
    if let Err(e) = validate_title(&title) {
        ui.set_status_message(format!("Invalid title: {}", e).into());
        return;
    }
    // ... validate username and password
    
    // Continue with save...
});
```

4. Add sanitization for display:
   - Truncate very long fields in UI
   - Escape special characters if needed
   - Prevent UI injection

**Files to Create:**
- `src/validation.rs` - Input validation functions

**Files to Modify:**
- `src/lib.rs` - Add validation module
- `src/storage.rs` - Add validation constants
- `src/main.rs` - Add input validation before save/load
- `tests/` - Add validation tests

**Testing:**
- Test maximum length enforcement
- Test minimum length enforcement (master password)
- Test empty input rejection
- Test control character rejection
- Test valid inputs are accepted
- Test clear error messages

**Acceptance Criteria:**
- [ ] Input validation module implemented
- [ ] Length limits enforced for all inputs
- [ ] Control characters rejected
- [ ] Clear, user-friendly error messages
- [ ] All existing functionality preserved
- [ ] Comprehensive test coverage

**Priority:** 🔵 LOW-MEDIUM
**Estimated Effort:** 2-3 hours
**Labels:** security, enhancement, ux

---

### Issue 10: 🔵 Improve Error Messages for Security

**Title:** Sanitize error messages to prevent information leakage

**Description:**
Some error messages may leak information about the internal state of the application or cryptographic operations, which could help attackers. Error messages should be informative for legitimate users but not reveal sensitive details.

**Security Impact:**
- Low severity
- Information leakage via verbose error messages
- Could aid attacker reconnaissance
- Best practice security enhancement

**Solution:**
Implement structured error handling with generic user-facing messages.

**Implementation Steps:**

1. Create error types in `src/errors.rs`:
```rust
use std::fmt;

#[derive(Debug)]
pub enum SecurityError {
    AuthenticationFailed,
    InvalidInput(String),
    StorageError,
    CryptographicError,
    PermissionDenied,
    RateLimitExceeded,
}

impl SecurityError {
    /// Returns user-friendly message that doesn't leak internal details
    pub fn user_message(&self) -> String {
        match self {
            Self::AuthenticationFailed => {
                "Incorrect master password. Please try again.".into()
            }
            Self::InvalidInput(field) => {
                format!("Invalid {}", field)
            }
            Self::StorageError => {
                "Unable to access password storage. Check file permissions.".into()
            }
            Self::CryptographicError => {
                "Encryption error occurred. Data may be corrupted.".into()
            }
            Self::PermissionDenied => {
                "Permission denied. Check file permissions.".into()
            }
            Self::RateLimitExceeded => {
                "Too many attempts. Please try again later.".into()
            }
        }
    }
    
    /// Returns detailed message for logging (not shown to user)
    pub fn debug_message(&self) -> String {
        format!("{:?}", self)
    }
}
```

2. Update `src/storage.rs` to use structured errors:
```rust
pub fn load_entries(&self, master_password: &str) -> Result<Vec<PasswordEntry>, SecurityError> {
    // ... existing code ...
    
    // Instead of:
    // .map_err(|e| format!("Decryption failed: {}", e))?;
    
    // Use:
    .map_err(|_| SecurityError::AuthenticationFailed)?;
}
```

3. Update UI handlers to use generic messages:
```rust
match storage.load_entries(&master_password) {
    Ok(entries) => { /* ... */ }
    Err(e) => {
        // Show generic message to user
        ui.set_status_message(e.user_message().into());
        
        // Log detailed error for debugging
        log::error!("Load failed: {}", e.debug_message());
    }
}
```

4. Add logging for detailed errors (for developers/debugging):
   - Log full error details with context
   - Include timestamps and operation details
   - Never show detailed crypto errors to users

**Files to Create:**
- `src/errors.rs` - Structured error types

**Files to Modify:**
- `src/lib.rs` - Add errors module
- `src/storage.rs` - Use SecurityError types
- `src/main.rs` - Handle errors with generic messages
- `tests/` - Update tests for new error types

**Testing:**
- Verify user messages are generic
- Verify detailed errors are logged
- Test all error paths
- Ensure no sensitive info in user messages

**Acceptance Criteria:**
- [ ] Structured error types implemented
- [ ] User-facing messages are generic and safe
- [ ] Detailed errors logged for debugging
- [ ] No cryptographic details in user messages
- [ ] All error paths tested
- [ ] Documentation updated

**Priority:** 🔵 LOW
**Estimated Effort:** 2-3 hours
**Labels:** security, enhancement, code-quality

---

## Reporting Security Vulnerabilities

### Responsible Disclosure

If you discover a security vulnerability in this project, please follow responsible disclosure practices:

1. **DO NOT** open a public GitHub issue
2. **DO NOT** disclose the vulnerability publicly until it has been addressed
3. **DO** email the maintainers directly at: [security contact needed]
4. **DO** provide detailed information about the vulnerability
5. **DO** allow reasonable time for the maintainers to address the issue

### What to Include in Your Report

Please include the following information:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact of the vulnerability
- Suggested remediation (if any)
- Your contact information for follow-up

### Response Timeline

We aim to:

- Acknowledge receipt of vulnerability reports within 48 hours
- Provide an initial assessment within 7 days
- Work on a fix with target completion within 30 days for critical issues
- Keep the reporter informed of progress

### Recognition

We appreciate security researchers who follow responsible disclosure. We will:

- Acknowledge your contribution in our security advisories (if desired)
- Provide credit in our SECURITY.md file (if desired)
- Work collaboratively to address the issue

---

## Security Best Practices for Contributors

### When Contributing Code

1. **Never commit secrets or credentials**
   - Use `.gitignore` for sensitive files
   - Review changes before committing
   - Use environment variables for configuration

2. **Follow secure coding practices**
   - Validate all inputs
   - Use constant-time comparisons for secrets
   - Clear sensitive data from memory
   - Set secure file permissions

3. **Use safe dependencies**
   - Run `cargo audit` before committing
   - Keep dependencies updated
   - Review security advisories for dependencies

4. **Write security tests**
   - Test authentication failure scenarios
   - Test input validation edge cases
   - Test cryptographic operations
   - Verify secure file permissions

5. **Document security considerations**
   - Comment on security-critical code
   - Explain cryptographic choices
   - Document threat models

### Code Review Checklist

When reviewing security-related PRs, verify:

- [ ] No hardcoded secrets or credentials
- [ ] Input validation is comprehensive
- [ ] Error messages don't leak sensitive information
- [ ] Sensitive data is cleared from memory
- [ ] File permissions are set correctly
- [ ] Cryptographic operations use approved algorithms
- [ ] Dependencies have no known vulnerabilities
- [ ] Tests cover security edge cases
- [ ] Documentation is updated

### Testing Security Features

Always test:

- Authentication with correct and incorrect credentials
- Input validation with edge cases
- File permission settings
- Cryptographic operations
- Error handling and messages
- Rate limiting and backoff

---

## Security Maintenance Schedule

### Regular Security Tasks

**Weekly:**
- Review dependency security advisories
- Monitor GitHub security alerts
- Check for new CVEs affecting Rust ecosystem

**Monthly:**
- Run comprehensive security audit (`cargo audit`)
- Review and update dependencies
- Check for new security best practices
- Review access logs (when implemented)

**Quarterly:**
- Full security audit of codebase
- Review cryptographic implementations
- Update security documentation
- Conduct threat modeling exercise

**Annually:**
- Comprehensive security review
- External security audit (if resources available)
- Review and update security policies
- Evaluate new security features

---

## Additional Resources

### Security Documentation

- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RustSec Advisory Database](https://rustsec.org/)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [AES-GCM Best Practices](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

### Security Tools

- `cargo-audit` - Audit dependencies for security vulnerabilities
- `cargo-deny` - Lint dependencies for security and license issues
- `cargo-geiger` - Detect unsafe code usage
- `cargo-crev` - Code review system for dependencies

### Cryptography References

- **Argon2**: Memory-hard password hashing algorithm
  - [Official specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)
  - Recommended for password storage by OWASP

- **AES-256-GCM**: Authenticated encryption
  - NIST approved encryption algorithm
  - Provides confidentiality and authenticity
  - Galois/Counter Mode for authenticated encryption

---

## Changelog

### 2026-02-08 - Initial Security Review

- Conducted comprehensive security audit
- Identified critical vulnerability in bytes dependency (RUSTSEC-2026-0007)
- Documented security architecture and recommendations
- Created 10 actionable security improvement tasks
- Established security reporting policy

---

**Last Updated:** 2026-02-08  
**Security Audit Status:** ⚠️ FAILING (1 critical issue)  
**Next Review Date:** 2026-03-08
