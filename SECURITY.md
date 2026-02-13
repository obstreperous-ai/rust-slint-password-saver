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

### ✅ Security Audit Status: **PASSING**

The automated security audit (cargo-audit) is passing. All critical vulnerabilities have been resolved. Only non-critical warnings for unmaintained transitive dependencies remain.

### Security Audit Results (as of 2026-02-08)

```
✅ Direct dependencies: No known vulnerabilities
✅ Transitive dependencies: No critical vulnerabilities
⚠️ Warnings: 2 unmaintained dependencies (non-critical)
🔍 Total dependencies scanned: 618 crates
```

**Critical Issues:**
- ~~`bytes` 1.11.0 - Integer overflow in `BytesMut::reserve` (RUSTSEC-2026-0007)~~ ✅ **FIXED** - Updated to bytes 1.11.1

**Warnings (Non-Critical):**
- `bincode` 2.0.1 - Unmaintained (RUSTSEC-2025-0141) - Transitive dependency via Slint, monitoring for updates
- `paste` 1.0.15 - Unmaintained (RUSTSEC-2024-0436) - Transitive dependency via Slint, minimal security exposure

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
│  │ Argon2id Key Derivation (Strengthened Parameters)     │ │
│  │  • Algorithm: Argon2id (hybrid mode)                  │ │
│  │  • Memory: 32 MiB (increased from ~19 MiB)            │ │
│  │  • Iterations: 2                                       │ │
│  │  • Parallelism: 4 threads                             │ │
│  │  • Version: V0x13 (latest)                            │ │
│  │  • Random salt (generated per save)                   │ │
│  │  • Output: 256-bit encryption key                     │ │
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
- Input validation (comprehensive validation for all inputs)
- Security audit logging with HMAC-based integrity protection
- Secure memory clearing via zeroize crate (passwords zeroized on drop)
- Password strength requirements/validation
- Master password change functionality
- Secure file permissions for encrypted storage file (Unix/Linux)
- Rate limiting for decryption attempts (prevents brute-force attacks)

❌ **Missing:**
- Protection against timing attacks in password verification (Issue #11)
- Secure deletion of old encrypted data (Issue #13)
- Backup and recovery mechanisms (Issue #17)
- Windows-specific secure file permissions (Issue #12)
- Session timeout and auto-lock functionality (Issue #14)
- Clipboard security with auto-clear (Issue #15)
- Password generator for strong passwords (Issue #16)
- Database integrity verification beyond GCM (Issue #18)
- Password search and filtering (Issue #19)
- Security update notifications (Issue #20)
- Emergency access and recovery codes (Issue #21)

✅ **Recently Added:**
- Password strength requirements/validation (v0.1.0) - Enforces strong master passwords on first use
- Rate limiting (v0.1.0) - Prevents brute-force attacks with configurable thresholds
- Secure file permissions (v0.1.0) - Unix/Linux file permissions set to 600 (owner read/write only)

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

#### 1. Memory Exposure of Sensitive Data ✅ FIXED

**Location:** `src/storage.rs`, `src/main.rs`

**Status:** ✅ **RESOLVED** - Implemented in current version

**Solution Implemented:**
- Added `zeroize` crate (v1.8) with derive features
- `PasswordEntry` now derives `Zeroize` and `ZeroizeOnDrop`
- Password fields are automatically cleared from memory when dropped
- Username and title fields skip zeroization (less sensitive)

```rust
// Updated implementation
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    #[zeroize(skip)]
    pub title: String,
    #[zeroize(skip)]
    pub username: String,
    pub password: String,  // ✅ Now securely cleared from memory on drop
    #[zeroize(skip)]
    pub created_at: u64,
}
```

**Impact:** 🟢 **RESOLVED** - Memory dumps no longer expose passwords
**Security Improvement:** Sensitive password data is now securely erased from memory when no longer needed

#### 2. Insufficient File Permissions ✅ FIXED

**Location:** `src/storage.rs`

**Status:** ✅ **RESOLVED** - Implemented in current version

**Solution Implemented:**
- Added `set_secure_permissions()` method that sets file permissions to 0600 (Unix/Linux)
- Automatically applied when saving encrypted data
- Creates parent directory with secure permissions (0700)
- Gracefully handles non-Unix platforms (Windows)

```rust
// Updated implementation
#[cfg(unix)]
pub fn set_secure_permissions(path: &Path) -> Result<(), SecurityError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path)
        .map_err(|e| SecurityError::storage_error(&format!("Failed to get file metadata: {}", e)))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600); // Owner read/write only
    fs::set_permissions(path, permissions)
        .map_err(|e| SecurityError::storage_error(&format!("Failed to set file permissions: {}", e)))?;
    Ok(())
}
```

**Impact:** 🟢 **RESOLVED** - Encrypted data now protected from other system users on Unix/Linux

#### 3. Weak Argon2 Parameters ✅ IMPROVED

**Location:** `src/storage.rs`

**Status:** ✅ **IMPROVED** - Strengthened in current version

**Solution Implemented:**
- Upgraded from default parameters to custom optimized parameters
- Memory cost increased to 32 MiB (from ~19 MiB)
- Using Argon2id (hybrid mode) for better security
- Maintains reasonable performance while significantly increasing attack resistance

```rust
// Updated implementation with strengthened parameters
let params = Params::new(
    32 * 1024,  // 32 MiB memory cost (increased from ~19 MiB)
    2,          // 2 iterations
    4,          // 4 threads parallelism
    None,
)
.map_err(|e| SecurityError::cryptographic_error(&format!("Invalid Argon2 params: {}", e)))?;

let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
```

**Impact:** 🟢 **IMPROVED** - Significantly stronger protection against brute-force attacks while maintaining usability

#### 4. No Rate Limiting on Decryption ✅ FIXED

**Location:** `src/rate_limit.rs`, `src/main.rs`

**Status:** ✅ **RESOLVED** - Implemented in current version

**Solution Implemented:**
- Added comprehensive rate limiting module (`src/rate_limit.rs`)
- Tracks failed authentication attempts with timestamps
- Enforces lockout after 5 failed attempts within 5 minutes
- 15-minute lockout period after threshold exceeded
- Automatic cleanup of old attempt records
- Thread-safe implementation using `Mutex`

```rust
// Rate limiter implementation
pub struct RateLimiter {
    attempts: Mutex<Vec<Instant>>,
}

impl RateLimiter {
    pub fn check_and_record_attempt(&self) -> Result<(), SecurityError> {
        // Enforces 5 attempts per 5 minutes with 15-minute lockout
    }
}
```

**Impact:** 🟢 **RESOLVED** - Effective protection against brute-force attacks on the master password

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

2. **✅ Implement Secure Memory Handling (COMPLETED)**
   - ✅ Added `zeroize` crate dependency (v1.8 with derive features)
   - ✅ Implemented `Zeroize` and `ZeroizeOnDrop` for `PasswordEntry`
   - ✅ Password fields are automatically cleared from memory on drop
   - ✅ Added test to verify zeroization behavior
   - ✅ Updated documentation with security guarantees

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

### Summary of Security Action Items

**Completed (✅ Resolved):**
1. ✅ Fix bytes Crate Vulnerability
2. ✅ Implement Secure Memory Clearing for Passwords  
3. ✅ Set Secure File Permissions for Encrypted Storage
4. ✅ Strengthen Argon2 Key Derivation Parameters
5. ✅ Add Password Strength Validation
6. ✅ Implement Decryption Rate Limiting
7. ✅ Add Security Audit Logging
8. ✅ Implement Master Password Change Functionality
9. ✅ Add Input Validation and Sanitization
10. ✅ Improve Error Messages for Security

**New Action Items (🔵 To Be Implemented):**
11. 🔵 Implement Timing Attack Protection for Password Verification
12. 🔵 Implement Windows File Permissions
13. 🔵 Implement Secure File Deletion
14. 🔵 Add Session Timeout and Auto-Lock
15. 🔵 Implement Clipboard Security and Auto-Clear
16. ✅ Add Secure Password Generator (Completed)
17. 🔵 Implement Backup and Export with Encryption
18. 🔵 Add Database Integrity Verification
19. 🔵 Implement Password Search and Filtering
20. 🔵 Add Security Update and Version Check
21. 🔵 Implement Emergency Access and Account Recovery

---

### Issue 1: ✅ Fix bytes Crate Vulnerability (RESOLVED)

**Title:** Fix critical security vulnerability in bytes crate dependency

**Status:** ✅ **RESOLVED** (2026-02-08)

**Description:**
The security audit was failing due to a critical vulnerability in the `bytes` crate v1.11.0 (RUSTSEC-2026-0007). This was a transitive dependency via the Slint UI framework.

**Vulnerability Details:**
- Advisory: RUSTSEC-2026-0007
- Component: bytes 1.11.0 → 1.11.1 ✅
- Issue: Integer overflow in `BytesMut::reserve`
- Severity: Critical
- Solution: Upgraded to bytes 1.11.1

**Resolution:**
1. ✅ Ran `cargo update -p bytes` to update the bytes crate
2. ✅ Verified the update with `cargo audit` - passes without critical errors
3. ✅ All tests pass: `cargo test` (13/13 tests passing)
4. ✅ Application builds successfully
5. ✅ Documented fix in commit message

**Files Updated:**
- `Cargo.lock` - bytes updated from 1.11.0 to 1.11.1

**Acceptance Criteria:**
- [x] `cargo audit` passes without critical errors (only 2 non-critical warnings remain)
- [x] All tests pass (13/13 passing)
- [x] Application builds and runs successfully
- [x] Cargo.lock updated with patched bytes version (1.11.1)

**Priority:** 🔴 CRITICAL → ✅ RESOLVED
**Effort:** 30 minutes (as estimated)
**Labels:** security, critical, dependencies, resolved

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

### Issue 3: ✅ Set Secure File Permissions for Encrypted Storage (RESOLVED)

**Status:** ✅ **RESOLVED** - Implemented in commit 9cc8a8a

**Title:** Implement secure file permissions (0600) for password storage file

**Description:**
The encrypted password file (`~/.password_saver/passwords.enc`) is currently created with default file permissions, which may allow other users on the system to read it. While the data is encrypted, defense-in-depth principles dictate we should also protect the file at the OS level.

**Security Impact:**
- Medium severity  
- Other system users could access encrypted data
- Reduces attack surface (defense in depth)
- Protects against future encryption vulnerabilities

**Solution Implemented:**
Set file permissions to 0600 (owner read/write only) for the encrypted storage file and 0700 for the parent directory.

**Implementation Summary:**

1. ✅ Added platform-specific file permission handling to `src/storage.rs`:
   - Added `use std::os::unix::fs::PermissionsExt` for Unix systems
   - Implemented `set_secure_permissions()` public method

2. ✅ Updated `save_entries()` in `src/storage.rs`:
   - Calls `set_secure_permissions()` immediately after file write
   - Sets file permissions to 0600 on Unix systems

3. ✅ Updated `get_storage_path()` in `src/main.rs`:
   - Sets directory permissions to 0700 on Unix systems
   - Ensures secure directory permissions when creating storage directory

4. ✅ Added comprehensive tests in `tests/storage_test.rs`:
   - `test_file_permissions_are_secure()` - Verifies file permissions are 0600
   - `test_directory_permissions_are_secure()` - Verifies directory permissions are 0700
   - `test_permissions_no_op_on_windows()` - Ensures Windows compatibility

**Files Modified:**
- `src/storage.rs` - Added permission setting functionality
- `src/main.rs` - Set directory permissions in get_storage_path()
- `tests/storage_test.rs` - Added permission verification tests

**Testing Results:**
- ✅ File permissions verified as 0600 after save on Unix systems
- ✅ Directory permissions verified as 0700 on Unix systems
- ✅ Functionality verified on Unix (no-op for Windows via conditional compilation)
- ✅ All existing tests pass (10 total tests)
- ✅ All new tests pass (3 new permission tests)

**Acceptance Criteria:**
- [x] File permissions set to 0600 on Unix systems after write
- [x] Directory permissions set to 0700 on Unix systems
- [x] No change in behavior on Windows
- [x] Tests verify correct permissions are set
- [x] All tests pass

**Priority:** 🟡 HIGH
**Estimated Effort:** 1-2 hours (Actual: ~1 hour)
**Labels:** security, enhancement, unix

**Resolution Date:** 2026-02-08

---

### Issue 4: ✅ Strengthen Argon2 Key Derivation Parameters (RESOLVED)

**Title:** Configure stronger Argon2 parameters for password manager use case

**Status:** ✅ **RESOLVED** - Implemented on 2026-02-08

**Description:**
The application now uses custom Argon2id parameters optimized for password manager use cases, replacing the default conservative parameters.

**Security Impact:**
- Medium severity
- Previous default parameters (~19 MiB memory, 2 iterations) were too weak for password manager use
- Strengthened parameters significantly increase resistance to brute-force attacks
- Balanced security with usability for good user experience

**Previous Parameters:**
- Memory: ~19 MiB
- Iterations: 2
- Parallelism: 4
- Algorithm: Argon2 (default variant)

**New Parameters (Implemented):**
- Memory: 32 MiB (32768 KiB)
- Iterations: 2
- Parallelism: 4
- Algorithm: Argon2id (hybrid mode, recommended variant)
- Version: V0x13 (latest)

**Implementation Details:**

The `derive_key()` function in `src/storage.rs` has been updated with:
- Custom Argon2id configuration with explicit parameters
- Enhanced security through increased memory cost (67% increase from ~19 MiB to 32 MiB)
- Algorithm upgrade to Argon2id (combines data-dependent and data-independent passes)
- Explicit version specification (V0x13 - latest with security improvements)

**Key Derivation Performance:**
- Measured time: ~869ms (on GitHub Actions CI runners - Ubuntu Linux)
- Expected range on typical hardware: 100ms-2000ms
- **Note**: Performance varies significantly by hardware - faster CPUs will see shorter times
- Balances security with user experience

**Security Benefits:**
1. **Increased Memory Cost**: 32 MiB makes parallel attacks more expensive
2. **Algorithm Upgrade**: Argon2id provides hybrid security (both data-dependent and data-independent)
3. **Version Guarantee**: Explicit V0x13 ensures latest security improvements
4. **Explicit Parameters**: No reliance on defaults that may change

**Backward Compatibility:**
- ✅ All existing tests pass
- ✅ Encrypted files created with new parameters can be decrypted
- ⚠️ Files encrypted with old default parameters cannot be decrypted with new implementation
- **Migration Note**: Users with existing password files will need to re-encrypt their data

**Testing:**
- ✅ Key derivation works correctly
- ✅ Key derivation time measured and verified (~869ms)
- ✅ All unit tests pass
- ✅ All integration tests pass
- ✅ New test added to verify derivation time remains reasonable

**Files Modified:**
- ✅ `src/storage.rs` - Updated derive_key() with custom Argon2id parameters
- ✅ Module documentation updated with new security parameters
- ✅ Function documentation enhanced with security rationale
- ✅ New test added for key derivation timing

**Acceptance Criteria:**
- ✅ Custom Argon2 parameters configured (32 MiB memory, 2 iterations, Argon2id)
- ✅ Key derivation time is reasonable (~869ms, within acceptable range)
- ⚠️ Backward compatibility note documented (old files need re-encryption)
- ✅ Documentation updated with security rationale
- ✅ All tests pass

**Priority:** 🟡 HIGH  
**Estimated Effort:** 2-3 hours  
**Actual Effort:** 2 hours  
**Labels:** security, enhancement, cryptography, resolved

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
- ✅ Added 14 unit tests covering various password scenarios
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
- [x] Rate limiting implemented with 5 attempts per 5 minutes
- [x] Lockout after exceeding max attempts (1 minute)
- [ ] Persistent tracking of attempts (survives restarts) - Not implemented (in-memory only for minimal security)
- [x] Clear user feedback about lockout status
- [x] Tests verify rate limiting behavior

**Status:** ✅ **COMPLETED** (Core functionality implemented)

**Implementation Notes:**
- Rate limiting uses in-memory tracking only (resets on app restart)
- This provides protection against online brute-force attacks during a single session
- Future enhancement: Add persistent tracking across app restarts for stronger protection

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
- [x] Audit logging implemented for security events
- [x] Logs stored in `~/.password_saver/audit.log`
- [x] Log entries include timestamp, event type, and result
- [x] Log integrity protected with HMAC
- [x] Log rotation implemented
- [x] Documentation added for audit log format

**Status:** ✅ **COMPLETED** (2026-02-08)

**Implementation Details:**
- Created `src/audit_log.rs` module with full audit logging functionality
- Logs stored at `~/.password_saver/audit.log`
- Each log entry includes timestamp, event type, success status, and optional details
- HMAC-SHA256 used for log integrity protection
- Size-based log rotation (10 MB threshold)
- Integrated logging into:
  - Application startup
  - File access operations
  - Encryption/decryption attempts (success/failure)
  - Password save/load operations
- Added comprehensive tests and documentation

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
- [x] Master password change functionality implemented
- [x] UI dialog for password change added
- [x] Password strength validation enforced
- [x] Old password verified before change
- [x] All data successfully re-encrypted
- [x] Comprehensive tests for edge cases
- [x] Documentation updated with password change instructions

**Priority:** 🔵 MEDIUM
**Estimated Effort:** 4-6 hours
**Labels:** security, enhancement, feature

**Status:** ✅ **RESOLVED**

**Resolution Date:** 2026-02-08

**Implementation Details:**
- Added `validate_password_strength()` function to enforce password requirements:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
- Added `change_master_password()` method to `PasswordStorage`:
  - Verifies old password by loading entries
  - Validates new password strength
  - Ensures new password differs from old
  - Re-encrypts all data with new password
- Added UI dialog with fields for current/new/confirm passwords
- Added comprehensive test coverage (5 test cases)
- All data successfully re-encrypted with new password
- Old password immediately invalidated after change

---

### Issue 9: ✅ Add Input Validation and Sanitization [RESOLVED]

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
- [x] Input validation module implemented
- [x] Length limits enforced for all inputs
- [x] Control characters rejected
- [x] Clear, user-friendly error messages
- [x] All existing functionality preserved
- [x] Comprehensive test coverage

**Status:** ✅ **RESOLVED** - PR #[number] (2026-02-08)

**Implementation Summary:**
- Created comprehensive validation module (`src/validation.rs`) with:
  - Length validation (title: 200, username: 500, password: 1000, master: 500 chars max)
  - Minimum master password length: 12 characters
  - Control character detection and rejection
  - User-friendly error messages
- Updated `src/main.rs` to validate all inputs before save/load operations
- Added 31 tests (21 unit tests + 10 integration tests)
- All tests passing, code formatted and linted

**Priority:** 🔵 LOW-MEDIUM
**Estimated Effort:** 2-3 hours
**Labels:** security, enhancement, ux

---

### Issue 10: ✅ Improve Error Messages for Security - COMPLETED

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

**Implementation Status:** ✅ **COMPLETED**

**What Was Done:**

1. ✅ Created `src/errors.rs` with SecurityError enum containing:
   - `AuthenticationFailed` - For wrong password or decryption failures
   - `InvalidInput` - For invalid user input
   - `StorageError` - For file I/O errors
   - `CryptographicError` - For encryption/hashing errors
   - `PermissionDenied` - For permission errors
   - `RateLimitExceeded` - For future rate limiting

2. ✅ Implemented `user_message()` method for generic, safe user-facing messages
3. ✅ Implemented `debug_message()` method for detailed developer/debugging information
4. ✅ Updated `src/storage.rs` to return `SecurityError` instead of `String`:
   - `derive_key()` returns `SecurityError::CryptographicError` on failures
   - `encrypt_data()` returns `SecurityError::CryptographicError` on failures
   - `decrypt_data()` returns `SecurityError::AuthenticationFailed` on failures
   - `save_entries()` returns appropriate errors for serialization, encryption, and I/O
   - `load_entries()` returns appropriate errors for reading, decryption, and deserialization

5. ✅ Updated `src/main.rs` to use generic error messages in UI:
   - Shows user-friendly messages via `e.user_message()`
   - Logs detailed errors to stderr via `e.debug_message()` using `eprintln!`

6. ✅ All existing tests pass with new error types
7. ✅ Added comprehensive unit tests for error types

**Acceptance Criteria:**
- [x] Structured error types implemented
- [x] User-facing messages are generic and safe
- [x] Detailed errors logged for debugging
- [x] No cryptographic details in user messages
- [x] All error paths tested
- [x] Documentation updated

**Examples of Sanitized Messages:**
- User sees: "Incorrect master password. Please try again."
- Developer logs: "AuthenticationFailed" with full context
- No exposure of: AES-GCM errors, Argon2 details, filesystem paths

**Priority:** 🔵 LOW
**Estimated Effort:** 2-3 hours
**Actual Effort:** ~2 hours
**Labels:** security, enhancement, code-quality

---

### Issue 11: ✅ Implement Timing Attack Protection for Password Verification

**Status:** ✅ COMPLETED

**Title:** Add constant-time comparison for password verification operations

**Description:**
Currently, password verification and comparison operations may be vulnerable to timing attacks. Attackers who can measure the time it takes to verify a password could potentially use statistical analysis to deduce information about the correct password. This is particularly relevant for master password verification where timing differences in Argon2 key derivation or AES-GCM decryption could leak information.

**Security Impact:**
- Low-Medium severity
- Timing side-channel could leak password information
- Requires local access or network proximity to measure timing
- Defense-in-depth principle - should be mitigated even if difficult to exploit

**Current Vulnerable Operations:**
1. Master password verification during load operations
2. Password comparison during master password change
3. Any string comparison of sensitive data

**Solution:**
Implement constant-time comparison operations for all password verification.

**Implementation Summary:**

1. ✅ Added `subtle = "2.6"` and `rand = "0.8"` dependencies to `Cargo.toml`
2. ✅ Implemented constant-time password comparison using `subtle::ConstantTimeEq` in `change_master_password()`
3. ✅ Added `add_timing_jitter()` helper function that introduces 1-10ms random delay
4. ✅ Integrated timing jitter into authentication paths:
   - `load_entries()` - jitter on both success and error paths
   - `change_master_password()` - jitter after password validation
5. ✅ Updated module documentation to include "Timing Attack Protection" in security properties
6. ✅ Added comprehensive tests:
   - `test_timing_attack_resistance_load_entries()` - verifies jitter is applied to authentication
   - `test_constant_time_password_comparison()` - validates constant-time comparison
   - `test_timing_jitter_is_applied()` - ensures timing variance exists

**Files Modified:**
- `Cargo.toml` - Added `subtle` and `rand` crate dependencies
- `src/storage.rs` - Implemented constant-time comparisons and timing jitter
- `tests/storage_test.rs` - Added timing attack resistance tests

**Testing:**
- ✅ Created tests that measure timing variance for correct vs incorrect passwords
- ✅ Verified timing jitter is applied to both success and failure paths
- ✅ Test that authentication operations include unpredictable delays
- ✅ Verified password comparison operations use constant-time functions

**Acceptance Criteria:**
- [x] `subtle` crate added to dependencies
- [x] All password comparisons use constant-time operations
- [x] Authentication operations have consistent timing with jitter
- [x] Timing jitter added to prevent precise measurements
- [x] Tests verify timing attack resistance
- [x] Documentation updated with timing attack considerations

**Priority:** 🔵 MEDIUM
**Estimated Effort:** 4-5 hours
**Actual Effort:** ~3 hours
**Labels:** security, enhancement, cryptography, timing-attacks

---

### Issue 12: 🔵 Implement Windows File Permissions

**Title:** Add secure file permissions for Windows platform

**Description:**
Currently, secure file permissions (0600/0700) are only implemented for Unix-like systems (macOS, Linux) using POSIX permissions. Windows systems use a different Access Control List (ACL) model that is not currently configured, potentially allowing other Windows users to read the encrypted password file.

**Security Impact:**
- Medium severity (Windows users only)
- Other Windows users on the same system could read encrypted files
- Defense-in-depth: encrypted data should also be protected at OS level
- Violates principle of least privilege

**Current State:**
- Unix/Linux: ✅ Secure permissions implemented (0600 for file, 0700 for directory)
- Windows: ❌ Default permissions used (potentially world-readable)

**Solution:**
Implement Windows ACL-based file permissions to restrict access to the current user only.

**Implementation Steps:**

1. Add Windows ACL dependency to `Cargo.toml`:
```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.52", features = ["Win32_Storage_FileSystem", "Win32_Security", "Win32_Foundation"] }
```

2. Create Windows-specific permission module `src/windows_permissions.rs`:
```rust
#[cfg(windows)]
pub fn set_windows_secure_permissions(path: &Path) -> Result<(), SecurityError> {
    use windows::Win32::Storage::FileSystem::*;
    use windows::Win32::Security::*;
    
    // Set ACL to allow access only to current user
    // Remove all other users and groups
    // This is the Windows equivalent of chmod 0600
    
    // Steps:
    // 1. Get current user SID
    // 2. Create new ACL with only current user having full control
    // 3. Remove BUILTIN\Users, BUILTIN\Administrators (except current user)
    // 4. Apply ACL to file
    
    Ok(())
}

#[cfg(windows)]
pub fn set_windows_directory_permissions(path: &Path) -> Result<(), SecurityError> {
    // Similar to file permissions, but for directory
    // Windows equivalent of chmod 0700
    Ok(())
}
```

3. Update `src/storage.rs` to call Windows permission functions:
```rust
#[cfg(windows)]
pub fn set_secure_permissions(path: &Path) -> Result<(), SecurityError> {
    use crate::windows_permissions::set_windows_secure_permissions;
    set_windows_secure_permissions(path)
}
```

4. Update `src/main.rs` directory creation with Windows permissions:
```rust
#[cfg(windows)]
{
    use crate::windows_permissions::set_windows_directory_permissions;
    let _ = set_windows_directory_permissions(parent);
}
```

5. Add comprehensive tests for Windows permissions:
```rust
#[test]
#[cfg(windows)]
fn test_windows_file_permissions_secure() {
    // Create file, set permissions, verify only current user can access
}

#[test]
#[cfg(windows)]
fn test_windows_directory_permissions_secure() {
    // Create directory, set permissions, verify access restrictions
}
```

**Files to Create:**
- `src/windows_permissions.rs` - Windows ACL permission handling

**Files to Modify:**
- `Cargo.toml` - Add Windows-specific dependencies
- `src/lib.rs` - Add windows_permissions module (conditional)
- `src/storage.rs` - Add Windows permission functions
- `src/main.rs` - Apply Windows directory permissions
- `tests/storage_test.rs` - Add Windows permission tests

**Testing:**
- Verify file is not accessible by other Windows users
- Verify directory is not accessible by other Windows users
- Test that standard Windows users cannot read the file
- Verify administrator can still access (this is Windows behavior)
- Test on different Windows versions (10, 11)

**Acceptance Criteria:**
- [ ] Windows ACL implementation for file permissions
- [ ] Windows ACL implementation for directory permissions
- [ ] Permissions applied automatically on save operations
- [ ] Only current user can read/write encrypted files on Windows
- [ ] Tests verify Windows permission security
- [ ] Documentation updated with Windows permission details
- [ ] Cross-platform compatibility maintained

**Priority:** 🟡 MEDIUM-HIGH (affects Windows users)
**Estimated Effort:** 6-8 hours
**Labels:** security, enhancement, windows, platform-specific

---

### Issue 13: 🔵 Implement Secure File Deletion

**Title:** Add secure overwriting of files before deletion

**Description:**
When password data is updated or the master password is changed, old encrypted files are simply deleted using standard file operations. On many filesystems (HDD, some SSD configurations), deleted file data can be recovered using forensic tools until the disk space is overwritten. This could expose old encrypted password data to forensic recovery attacks.

**Security Impact:**
- Low severity (data is encrypted)
- Old encrypted password data could be forensically recovered
- Defense-in-depth: even encrypted data should be securely deleted
- More relevant for HDDs than SSDs (due to wear-leveling)

**Current Behavior:**
- Old encrypted file is replaced with `std::fs::write()` 
- No secure overwriting before deletion
- Filesystem may leave old data in unallocated blocks

**Solution:**
Implement secure file deletion that overwrites data multiple times before removal.

**Implementation Steps:**

1. Add secure deletion crate to `Cargo.toml`:
```toml
[dependencies]
# Option 1: Use existing secure_delete crate
secure-delete = "0.1"

# Option 2: Implement custom secure deletion
```

2. Create secure deletion module `src/secure_delete.rs`:
```rust
use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use crate::errors::SecurityError;

/// Securely overwrites a file multiple times before deletion.
///
/// This implements a simple 3-pass overwrite:
/// 1. Overwrite with random data
/// 2. Overwrite with zeros
/// 3. Overwrite with random data
/// 4. Delete file
///
/// # Arguments
///
/// * `path` - Path to file to securely delete
///
/// # Security Notes
///
/// - Modern SSDs with wear-leveling may not actually overwrite the same physical blocks
/// - Encrypting the filesystem (LUKS, FileVault, BitLocker) provides better protection
/// - This provides defense-in-depth for HDDs and some SSD configurations
pub fn secure_delete_file(path: &Path) -> Result<(), SecurityError> {
    // Get file size
    let metadata = fs::metadata(path)
        .map_err(|e| SecurityError::storage_error(&format!("Failed to get file metadata: {}", e)))?;
    let file_size = metadata.len() as usize;
    
    // Open file for writing
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| SecurityError::storage_error(&format!("Failed to open file for secure deletion: {}", e)))?;
    
    // Pass 1: Overwrite with random data
    let random_data: Vec<u8> = (0..file_size).map(|_| rand::random::<u8>()).collect();
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&random_data)?;
    file.sync_all()?;
    
    // Pass 2: Overwrite with zeros
    let zero_data = vec![0u8; file_size];
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&zero_data)?;
    file.sync_all()?;
    
    // Pass 3: Overwrite with random data again
    let random_data2: Vec<u8> = (0..file_size).map(|_| rand::random::<u8>()).collect();
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&random_data2)?;
    file.sync_all()?;
    
    // Close file and delete
    drop(file);
    fs::remove_file(path)
        .map_err(|e| SecurityError::storage_error(&format!("Failed to delete file: {}", e)))?;
    
    Ok(())
}

/// Creates a backup copy before secure deletion for atomic updates
pub fn secure_update_file(path: &Path, new_data: &[u8]) -> Result<(), SecurityError> {
    let backup_path = path.with_extension("enc.backup");
    
    // If file exists, rename to backup
    if path.exists() {
        fs::rename(path, &backup_path)?;
    }
    
    // Write new data
    fs::write(path, new_data)?;
    
    // If backup exists, securely delete it
    if backup_path.exists() {
        secure_delete_file(&backup_path)?;
    }
    
    Ok(())
}
```

3. Update `src/storage.rs` to use secure deletion:
```rust
use crate::secure_delete::secure_update_file;

pub fn save_entries(&self, entries: &[PasswordEntry], master_password: &str) -> Result<(), SecurityError> {
    // Serialize, encrypt...
    
    // Use secure update instead of direct write
    secure_update_file(&self.storage_path, &encrypted_data_bytes)?;
    
    // Set permissions...
    Ok(())
}
```

4. Add configuration option for secure deletion:
```rust
pub struct SecureDeletionConfig {
    pub enabled: bool,
    pub passes: usize,  // Number of overwrite passes (1-7)
}

impl Default for SecureDeletionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            passes: 3,  // Balance between security and performance
        }
    }
}
```

**Files to Create:**
- `src/secure_delete.rs` - Secure file deletion implementation

**Files to Modify:**
- `Cargo.toml` - Add dependencies for secure deletion
- `src/lib.rs` - Add secure_delete module
- `src/storage.rs` - Use secure deletion for file updates
- `tests/` - Add tests for secure deletion

**Testing:**
- Test secure deletion completes successfully
- Test file is actually deleted after overwriting
- Verify overwrite passes are executed (check file size during operation)
- Test atomic updates (backup and restore on failure)
- Performance test: measure impact on save operations

**Acceptance Criteria:**
- [ ] Secure deletion module implemented with multi-pass overwrite
- [ ] Integrated into save_entries() for automatic use
- [ ] Atomic updates with backup/restore on failure
- [ ] Configurable number of overwrite passes
- [ ] Tests verify secure deletion behavior
- [ ] Documentation includes limitations (SSDs, encrypted filesystems)
- [ ] Performance impact documented

**Priority:** 🔵 LOW-MEDIUM
**Estimated Effort:** 5-6 hours
**Labels:** security, enhancement, filesystem

**Notes:**
- Modern SSDs with wear-leveling may not benefit from secure deletion
- Filesystem encryption (LUKS, FileVault, BitLocker) is more effective
- This provides defense-in-depth for systems without full disk encryption
- Consider making this optional via configuration

---

### Issue 14: 🔵 Add Session Timeout and Auto-Lock

**Title:** Implement automatic screen locking after inactivity period

**Description:**
Currently, the password manager application stays unlocked indefinitely once the master password is entered. If a user leaves their computer unattended, the application remains accessible to anyone with physical access. An auto-lock feature that requires re-entering the master password after a period of inactivity would significantly improve security.

**Security Impact:**
- Medium severity
- Unlocked application exposes all stored passwords
- Physical access security risk
- Common attack vector: unattended computer

**Current Behavior:**
- Application remains unlocked after authentication
- No automatic timeout or lock mechanism
- User must manually close application to "lock" passwords

**Solution:**
Implement session timeout with configurable inactivity period and auto-lock functionality.

**Implementation Steps:**

1. Create session management module `src/session.rs`:
```rust
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

pub struct SessionManager {
    last_activity: Arc<Mutex<Instant>>,
    timeout_duration: Duration,
    is_locked: Arc<Mutex<bool>>,
}

impl SessionManager {
    pub fn new(timeout_minutes: u64) -> Self {
        Self {
            last_activity: Arc::new(Mutex::new(Instant::now())),
            timeout_duration: Duration::from_secs(timeout_minutes * 60),
            is_locked: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Record user activity (resets timeout timer)
    pub fn record_activity(&self) {
        let mut last_activity = self.last_activity.lock().unwrap();
        *last_activity = Instant::now();
        
        // Unlock if locked
        let mut is_locked = self.is_locked.lock().unwrap();
        *is_locked = false;
    }
    
    /// Check if session should be locked due to inactivity
    pub fn should_lock(&self) -> bool {
        let last_activity = self.last_activity.lock().unwrap();
        let elapsed = Instant::now().duration_since(*last_activity);
        elapsed >= self.timeout_duration
    }
    
    /// Lock the session
    pub fn lock(&self) {
        let mut is_locked = self.is_locked.lock().unwrap();
        *is_locked = true;
    }
    
    /// Check if session is currently locked
    pub fn is_locked(&self) -> bool {
        *self.is_locked.lock().unwrap()
    }
    
    /// Get remaining time before auto-lock
    pub fn time_until_lock(&self) -> Duration {
        let last_activity = self.last_activity.lock().unwrap();
        let elapsed = Instant::now().duration_since(*last_activity);
        
        if elapsed >= self.timeout_duration {
            Duration::from_secs(0)
        } else {
            self.timeout_duration - elapsed
        }
    }
}
```

2. Update UI to show lock screen in `src/ui/main.slint`:
```slint
export component AppWindow inherits Window {
    // ... existing properties ...
    in-out property <bool> is-locked: false;
    in-out property <int> seconds-until-lock: 0;
    
    callback unlock(string);
    callback lock-session();
    
    // Lock screen overlay
    if root.is-locked : Rectangle {
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        
        Rectangle {
            width: 400px;
            height: 300px;
            background: white;
            border-radius: 8px;
            
            VerticalBox {
                padding: 30px;
                spacing: 20px;
                
                Text {
                    text: "🔒 Session Locked";
                    font-size: 24px;
                    horizontal-alignment: center;
                }
                
                Text {
                    text: "Enter master password to unlock";
                    horizontal-alignment: center;
                }
                
                unlock-password := LineEdit {
                    placeholder-text: "Master password";
                    input-type: password;
                }
                
                Button {
                    text: "Unlock";
                    primary: true;
                    clicked => {
                        root.unlock(unlock-password.text);
                        unlock-password.text = "";
                    }
                }
            }
        }
    }
    
    // Timer countdown display (when not locked)
    if !root.is-locked && root.seconds-until-lock > 0 : HorizontalBox {
        Text {
            text: "Auto-lock in: " + root.seconds-until-lock + "s";
            color: #666;
            font-size: 12px;
        }
    }
}
```

3. Integrate session management in `src/main.rs`:
```rust
use session::SessionManager;
use std::sync::Arc;

lazy_static! {
    static ref SESSION_MANAGER: Arc<SessionManager> = Arc::new(SessionManager::new(5)); // 5 minute timeout
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    
    // Start background thread to check for timeout
    let ui_weak = ui.as_weak();
    let session_manager = SESSION_MANAGER.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            
            if session_manager.should_lock() {
                session_manager.lock();
                
                // Update UI to show lock screen
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_is_locked(true);
                }
            }
            
            // Update countdown timer
            if let Some(ui) = ui_weak.upgrade() {
                let time_left = session_manager.time_until_lock();
                ui.set_seconds_until_lock(time_left.as_secs() as i32);
            }
        }
    });
    
    // Record activity on any user interaction
    ui.on_save_password(move |master_password, title, username, password| {
        SESSION_MANAGER.record_activity();
        // ... existing save logic ...
    });
    
    ui.on_load_passwords(move |master_password| {
        SESSION_MANAGER.record_activity();
        // ... existing load logic ...
    });
    
    // Handle unlock
    ui.on_unlock(move |password| {
        // Verify password by attempting to load entries
        // If successful, unlock session
        // If failed, show error and remain locked
    });
    
    ui.run()
}
```

4. Add configuration for timeout duration:
```rust
pub struct SessionConfig {
    pub timeout_minutes: u64,
    pub show_countdown: bool,
    pub lock_on_minimize: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_minutes: 5,  // 5 minutes default
            show_countdown: true,
            lock_on_minimize: false,
        }
    }
}
```

**Files to Create:**
- `src/session.rs` - Session management and timeout logic

**Files to Modify:**
- `src/lib.rs` - Add session module
- `src/main.rs` - Integrate session management with UI
- `src/ui/main.slint` - Add lock screen UI
- `Cargo.toml` - Add any threading dependencies if needed
- `tests/` - Add session timeout tests

**Testing:**
- Test session locks after configured timeout period
- Test user activity resets the timeout timer
- Verify locked session requires correct master password to unlock
- Test that incorrect password keeps session locked
- Verify countdown timer displays correctly
- Test edge case: timeout during active encryption operation

**Acceptance Criteria:**
- [ ] Session manager implemented with configurable timeout
- [ ] UI shows lock screen when session times out
- [ ] User activity resets timeout timer
- [ ] Locked session requires master password to unlock
- [ ] Countdown timer shows time remaining before lock (optional)
- [ ] Manual lock button added to UI
- [ ] Tests verify timeout and unlock behavior
- [ ] Configuration options for timeout duration
- [ ] Documentation updated with auto-lock feature

**Priority:** 🟡 MEDIUM
**Estimated Effort:** 6-8 hours
**Labels:** security, enhancement, ux, session-management

---

### Issue 15: ✅ Implement Clipboard Security and Auto-Clear

**Title:** Add clipboard clearing after password copy operations

**Description:**
Password managers typically provide functionality to copy passwords to the clipboard for easy pasting into login forms. However, clipboard data persists in system memory and can be accessed by any application. Sensitive password data should be automatically cleared from the clipboard after a short period to minimize exposure risk.

**Security Impact:**
- Medium severity
- Clipboard data accessible to any running application
- Password remains in clipboard indefinitely
- Malware or clipboard monitoring tools could capture passwords
- Cross-application information leakage

**Current Behavior:**
- Application does not currently have copy-to-clipboard functionality
- When implemented, clipboard should be automatically cleared

**Solution:**
Implement clipboard operations with automatic clearing after a configurable timeout period.

**Implementation Steps:**

1. Add clipboard dependency to `Cargo.toml`:
```toml
[dependencies]
copypasta = "0.10"  # Cross-platform clipboard access
# OR
arboard = "3.4"     # Alternative clipboard library
```

2. Create clipboard management module `src/clipboard.rs`:
```rust
use arboard::Clipboard;
use std::time::Duration;
use std::thread;

pub struct SecureClipboard {
    clipboard: Clipboard,
    clear_timeout: Duration,
}

impl SecureClipboard {
    pub fn new(clear_timeout_seconds: u64) -> Result<Self, String> {
        Ok(Self {
            clipboard: Clipboard::new().map_err(|e| format!("Failed to initialize clipboard: {}", e))?,
            clear_timeout: Duration::from_secs(clear_timeout_seconds),
        })
    }
    
    /// Copy text to clipboard and automatically clear after timeout
    pub fn copy_with_autoclear(&mut self, text: String) -> Result<(), String> {
        // Copy to clipboard
        self.clipboard.set_text(&text)
            .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;
        
        // Spawn thread to clear clipboard after timeout
        let clear_timeout = self.clear_timeout;
        let text_to_clear = text.clone();
        
        thread::spawn(move || {
            thread::sleep(clear_timeout);
            
            // Clear clipboard only if it still contains our text
            // This prevents clearing user's subsequent clipboard operations
            if let Ok(mut clipboard) = Clipboard::new() {
                if let Ok(current_content) = clipboard.get_text() {
                    if current_content == text_to_clear {
                        let _ = clipboard.set_text(""); // Clear clipboard
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Immediately clear clipboard
    pub fn clear(&mut self) -> Result<(), String> {
        self.clipboard.set_text("")
            .map_err(|e| format!("Failed to clear clipboard: {}", e))
    }
}

/// Configuration for clipboard security
pub struct ClipboardConfig {
    pub auto_clear_enabled: bool,
    pub clear_timeout_seconds: u64,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            auto_clear_enabled: true,
            clear_timeout_seconds: 30,  // Clear after 30 seconds
        }
    }
}
```

3. Add copy button to password display in `src/ui/main.slint`:
```slint
// In password display section:
HorizontalBox {
    spacing: 10px;
    
    Text {
        text: "Password: ********";
    }
    
    Button {
        text: "📋 Copy";
        clicked => {
            root.copy-password(password-value);
        }
    }
}
```

4. Integrate clipboard functionality in `src/main.rs`:
```rust
use clipboard::{SecureClipboard, ClipboardConfig};

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    
    // Initialize clipboard with 30-second auto-clear
    let clipboard_config = ClipboardConfig::default();
    let clipboard = SecureClipboard::new(clipboard_config.clear_timeout_seconds);
    
    // Handle copy password operation
    ui.on_copy_password(move |password| {
        match clipboard.copy_with_autoclear(password.to_string()) {
            Ok(()) => {
                ui.set_status_message(
                    format!("Password copied to clipboard (will auto-clear in {}s)", 
                            clipboard_config.clear_timeout_seconds).into()
                );
            }
            Err(e) => {
                ui.set_status_message(format!("Failed to copy password: {}", e).into());
            }
        }
    });
    
    ui.run()
}
```

5. Add visual feedback for clipboard operations:
```rust
// Show temporary notification when password is copied
// Show countdown timer until clipboard is cleared
```

**Files to Create:**
- `src/clipboard.rs` - Secure clipboard management

**Files to Modify:**
- `Cargo.toml` - Add clipboard dependency
- `src/lib.rs` - Add clipboard module
- `src/main.rs` - Integrate clipboard operations
- `src/ui/main.slint` - Add copy buttons to password display
- `tests/` - Add clipboard security tests

**Testing:**
- Test password is copied to clipboard successfully
- Verify clipboard is cleared after timeout period
- Test that clipboard is not cleared if user copies something else
- Test manual clipboard clear operation
- Verify cross-platform clipboard access (macOS, Linux, Windows)
- Test error handling for clipboard access failures

**Acceptance Criteria:**
- [x] Clipboard copy functionality implemented
- [x] Automatic clipboard clearing after configurable timeout (30s default)
- [x] UI shows copy functionality for passwords
- [x] Visual feedback when password is copied
- [ ] Countdown timer shows when clipboard will be cleared (not implemented - not critical for MVP)
- [ ] Manual "Clear Clipboard" button available (not implemented - auto-clear is sufficient)
- [x] Cross-platform clipboard support (macOS, Linux, Windows)
- [x] Tests verify clipboard security behavior
- [x] Configuration options for clipboard timeout
- [x] Documentation updated with clipboard security feature

**Priority:** 🟡 MEDIUM
**Estimated Effort:** 4-5 hours
**Labels:** security, enhancement, ux, clipboard

---

### Issue 16: ✅ Add Secure Password Generator (Completed)

**Title:** Implement cryptographically secure password generator

**Status:** ✅ COMPLETED

**Description:**
Users need to create strong, unique passwords for their accounts. A built-in password generator would improve security by making it easy to create high-entropy passwords that resist brute-force attacks. The generator should use cryptographically secure randomness and provide customizable options for password complexity.

**Security Impact:**
- Medium severity (missing security feature)
- Users may create weak passwords without a generator
- Strong generated passwords significantly improve account security
- Encourages use of unique passwords per account

**Current Behavior:**
- No password generation functionality
- Users must manually create passwords
- No guidance on password strength beyond validation

**Solution:**
Implement a password generator with customizable options and cryptographically secure randomness.

**Implementation Steps:**

1. Add password generation dependency to `Cargo.toml`:
```toml
[dependencies]
rand = "0.8"  # Cryptographically secure random number generation
```

2. Create password generator module `src/password_generator.rs`:
```rust
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

pub struct PasswordGeneratorConfig {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_digits: bool,
    pub use_special: bool,
    pub exclude_ambiguous: bool,  // Exclude O,0,I,l,1, etc.
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_digits: true,
            use_special: true,
            exclude_ambiguous: true,
        }
    }
}

pub fn generate_password(config: &PasswordGeneratorConfig) -> Result<String, String> {
    if config.length < 8 {
        return Err("Password length must be at least 8 characters".to_string());
    }
    
    if config.length > 128 {
        return Err("Password length must not exceed 128 characters".to_string());
    }
    
    // Build character set based on configuration
    let mut charset = String::new();
    
    if config.use_lowercase {
        if config.exclude_ambiguous {
            charset.push_str("abcdefghjkmnpqrstuvwxyz");  // Exclude i, l, o
        } else {
            charset.push_str("abcdefghijklmnopqrstuvwxyz");
        }
    }
    
    if config.use_uppercase {
        if config.exclude_ambiguous {
            charset.push_str("ABCDEFGHJKLMNPQRSTUVWXYZ");  // Exclude I, O
        } else {
            charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
    }
    
    if config.use_digits {
        if config.exclude_ambiguous {
            charset.push_str("23456789");  // Exclude 0, 1
        } else {
            charset.push_str("0123456789");
        }
    }
    
    if config.use_special {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
    }
    
    if charset.is_empty() {
        return Err("At least one character type must be selected".to_string());
    }
    
    let charset: Vec<char> = charset.chars().collect();
    let mut rng = thread_rng();
    
    // Generate password
    let password: String = (0..config.length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx]
        })
        .collect();
    
    // Ensure password contains at least one character from each selected type
    // If not, regenerate (recursive call with limit)
    if !validate_generated_password(&password, config) {
        return generate_password(config);
    }
    
    Ok(password)
}

fn validate_generated_password(password: &str, config: &PasswordGeneratorConfig) -> bool {
    if config.use_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return false;
    }
    if config.use_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return false;
    }
    if config.use_digits && !password.chars().any(|c| c.is_numeric()) {
        return false;
    }
    if config.use_special && !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
        return false;
    }
    true
}

/// Calculate entropy bits for a generated password
pub fn calculate_entropy(password: &str, charset_size: usize) -> f64 {
    let length = password.len() as f64;
    let charset_size = charset_size as f64;
    length * charset_size.log2()
}
```

3. Add password generator UI in `src/ui/main.slint`:
```slint
GroupBox {
    title: "Password Generator";
    
    VerticalBox {
        spacing: 10px;
        
        HorizontalBox {
            Text {
                text: "Length:";
                min-width: 100px;
            }
            length-slider := Slider {
                minimum: 8;
                maximum: 32;
                value: 16;
            }
            Text {
                text: length-slider.value;
            }
        }
        
        HorizontalBox {
            CheckBox {
                text: "Uppercase (A-Z)";
                checked: true;
            }
            CheckBox {
                text: "Lowercase (a-z)";
                checked: true;
            }
        }
        
        HorizontalBox {
            CheckBox {
                text: "Digits (0-9)";
                checked: true;
            }
            CheckBox {
                text: "Special (!@#$...)";
                checked: true;
            }
        }
        
        HorizontalBox {
            CheckBox {
                text: "Exclude ambiguous (0,O,l,1)";
                checked: true;
            }
        }
        
        HorizontalBox {
            generated-password-display := LineEdit {
                placeholder-text: "Generated password will appear here";
                read-only: true;
            }
            
            Button {
                text: "🔄 Generate";
                clicked => {
                    root.generate-password();
                }
            }
            
            Button {
                text: "📋 Copy";
                enabled: generated-password-display.text != "";
                clicked => {
                    root.copy-generated-password(generated-password-display.text);
                }
            }
            
            Button {
                text: "✓ Use";
                enabled: generated-password-display.text != "";
                clicked => {
                    root.use-generated-password(generated-password-display.text);
                }
            }
        }
        
        // Entropy display
        Text {
            text: "Entropy: XX bits (Very Strong)";
            font-size: 12px;
            color: #4caf50;
        }
    }
}
```

4. Integrate generator in `src/main.rs`:
```rust
use password_generator::{generate_password, PasswordGeneratorConfig, calculate_entropy};

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    
    ui.on_generate_password(move || {
        let config = PasswordGeneratorConfig {
            length: /* get from UI slider */,
            use_uppercase: /* get from UI checkbox */,
            // ... other options from UI
            ..Default::default()
        };
        
        match generate_password(&config) {
            Ok(password) => {
                ui.set_generated_password(password.into());
                
                // Calculate and display entropy
                let charset_size = calculate_charset_size(&config);
                let entropy = calculate_entropy(&password, charset_size);
                ui.set_password_entropy(format!("{:.1} bits", entropy).into());
            }
            Err(e) => {
                ui.set_status_message(format!("Password generation failed: {}", e).into());
            }
        }
    });
    
    ui.on_use_generated_password(move |password| {
        // Auto-fill password field with generated password
        ui.set_password_input(password);
    });
    
    ui.run()
}
```

**Files to Create:**
- `src/password_generator.rs` - Password generation logic

**Files to Modify:**
- `Cargo.toml` - Add `rand` dependency if not already present
- `src/lib.rs` - Add password_generator module
- `src/main.rs` - Integrate password generator
- `src/ui/main.slint` - Add password generator UI
- `tests/` - Add password generator tests

**Testing:**
- Test generated passwords meet specified criteria
- Verify cryptographic randomness (statistical tests)
- Test all character set combinations
- Verify minimum length enforcement
- Test exclusion of ambiguous characters
- Verify entropy calculations
- Test edge cases (min/max length, single character type)

**Acceptance Criteria:**
- [x] Password generator implemented with customizable options
- [x] Cryptographically secure random number generation (using `rand::thread_rng()`)
- [x] UI for configuring generator options (length, character types)
- [x] Generated password displayed with entropy calculation
- [x] Copy and use buttons for generated passwords
- [x] Exclusion of ambiguous characters (optional)
- [x] Tests verify password generation quality (18 comprehensive tests)
- [x] Documentation with usage examples

**Implementation Summary:**
- Created `src/password_generator.rs` module with full password generation functionality
- Added comprehensive test suite in `tests/password_generator_test.rs`
- Integrated UI components in `src/ui/main.slint` with configurable options
- Implemented callbacks in `src/main.rs` for password generation, copying, and using generated passwords
- All tests pass (100 unit tests + 18 integration tests)
- Code quality verified with cargo fmt and clippy

**Priority:** ✅ COMPLETED
**Estimated Effort:** 4-6 hours (Actual: ~4 hours)
**Labels:** security, enhancement, ux, password-generation

---

### Issue 17: ✅ Implement Backup and Export with Encryption - IMPLEMENTED

**Status:** ✅ **IMPLEMENTED** - Completed in current version

**Implementation Summary:**
- ✅ Created `src/backup.rs` module with `BackupManager` struct
- ✅ Implemented encrypted backup creation with master password
- ✅ Implemented export with different password for secure sharing
- ✅ Implemented import with automatic duplicate detection and merging
- ✅ Implemented backup listing functionality
- ✅ Added comprehensive test coverage (7 tests, all passing)
- ✅ All operations use Argon2 + AES-256-GCM encryption (same as main storage)

**Title:** Add encrypted backup and export functionality

**Description:**
Users need the ability to create encrypted backups of their password database for disaster recovery. Additionally, export functionality would allow migration to other password managers or devices. Both operations must maintain security by encrypting exports with a password or key.

**Security Impact:**
- Medium severity (missing critical feature)
- No backup = risk of total data loss
- Export without encryption = potential data exposure
- Users cannot easily migrate to other devices

**Current Behavior:**
- No backup functionality
- No export functionality
- Users must manually copy `~/.password_saver/passwords.enc`
- No import from other sources

**Solution:**
Implement encrypted backup/export and secure import functionality.

**Implementation Steps:**

1. Create backup module `src/backup.rs`:
```rust
use crate::storage::{PasswordStorage, PasswordEntry};
use crate::errors::SecurityError;
use serde::{Serialize, Deserialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct PasswordBackup {
    pub version: String,  // Backup format version
    pub created_at: u64,  // Timestamp
    pub hostname: String, // Device identifier
    pub entries: Vec<PasswordEntry>,
}

pub struct BackupManager {
    storage: PasswordStorage,
}

impl BackupManager {
    pub fn new(storage: PasswordStorage) -> Self {
        Self { storage }
    }
    
    /// Create encrypted backup file
    pub fn create_backup(
        &self,
        master_password: &str,
        backup_path: &Path,
    ) -> Result<(), SecurityError> {
        // Load current entries
        let entries = self.storage.load_entries(master_password)?;
        
        // Create backup structure
        let backup = PasswordBackup {
            version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            hostname: hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string()),
            entries,
        };
        
        // Serialize and encrypt using same method as main storage
        let backup_storage = PasswordStorage::new(backup_path.to_path_buf());
        backup_storage.save_entries(&backup.entries, master_password)?;
        
        Ok(())
    }
    
    /// Export to JSON format (encrypted)
    pub fn export_encrypted(
        &self,
        master_password: &str,
        export_password: &str,
        export_path: &Path,
    ) -> Result<(), SecurityError> {
        // Load entries with master password
        let entries = self.storage.load_entries(master_password)?;
        
        // Export encrypted with different password (allows secure sharing)
        let export_storage = PasswordStorage::new(export_path.to_path_buf());
        export_storage.save_entries(&entries, export_password)?;
        
        Ok(())
    }
    
    /// Import from backup or export file
    pub fn import_from_file(
        &self,
        import_path: &Path,
        import_password: &str,
        master_password: &str,
    ) -> Result<usize, SecurityError> {
        // Load entries from import file
        let import_storage = PasswordStorage::new(import_path.to_path_buf());
        let imported_entries = import_storage.load_entries(import_password)?;
        
        // Load current entries (if any)
        let mut current_entries = if self.storage.exists() {
            self.storage.load_entries(master_password)?
        } else {
            Vec::new()
        };
        
        // Merge imported entries (check for duplicates by title)
        let mut import_count = 0;
        for entry in imported_entries {
            if !current_entries.iter().any(|e| e.title == entry.title) {
                current_entries.push(entry);
                import_count += 1;
            }
        }
        
        // Save merged entries
        self.storage.save_entries(&current_entries, master_password)?;
        
        Ok(import_count)
    }
    
    /// List available backups in backup directory
    pub fn list_backups(backup_dir: &Path) -> Result<Vec<PathBuf>, SecurityError> {
        let mut backups = Vec::new();
        
        if !backup_dir.exists() {
            return Ok(backups);
        }
        
        for entry in fs::read_dir(backup_dir)
            .map_err(|e| SecurityError::storage_error(&format!("Failed to read backup directory: {}", e)))?
        {
            let entry = entry.map_err(|e| SecurityError::storage_error(&format!("Failed to read directory entry: {}", e)))?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("bak") {
                backups.push(path);
            }
        }
        
        // Sort by modification time (newest first)
        backups.sort_by(|a, b| {
            let a_time = fs::metadata(a).and_then(|m| m.modified()).ok();
            let b_time = fs::metadata(b).and_then(|m| m.modified()).ok();
            b_time.cmp(&a_time)
        });
        
        Ok(backups)
    }
}
```

2. Add backup UI in `src/ui/main.slint`:
```slint
// Add to main menu or toolbar
Button {
    text: "💾 Backup";
    clicked => {
        root.show-backup-dialog = true;
    }
}

Button {
    text: "📥 Import";
    clicked => {
        root.show-import-dialog = true;
    }
}

// Backup dialog
if root.show-backup-dialog : Rectangle {
    // ... dialog UI for backup/export options
    VerticalBox {
        Text { text: "Create Backup"; }
        
        LineEdit {
            placeholder-text: "Backup filename";
        }
        
        Button {
            text: "Create Backup";
            clicked => {
                root.create-backup();
            }
        }
        
        Button {
            text: "Export (with different password)";
            clicked => {
                root.export-encrypted();
            }
        }
    }
}
```

3. Integrate backup functionality in `src/main.rs`:
```rust
use backup::BackupManager;

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let storage_path = get_storage_path();
    
    ui.on_create_backup(move |master_password, backup_filename| {
        let storage = PasswordStorage::new(storage_path.clone());
        let backup_manager = BackupManager::new(storage);
        
        let backup_dir = storage_path.parent().unwrap().join("backups");
        fs::create_dir_all(&backup_dir)?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let backup_path = backup_dir.join(format!("passwords_backup_{}.bak", timestamp));
        
        match backup_manager.create_backup(&master_password, &backup_path) {
            Ok(()) => {
                ui.set_status_message(format!("Backup created: {}", backup_path.display()).into());
            }
            Err(e) => {
                ui.set_status_message(format!("Backup failed: {}", e.user_message()).into());
            }
        }
    });
    
    ui.on_import_from_backup(move |master_password, import_path, import_password| {
        let storage = PasswordStorage::new(storage_path.clone());
        let backup_manager = BackupManager::new(storage);
        
        match backup_manager.import_from_file(&import_path, &import_password, &master_password) {
            Ok(count) => {
                ui.set_status_message(format!("Imported {} password entries", count).into());
            }
            Err(e) => {
                ui.set_status_message(format!("Import failed: {}", e.user_message()).into());
            }
        }
    });
    
    ui.run()
}
```

4. Add automatic periodic backups:
```rust
pub struct AutoBackupConfig {
    pub enabled: bool,
    pub interval_days: u64,
    pub max_backups: usize,  // Keep only N most recent backups
}

impl Default for AutoBackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_days: 7,  // Weekly backups
            max_backups: 5,    // Keep 5 most recent
        }
    }
}
```

**Files to Create:**
- `src/backup.rs` - Backup and export functionality

**Files to Modify:**
- `src/lib.rs` - Add backup module
- `src/main.rs` - Integrate backup operations
- `src/ui/main.slint` - Add backup/import UI
- `tests/` - Add backup/import tests

**Testing:**
- Test backup creation with correct password
- Test backup restore functionality
- Test export with different password
- Test import merges entries correctly
- Verify duplicate detection works
- Test backup listing and cleanup
- Test automatic backup scheduling

**Acceptance Criteria:**
- [x] Backup creation with encryption
- [x] Export with different password option
- [x] Import from backup or export files
- [x] Duplicate detection during import
- [ ] UI for backup/import operations (planned for future)
- [ ] Automatic periodic backups (optional, planned for future)
- [x] Backup file management (list, delete old backups)
- [x] Tests verify backup integrity
- [x] Documentation with backup procedures

**Priority:** 🟡 MEDIUM-HIGH
**Estimated Effort:** 6-8 hours
**Labels:** security, enhancement, backup, disaster-recovery

---

### Issue 18: ✅ Add Database Integrity Verification - COMPLETED

**Title:** Implement database corruption detection and integrity checks

**Status:** ✅ **COMPLETED** (2026-02-12)

**Description:**
Storage corruption can occur due to filesystem errors, incomplete writes, or malicious tampering. The application should detect and report database integrity issues before attempting to decrypt or use corrupted data. This provides early warning of potential data loss and security compromises.

**Security Impact:**
- Low-Medium severity
- Corrupted database could expose partial data
- Malicious tampering might go undetected beyond GCM authentication
- Data loss risk from silent corruption

**Current Security:**
- ✅ AES-GCM provides authentication (detects tampering of encrypted data)
- ✅ Detection of file truncation or incomplete writes
- ✅ Corruption checks before decryption attempt
- ✅ Warning signs of corruption before user loses data

**Solution:**
Add database integrity verification with checksums and corruption detection.

**Implementation Summary:**

**Files Created:**
- `src/integrity.rs` - Complete database integrity verification module (600+ lines)

**Files Modified:**
- `src/lib.rs` - Added integrity module export
- `src/storage.rs` - Integrated integrity checks into load_entries()
- `src/main.rs` - Added automatic startup integrity check with user warnings
- `Cargo.toml` - Added tempfile dev-dependency for tests

**Implementation Details:**

1. ✅ **Integrity Verification Module** (`src/integrity.rs`):
   - `IntegrityChecker` struct with SHA-256 checksum support
   - `CorruptionReport` struct with detailed health indicators
   - Checks for JSON validity
   - Validates presence of required fields (salt, nonce, `encrypted_data`)
   - Detects file truncation (files < 100 bytes flagged as suspicious)
   - Detects null bytes (corruption indicator)
   - 15 comprehensive unit tests

2. ✅ **Storage Integration** (`src/storage.rs`):
   - Added `verify_integrity()` method to `PasswordStorage`
   - Automatic integrity check at the start of `load_entries()`
   - Returns `SecurityError::CryptographicError` for corrupted databases
   - Logs detected issues with warning level

3. ✅ **Startup Integrity Check** (`src/main.rs`):
   - Automatic integrity verification on application startup
   - User-facing warning messages when corruption detected
   - Non-blocking checks (continues even if warnings are shown)
   - Detailed issue reporting to users

4. ✅ **Comprehensive Testing**:
   - 15 unit tests for integrity module
   - Test healthy database detection
   - Test truncated file detection
   - Test invalid JSON detection
   - Test missing field detection
   - Test null byte detection
   - Test checksum calculation and verification
   - All 339 total tests passing

**Security Benefits:**
- Early detection of database corruption before decryption
- Protection against incomplete writes and filesystem errors
- Additional layer of tamper detection beyond AES-GCM
- User warnings prevent data loss scenarios
- Comprehensive health checks for common corruption patterns

**Acceptance Criteria:**
- [x] Integrity checker module implemented
- [x] Automatic integrity check on database load
- [x] Corruption detection for common issues
- [x] SHA-256 checksum calculation
- [x] Startup integrity check with warning display
- [x] Tests verify corruption detection (15 tests)
- [x] Documentation with detailed comments
- [x] All linting and formatting checks pass

**Note on UI:**
Manual integrity verification UI button was not added as the automatic checks (on load and startup) provide sufficient coverage. A manual UI can be added in a future enhancement if users request it.

**Priority:** 🔵 MEDIUM → ✅ RESOLVED
**Estimated Effort:** 4-5 hours
**Actual Effort:** ~3 hours
**Labels:** security, enhancement, reliability, data-integrity, resolved

---

### Issue 19: ✅ Implement Password Search and Filtering [COMPLETED]

**Title:** Add secure search functionality with protection against information leakage

**Status:** ✅ **COMPLETED** (2026-02-12)

**Description:**
As users accumulate many password entries, they need efficient search and filtering capabilities to quickly find specific passwords. However, search functionality must be implemented securely to avoid timing attacks or information leakage through search patterns. This is both a security and usability feature.

**Security Impact:**
- Low severity (security through usability)
- Poor search UX leads to password reuse or weak passwords
- Search timing could leak information about password count
- Improves security by making password manager more practical to use

**Implementation Summary:**
✅ Created `src/search.rs` module with search and sorting functionality
✅ Integrated search callbacks in `src/main.rs` with secure implementation
✅ Added search UI in `src/ui/main.slint` with search input and sort buttons
✅ Implemented comprehensive test suite (14 tests, all passing)
✅ All tests pass, build succeeds, clippy checks pass

**Features Implemented:**
- ✅ Search functionality with case-insensitive search by default
- ✅ Search across title and username fields
- ✅ Sorting by multiple criteria (Title A-Z, Title Z-A, Newest, Oldest, Username)
- ✅ Real-time search results (as user types)
- ✅ Display match count and total count
- ✅ Clear search button
- ✅ Comprehensive test coverage

**Files Created:**
- `src/search.rs` - Search and filtering logic with 14 unit tests

**Files Modified:**
- `src/lib.rs` - Added search module export
- `src/main.rs` - Integrated search functionality with callbacks
- `src/ui/main.slint` - Added search UI components

**Security Considerations:**
- Returns indices rather than copying entries to avoid timing attacks
- No information leakage through search patterns
- Search query sanitization handled by existing validation layer
- Constant-time comparison for sensitive operations maintained

**Acceptance Criteria:**
- [x] Search functionality implemented
- [x] Case-sensitive and case-insensitive options (case-insensitive by default)
- [x] Search across title and username fields
- [x] Sorting by multiple criteria (5 options available)
- [x] Real-time search results (as user types)
- [x] Display match count and total count
- [x] Clear search button
- [x] Tests verify search accuracy (14 tests, all passing)
- [x] Documentation with search usage (inline documentation added)

**Priority:** 🔵 MEDIUM
**Estimated Effort:** 4-5 hours
**Actual Effort:** ~4 hours
**Labels:** security, enhancement, ux, usability

---

### Issue 20: ✅ Add Security Update and Version Check [COMPLETED]

**Title:** Implement automatic security update notifications

**Status:** ✅ **COMPLETED** - Update notification feature fully implemented and tested.

**Description:**
Users should be notified when security updates or new versions are available. This ensures users stay protected against newly discovered vulnerabilities and benefit from security improvements. The check should be privacy-preserving and not leak usage information.

**Implementation Summary:**
- Created `src/update_checker.rs` module with privacy-preserving version checking
- Added update notification UI banner and manual check button in Slint UI
- Integrated automatic startup check and manual update checking in main.rs
- Implemented semantic version comparison using semver crate
- Added security release detection based on release notes keywords
- All tests passing, clippy clean, fully documented

**Security Impact:**
- Medium severity (user awareness)
- Users may run outdated versions with known vulnerabilities
- No notification of critical security patches
- Manual update checking is inconvenient

**Current Behavior:**
- ✅ Automatic version check on startup (2-second delay, non-blocking)
- ✅ Manual "Check for Updates" button in UI
- ✅ Visual notification banner for available updates (dismissible)
- ✅ Prominent orange warning for security updates vs. blue info for regular updates
- ✅ Direct link to GitHub release page
- ✅ Privacy-preserving (only GitHub API GET request, no telemetry)

**Solution:**
Implement privacy-preserving version check with security update notifications.

**Implementation Steps:**

1. Create version check module `src/update_checker.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionInfo {
    pub latest_version: String,
    pub release_date: String,
    pub security_update: bool,
    pub download_url: String,
    pub changelog_url: String,
}

pub struct UpdateChecker {
    current_version: String,
    check_url: String,
}

impl UpdateChecker {
    pub fn new() -> Self {
        Self {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            check_url: "https://api.github.com/repos/obstreperous-ai/rust-slint-password-saver/releases/latest".to_string(),
        }
    }
    
    /// Check for updates (privacy-preserving - no telemetry)
    pub async fn check_for_updates(&self) -> Result<Option<VersionInfo>, String> {
        // Make HTTP request to GitHub API
        // Parse release information
        // Compare versions
        // Return update info if newer version available
        
        // Example implementation:
        // let response = reqwest::get(&self.check_url).await?;
        // let release: GitHubRelease = response.json().await?;
        // 
        // if is_newer_version(&release.tag_name, &self.current_version) {
        //     return Ok(Some(VersionInfo {
        //         latest_version: release.tag_name,
        //         security_update: is_security_release(&release),
        //         ...
        //     }));
        // }
        
        Ok(None)
    }
    
    /// Parse version string and compare
    fn is_newer_version(latest: &str, current: &str) -> bool {
        // Parse semantic version (e.g., "v1.2.3")
        // Compare major.minor.patch
        semver::Version::parse(latest.trim_start_matches('v'))
            .and_then(|latest_ver| {
                semver::Version::parse(current.trim_start_matches('v'))
                    .map(|current_ver| latest_ver > current_ver)
            })
            .unwrap_or(false)
    }
    
    /// Check if release contains security fixes
    fn is_security_release(release: &GitHubRelease) -> bool {
        let body_lower = release.body.to_lowercase();
        body_lower.contains("security") 
            || body_lower.contains("vulnerability")
            || body_lower.contains("cve")
    }
}

pub struct UpdateCheckConfig {
    pub enabled: bool,
    pub check_interval_days: u64,
    pub notify_security_only: bool,
}

impl Default for UpdateCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_days: 7,  // Check weekly
            notify_security_only: false,
        }
    }
}
```

2. Add update notification UI in `src/ui/main.slint`:
```slint
// Update notification banner
if root.update-available : Rectangle {
    background: root.is-security-update ? #ff9800 : #2196f3;
    
    HorizontalBox {
        padding: 10px;
        
        Text {
            text: root.is-security-update ? 
                "⚠️ Security Update Available: " + root.latest-version :
                "ℹ️ New Version Available: " + root.latest-version;
            color: white;
        }
        
        Button {
            text: "View Release";
            clicked => {
                root.open-release-page();
            }
        }
        
        Button {
            text: "Dismiss";
            clicked => {
                root.update-available = false;
            }
        }
    }
}

// Manual update check button
Button {
    text: "Check for Updates";
    clicked => {
        root.check-for-updates();
    }
}
```

3. Integrate update checking in `src/main.rs`:
```rust
use update_checker::{UpdateChecker, UpdateCheckConfig};

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    
    // Check for updates on startup (non-blocking)
    let ui_weak = ui.as_weak();
    std::thread::spawn(move || {
        let checker = UpdateChecker::new();
        
        match checker.check_for_updates() {
            Ok(Some(update_info)) => {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_update_available(true);
                    ui.set_latest_version(update_info.latest_version.into());
                    ui.set_is_security_update(update_info.security_update);
                    ui.set_download_url(update_info.download_url.into());
                }
            }
            Ok(None) => {
                // No update available
            }
            Err(e) => {
                warn!("Failed to check for updates: {}", e);
            }
        }
    });
    
    // Manual update check
    ui.on_check_for_updates(move || {
        // Trigger update check...
    });
    
    ui.on_open_release_page(move || {
        // Open browser to release page
        let url = ui.get_download_url();
        let _ = webbrowser::open(&url);
    });
    
    ui.run()
}
```

4. Add privacy-preserving telemetry option:
```rust
// Optional: Anonymous usage statistics (opt-in only)
pub struct TelemetryConfig {
    pub enabled: bool,  // Default: false (opt-in)
    pub anonymous_id: String,  // Random UUID, not linked to user
}
```

**Files to Create:**
- `src/update_checker.rs` - Version checking logic

**Files to Modify:**
- `Cargo.toml` - Add dependencies (reqwest, semver)
- `src/lib.rs` - Add update_checker module
- `src/main.rs` - Integrate update checking
- `src/ui/main.slint` - Add update notification UI
- `tests/` - Add version comparison tests

**Testing:**
- Test version comparison logic
- Test security release detection
- Test update notification display
- Test manual update check
- Test privacy (no user data sent)
- Test offline mode (graceful failure)

**Acceptance Criteria:**
- [x] Automatic update check on startup
- [x] Manual "Check for Updates" button
- [x] Visual notification for available updates
- [x] Prominent warning for security updates
- [x] Link to release notes and download
- [x] Privacy-preserving (no user data sent)
- [x] Configurable check interval (API available, not yet used in UI)
- [x] Tests verify version comparison
- [x] Documentation with privacy policy

**Priority:** 🔵 MEDIUM
**Estimated Effort:** 5-6 hours
**Actual Effort:** ~4 hours
**Labels:** security, enhancement, updates, maintenance

---

### Issue 21: 🔵 Implement Emergency Access and Account Recovery

**Title:** Add emergency access mechanism for account recovery

**Description:**
Users may lose access to their password database due to forgotten master passwords, corrupted files, or other emergencies. An emergency recovery mechanism would help users regain access while maintaining security. This could include recovery codes, backup questions, or split-key recovery.

**Security Impact:**
- Medium severity (availability vs security tradeoff)
- Lost master password = complete data loss
- No recovery mechanism forces users to write down master passwords
- Recovery mechanism must not weaken overall security

**Current Behavior:**
- No recovery mechanism
- Forgotten master password = permanent data loss
- No emergency access options

**Solution:**
Implement secure emergency recovery using recovery codes or split-key approach.

**Implementation Steps:**

1. Create recovery module `src/recovery.rs`:
```rust
use rand::Rng;
use sha2::{Sha256, Digest};

pub struct RecoveryCode {
    code: String,
    hash: String,  // Hash of code for verification
}

impl RecoveryCode {
    /// Generate cryptographically secure recovery code
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        
        // Generate 6 words from word list (like BIP39)
        // Or 12-16 random characters
        let code = (0..16)
            .map(|_| {
                let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
                let idx = rng.gen_range(0..chars.len());
                chars.chars().nth(idx).unwrap()
            })
            .collect::<String>();
        
        // Format as XXXX-XXXX-XXXX-XXXX
        let formatted = format!(
            "{}-{}-{}-{}",
            &code[0..4],
            &code[4..8],
            &code[8..12],
            &code[12..16]
        );
        
        // Hash for verification
        let mut hasher = Sha256::new();
        hasher.update(formatted.as_bytes());
        let hash = hex::encode(hasher.finalize());
        
        Self {
            code: formatted,
            hash,
        }
    }
    
    /// Verify recovery code matches hash
    pub fn verify(&self, input: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let input_hash = hex::encode(hasher.finalize());
        
        input_hash == self.hash
    }
}

pub struct EmergencyRecovery {
    recovery_codes: Vec<RecoveryCode>,
    recovery_master_key: Option<Vec<u8>>,
}

impl EmergencyRecovery {
    /// Create emergency recovery during initial setup
    pub fn create(master_password: &str) -> Self {
        // Generate recovery codes
        let codes: Vec<RecoveryCode> = (0..3).map(|_| RecoveryCode::generate()).collect();
        
        // Derive recovery key from recovery codes
        // This key can decrypt the database if master password is lost
        let recovery_master_key = derive_recovery_key(&codes);
        
        Self {
            recovery_codes: codes,
            recovery_master_key: Some(recovery_master_key),
        }
    }
    
    /// Verify recovery code and provide access
    pub fn recover_access(&self, code: &str) -> Result<Vec<u8>, String> {
        // Verify code matches one of the recovery codes
        if self.recovery_codes.iter().any(|rc| rc.verify(code)) {
            self.recovery_master_key.clone()
                .ok_or_else(|| "No recovery key available".to_string())
        } else {
            Err("Invalid recovery code".to_string())
        }
    }
}

fn derive_recovery_key(codes: &[RecoveryCode]) -> Vec<u8> {
    // Combine recovery codes to derive key
    // Use KDF to generate recovery key
    let combined = codes.iter()
        .map(|c| c.code.as_str())
        .collect::<Vec<&str>>()
        .join("");
    
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    hasher.finalize().to_vec()
}
```

2. Add recovery setup UI in `src/ui/main.slint`:
```slint
// First-time setup: show recovery codes
if root.show-recovery-setup : Rectangle {
    VerticalBox {
        Text {
            text: "⚠️ Important: Save Your Recovery Codes";
            font-size: 20px;
            font-weight: 700;
        }
        
        Text {
            text: "Write down these recovery codes and store them securely.\nYou will need them if you forget your master password.";
        }
        
        // Display recovery codes
        Rectangle {
            background: #f5f5f5;
            border-radius: 4px;
            
            VerticalBox {
                padding: 20px;
                
                Text {
                    text: "Recovery Code 1: " + root.recovery-code-1;
                    font-family: "monospace";
                }
                Text {
                    text: "Recovery Code 2: " + root.recovery-code-2;
                    font-family: "monospace";
                }
                Text {
                    text: "Recovery Code 3: " + root.recovery-code-3;
                    font-family: "monospace";
                }
            }
        }
        
        HorizontalBox {
            Button {
                text: "📋 Copy All Codes";
                clicked => {
                    root.copy-recovery-codes();
                }
            }
            
            Button {
                text: "🖨️ Print Codes";
                clicked => {
                    root.print-recovery-codes();
                }
            }
        }
        
        CheckBox {
            text: "I have saved my recovery codes in a secure location";
            checked <=> root.recovery-codes-confirmed;
        }
        
        Button {
            text: "Continue";
            enabled: root.recovery-codes-confirmed;
            primary: true;
            clicked => {
                root.show-recovery-setup = false;
            }
        }
    }
}

// Recovery mode login
if root.show-recovery-login : Rectangle {
    VerticalBox {
        Text {
            text: "Emergency Recovery";
            font-size: 20px;
        }
        
        Text {
            text: "Enter one of your recovery codes to regain access:";
        }
        
        recovery-code-input := LineEdit {
            placeholder-text: "XXXX-XXXX-XXXX-XXXX";
        }
        
        Button {
            text: "Recover Access";
            clicked => {
                root.recover-with-code(recovery-code-input.text);
            }
        }
    }
}
```

3. Integrate recovery in `src/main.rs`:
```rust
use recovery::{EmergencyRecovery, RecoveryCode};

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let storage_path = get_storage_path();
    let storage = PasswordStorage::new(storage_path);
    
    // On first use: generate and display recovery codes
    if !storage.exists() {
        let recovery = EmergencyRecovery::create(&master_password);
        
        // Display recovery codes to user
        ui.set_show_recovery_setup(true);
        ui.set_recovery_code_1(recovery.recovery_codes[0].code.clone().into());
        ui.set_recovery_code_2(recovery.recovery_codes[1].code.clone().into());
        ui.set_recovery_code_3(recovery.recovery_codes[2].code.clone().into());
        
        // Store recovery hashes with encrypted data
        // (encrypted separately with recovery key)
    }
    
    // "Forgot Password?" link in UI
    ui.on_show_recovery(move || {
        ui.set_show_recovery_login(true);
    });
    
    ui.on_recover_with_code(move |code| {
        match recovery.recover_access(&code) {
            Ok(recovery_key) => {
                // Use recovery key to decrypt database
                // Allow user to set new master password
                ui.set_status_message("Recovery successful! Please set a new master password.".into());
            }
            Err(e) => {
                ui.set_status_message(format!("Recovery failed: {}", e).into());
            }
        }
    });
    
    ui.run()
}
```

**Files to Create:**
- `src/recovery.rs` - Emergency recovery logic

**Files to Modify:**
- `src/lib.rs` - Add recovery module
- `src/main.rs` - Integrate recovery functionality
- `src/storage.rs` - Store recovery data
- `src/ui/main.slint` - Add recovery UI
- `tests/` - Add recovery tests

**Testing:**
- Test recovery code generation
- Test recovery code verification
- Test successful account recovery
- Test invalid recovery code rejection
- Test recovery code display and copy
- Verify security of recovery mechanism

**Acceptance Criteria:**
- [ ] Recovery code generation on first use
- [ ] Display and storage of recovery codes
- [ ] Recovery UI for forgotten master password
- [ ] Account recovery with valid code
- [ ] Option to regenerate recovery codes
- [ ] Print/save recovery codes
- [ ] Tests verify recovery mechanism security
- [ ] Documentation with recovery procedures

**Priority:** 🟡 MEDIUM-HIGH
**Estimated Effort:** 6-8 hours
**Labels:** security, enhancement, recovery, availability

**Security Notes:**
- Recovery codes must be as strong as master password
- Users must store recovery codes securely (not in password manager!)
- Consider limiting recovery attempts to prevent brute force
- Recovery mechanism must not weaken overall security

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

### 2026-02-10 - Security Properties Expansion

- Conducted comprehensive security review of all aspects
- Identified 11 additional missing security properties
- Added 11 new detailed actionable items (Issues #11-#21):
  - Timing attack protection
  - Windows file permissions
  - Secure file deletion
  - Session timeout and auto-lock
  - Clipboard security
  - Password generator
  - Backup and export functionality
  - Database integrity verification
  - Password search and filtering
  - Security update notifications
  - Emergency access and recovery
- Each item formatted as complete GitHub issue with implementation guidance
- All items designed for agentic development workflows
- Updated security status summary with new missing items

### 2026-02-08 - Initial Security Review

- Conducted comprehensive security audit
- Identified critical vulnerability in bytes dependency (RUSTSEC-2026-0007)
- Documented security architecture and recommendations
- Created 10 actionable security improvement tasks
- Established security reporting policy

---

**Last Updated:** 2026-02-10  
**Security Audit Status:** ⚠️ PASSING (0 critical issues, 2 non-critical warnings, 11 enhancement opportunities)  
**Next Review Date:** 2026-03-10
