# Security Testing Note

## Hardcoded Credentials in Test Code

This project contains intentional hardcoded passwords and credentials in test files. These are **NOT** security vulnerabilities but rather necessary test fixtures.

### Purpose

The test files contain hardcoded passwords for the following legitimate testing purposes:

1. **Validation Testing**: Testing input validation logic requires sample passwords
2. **Encryption Testing**: Testing encryption/decryption requires known test passwords
3. **Integration Testing**: End-to-end tests require complete test data including passwords

### Security Scanning Suppressions

All test files with hardcoded credentials have been marked with appropriate security scanning suppressions:

#### Files with Suppressions

1. **`tests/validation_test.rs`**
   - Purpose: Tests input validation rules
   - Contains: Example passwords for validation testing
   - Suppressions: File-level comment and per-test CodeQL annotations

2. **`tests/storage_test.rs`**
   - Purpose: Tests encryption/decryption functionality
   - Contains: Test master passwords and sample password entries
   - Suppressions: File-level comment and per-test CodeQL annotations

3. **`tests/integration_test.rs`**
   - Purpose: Tests cross-platform integration and password change functionality
   - Contains: Test master passwords and password change scenarios
   - Suppressions: File-level comment and per-test CodeQL annotations

4. **`tests/error_sanitization_test.rs`**
   - Purpose: Tests error message sanitization
   - Contains: Test passwords for authentication error testing
   - Suppressions: File-level comment and per-test CodeQL annotations

5. **`src/validation.rs`**
   - Purpose: Documentation examples for validation functions
   - Contains: Example passwords in doc comments
   - Suppressions: Module-level security note and inline CodeQL annotations

### Suppression Format

We use the following suppression patterns:

```rust
// File-level suppression
#![allow(clippy::identity_op)]

// Function-level CodeQL suppression
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_function() {
    let test_password = "example_password_123";
    // ... test code
}

// Inline documentation suppression
/// ```
/// // codeql[rust/hardcoded-credentials] - Example password for documentation only
/// assert!(validate_password("MySecureP@ssw0rd!").is_ok());
/// ```
```

### Important Notes

1. **These are NOT real passwords**: All hardcoded values in test files are synthetic test data
2. **Never used in production**: Test passwords are only used in test environments
3. **Clear documentation**: All test files include security notes explaining the presence of test data
4. **Industry standard practice**: Hardcoded test fixtures are a standard and accepted practice in software testing

### Verification

To verify that these are legitimate test files and not production code:

1. All affected files are in the `tests/` directory or are test-related
2. All functions are marked with `#[test]` or are doc examples
3. Files contain clear documentation about test purposes
4. No test credentials are used in production code paths

### For Security Auditors

If your security scanning tool flags these files:

1. Verify the file is in `tests/` directory or contains doc tests
2. Check for suppression comments explaining the test fixtures
3. Confirm no test credentials are used in `src/main.rs` or other production code
4. These warnings are **false positives** and can be safely suppressed

### Maintenance

When adding new tests with passwords:

1. Add file-level security note at the top of the test file
2. Add `#![allow(clippy::identity_op)]` to suppress lint warnings
3. Add `// codeql[rust/hardcoded-credentials]` comment before test functions
4. Document the test purpose in comments
5. Update this document if adding new test files with credentials

---

Last Updated: 2026-02-11
Maintained by: GitHub Copilot AI
