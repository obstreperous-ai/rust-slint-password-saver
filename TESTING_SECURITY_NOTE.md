# Security Testing Note

## Hardcoded Credentials in Test Code

This project contains intentional hardcoded passwords and credentials in test files. These are **NOT** security vulnerabilities but rather necessary test fixtures.

### Purpose

The test files contain hardcoded passwords for the following legitimate testing purposes:

1. **Validation Testing**: Testing input validation logic requires sample passwords
2. **Encryption Testing**: Testing encryption/decryption requires known test passwords
3. **Integration Testing**: End-to-end tests require complete test data including passwords

### CodeQL Path Exclusion

The `tests/` directory is **excluded from CodeQL analysis entirely** via a CodeQL
configuration file (`.github/codeql/codeql-config.yml`). This is the primary
mechanism for preventing false-positive security alerts on test fixtures.

The CodeQL workflow (`.github/workflows/codeql.yml`) references this configuration
and uses `build-mode: none` for Rust analysis. Because the entire `tests/` directory
is excluded at the CodeQL level, individual inline `// codeql[...]` suppression
comments in test files are no longer required for files under `tests/`.

#### Why Path Exclusion Over Inline Suppressions

Inline CodeQL suppression comments (`// codeql[rust/hardcoded-credentials]`) are
brittle—they must be placed precisely and can break when code is refactored.
Excluding the entire test directory is more reliable and maintainable.

#### Files in `src/` with Inline Suppressions

For `#[cfg(test)]` modules and doc-test examples inside `src/` files, inline
CodeQL suppression comments are still used because those files contain production
code that must remain under CodeQL analysis. Current files with inline suppressions:

- **`src/validation.rs`** — Example passwords in doc comments
- **`src/search.rs`** — Test helper with sample credentials in `#[cfg(test)]`
- **`src/password_strength.rs`** — Test fixtures in `#[cfg(test)]`
- **`src/storage.rs`** — Cryptographic test values in `#[cfg(test)]`
- **`src/ui_handlers.rs`** — Test fixtures in `#[cfg(test)]`

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

1. If the test is in the `tests/` directory — no CodeQL suppression is needed (excluded by config)
2. If the test is in a `#[cfg(test)]` module inside `src/` — add `// codeql[rust/hardcoded-credentials]` before the relevant line
3. Add file-level security note at the top of the test file
4. Document the test purpose in comments
5. Update this document if adding new test files with credentials

---

Last Updated: 2026-04-10
Maintained by: GitHub Copilot AI
