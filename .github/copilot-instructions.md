# GitHub Copilot Instructions for rust-slint-password-saver

This file provides repository-specific guidance for GitHub Copilot coding agent when working on this project.

## Project Overview

This is a cross-platform desktop password manager built with Rust and Slint UI framework. It uses military-grade encryption (Argon2 + AES-256-GCM) for secure password storage. The project prioritizes security, code quality, and cross-platform compatibility (macOS and Linux).

## Tech Stack

- **Language**: Rust (Edition 2021, version 1.70+)
- **UI Framework**: [Slint](https://slint.dev/) v1.14 - UI definitions in `.slint` files
- **Cryptography**:
  - `argon2` v0.5.3 - Password hashing and key derivation
  - `aes-gcm` v0.10.3 - AES-256-GCM encryption/decryption
- **Serialization**: `serde` v1.0 with `serde_json` for JSON storage format
- **Build**: `slint-build` v1.14 as build dependency (compiles `.slint` files)

## Mandatory Development Workflow

**CRITICAL: Always follow this workflow before making ANY code changes:**

### 1. Before Making Changes (Build Verification)

```bash
# ALWAYS run these commands FIRST to understand current state
cargo build              # Verify project builds successfully
cargo test               # Verify all tests pass
cargo fmt -- --check     # Verify code is formatted
cargo clippy --all-targets -- -D warnings  # Verify no lint warnings
```

**Why this matters**: Understanding the current state prevents introducing new issues and helps identify pre-existing problems that are unrelated to your changes.

### 2. Development Process (TDD Best Practices)

For any new feature or bug fix:

1. **Write failing tests first** (Test-Driven Development)
   ```bash
   # Create test that demonstrates the requirement
   cargo test <test_name>  # Should fail initially
   ```

2. **Implement minimal code** to make tests pass
   ```bash
   # Write just enough code to pass the test
   cargo test <test_name>  # Should now pass
   ```

3. **Refactor if needed** while keeping tests passing
   ```bash
   cargo test              # All tests should still pass
   ```

4. **Verify code quality** before moving to next task
   ```bash
   cargo fmt               # Auto-format code
   cargo clippy --all-targets -- -D warnings  # Check for issues
   ```

### 3. Before Committing (Quality Verification)

**MANDATORY checklist - run in this exact order:**

```bash
# Step 1: Format code (auto-fixes formatting issues)
cargo fmt

# Step 2: Verify build succeeds
cargo build

# Step 3: Verify all tests pass
cargo test

# Step 4: Verify no lint warnings (treat as errors)
cargo clippy --all-targets -- -D warnings

# Step 5: (Optional but recommended) Security audit
cargo audit
```

**If ANY step fails, you MUST fix it before committing.**

### 4. Commit Guidelines

- Only commit after ALL quality checks pass
- Write clear, descriptive commit messages
- Keep commits focused and atomic
- Pre-commit hooks (if installed) will automatically verify quality

## Code Quality Standards

### Formatting (rustfmt)

- **ALWAYS run** `cargo fmt` before committing (see workflow above)
- Configuration: `rustfmt.toml`
  - Maximum line width: 100 characters
  - 4 spaces for indentation (no hard tabs)
  - Automatic import reordering enabled
  - Use field init shorthand and try shorthand
- Verify formatting with: `cargo fmt -- --check`
- **Never commit unformatted code** - this will cause CI failures

### Linting (Clippy)

- **ALWAYS run** `cargo clippy --all-targets -- -D warnings` before committing
- Configuration in `Cargo.toml` under `[lints.clippy]`
- Pedantic lint group enabled as warnings
- Some specific lints are allowed:
  - `module_name_repetitions`
  - `missing_errors_doc`
  - `missing_panics_doc`
  - `uninlined_format_args`
  - `items_after_statements`
- In CI, clippy warnings are treated as errors
- **Fix all clippy warnings** - don't suppress them unless absolutely necessary

### Testing

- **Write tests first** (TDD approach) whenever possible
- Run tests with: `cargo test`
- Run with output: `cargo test -- --nocapture`
- Run specific test: `cargo test <test_name>`
- Test files located in `tests/` directory
- Follow existing test patterns in `tests/storage_test.rs` and `tests/integration_test.rs`
- **All tests must pass** before committing
- Add tests for:
  - New features (before implementing)
  - Bug fixes (reproduce bug first, then fix)
  - Edge cases and error conditions
  - Security-critical code paths

### Build Commands

- Development build: `cargo build`
- Run application: `cargo run`
- Release build: `cargo build --release`
- Release run: `cargo run --release`
- Clean build: `cargo clean && cargo build` (useful for troubleshooting)

## Security Requirements

**This is a security-critical application. All changes must be reviewed for security implications.**

### Security Best Practices

1. **Never commit secrets or hardcoded passwords** to source code
2. **Always use cryptographically secure random number generators** (e.g., `OsRng` available through `aes_gcm::aead` module)
3. **Follow the existing encryption patterns** in `src/storage.rs`:
   - Use Argon2 for key derivation with random salts
   - Use AES-256-GCM for encryption with random nonces
   - Generate new salt and nonce for each save operation
4. **Zero-knowledge principle**: Master password must never be stored or logged
5. **Zeroize sensitive data** when possible (consider using `zeroize` crate if handling sensitive data in memory)
6. **Validate all user inputs** before processing
7. **Security audit**: Run `cargo audit` to check dependencies for known vulnerabilities
   - Install with: `cargo install cargo-audit`
   - Run before major changes affecting dependencies

### Security-Related Files

- `src/storage.rs` - All encryption/decryption logic (handle with extreme care)
- `Cargo.toml` / `Cargo.lock` - Dependencies must be kept secure and up-to-date

## Architecture and File Structure

```
src/
├── main.rs       - Application entry point, UI callbacks, event handlers
├── lib.rs        - Library crate root
├── storage.rs    - Encryption/decryption logic, password storage management
└── ui/
    └── main.slint - UI definition (Slint markup language)

tests/
├── integration_test.rs - Integration tests
└── storage_test.rs     - Storage module unit tests
```

### Key Conventions

- **Module organization**: Main application logic in `main.rs`, encryption in `storage.rs`
- **UI updates**: Slint UI changes require modifying `.slint` files AND corresponding callbacks in `main.rs`
- **Error handling**: Use `Result<T, String>` for error propagation with descriptive error messages
- **Documentation**: Add doc comments (///) for public APIs and complex logic
- **Attributes**: Use `#[must_use]` for functions returning important values (see `PasswordStorage::new`)

## Platform Support

- **Primary targets**: macOS and Linux
- **Storage path**: `~/.password_saver/passwords.enc` (uses HOME environment variable on Unix-like systems)
- **System dependencies**: Slint requires platform-specific libraries
  - macOS: cmake
  - Linux: cmake, libfontconfig1-dev, libxcb-shape0-dev, libxcb-xfixes0-dev

## CI/CD Integration

All quality checks run automatically in GitHub Actions:

- `.github/workflows/ci.yml` - Build and test on Ubuntu and macOS
- `.github/workflows/quality.yml` - Format and lint checks
- `.github/workflows/security.yml` - Daily security audits with cargo-audit
- `.github/workflows/release.yml` - Release builds for multiple targets

**Before submitting PR**: Ensure all CI checks will pass by running locally:
```bash
# Quality checks
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test

# Security audit (REQUIRED - workflow will fail if this fails)
cargo audit

# If any check fails, you MUST fix it before submitting the PR
```

### GitHub Actions Workflow Requirements

**CRITICAL: When modifying or creating GitHub Actions workflows, ensure:**

1. **Rust Toolchain Action** (`dtolnay/rust-toolchain`):
   - ALWAYS provide the `toolchain` input parameter explicitly
   - Correct usage:
     ```yaml
     - name: Install Rust toolchain
       uses: dtolnay/rust-toolchain@stable
       with:
         toolchain: stable  # Required parameter
     ```
   - ❌ INCORRECT: `uses: dtolnay/rust-toolchain@stable` (missing `with:` block)
   - ✅ CORRECT: Include `with:` block with explicit `toolchain` parameter

2. **Security Audit Workflow** (`.github/workflows/security.yml`):
   - Must run `cargo audit` successfully
   - Requires `cargo-audit` to be installed
   - Should fail the build if vulnerabilities are found
   - Run locally before PR: `cargo audit`

3. **Before submitting ANY PR that touches workflows**:
   - Verify the workflow syntax is correct
   - Check that all required action inputs are provided
   - Review the action's documentation for required parameters
   - Test locally when possible (e.g., run cargo commands directly)

4. **Common GitHub Actions mistakes to avoid**:
   - ❌ Using action version tags as input parameters
   - ❌ Forgetting `with:` block for actions that require inputs
   - ❌ Not checking action documentation for required parameters
   - ❌ Assuming version tags automatically set parameters

### Pre-PR Security Checklist

Before submitting a pull request, ALWAYS verify:

```bash
# 1. Run security audit
cargo audit

# 2. If cargo audit fails, investigate and fix vulnerabilities
#    - Update dependencies if patches are available
#    - Review security advisories
#    - Document any accepted risks

# 3. Ensure all CI workflows would pass
#    Check each workflow file and verify you can run equivalent commands locally
```

If `cargo audit` reports vulnerabilities:
- Check if updated versions of dependencies are available
- Review the security advisory to understand the risk
- Update `Cargo.toml` and run `cargo update`
- Re-run `cargo audit` to verify fixes
- Document any vulnerabilities that cannot be immediately fixed


## TDD (Test-Driven Development) Best Practices

### Why TDD for Rust?

Rust's strong type system and compiler work best with TDD:
- Tests help drive better API design
- Compiler errors guide you toward correct solutions
- Refactoring is safer with comprehensive test coverage
- Security-critical code (like encryption) requires thorough testing

### TDD Workflow for This Project

1. **Red Phase** (Write failing test)
   ```rust
   #[test]
   fn test_new_feature() {
       // Arrange: Set up test data
       let input = "test";
       
       // Act: Call the function (doesn't exist yet)
       let result = my_new_function(input);
       
       // Assert: Verify expected behavior
       assert_eq!(result, "expected");
   }
   ```
   Run: `cargo test test_new_feature` → Should fail with compilation error

2. **Green Phase** (Make test pass)
   ```rust
   fn my_new_function(input: &str) -> String {
       // Minimal implementation to pass test
       "expected".to_string()
   }
   ```
   Run: `cargo test test_new_feature` → Should pass

3. **Refactor Phase** (Improve while keeping tests green)
   - Clean up code
   - Remove duplication
   - Improve naming
   - Run `cargo test` after each change to ensure tests still pass

### Testing Guidelines for This Project

**Storage Module Tests** (`src/storage.rs` and `tests/storage_test.rs`):
- Test encryption/decryption round-trips
- Test error conditions (wrong password, corrupted data)
- Test edge cases (empty entries, special characters)
- **NEVER** test with actual files in automated tests (use temporary paths)

**Integration Tests** (`tests/integration_test.rs`):
- Test full user workflows
- Test cross-platform compatibility
- Test file system operations with temporary directories

**Slint UI Tests**:
- Test UI callbacks independently when possible
- Test business logic separately from UI code
- Consider manual testing for complex UI interactions

### When to Skip TDD

TDD is not always required for:
- Exploratory prototypes (but add tests before committing)
- Documentation changes
- Simple configuration changes
- UI layout tweaks (but test the underlying logic)

## Development Workflow

### Pre-commit Hooks

- Configuration: `.pre-commit-config.yaml`
- Install with: `pip install pre-commit && pre-commit install`
- Hooks automatically run: rustfmt, clippy, cargo-audit, and general file checks
- **Strongly recommended** - prevents committing broken code
- Skip in emergency only: `git commit --no-verify` (not recommended)
- If hooks fail, fix the issues - don't skip them

### Dev Container

- Fully configured dev container available in `.devcontainer/`
- Includes all dependencies and VS Code extensions
- See `.devcontainer/README.md` for details

### Troubleshooting Build/Test Failures

**Build Failures:**

1. **Slint compilation errors**
   ```bash
   # Clean and rebuild if .slint files were modified
   cargo clean
   cargo build
   ```
   - Check `.slint` syntax in `src/ui/main.slint`
   - Verify callbacks match between `.slint` and `main.rs`

2. **Dependency issues**
   ```bash
   # Update dependencies
   cargo update
   cargo build
   ```

3. **Platform-specific build failures**
   - macOS: Ensure cmake is installed (`brew install cmake`)
   - Linux: Install required libraries (see README.md)

**Test Failures:**

1. **Encryption tests fail intermittently**
   - Check if file permissions are correct
   - Ensure test temporary directories are unique
   - Verify no parallel tests are accessing same files

2. **Path-related tests fail**
   - Use `std::env::temp_dir()` for test files
   - Clean up test files in test teardown
   - Don't hardcode paths - use platform-agnostic path construction

**Format/Lint Failures:**

1. **`cargo fmt -- --check` fails**
   ```bash
   # Fix automatically
   cargo fmt
   ```

2. **`cargo clippy` warnings**
   ```bash
   # See detailed warnings
   cargo clippy --all-targets
   
   # Fix the issues in code - don't use #[allow(...)] without justification
   ```

3. **Pre-commit hooks fail**
   ```bash
   # Run hooks manually to see specific failures
   pre-commit run --all-files
   
   # Fix issues and try committing again
   ```

### Adding New Features

1. **Follow the mandatory workflow** (see "Mandatory Development Workflow" above)
2. Check `README.md` "Future Tasks & Roadmap" section for planned features
3. **Write tests first** (TDD approach)
4. Implement minimal code to pass tests
5. Update both code and documentation
6. Run full quality checks before committing
7. Commit with descriptive message

### Modifying UI

1. **Test current UI behavior first** (manual or automated)
2. Edit `.slint` files in `src/ui/` directory
3. Update corresponding callbacks in `src/main.rs`
4. Ensure callbacks are properly connected
5. **Build and test**: `cargo build && cargo run`
6. Verify UI changes work as expected
7. Run quality checks before committing

### Modifying Encryption Logic

1. **Extra scrutiny required** for changes to `src/storage.rs`
2. **Write comprehensive tests first** (TDD is mandatory here)
3. Maintain backward compatibility with existing encrypted files
4. Test with various password scenarios (correct, wrong, empty)
5. Document security implications in commit messages
6. Consider running `cargo audit` to check for security issues
7. Review changes multiple times before committing

## Common Pitfalls and How to Avoid Them

### ❌ Pitfall #1: Committing Without Running Quality Checks

**Problem**: Code fails in CI but worked locally
**Solution**: ALWAYS run the mandatory pre-commit workflow:
```bash
cargo fmt && cargo build && cargo test && cargo clippy --all-targets -- -D warnings
```

### ❌ Pitfall #2: Skipping Tests or Writing Tests After Implementation

**Problem**: Tests become biased toward implementation, not requirements
**Solution**: Practice TDD - write tests FIRST, then implement

### ❌ Pitfall #3: Ignoring Clippy Warnings

**Problem**: Accumulation of code quality issues leads to maintenance burden
**Solution**: Fix all clippy warnings immediately - they often catch real bugs

### ❌ Pitfall #4: Not Building Before Making Changes

**Problem**: Introducing new issues when pre-existing issues exist
**Solution**: Run `cargo build && cargo test` BEFORE making any changes

### ❌ Pitfall #5: Forgetting to Format Code

**Problem**: Formatting-only changes clutter git history and cause merge conflicts
**Solution**: Set up pre-commit hooks or always run `cargo fmt` before committing

### ❌ Pitfall #6: Modifying Generated Code

**Problem**: Changes to generated code (e.g., from `slint-build`) get overwritten
**Solution**: Only modify source files (`.slint`, `.rs`), never generated files

### ❌ Pitfall #7: Testing on Only One Platform

**Problem**: Code works on your machine but fails on other platforms (macOS vs Linux)
**Solution**: 
- Use platform-agnostic APIs when possible
- Test path construction with `std::path::PathBuf`
- Check CI results for both platforms

### ❌ Pitfall #8: Not Cleaning Build Artifacts When Troubleshooting

**Problem**: Stale build artifacts cause mysterious failures
**Solution**: Run `cargo clean && cargo build` when troubleshooting build issues

### ❌ Pitfall #9: Hardcoding Paths or Secrets in Tests

**Problem**: Tests fail on different machines or expose sensitive data
**Solution**: Use `std::env::temp_dir()` and mock data in tests

### ❌ Pitfall #10: Adding Dependencies Without Security Review

**Problem**: New dependencies introduce security vulnerabilities
**Solution**: Run `cargo audit` after adding/updating dependencies

## Rust-Specific Best Practices

### Error Handling

- Use `Result<T, String>` for error propagation with descriptive messages
- Avoid `.unwrap()` in production code - handle errors explicitly
- Use `?` operator for error propagation
- Provide context in error messages: `Err(format!("Failed to load file: {}", path))`

### Memory Safety

- Leverage Rust's ownership system - don't fight the borrow checker
- Use references (`&T`) for read-only access
- Use mutable references (`&mut T`) for write access
- Clone only when necessary (consider using `Cow<'_, T>` for efficiency)

### Type Safety

- Use strong types instead of primitive obsession (e.g., `struct UserId(String)`)
- Leverage the type system to make invalid states unrepresentable
- Use enums for state machines
- Add `#[must_use]` attribute to functions with important return values

### Slint UI Best Practices

- Keep business logic separate from UI code
- Use callbacks to communicate between Slint UI and Rust backend
- Test Rust business logic independently of UI
- Keep `.slint` files focused and modular
- Follow Slint naming conventions (PascalCase for components)

## What NOT to Do

### Code Quality Violations

- ❌ Do not commit without running `cargo fmt` and `cargo clippy`
- ❌ Do not suppress clippy warnings without strong justification
- ❌ Do not commit failing tests or broken builds
- ❌ Do not skip the pre-commit quality verification workflow
- ❌ Do not use `#[allow(clippy::...)]` without explaining why in comments

### Security Violations

- ❌ Do not use overly permissive types or unsafe code without explicit justification
- ❌ Do not remove or weaken existing security measures
- ❌ Do not commit secrets or hardcoded passwords to source code
- ❌ Do not add dependencies without security review (`cargo audit`)
- ❌ Do not log or print sensitive data (passwords, keys, etc.)
- ❌ Do not use weak random number generators for cryptographic operations
- ❌ Do not store master password or derived keys persistently

### Build and Development Violations

- ❌ Do not modify `Cargo.lock` manually (use `cargo update`)
- ❌ Do not commit generated code or build artifacts (target/ directory)
- ❌ Do not skip building/testing before making changes
- ❌ Do not commit without verifying code compiles and passes tests
- ❌ Do not modify files in `target/` directory

### Testing Violations

- ❌ Do not skip writing tests for new features
- ❌ Do not write tests that depend on external state or network
- ❌ Do not commit tests that are flaky or non-deterministic
- ❌ Do not hardcode file paths in tests (use `std::env::temp_dir()`)
- ❌ Do not leave test files or artifacts in the repository

### Code Practice Violations

- ❌ Do not use `.unwrap()` or `.expect()` in production code without careful consideration
- ❌ Do not ignore compiler warnings - fix them
- ❌ Do not use `unsafe` without thorough documentation and justification
- ❌ Do not introduce dependencies without checking license compatibility
- ❌ Do not create overly complex functions (keep them focused and testable)

## Quick Reference - Common Commands

### Daily Development

```bash
# Start working on a feature
cargo build          # Verify current state
cargo test           # Verify all tests pass

# Make changes, following TDD...

# Before committing
cargo fmt            # Format code
cargo build          # Verify builds
cargo test           # Verify tests pass
cargo clippy --all-targets -- -D warnings  # Check quality
git add .
git commit -m "Descriptive message"
```

### Running Tests

```bash
cargo test                    # Run all tests
cargo test -- --nocapture     # Run tests with output
cargo test <test_name>        # Run specific test
cargo test --package rust-slint-password-saver  # Run package tests
```

### Code Quality Checks

```bash
cargo fmt -- --check          # Check formatting (no changes)
cargo fmt                     # Fix formatting
cargo clippy --all-targets    # Run linter (warnings)
cargo clippy --all-targets -- -D warnings  # Treat warnings as errors
```

### Build Commands

```bash
cargo build                   # Development build
cargo build --release         # Optimized release build
cargo run                     # Build and run
cargo clean                   # Remove build artifacts
cargo check                   # Fast compilation check (no binary)
```

### Security and Dependencies

```bash
cargo audit                   # Check for security vulnerabilities
cargo update                  # Update dependencies
cargo tree                    # Show dependency tree
```

## Additional Notes

- **License**: MIT (see LICENSE file)
- **Rust Edition**: 2021
- **Minimum Rust Version**: 1.70 or later
- **Documentation**: This is an educational/experimental project - see README disclaimer
- **Agent-friendly**: The codebase is designed to be clear and maintainable for both humans and AI assistants

## References

- README.md - Comprehensive project documentation
- CODE_QUALITY.md - Detailed code quality tools documentation
- [Slint Documentation](https://slint.dev/docs)
- [Rust Cryptography Working Group](https://github.com/RustCrypto)
