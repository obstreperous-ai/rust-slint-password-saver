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

## Code Quality Standards

### Formatting (rustfmt)

- **Always run** `cargo fmt` before committing
- Configuration: `rustfmt.toml`
  - Maximum line width: 100 characters
  - 4 spaces for indentation (no hard tabs)
  - Automatic import reordering enabled
  - Use field init shorthand and try shorthand
- Verify formatting with: `cargo fmt -- --check`

### Linting (Clippy)

- **Always run** `cargo clippy --all-targets` before committing
- Configuration in `Cargo.toml` under `[lints.clippy]`
- Pedantic lint group enabled as warnings
- Some specific lints are allowed:
  - `module_name_repetitions`
  - `missing_errors_doc`
  - `missing_panics_doc`
  - `uninlined_format_args`
  - `items_after_statements`
- In CI, clippy warnings are treated as errors: `cargo clippy --all-targets -- -D warnings`

### Testing

- Run tests with: `cargo test`
- Run with output: `cargo test -- --nocapture`
- Test files located in `tests/` directory
- Follow existing test patterns in `tests/storage_test.rs` and `tests/integration_test.rs`

### Build Commands

- Development build: `cargo build`
- Run application: `cargo run`
- Release build: `cargo build --release`
- Release run: `cargo run --release`

## Security Requirements

**This is a security-critical application. All changes must be reviewed for security implications.**

### Security Best Practices

1. **Never commit secrets or hardcoded passwords** to source code
2. **Always use cryptographically secure random number generators** (e.g., `OsRng` re-exported from `aes_gcm::aead`)
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
- **Storage path**: `~/.password_saver/passwords.enc` (resolved via `std::env::var("HOME")` on Unix-like systems)
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
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
```

## Development Workflow

### Pre-commit Hooks

- Configuration: `.pre-commit-config.yaml`
- Install with: `pip install pre-commit && pre-commit install`
- Hooks automatically run: rustfmt, clippy, cargo-audit, and general file checks
- Skip in emergency only: `git commit --no-verify` (not recommended)

### Dev Container

- Fully configured dev container available in `.devcontainer/`
- Includes all dependencies and VS Code extensions
- See `.devcontainer/README.md` for details

## Common Tasks

### Adding New Features

1. Check `README.md` "Future Tasks & Roadmap" section for planned features
2. Update both code and documentation
3. Add tests for new functionality
4. Run full quality checks before committing

### Modifying UI

1. Edit `.slint` files in `src/ui/` directory
2. Update corresponding callbacks in `src/main.rs`
3. Test UI changes by running the application

### Modifying Encryption Logic

1. **Extra scrutiny required** for changes to `src/storage.rs`
2. Maintain backward compatibility with existing encrypted files
3. Add comprehensive tests for any cryptographic changes
4. Document security implications in commit messages

## What NOT to Do

- ❌ Do not use `any` types or unsafe code without explicit justification
- ❌ Do not remove or weaken existing security measures
- ❌ Do not commit without running `cargo fmt` and `cargo clippy`
- ❌ Do not add dependencies without security review (`cargo audit`)
- ❌ Do not log or print sensitive data (passwords, keys, etc.)
- ❌ Do not modify `Cargo.lock` manually (use `cargo update`)
- ❌ Do not use weak random number generators for cryptographic operations
- ❌ Do not store master password or derived keys persistently

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
