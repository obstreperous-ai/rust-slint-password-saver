# 🔐 Rust Slint Password Saver

A cross-platform, secure desktop password manager application built with **Rust** and **Slint UI** framework. This application provides military-grade password storage using industry-standard encryption algorithms, with native support for macOS and Linux, and experimental Windows support.

[![CI](https://github.com/obstreperous-ai/rust-slint-password-saver/workflows/CI/badge.svg)](https://github.com/obstreperous-ai/rust-slint-password-saver/actions)
[![Code Quality](https://github.com/obstreperous-ai/rust-slint-password-saver/workflows/Code%20Quality/badge.svg)](https://github.com/obstreperous-ai/rust-slint-password-saver/actions)
[![Security Audit](https://github.com/obstreperous-ai/rust-slint-password-saver/workflows/Security%20Audit/badge.svg)](https://github.com/obstreperous-ai/rust-slint-password-saver/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📋 Table of Contents

- [Features](#-features)
- [Security Details](#-security-details)
- [Installation](#-installation)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Development Setup](#-development-setup)
- [CI/CD Pipeline](#-cicd-pipeline)
- [Design & Style Guide](#-design--style-guide)
- [Contributing](#-contributing)
- [Future Tasks & Roadmap](#-future-tasks--roadmap)
- [License](#-license)

---

## ✨ Features

- **🎨 Modern UI**: Built with [Slint](https://slint.dev/) UI framework for a native look and feel
- **🔒 Military-Grade Encryption**: Uses Argon2 for password hashing and AES-256-GCM for encryption
- **💻 Cross-Platform**: Native support for macOS and Linux; experimental Windows support
- **⚡ Rust-Powered**: Leverages Rust's memory safety and performance guarantees
- **🛡️ Security-First Design**: Zero-knowledge architecture with local-only storage
- **🔍 Automated Security Audits**: Daily vulnerability scanning via CI/CD
- **📦 Portable**: Single binary with no external dependencies (except system libraries)

---

## 🔒 Security Details

### Encryption Architecture

This application implements a **zero-knowledge encryption** model where all sensitive data is encrypted locally before storage. The security model is built on three core principles:

#### 1. **Password Hashing with Argon2**
- **Algorithm**: Argon2 (winner of the Password Hashing Competition)
- **Purpose**: Derives encryption keys from master passwords
- **Resistance**: Memory-hard function designed to resist GPU/ASIC cracking attacks
- **Salt**: Cryptographically random salt generated for each storage operation

#### 2. **Symmetric Encryption with AES-256-GCM**
- **Algorithm**: AES-256-GCM (Advanced Encryption Standard in Galois/Counter Mode)
- **Key Size**: 256 bits
- **Authentication**: Built-in authenticity verification (AEAD - Authenticated Encryption with Associated Data)
- **Nonce**: 96-bit cryptographically random nonce for each encryption operation

#### 3. **Secure Storage Format**
```json
{
  "salt": "<base64-encoded-random-salt>",
  "nonce": "<base64-encoded-random-nonce>",
  "encrypted_data": "<aes-256-gcm-encrypted-password-entries>"
}
```

### Security Properties

✅ **Confidentiality**: All password data is encrypted with AES-256-GCM  
✅ **Authenticity**: GCM mode provides tamper detection  
✅ **Integrity**: Any modification to encrypted data will cause decryption to fail  
✅ **Zero-Knowledge**: Master password never stored; only used to derive encryption keys  
✅ **Forward Secrecy**: New salt and nonce generated for each save operation  

### Storage Location

Encrypted passwords are stored at:
- **macOS/Linux**: `~/.password_saver/passwords.enc`
- **Windows**: `%LOCALAPPDATA%\PasswordSaver\passwords.enc` (falls back to `%USERPROFILE%\.password_saver\passwords.enc` if `LOCALAPPDATA` is unset)

### Master Password Requirements

To ensure maximum security, the application enforces strict password requirements for your master password:

✅ **Minimum Requirements:**
- At least **12 characters** in length
- At least **one uppercase** letter (A-Z)
- At least **one lowercase** letter (a-z)
- At least **one digit** (0-9)
- At least **one special** character (!@#$%^&*()_+-=[]{}|;:,.<>?)
- Must achieve **"Strong"** or better rating from entropy analysis

🛡️ **Password Strength Analysis:**
The application uses the [zxcvbn](https://github.com/dropbox/zxcvbn) password strength estimator to detect:
- Common passwords and dictionary words
- Keyboard patterns (e.g., "qwerty", "asdf")
- Repeated patterns (e.g., "abcabc", "123123")
- Sequential patterns (e.g., "abc", "123")
- Date patterns and names

**Example Strong Passwords:**
- `MyS3cur3P@ssw0rd!` ✅
- `Tr0ub4dor&3!xKcd` ✅
- `C0rr3ct-H0rs3-B@tt3ry` ✅

**Example Weak Passwords (will be rejected):**
- `Password123!` ❌ (too common)
- `Qwerty123!` ❌ (keyboard pattern)
- `Abcdef123!` ❌ (sequential pattern)

⚠️ **Note:** Password requirements are only enforced when creating a new password database (first use). Existing databases are not affected.

### Security Considerations

📋 **For comprehensive security information, see [SECURITY.md](SECURITY.md)**

⚠️ **Important Notes**:
- The security of your passwords depends entirely on the strength of your master password
- Master password strength is validated only on first use (when creating new database)
- Master password is never stored and cannot be recovered if forgotten
- The application does not implement any backup/recovery mechanism by design
- All data is stored locally; no cloud synchronization (enhances security, reduces attack surface)

🔍 **Security Status**: The project undergoes regular security audits. Current security status and identified issues are documented in [SECURITY.md](SECURITY.md).

---

## 📦 Installation

### Prerequisites

#### System Requirements
- **Operating System**: macOS 10.15+ or Linux (Ubuntu 20.04+, Fedora 35+, etc.), or Windows 10/11 (experimental)
- **Rust Toolchain**: 1.70 or later

#### Install Rust

If you don't have Rust installed:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### Platform-Specific Dependencies

**macOS**:
```bash
brew install cmake
```

**Linux (Ubuntu/Debian)**:
```bash
sudo apt-get update
sudo apt-get install -y cmake libfontconfig1-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

**Linux (Fedora/RHEL)**:
```bash
sudo dnf install cmake fontconfig-devel libxcb-devel
```

**Windows**:
- Visual C++ Build Tools 2019 or later (install via https://visualstudio.microsoft.com/visual-cpp-build-tools/ or `winget install Microsoft.VisualStudio.2022.BuildTools`)
- No additional system libraries required; Slint uses Direct3D on Windows

> **Note**: Windows support is experimental. See [Known Windows Limitations](#known-windows-limitations) below.

### Building from Source

1. **Clone the repository**:
```bash
git clone https://github.com/obstreperous-ai/rust-slint-password-saver.git
cd rust-slint-password-saver
```

2. **Build the project**:
```bash
cargo build --release
```

3. **Run the application**:
```bash
cargo run --release
```

### Install Binary (Optional)

```bash
cargo install --path .
```

This installs the binary to `~/.cargo/bin/rust-slint-password-saver`.

### Windows Package Managers

The following package manager options are available for Windows users. Manifest files are included in this repository under `winget/` and `scoop/`.

#### Winget

```powershell
winget install obstreperous-ai.RustSlintPasswordSaver
```

> **Note**: The Winget manifest is available in the repository under
> `winget/manifests/o/obstreperous-ai/RustSlintPasswordSaver/0.1.0/`. Submission to
> [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) is pending. Until the manifest
> is accepted into the community repository, you can install locally with:
> ```powershell
> winget install --manifest winget/manifests/o/obstreperous-ai/RustSlintPasswordSaver/0.1.0/
> ```

#### Scoop

```powershell
# Install from the local manifest (one-time)
scoop install scoop/rust-slint-password-saver.json
```

The Scoop manifest (`scoop/rust-slint-password-saver.json`) points to the GitHub release `.zip`
and supports `scoop update` via the `autoupdate` block.

#### MSI Installer

A Windows `.msi` installer built with [WiX 4](https://wixtoolset.org/) is attached to every
GitHub release as `rust-slint-password-saver-windows-x86_64.msi`. It:

- Installs `rust-slint-password-saver.exe` to `%ProgramFiles%\PasswordSaver\`
- Creates a **Start Menu** shortcut
- Registers an **Add/Remove Programs** entry for clean uninstallation

```powershell
# Silent install
msiexec /i rust-slint-password-saver-windows-x86_64.msi /quiet

# Silent uninstall
msiexec /x rust-slint-password-saver-windows-x86_64.msi /quiet
```

See [WINDOWS.md](WINDOWS.md) for full Windows packaging details.

---

### Known Windows Limitations

The following limitations apply to the current Windows (experimental) build:

- **Console window**: A console/terminal window may appear alongside the main UI on some Windows configurations. This will be resolved in a future release.
- **SmartScreen warning**: Windows SmartScreen may show an "Unknown publisher" warning when running the pre-built binary from GitHub Releases, because the executable is unsigned. See the [Running on Windows — SmartScreen Warning](#running-on-windows--smartscreen-warning) section below for step-by-step bypass instructions.
- **Storage location**: Passwords are stored in `%LOCALAPPDATA%\PasswordSaver\` (e.g. `C:\Users\Alice\AppData\Local\PasswordSaver\`). This folder is not hidden, but `AppData` itself is hidden by default in Windows Explorer. To open it, type `%LOCALAPPDATA%` in the Explorer address bar.

---

### Running on Windows — SmartScreen Warning

When you download `rust-slint-password-saver-windows-x86_64.zip` from the GitHub Releases page and run the extracted `.exe`, Windows SmartScreen will show a blue dialog reading **"Windows protected your PC"**. This happens because the release binary is currently **unsigned** (no Authenticode certificate), so Windows marks it as coming from an unknown publisher.

**This is a known limitation and does not indicate malware.** Follow the steps below to run the application:

1. In the SmartScreen dialog, click **"More info"**.
2. A **"Run anyway"** button will appear at the bottom of the dialog.
3. Click **"Run anyway"** to launch the application.

> **Why does SmartScreen trigger?**  
> Windows SmartScreen blocks unsigned executables from unknown publishers by default. The release binary is built by GitHub Actions and is not yet signed with an Authenticode certificate. Code-signing is planned for a future release (see [WINDOWS.md](WINDOWS.md) Finding D for details).

> **Building from source bypasses this warning.**  
> Binaries compiled locally with `cargo build --release` are not downloaded from the internet and therefore do not accumulate a SmartScreen download reputation score — they run without any SmartScreen prompt.

---

## 🚀 Usage

### Quick Start

1. **Launch the application**:
```bash
cargo run --release
# or if installed:
rust-slint-password-saver
```

2. **Create a Master Password**:
   - Enter a strong master password in the "Master Password" field
   - This password will encrypt/decrypt all your stored passwords
   - **Remember it well** - it cannot be recovered!

3. **Add a Password Entry**:
   - Fill in the Title (e.g., "Gmail", "GitHub")
   - Enter Username/Email (optional)
   - Enter the Password you want to store
   - Click "Save Password"

4. **Load Stored Passwords**:
   - Enter your master password
   - Click "Load Passwords"
   - View the list of stored passwords in the status area

### Example Workflow

```
┌─────────────────────────────────────┐
│     Password Saver Application      │
├─────────────────────────────────────┤
│ Master Password: ********            │
├─────────────────────────────────────┤
│ Title:    GitHub                     │
│ Username: myuser@example.com         │
│ Password: ********                   │
│                                      │
│ [Save Password]  [Load Passwords]    │
└─────────────────────────────────────┘
```

### Data Persistence

- Passwords are automatically saved to `~/.password_saver/passwords.enc`
- Each save operation re-encrypts all data with a new salt and nonce
- No network access required - all operations are local

---

## 🏗️ Architecture

This section provides a technical overview for developers and AI agents working with the codebase.

### Project Structure

```
rust-slint-password-saver/
├── .devcontainer/              # VS Code dev container configuration
│   ├── devcontainer.json       # Container setup with all dependencies
│   ├── setup.sh                # System dependencies installation script
│   └── README.md               # Dev container documentation
├── .github/
│   └── workflows/              # CI/CD pipeline definitions
│       ├── ci.yml              # Build and test workflow (macOS + Linux)
│       ├── quality.yml         # Code quality checks (rustfmt, clippy)
│       ├── security.yml        # Security audit (cargo-audit, daily)
│       └── release.yml         # Release builds for multiple targets
├── src/
│   ├── main.rs                 # Application entry point and UI callbacks
│   ├── lib.rs                  # Library crate root
│   ├── storage.rs              # Encryption/decryption and storage logic
│   └── ui/
│       └── main.slint          # UI definition (Slint markup)
├── tests/
│   ├── integration_test.rs     # Integration tests
│   └── storage_test.rs         # Storage module tests
├── build.rs                    # Build script (compiles Slint UI)
├── Cargo.toml                  # Project dependencies and metadata
├── rustfmt.toml                # Code formatting configuration
├── .pre-commit-config.yaml     # Pre-commit hooks configuration
├── CODE_QUALITY.md             # Code quality tools documentation
└── README.md                   # This file
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│                     (main.rs)                            │
│  - UI Event Handlers                                     │
│  - Application Logic                                     │
│  - Cross-platform path resolution                        │
└────────────────┬────────────────────────────────────────┘
                 │
                 ├─── UI Layer (Slint) ───────────────────┐
                 │    - Window Management                  │
                 │    - User Input Forms                   │
                 │    - Status Display                     │
                 │                                         │
                 └─── Storage Layer (storage.rs) ─────────┤
                      ├─ Argon2 Key Derivation             │
                      ├─ AES-256-GCM Encryption/Decryption │
                      ├─ JSON Serialization (serde)        │
                      └─ File I/O Operations               │
                                                            │
┌─────────────────────────────────────────────────────────┘
│                    Storage Format                        
│  {                                                       
│    "salt": [u8],        // Random salt for key derivation
│    "nonce": [u8],       // Random nonce for AES-GCM     
│    "encrypted_data": [u8]  // AES-256-GCM ciphertext    
│  }                                                       
└─────────────────────────────────────────────────────────
```

### Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| [slint](https://slint.dev/) | 1.14 | UI framework and rendering |
| [argon2](https://crates.io/crates/argon2) | 0.5.3 | Password hashing and key derivation |
| [aes-gcm](https://crates.io/crates/aes-gcm) | 0.10.3 | AES-256-GCM encryption |
| [zxcvbn](https://crates.io/crates/zxcvbn) | 3.1 | Password strength estimation |
| [serde](https://crates.io/crates/serde) | 1.0 | Serialization/deserialization |
| [serde_json](https://crates.io/crates/serde_json) | 1.0 | JSON format support |

### Data Flow

#### Saving a Password
```
User Input → Validate → Serialize to JSON → Derive Key (Argon2) → 
Encrypt (AES-256-GCM) → Write to Disk (~/.password_saver/passwords.enc)
```

#### Loading Passwords
```
Read from Disk → Deserialize Storage → Derive Key (Argon2) → 
Decrypt (AES-256-GCM) → Deserialize Entries → Display to User
```

---

## 🛠️ Development Setup

### Option 1: Dev Container (Recommended)

The repository includes a fully configured development container for VS Code with all dependencies pre-installed.

**Prerequisites**: Docker and VS Code with the "Dev Containers" extension

1. Open the repository in VS Code
2. Click "Reopen in Container" when prompted
3. Wait for the container to build (includes Rust, system dependencies, and tools)
4. Start coding!

**What's Included**:
- Rust stable toolchain
- All system dependencies for Slint
- VS Code extensions (rust-analyzer, Slint, LLDB debugger)
- Development tools (cargo-watch, cargo-audit, cargo-edit)
- Pre-configured settings and formatting

See [.devcontainer/README.md](.devcontainer/README.md) for detailed documentation.

### Option 2: Local Development

1. **Install Prerequisites** (see [Installation](#-installation) section)

   > **Windows users**: Before building locally you must have the **Visual C++ Build Tools** installed.  
   > Download from <https://visualstudio.microsoft.com/visual-cpp-build-tools/> or run:
   > ```powershell
   > winget install Microsoft.VisualStudio.2022.BuildTools
   > ```
   > No additional system libraries are required — Slint uses Direct3D on Windows.  
   > GitHub-hosted `windows-latest` runners ship with MSVC pre-installed, so no extra
   > setup step is needed in CI.

2. **Install Development Tools**:
```bash
# Code formatting
rustup component add rustfmt

# Linting
rustup component add clippy

# Security auditing
cargo install cargo-audit

# Live reloading (optional)
cargo install cargo-watch

# Pre-commit hooks (optional, requires Python)
pip install pre-commit
pre-commit install
```

3. **Common Development Commands**:

```bash
# Build the project
cargo build

# Run the application
cargo run

# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Format code
cargo fmt

# Lint code
cargo clippy --all-targets

# Security audit
cargo audit

# Live reload during development
cargo watch -x run

# Build release binary
cargo build --release
```

### Testing

The project includes comprehensive tests:

```bash
# Run all tests
cargo test

# Run specific test module
cargo test storage

# Run integration tests
cargo test --test integration_test

# Run with verbose output
cargo test -- --nocapture --test-threads=1
```

### Code Quality

This project maintains high code quality standards:

- **Formatting**: `cargo fmt` (enforced in CI)
- **Linting**: `cargo clippy` with pedantic warnings (enforced in CI)
- **Security**: `cargo audit` runs daily in CI
- **Pre-commit hooks**: Automatic checks before commits

See [CODE_QUALITY.md](CODE_QUALITY.md) for detailed information.

---

## 🔄 CI/CD Pipeline

The project uses GitHub Actions for continuous integration and deployment.

### Workflows

#### 1. **CI Workflow** (`.github/workflows/ci.yml`)
- **Trigger**: Push to `main`, Pull Requests
- **Platforms**: Ubuntu (Linux), macOS, Windows
- **Steps**:
  - Install system dependencies (Linux/macOS); verify MSVC toolchain (Windows — pre-installed on runner)
  - Cache cargo registry and build artifacts
  - Build project
  - Run test suite
- **Purpose**: Ensure code builds and tests pass on all supported platforms

#### 2. **Code Quality Workflow** (`.github/workflows/quality.yml`)
- **Trigger**: Push to `main`, Pull Requests
- **Jobs**:
  - **Format Check**: `cargo fmt --check`
  - **Clippy Lint**: `cargo clippy --all-targets -- -D warnings`
- **Purpose**: Enforce code style and catch common mistakes

#### 3. **Security Audit Workflow** (`.github/workflows/security.yml`)
- **Trigger**: 
  - Push to `main` (if Cargo files changed)
  - Pull Requests (if Cargo files changed)
  - Daily at 00:00 UTC
- **Steps**:
  - Install `cargo-audit`
  - Check dependencies against RustSec advisory database
- **Purpose**: Detect known security vulnerabilities in dependencies

#### 4. **Release Workflow** (`.github/workflows/release.yml`)
- **Trigger**: Version tags (`v*.*.*`)
- **Targets**:
  - `x86_64-unknown-linux-gnu` (Linux x64)
  - `x86_64-apple-darwin` (macOS Intel)
  - `aarch64-apple-darwin` (macOS Apple Silicon)
- **Steps**:
  - Build release binaries for all targets
  - Strip debug symbols
  - Create tarballs
  - Create GitHub release with artifacts
- **Purpose**: Automated release builds and distribution

### CI/CD Best Practices

- ✅ Matrix builds for cross-platform testing
- ✅ Dependency caching for faster builds
- ✅ Automated security scanning
- ✅ Release automation with version tagging
- ✅ Build artifacts for all major platforms

---

## 🎨 Design & Style Guide

This project follows a comprehensive design system inspired by Meiji era Japan, Edwardian England, early Apple design philosophy, and David Ogilvy's visual communication principles.

**📖 See [STYLE_GUIDE.md](STYLE_GUIDE.md) for:**
- Complete design vision and principles
- Color palette, typography, and spacing specifications
- Component design patterns and best practices
- Current codebase analysis and UX findings
- Prioritized list of actionable UI/UX improvement tasks
- Implementation guidelines for AI agents and developers

The style guide ensures consistent, elegant, and security-conscious design throughout the application while maintaining a minimal and refined aesthetic.

---

## 🤝 Contributing

We welcome contributions from the community! This project is designed to be agent-friendly and easy to work with.

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Run tests**: `cargo test`
5. **Run quality checks**: `cargo fmt && cargo clippy`
6. **Commit your changes**: `git commit -m 'Add amazing feature'`
7. **Push to the branch**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

### Contribution Guidelines

#### Code Style
- Follow Rust standard naming conventions
- Run `cargo fmt` before committing
- Address all `cargo clippy` warnings
- Add tests for new functionality
- Update documentation as needed

#### Commit Messages
- Use clear, descriptive commit messages
- Reference issue numbers when applicable
- Follow conventional commits format (optional)

#### Pull Request Process
1. Ensure all CI checks pass
2. Update README if adding features
3. Add tests for bug fixes and new features
4. Request review from maintainers
5. Address review feedback promptly

#### Security Issues

**For detailed security information, policies, and vulnerability reporting, please see [SECURITY.md](SECURITY.md).**

If you discover a security vulnerability, please follow the responsible disclosure process outlined in [SECURITY.md](SECURITY.md) rather than opening a public issue.

### Development Workflow

```bash
# 1. Create a branch
git checkout -b feature/my-feature

# 2. Make changes and test
cargo test

# 3. Format and lint
cargo fmt
cargo clippy --all-targets

# 4. Commit and push
git commit -m "Add my feature"
git push origin feature/my-feature

# 5. Open PR on GitHub
```

---

## 🚧 Future Tasks & Roadmap

This section outlines planned improvements and features. It's designed to be **agent-friendly** for AI assistants working on the codebase.

### High Priority

- [ ] **Password Search/Filter**: Add search functionality to quickly find stored passwords
  - **Files to modify**: `src/ui/main.slint` (add search input), `src/main.rs` (filter logic)
  - **Complexity**: Medium
  - **Dependencies**: None

- [ ] **Password Export/Import**: Allow users to export/import password databases
  - **Files to modify**: `src/storage.rs` (add export/import methods), `src/main.rs` (UI callbacks)
  - **Security consideration**: Export format should maintain encryption
  - **Complexity**: Medium-High

- [ ] **Password Generator**: Built-in secure password generator
  - **New module**: `src/generator.rs`
  - **Dependencies**: Consider `rand` crate (already indirect dependency)
  - **UI changes**: Add generator button in `src/ui/main.slint`
  - **Complexity**: Low-Medium

- [ ] **Master Password Change**: Allow changing the master password
  - **Files to modify**: `src/storage.rs` (decrypt with old, encrypt with new)
  - **UI changes**: Add "Change Master Password" dialog
  - **Complexity**: Medium

### Medium Priority

- [ ] **Password Strength Indicator**: Visual feedback on password strength
  - **New module**: `src/strength.rs`
  - **Dependencies**: Consider `zxcvbn` crate
  - **UI changes**: Add strength meter in `src/ui/main.slint`
  - **Complexity**: Low

- [ ] **Clipboard Integration**: Copy passwords to clipboard with auto-clear
  - **Dependencies**: `arboard` or `clipboard` crate
  - **Security**: Clear clipboard after timeout
  - **Complexity**: Medium

- [ ] **Dark Mode Support**: Add theme switching
  - **Files to modify**: `src/ui/main.slint` (add theme property)
  - **Complexity**: Low

- [x] **Windows Support**: Experimental Windows support is now available
  - Windows build and run confirmed; pre-built binaries shipped in release workflow
  - Storage path uses `%LOCALAPPDATA%\PasswordSaver\` on Windows
  - See [Known Windows Limitations](#known-windows-limitations) for current caveats
  - **Remaining**: Code-signing for SmartScreen, DPI manifest, Windows installer

### Low Priority / Nice to Have

- [ ] **Auto-lock**: Lock after period of inactivity
- [ ] **Password History**: Track password changes over time
- [ ] **Trash/Recovery**: Soft delete with recovery option
- [ ] **Categories/Tags**: Organize passwords by category
- [ ] **Two-Factor Auth Storage**: Store TOTP secrets (requires TOTP implementation)
- [ ] **Browser Extension**: Integrate with web browsers
- [ ] **Mobile Apps**: iOS/Android versions (significant effort)

### Infrastructure & Tooling

- [ ] **Benchmarking**: Add performance benchmarks for encryption operations
  - **Tool**: Use `criterion` crate
  - **Files**: Create `benches/` directory
  - **Complexity**: Low

- [ ] **Integration Tests**: Expand integration test coverage
  - **Files**: `tests/integration_test.rs`
  - **Coverage**: Add tests for UI interactions
  - **Complexity**: Medium

- [ ] **Documentation**: Generate API docs with `cargo doc`
  - **Action**: Add doc comments to public APIs
  - **CI integration**: Publish docs to GitHub Pages
  - **Complexity**: Low

### Agent-Friendly Notes

When working on new features:
1. Check existing tests in `tests/` directory for patterns
2. Follow the encryption pattern in `src/storage.rs` for security-related code
3. UI changes require editing both `.slint` files and callback handlers in `main.rs`
4. Always run `cargo test` and `cargo clippy` before committing
5. Security-related changes require extra scrutiny and testing
6. Update this README when adding major features

---

## 📄 License

### Project Source Code

This project's own source code is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 obstreperous-ai

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

### Third-Party Framework — Slint UI

The [Slint](https://slint.dev/) UI framework components used in this application are licensed under the
**[Slint Royalty-Free Desktop, Mobile, and Web Applications License, Version 2.0](https://github.com/slint-ui/slint/blob/master/LICENSES/LicenseRef-Slint-Royalty-free-2.0.md)**.

This license permits use in non-commercial and qualifying commercial applications at no cost,
subject to the attribution requirement satisfied by the **"Built with Slint"** notice displayed
within the application (accessible via the footer link).

All other dependencies are permissively licensed (MIT, Apache-2.0, or BSD-3-Clause) and are
fully compatible with this project's MIT license. See [LICENSING_AUDIT.txt](LICENSING_AUDIT.txt)
for a full dependency license inventory.

---

## 📞 Contact & Support

- **Repository**: [github.com/obstreperous-ai/rust-slint-password-saver](https://github.com/obstreperous-ai/rust-slint-password-saver)
- **Issues**: [GitHub Issues](https://github.com/obstreperous-ai/rust-slint-password-saver/issues)
- **Discussions**: [GitHub Discussions](https://github.com/obstreperous-ai/rust-slint-password-saver/discussions)

---

## 🙏 Acknowledgments

- **[Slint](https://slint.dev/)** - Modern UI framework for Rust
- **Rust Cryptography Working Group** - For excellent cryptography crates
- **RustSec Advisory Database** - For security vulnerability tracking
- **GitHub Actions** - For CI/CD infrastructure

---

**⚠️ Disclaimer**: This is an educational/experimental project. While it implements industry-standard encryption, it has not undergone professional security audit. Use at your own risk for non-critical password storage. For production use, consider established password managers like Bitwarden, 1Password, or KeePassXC.

