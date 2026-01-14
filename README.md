# rust-slint-password-saver

A cross-platform desktop password saver application built with Rust and Slint UI framework. This application provides secure password storage using industry-standard encryption algorithms.

## Features

- **Modern UI**: Built with Slint UI framework for a native look and feel
- **Secure Storage**: Uses Argon2 for password hashing and AES-256-GCM for encryption
- **Cross-Platform**: Targets macOS and Linux
- **Rust-Powered**: Leverages Rust's safety and performance guarantees

## Dependencies

The application uses the following key dependencies:

- **[Slint](https://slint.dev/)** (v1.14.1): Modern UI framework
- **[argon2](https://crates.io/crates/argon2)** (v0.5.3): Password hashing
- **[aes-gcm](https://crates.io/crates/aes-gcm)** (v0.10.3): Encryption (AES-256-GCM)
- **[serde](https://crates.io/crates/serde)** (v1.0): Serialization for data storage

## Project Structure

```
rust-slint-password-saver/
├── Cargo.toml           # Project dependencies and metadata
├── build.rs             # Build script for Slint compilation
├── src/
│   ├── main.rs         # Application entry point
│   ├── storage.rs      # Encrypted storage logic
│   └── ui/
│       └── main.slint  # UI definition
└── README.md
```

## Building

### Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)

On macOS, you may also need:
```bash
brew install cmake
```

On Linux (Ubuntu/Debian), you may need:
```bash
sudo apt-get install cmake libfontconfig1-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

### Build the Project

```bash
cargo build --release
```

## Running

```bash
cargo run --release
```

## Testing

Run the test suite:

```bash
cargo test
```

## Security Features

- **Password Hashing**: Master passwords are hashed using Argon2, a memory-hard function designed to resist GPU cracking attacks
- **Encryption**: Password entries are encrypted using AES-256-GCM, providing both confidentiality and authenticity
- **Secure Storage**: All sensitive data is encrypted before being written to disk

## Platform Support

- ✅ macOS
- ✅ Linux

## Development

The project follows standard Rust project conventions:

- Source code is in `src/`
- UI files are in `src/ui/`
- Tests are co-located with the code they test
- Build artifacts go to `target/`

### Code Quality Tools

This project uses several code quality tools to maintain high standards:
- **rustfmt** for code formatting
- **clippy** for linting
- **cargo-audit** for security vulnerability scanning
- **pre-commit hooks** for automated checks

For detailed information about code quality tools and how to use them, see [CODE_QUALITY.md](CODE_QUALITY.md).

## License

MIT License - See LICENSE file for details

## Contributing

This is an experimental project. Feel free to open issues or submit pull requests.

