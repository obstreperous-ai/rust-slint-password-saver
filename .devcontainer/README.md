# Development Container Configuration

This directory contains the development container (devcontainer) configuration for the Rust Slint Password Saver project.

## What's Included

### Base Image
- **Microsoft's official Rust devcontainer image** with Rust stable toolchain pre-installed

### VS Code Extensions
- **rust-analyzer**: Rust language server for IDE features
- **Slint**: Official Slint UI framework extension for .slint file support
- **vscode-lldb**: Debugger for Rust applications
- **crates**: Helper for managing Cargo.toml dependencies
- **even-better-toml**: Enhanced TOML language support

### Development Tools
- **cargo-watch**: Automatic rebuild and rerun on file changes
- **cargo-audit**: Security vulnerability scanner for dependencies
- **cargo-edit**: Easy dependency management (add/rm/upgrade)
- **cargo-outdated**: Check for outdated dependencies
- **clippy**: Rust linter for catching common mistakes
- **rustfmt**: Code formatter for consistent style

### System Dependencies
All dependencies required for Slint UI framework on Linux:
- CMake for build system
- fontconfig for font rendering
- XCB libraries for X11 window system integration
- OpenGL libraries for graphics rendering
- GTK/GLib for additional UI support

### Features
- **GitHub CLI**: Pre-installed for GitHub integration
- **Zsh with Oh My Zsh**: Enhanced shell experience
- **Volume caching**: Cargo registry and build artifacts cached for faster rebuilds

## Usage

### Opening in VS Code
1. Install the "Dev Containers" extension in VS Code
2. Open the repository in VS Code
3. Click "Reopen in Container" when prompted (or use Command Palette: "Dev Containers: Reopen in Container")

### Opening in GitHub Codespaces
1. Navigate to the repository on GitHub
2. Click the "Code" button
3. Select "Codespaces" tab
4. Click "Create codespace on main" (or your desired branch)

### Common Development Commands

```bash
# Run the application
cargo run

# Run with automatic reload on file changes
cargo watch -x run

# Build the project
cargo build

# Run tests
cargo test

# Check for security vulnerabilities
cargo audit

# Check for outdated dependencies
cargo outdated

# Format code
cargo fmt

# Run linter
cargo clippy
```

## Security Features

The devcontainer includes cargo-audit, which is automatically run during setup to check for known security vulnerabilities in dependencies. This is particularly important for a password manager application.

Run security audits regularly:
```bash
cargo audit
```

## Performance Optimizations

### Caching
The devcontainer uses Docker volumes to cache:
- Cargo registry (`~/.cargo/registry`)
- Build artifacts (`target/`)

This significantly speeds up rebuilds and reduces download times.

### Live Reloading
Use `cargo watch -x run` for automatic recompilation and execution when source files change. This is especially useful during UI development.

## Troubleshooting

### Build Errors
If you encounter build errors related to missing libraries, ensure the setup script ran successfully:
```bash
bash .devcontainer/setup.sh
```

### Permission Issues
The container runs as the `vscode` user (non-root) for security. If you need to install additional system packages:
```bash
sudo apt-get update
sudo apt-get install <package-name>
```

### Slint UI Not Rendering
Ensure all XCB and OpenGL dependencies are installed. The setup script should handle this, but you can manually verify:
```bash
dpkg -l | grep -E "libxcb|libgl|libfontconfig"
```

## Customization

You can customize the devcontainer by editing `.devcontainer/devcontainer.json`:
- Add more VS Code extensions
- Install additional tools in `setup.sh`
- Adjust VS Code settings
- Add environment variables

## Cross-Platform Notes

This devcontainer is optimized for Linux-based containers and includes all dependencies needed for building Linux applications with Slint UI framework. The Slint framework itself is cross-platform and can target multiple platforms.

For building macOS binaries, you would need to:
1. Set up a macOS cross-compilation toolchain (not included in this devcontainer)
2. Use a macOS runner for actual builds
3. Or develop and test in this Linux container, then build for macOS on a Mac system

The current setup focuses on Linux development and testing in a containerized environment.
