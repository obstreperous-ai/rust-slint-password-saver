#!/bin/bash

# Setup script for Rust + Slint devcontainer
# This script installs all necessary dependencies for cross-platform development

set -e

echo "🚀 Setting up Rust + Slint development environment..."

# Update package lists
echo "📦 Updating package lists..."
sudo apt-get update

# Install Slint dependencies for Linux
echo "🎨 Installing Slint UI framework dependencies..."
sudo apt-get install -y \
    cmake \
    libfontconfig1-dev \
    libxcb-shape0-dev \
    libxcb-xfixes0-dev \
    libxkbcommon-dev \
    libxcb-render0-dev \
    libxcb-render-util0-dev \
    libxcb-randr0-dev \
    libxcb-xinerama0-dev \
    libxcb-xinput-dev \
    libxcb-cursor-dev \
    libxcb-keysyms1-dev \
    libxcb-image0-dev \
    libxcb-shm0-dev \
    libxcb-sync-dev \
    libxcb-xkb-dev \
    libgl1-mesa-dev \
    libglib2.0-dev

# Install additional build tools
echo "🔧 Installing build tools..."
sudo apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential

# Install Rust components
echo "🦀 Installing Rust components..."
rustup component add rustfmt clippy rust-src

# Install cargo tools for development
echo "📦 Installing cargo development tools..."

# Install cargo-watch for live reloading
cargo install cargo-watch --quiet || echo "cargo-watch already installed or failed to install"

# Install cargo-audit for security vulnerability scanning
cargo install cargo-audit --quiet || echo "cargo-audit already installed or failed to install"

# Install cargo-edit for easy dependency management
cargo install cargo-edit --quiet || echo "cargo-edit already installed or failed to install"

# Install cargo-outdated to check for outdated dependencies
cargo install cargo-outdated --quiet || echo "cargo-outdated already installed or failed to install"

# Note: cargo-tree is built into Cargo since 1.44.0, no separate installation needed

# Update cargo audit database
echo "🔒 Updating security audit database..."
cargo audit --version && cargo audit || echo "Cargo audit check skipped"

# Clean up
echo "🧹 Cleaning up..."
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*

# Build the project to cache dependencies
echo "🏗️  Building project to cache dependencies..."
cargo fetch || echo "Failed to fetch dependencies, but continuing..."

echo "✅ Setup complete! Your development environment is ready."
echo ""
echo "Available tools:"
echo "  - cargo-watch: Live reloading (cargo watch -x run)"
echo "  - cargo-audit: Security vulnerability scanning"
echo "  - cargo-edit: Easy dependency management"
echo "  - cargo-outdated: Check for outdated dependencies"
echo "  - clippy: Rust linter"
echo "  - rustfmt: Code formatter"
echo ""
echo "Get started with: cargo run"
