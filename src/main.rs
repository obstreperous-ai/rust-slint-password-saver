//! # Password Saver Application
//!
//! A cross-platform desktop password manager built with Slint UI framework.
//!
//! This application provides a graphical interface for securely storing and
//! retrieving passwords using military-grade encryption (Argon2 + AES-256-GCM).
//!
//! ## Features
//!
//! - Save password entries with title, username, and password
//! - Load and view stored passwords
//! - All data encrypted with master password
//! - Rate limiting to prevent brute-force attacks
//! - Cross-platform support (macOS, Linux)
//! - Security audit logging for all operations
//!
//! ## Usage
//!
//! Run the application with:
//! ```bash
//! cargo run --release
//! ```

// Allow lazy_static for compatibility with Rust 1.70+
// Will migrate to std::sync::LazyLock when minimum version is 1.80+
#![allow(clippy::non_std_lazy_statics)]

mod audit_log;
mod errors;
mod password_strength;
mod rate_limit;
mod storage;
mod validation;

#[cfg(windows)]
mod windows_permissions;

use audit_log::{get_audit_log_path, AuditEventType, AuditLogger};
use lazy_static::lazy_static;
use log::warn;
use password_strength::{validate_password_strength, PasswordRequirements, PasswordStrength};
use rate_limit::RateLimiter;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use storage::{PasswordEntry, PasswordStorage};
use validation::{validate_master_password, validate_password, validate_title, validate_username};

slint::include_modules!();

// Global rate limiter instance
// Note: Using lazy_static for compatibility with Rust 1.70+
lazy_static! {
    static ref RATE_LIMITER: RateLimiter = RateLimiter::new();
}

/// Maximum number of password entries to display in status message
const MAX_DISPLAY_ENTRIES: usize = 5;

/// Get cross-platform path for storing encrypted passwords.
///
/// This function determines the appropriate location for password storage
/// based on the operating system:
/// - Unix-like systems (macOS, Linux): `~/.password_saver/passwords.enc`
/// - Windows: `%USERPROFILE%/.password_saver/passwords.enc`
///
/// # Returns
///
/// A `PathBuf` pointing to the storage file location. Parent directory
/// is created if it doesn't exist. On Unix systems, the directory is
/// created with secure permissions (0700).
///
/// # Platform Support
///
/// Works on macOS, Linux, and other Unix-like systems. Uses `HOME` environment
/// variable on Unix and `USERPROFILE` on Windows.
fn get_storage_path() -> PathBuf {
    // Try to get home directory from environment variables
    // On Unix: $HOME, on Windows: %USERPROFILE%
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| String::from("."));

    let mut path = PathBuf::from(home_dir);
    path.push(".password_saver");
    path.push("passwords.enc");

    // Create parent directory if it doesn't exist
    // This ensures ~/.password_saver/ exists before we try to write
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);

        // Set secure permissions on the directory (0700 on Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(parent, permissions);
        }

        // Set secure permissions on the directory (ACL on Windows)
        #[cfg(windows)]
        {
            use crate::windows_permissions::set_windows_directory_permissions;
            let _ = set_windows_directory_permissions(parent);
        }
    }

    path
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), slint::PlatformError> {
    // Initialize audit logging
    let audit_logger = AuditLogger::new(get_audit_log_path());
    let startup_entry = AuditLogger::create_entry(
        AuditEventType::ApplicationStartup,
        true,
        Some("Password Manager application started".to_string()),
    );
    if let Err(e) = audit_logger.log_event(&startup_entry) {
        warn!("Failed to log application startup: {}", e);
    }

    // Create and initialize the main UI window
    let ui = AppWindow::new()?;

    // Initialize storage with cross-platform path
    let storage_path = get_storage_path();

    // Set up save password callback
    // This is called when the user clicks "Save Password" button
    let ui_weak = ui.as_weak();
    let storage_path_clone = storage_path.clone();
    ui.on_save_password(move |master_password, title, username, password| {
        if let Some(ui) = ui_weak.upgrade() {
            // Validate master password
            if let Err(e) = validate_master_password(&master_password) {
                ui.set_status_message(format!("Invalid master password: {}", e).into());
                return;
            }

            // Validate title
            if let Err(e) = validate_title(&title) {
                ui.set_status_message(format!("Invalid title: {}", e).into());
                return;
            }

            // Validate username
            if let Err(e) = validate_username(&username) {
                ui.set_status_message(format!("Invalid username: {}", e).into());
                return;
            }

            // Validate password
            if let Err(e) = validate_password(&password) {
                ui.set_status_message(format!("Invalid password: {}", e).into());
                return;
            }

            let storage = PasswordStorage::new(storage_path_clone.clone());

            // Validate master password strength on first use (when no storage file exists)
            // This ensures new users create strong master passwords
            if !storage.exists() {
                let requirements = PasswordRequirements::default();
                match validate_password_strength(&master_password, &requirements) {
                    Ok(strength) if strength >= PasswordStrength::Strong => {
                        // Password is strong enough, continue
                    }
                    Ok(strength) => {
                        // Password meets basic requirements but is not strong enough
                        ui.set_status_message(
                            format!(
                                "Master password is too weak (strength: {:?}). Please use a stronger password with at least 12 characters, including uppercase, lowercase, digits, and special characters.",
                                strength
                            ).into()
                        );
                        return;
                    }
                    Err(e) => {
                        // Password fails basic requirements
                        ui.set_status_message(
                            format!("Master password validation failed: {}", e).into()
                        );
                        return;
                    }
                }
            }

            // Load existing entries or create new list
            // This allows adding to existing passwords without overwriting
            let mut entries = if storage.exists() {
                match storage.load_entries(&master_password) {
                    Ok(entries) => entries,
                    Err(e) => {
                        // Show generic message to user
                        ui.set_status_message(e.user_message().into());
                        // Log detailed error for debugging
                        eprintln!("Load entries failed: {}", e.debug_message());
                        return;
                    }
                }
            } else {
                Vec::new()
            };

            // Create new entry with current timestamp
            let new_entry = PasswordEntry {
                title: title.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            // Add new entry to the list
            entries.push(new_entry);

            // Save all entries (including new one) with encryption
            match storage.save_entries(&entries, &master_password) {
                Ok(()) => {
                    ui.set_status_message(format!("Password saved for: {}", title).into());
                }
                Err(e) => {
                    // Show generic message to user
                    ui.set_status_message(e.user_message().into());
                    // Log detailed error for debugging
                    eprintln!("Save entries failed: {}", e.debug_message());
                }
            }
        }
    });

    // Set up load passwords callback
    // This is called when the user clicks "Load Passwords" button
    let ui_weak = ui.as_weak();
    let storage_path_clone = storage_path.clone();
    ui.on_load_passwords(move |master_password| {
        if let Some(ui) = ui_weak.upgrade() {
            // Validate master password
            if let Err(e) = validate_master_password(&master_password) {
                ui.set_status_message(format!("Invalid master password: {}", e).into());
                return;
            }

            // Check rate limit before attempting decryption
            if let Err(e) = RATE_LIMITER.check_and_record_attempt() {
                ui.set_status_message(e.into());
                return;
            }

            let storage = PasswordStorage::new(storage_path_clone.clone());

            if !storage.exists() {
                ui.set_status_message("No passwords stored yet".into());
                return;
            }

            match storage.load_entries(&master_password) {
                Ok(entries) => {
                    // Clear rate limiter on successful authentication
                    RATE_LIMITER.record_success();

                    let count = entries.len();
                    let mut message = format!("Loaded {} password(s):\n", count);

                    // Display first few entries to avoid overwhelming the status area
                    for entry in entries.iter().take(MAX_DISPLAY_ENTRIES) {
                        let _ = write!(message, "- {}", entry.title);
                        if !entry.username.is_empty() {
                            let _ = write!(message, " ({})", entry.username);
                        }
                        message.push('\n');
                    }

                    // Show count of remaining entries if list is long
                    if entries.len() > MAX_DISPLAY_ENTRIES {
                        let _ = write!(
                            message,
                            "... and {} more",
                            entries.len() - MAX_DISPLAY_ENTRIES
                        );
                    }
                    ui.set_status_message(message.into());
                }
                Err(e) => {
                    // Show generic message to user
                    ui.set_status_message(e.user_message().into());
                    // Log detailed error for debugging
                    eprintln!("Load passwords failed: {}", e.debug_message());
                }
            }
        }
    });

    // Run the UI event loop
    ui.run()
}
