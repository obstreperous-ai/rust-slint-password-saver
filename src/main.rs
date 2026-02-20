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
mod clipboard;
mod errors;
mod integrity;
mod password_generator;
mod password_strength;
mod rate_limit;
mod recovery;
mod search;
mod secure_delete;
mod session;
mod storage;
mod update_checker;
mod validation;

#[cfg(windows)]
mod windows_permissions;

use audit_log::{get_audit_log_path, AuditEventType, AuditLogger};
use clipboard::{ClipboardConfig, SecureClipboard};
use lazy_static::lazy_static;
use log::warn;
use password_generator::{
    calculate_charset_size, calculate_entropy, generate_password, PasswordGeneratorConfig,
};
use password_strength::{
    assess_password_strength, validate_password_strength, PasswordRequirements, PasswordStrength,
};
use rate_limit::RateLimiter;
use recovery::EmergencyRecovery;
use search::{search_entries, sort_entries, SearchConfig, SortCriteria};
use session::SessionManager;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage::{PasswordEntry, PasswordStorage};
use subtle::ConstantTimeEq;
use update_checker::UpdateChecker;
use validation::{validate_master_password, validate_password, validate_title, validate_username};

slint::include_modules!();

// Global rate limiter instance
// Note: Using lazy_static for compatibility with Rust 1.70+
lazy_static! {
    static ref RATE_LIMITER: RateLimiter = RateLimiter::new();
    static ref SESSION_MANAGER: Arc<SessionManager> = Arc::new(SessionManager::new(5)); // 5 minute timeout
    static ref CLIPBOARD: Arc<Mutex<Option<SecureClipboard>>> = Arc::new(Mutex::new(None));
    static ref CLIPBOARD_CONFIG: ClipboardConfig = ClipboardConfig::default();
}

/// Maximum number of password entries to display in status message
const MAX_DISPLAY_ENTRIES: usize = 5;

/// Status message for generated password copied to clipboard
const GENERATED_PASSWORD_COPIED_MESSAGE: &str =
    "Generated password copied to clipboard. Paste it into the Password field.";

// Password strength indicator colors (matching design guide)
/// Color for very weak passwords (Vermillion - error color)
const STRENGTH_COLOR_VERY_WEAK: (u8, u8, u8) = (193, 68, 14);
/// Color for weak to medium passwords (Warning color)
const STRENGTH_COLOR_WEAK_MEDIUM: (u8, u8, u8) = (184, 134, 11);
/// Color for strong to excellent passwords (Forest Green - success color)
const STRENGTH_COLOR_STRONG: (u8, u8, u8) = (45, 80, 22);

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

    // Shared state for loaded password entries (for search/filter functionality)
    let loaded_entries: Arc<Mutex<Vec<PasswordEntry>>> = Arc::new(Mutex::new(Vec::new()));

    // Automatic integrity check on startup if database exists
    let storage = PasswordStorage::new(storage_path.clone());
    if storage.exists() {
        match storage.verify_integrity() {
            Ok(report) if !report.is_healthy() => {
                let issues_str = report.issues().join(", ");
                warn!(
                    "Database integrity issues detected on startup: {}",
                    issues_str
                );
                ui.set_status_is_error(true);
                ui.set_status_message(
                    format!("⚠️ Database integrity warning: {}", issues_str).into(),
                );
            }
            Err(e) => {
                warn!("Failed to verify database integrity: {}", e.debug_message());
            }
            _ => {
                // Database is healthy
            }
        }
    }

    // Start background thread to check for timeout
    let ui_weak_timeout = ui.as_weak();
    let session_manager = SESSION_MANAGER.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));

            // Check if UI is still alive, exit thread if not
            let Some(ui) = ui_weak_timeout.upgrade() else {
                break; // UI is gone, exit thread
            };

            if session_manager.should_lock() && !session_manager.is_locked() {
                session_manager.lock();
                ui.set_is_locked(true);
            }

            // Update countdown timer (only show when less than 60 seconds remaining)
            let time_left = session_manager.time_until_lock();
            // Safely convert u64 to i32, capping at i32::MAX
            let seconds = time_left.as_secs().try_into().unwrap_or(i32::MAX);
            ui.set_seconds_until_lock(seconds);
        }
    });

    // Set up save password callback
    // This is called when the user clicks "Save Password" button
    let ui_weak = ui.as_weak();
    let storage_path_clone = storage_path.clone();
    ui.on_save_password(move |master_password, title, username, password| {
        // Record user activity
        SESSION_MANAGER.record_activity();

        if let Some(ui) = ui_weak.upgrade() {
            // Validate master password
            if let Err(e) = validate_master_password(&master_password) {
                ui.set_status_message(format!("Invalid master password: {}", e).into());
                return;
            }

            // Validate title
            if let Err(e) = validate_title(&title) {
                ui.set_status_is_error(true);
                ui.set_status_message(format!("Invalid title: {}", e).into());
                return;
            }

            // Validate username
            if let Err(e) = validate_username(&username) {
                ui.set_status_is_error(true);
                ui.set_status_message(format!("Invalid username: {}", e).into());
                return;
            }

            // Validate password
            if let Err(e) = validate_password(&password) {
                ui.set_status_is_error(true);
                ui.set_status_message(format!("Invalid password: {}", e).into());
                return;
            }

            let storage = PasswordStorage::new(storage_path_clone.clone());

            // Check if this is first-time use
            let is_first_use = !storage.exists();

            // Validate master password strength on first use (when no storage file exists)
            // This ensures new users create strong master passwords
            if is_first_use {
                let requirements = PasswordRequirements::default();
                match validate_password_strength(&master_password, &requirements) {
                    Ok(strength) if strength >= PasswordStrength::Strong => {
                        // Password is strong enough, continue
                    }
                    Ok(strength) => {
                        // Password meets basic requirements but is not strong enough
                        ui.set_status_is_error(true);
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
                        ui.set_status_is_error(true);
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
            // On first use, also save recovery data
            if is_first_use {
                // Generate recovery codes for first-time setup
                let recovery = EmergencyRecovery::create(&master_password);
                let recovery_codes = recovery.get_codes();
                let recovery_hashes = recovery.get_code_hashes();
                let recovery_key = recovery.get_recovery_key();

                // Save entries with recovery data
                match storage.save_entries_with_recovery(&entries, &master_password, recovery_hashes, &recovery_key) {
                    Ok(()) => {
                        // Show recovery codes to user
                        ui.set_recovery_code_1(recovery_codes[0].clone().into());
                        ui.set_recovery_code_2(recovery_codes[1].clone().into());
                        ui.set_recovery_code_3(recovery_codes[2].clone().into());
                        ui.set_show_recovery_setup(true);
                        ui.set_status_is_error(false);
                        ui.set_status_message(format!("Password saved for: {}. Please save your recovery codes!", title).into());
                    }
                    Err(e) => {
                        // Show generic message to user
                        ui.set_status_is_error(true);
                        ui.set_status_message(e.user_message().into());
                        // Log detailed error for debugging
                        eprintln!("Save entries with recovery failed: {}", e.debug_message());
                    }
                }
            } else {
                // Not first use, save normally
                match storage.save_entries(&entries, &master_password) {
                    Ok(()) => {
                        ui.set_status_is_error(false);
                        ui.set_status_message(format!("Password saved for: {}", title).into());
                    }
                    Err(e) => {
                        // Show generic message to user
                        ui.set_status_is_error(true);
                        ui.set_status_message(e.user_message().into());
                        // Log detailed error for debugging
                        eprintln!("Save entries failed: {}", e.debug_message());
                    }
                }
            }
        }
    });

    // Set up password strength check callback
    // This is called when the user types in the password field
    let ui_weak = ui.as_weak();
    ui.on_check_password_strength(move |password| {
        if let Some(ui) = ui_weak.upgrade() {
            // Empty password - clear the indicator
            if password.is_empty() {
                ui.set_password_strength_text("".into());
                ui.set_password_strength_color(slint::Color::from_argb_u8(0, 0, 0, 0));
                return;
            }

            // Assess password strength using zxcvbn
            let (strength, description) = assess_password_strength(&password);

            // Map strength to colors based on design guide
            let color = match strength {
                PasswordStrength::VeryWeak => {
                    let (r, g, b) = STRENGTH_COLOR_VERY_WEAK;
                    slint::Color::from_rgb_u8(r, g, b)
                }
                PasswordStrength::Weak | PasswordStrength::Medium => {
                    let (r, g, b) = STRENGTH_COLOR_WEAK_MEDIUM;
                    slint::Color::from_rgb_u8(r, g, b)
                }
                PasswordStrength::Strong | PasswordStrength::VeryStrong => {
                    let (r, g, b) = STRENGTH_COLOR_STRONG;
                    slint::Color::from_rgb_u8(r, g, b)
                }
            };

            ui.set_password_strength_text(description.into());
            ui.set_password_strength_color(color);
        }
    });

    // Set up load passwords callback
    // This is called when the user clicks "Load Passwords" button
    let ui_weak = ui.as_weak();
    let storage_path_clone = storage_path.clone();
    let loaded_entries_clone = loaded_entries.clone();
    ui.on_load_passwords(move |master_password| {
        // Record user activity
        SESSION_MANAGER.record_activity();

        if let Some(ui) = ui_weak.upgrade() {
            // Validate master password
            if let Err(e) = validate_master_password(&master_password) {
                ui.set_status_is_error(true);
                ui.set_status_message(format!("Invalid master password: {}", e).into());
                return;
            }

            // Check rate limit before attempting decryption
            if let Err(e) = RATE_LIMITER.check_and_record_attempt() {
                ui.set_status_is_error(true);
                ui.set_status_message(e.into());
                return;
            }

            let storage = PasswordStorage::new(storage_path_clone.clone());

            if !storage.exists() {
                ui.set_status_is_error(false);
                ui.set_status_message("No passwords stored yet".into());
                return;
            }

            match storage.load_entries(&master_password) {
                Ok(entries) => {
                    // Clear rate limiter on successful authentication
                    RATE_LIMITER.record_success();

                    let count = entries.len();

                    // Store entries in memory for search/filter operations
                    // We need a full clone to maintain a searchable cache
                    {
                        let mut loaded = loaded_entries_clone.lock().unwrap_or_else(|poisoned| {
                            warn!("Loaded entries mutex poisoned, recovering");
                            poisoned.into_inner()
                        });
                        loaded.clone_from(&entries);
                    }

                    // Update UI with counts (cap at 999999 for display purposes)
                    let max_display = 999_999;
                    ui.set_total_count(count.try_into().unwrap_or(max_display));
                    ui.set_filtered_count(count.try_into().unwrap_or(max_display));

                    // Populate password entries for display in UI list
                    let ui_entries: Vec<_> = entries
                        .iter()
                        .map(|entry| PasswordEntryData {
                            title: entry.title.clone().into(),
                            username: entry.username.clone().into(),
                            password: entry.password.clone().into(),
                        })
                        .collect();

                    let model = std::rc::Rc::new(slint::VecModel::from(ui_entries));
                    ui.set_password_entries(model.into());

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
                    ui.set_status_is_error(false);
                    ui.set_status_message(message.into());
                }
                Err(e) => {
                    // Show generic message to user
                    ui.set_status_is_error(true);
                    ui.set_status_message(e.user_message().into());
                    // Log detailed error for debugging
                    eprintln!("Load passwords failed: {}", e.debug_message());
                }
            }
        }
    });

    // Set up unlock callback
    // This is called when the user tries to unlock the session
    let ui_weak = ui.as_weak();
    let storage_path_clone = storage_path.clone();
    ui.on_unlock(move |password| {
        if let Some(ui) = ui_weak.upgrade() {
            // Validate master password
            if let Err(e) = validate_master_password(&password) {
                ui.set_status_is_error(true);
                ui.set_status_message(format!("Invalid password: {}", e).into());
                return;
            }

            // Check rate limit before attempting unlock
            if let Err(e) = RATE_LIMITER.check_and_record_attempt() {
                ui.set_status_is_error(true);
                ui.set_status_message(e.into());
                return;
            }

            let storage = PasswordStorage::new(storage_path_clone.clone());

            // Verify password by attempting to load entries
            // This ensures user enters correct master password to unlock
            if storage.exists() {
                match storage.load_entries(&password) {
                    Ok(_) => {
                        // Password is correct, unlock session
                        RATE_LIMITER.record_success();
                        SESSION_MANAGER.record_activity();
                        ui.set_is_locked(false);
                        ui.set_status_is_error(false);
                        ui.set_status_message("Session unlocked successfully".into());
                    }
                    Err(e) => {
                        // Wrong password, remain locked
                        ui.set_status_is_error(true);
                        ui.set_status_message(e.user_message().into());
                        eprintln!("Unlock failed: {}", e.debug_message());
                    }
                }
            } else {
                // No storage file exists yet, can't verify password
                ui.set_status_is_error(false);
                ui.set_status_message("No passwords stored yet. Cannot verify unlock.".into());
            }
        }
    });

    // Set up copy password callback
    // This is called when the user wants to copy a password to clipboard
    let ui_weak = ui.as_weak();
    ui.on_copy_password(move |password| {
        // Record user activity
        SESSION_MANAGER.record_activity();

        if let Some(ui) = ui_weak.upgrade() {
            // Initialize clipboard if not already done
            let mut clipboard_guard = CLIPBOARD.lock().unwrap_or_else(|poisoned| {
                warn!("Clipboard mutex poisoned, recovering");
                poisoned.into_inner()
            });
            if clipboard_guard.is_none() {
                match SecureClipboard::new(CLIPBOARD_CONFIG.clear_timeout_seconds) {
                    Ok(clipboard) => {
                        *clipboard_guard = Some(clipboard);
                    }
                    Err(e) => {
                        ui.set_status_is_error(true);
                        ui.set_status_message(
                            format!("Failed to initialize clipboard: {}", e).into(),
                        );
                        return;
                    }
                }
            }

            // Copy password to clipboard with auto-clear
            if let Some(clipboard) = clipboard_guard.as_mut() {
                match clipboard.copy_with_autoclear(&password) {
                    Ok(()) => {
                        ui.set_status_is_error(false);
                        ui.set_status_message(
                            format!(
                                "Password copied to clipboard (will auto-clear in {}s)",
                                CLIPBOARD_CONFIG.clear_timeout_seconds
                            )
                            .into(),
                        );
                    }
                    Err(e) => {
                        ui.set_status_is_error(true);
                        ui.set_status_message(format!("Failed to copy password: {}", e).into());
                    }
                }
            }
        }
    });

    // Set up copy entry password callback (by index)
    // This is called when user clicks copy button next to a password entry
    let ui_weak = ui.as_weak();
    let loaded_entries_clone = loaded_entries.clone();
    ui.on_copy_entry_password(move |index| {
        // Record user activity
        SESSION_MANAGER.record_activity();

        if let Some(ui) = ui_weak.upgrade() {
            // Get password from loaded entries at the specified index
            let password = {
                let entries = loaded_entries_clone.lock().unwrap_or_else(|poisoned| {
                    warn!("Loaded entries mutex poisoned, recovering");
                    poisoned.into_inner()
                });
                #[allow(clippy::cast_sign_loss)]
                let idx = index as usize;
                if idx < entries.len() {
                    Some(entries[idx].password.clone())
                } else {
                    None
                }
            };

            if let Some(password) = password {
                // Initialize clipboard if not already done
                let mut clipboard_guard = CLIPBOARD.lock().unwrap_or_else(|poisoned| {
                    warn!("Clipboard mutex poisoned, recovering");
                    poisoned.into_inner()
                });
                if clipboard_guard.is_none() {
                    match SecureClipboard::new(CLIPBOARD_CONFIG.clear_timeout_seconds) {
                        Ok(clipboard) => {
                            *clipboard_guard = Some(clipboard);
                        }
                        Err(e) => {
                            ui.set_status_is_error(true);
                            ui.set_status_message(
                                format!("Failed to initialize clipboard: {}", e).into(),
                            );
                            return;
                        }
                    }
                }

                // Copy password to clipboard with auto-clear
                if let Some(clipboard) = clipboard_guard.as_mut() {
                    match clipboard.copy_with_autoclear(&password) {
                        Ok(()) => {
                            ui.set_status_is_error(false);
                            ui.set_status_message(
                                format!(
                                    "Password copied to clipboard (will auto-clear in {}s)",
                                    CLIPBOARD_CONFIG.clear_timeout_seconds
                                )
                                .into(),
                            );
                        }
                        Err(e) => {
                            ui.set_status_is_error(true);
                            ui.set_status_message(format!("Failed to copy password: {}", e).into());
                        }
                    }
                }
            } else {
                ui.set_status_is_error(true);
                ui.set_status_message("Invalid password entry index".into());
            }
        }
    });

    // Set up generate password callback
    let ui_weak = ui.as_weak();
    ui.on_generate_password(move || {
        // Record user activity
        SESSION_MANAGER.record_activity();

        if let Some(ui) = ui_weak.upgrade() {
            // Get configuration from UI
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let config = PasswordGeneratorConfig {
                length: ui.get_generator_length() as usize,
                use_uppercase: ui.get_generator_use_uppercase(),
                use_lowercase: ui.get_generator_use_lowercase(),
                use_digits: ui.get_generator_use_digits(),
                use_special: ui.get_generator_use_special(),
                exclude_ambiguous: ui.get_generator_exclude_ambiguous(),
            };

            match generate_password(&config) {
                Ok(password) => {
                    ui.set_generated_password(password.clone().into());

                    // Calculate and display entropy
                    let charset_size = calculate_charset_size(&config);
                    let entropy = calculate_entropy(&password, charset_size);

                    let strength_text = if entropy >= 80.0 {
                        "Very Strong"
                    } else if entropy >= 60.0 {
                        "Strong"
                    } else if entropy >= 40.0 {
                        "Moderate"
                    } else {
                        "Weak"
                    };

                    ui.set_password_entropy_text(
                        format!("Entropy: {:.1} bits ({})", entropy, strength_text).into(),
                    );
                }
                Err(e) => {
                    ui.set_status_is_error(true);
                    ui.set_status_message(format!("Password generation failed: {}", e).into());
                    ui.set_generated_password("".into());
                    ui.set_password_entropy_text("".into());
                }
            }
        }
    });

    // Set up use generated password callback
    // This copies the generated password to the password input field
    let ui_weak = ui.as_weak();
    ui.on_use_generated_password(move |password| {
        // Record user activity
        SESSION_MANAGER.record_activity();

        if let Some(ui) = ui_weak.upgrade() {
            // Find the password input field in the "Add New Password" section
            // We need to set it through a property or find another way
            // For now, we'll just copy to clipboard and show a message
            ui.set_status_is_error(false);
            ui.set_status_message(GENERATED_PASSWORD_COPIED_MESSAGE.into());

            // Copy to clipboard
            let mut clipboard_guard = CLIPBOARD.lock().unwrap_or_else(|poisoned| {
                warn!("Clipboard mutex poisoned, recovering");
                poisoned.into_inner()
            });
            if clipboard_guard.is_none() {
                match SecureClipboard::new(CLIPBOARD_CONFIG.clear_timeout_seconds) {
                    Ok(clipboard) => {
                        *clipboard_guard = Some(clipboard);
                    }
                    Err(e) => {
                        ui.set_status_is_error(true);
                        ui.set_status_message(
                            format!("Failed to initialize clipboard: {}", e).into(),
                        );
                        return;
                    }
                }
            }

            if let Some(clipboard) = clipboard_guard.as_mut() {
                match clipboard.copy_with_autoclear(&password) {
                    Ok(()) => {
                        ui.set_status_is_error(false);
                        ui.set_status_message(GENERATED_PASSWORD_COPIED_MESSAGE.into());
                    }
                    Err(e) => {
                        ui.set_status_is_error(true);
                        ui.set_status_message(format!("Failed to copy password: {}", e).into());
                    }
                }
            }
        }
    });

    // Set up search passwords callback
    // This is called when the user types in the search box or clicks Search
    let ui_weak = ui.as_weak();
    let loaded_entries_clone = loaded_entries.clone();
    ui.on_search_passwords(move |query| {
        // Record user activity
        SESSION_MANAGER.record_activity();

        if let Some(ui) = ui_weak.upgrade() {
            let entries = loaded_entries_clone.lock().unwrap_or_else(|poisoned| {
                warn!("Loaded entries mutex poisoned, recovering");
                poisoned.into_inner()
            });

            let config = SearchConfig::default();
            let matching_indices = search_entries(&entries, query.as_str(), &config);

            // Update UI with filtered count (cap at 999999 for display purposes)
            let max_display = 999_999;
            let filtered_count: i32 = matching_indices.len().try_into().unwrap_or(max_display);
            let total_count: i32 = entries.len().try_into().unwrap_or(max_display);

            ui.set_filtered_count(filtered_count);
            ui.set_total_count(total_count);

            // Update password entries list with filtered results
            let filtered_entries: Vec<_> = matching_indices
                .iter()
                .filter_map(|&idx| entries.get(idx))
                .map(|entry| PasswordEntryData {
                    title: entry.title.clone().into(),
                    username: entry.username.clone().into(),
                    password: entry.password.clone().into(),
                })
                .collect();

            let model = std::rc::Rc::new(slint::VecModel::from(filtered_entries));
            ui.set_password_entries(model.into());

            // Display filtered entries in status message
            if query.is_empty() {
                ui.set_status_is_error(false);
                ui.set_status_message(format!("Showing all {} passwords", total_count).into());
            } else if matching_indices.is_empty() {
                ui.set_status_is_error(false);
                ui.set_status_message(format!("No passwords match '{}'", query).into());
            } else {
                let mut message = format!(
                    "Found {} password(s) matching '{}':\n",
                    filtered_count, query
                );

                // Display first few matching entries
                for &idx in matching_indices.iter().take(MAX_DISPLAY_ENTRIES) {
                    if let Some(entry) = entries.get(idx) {
                        let _ = write!(message, "- {}", entry.title);
                        if !entry.username.is_empty() {
                            let _ = write!(message, " ({})", entry.username);
                        }
                        message.push('\n');
                    }
                }

                if matching_indices.len() > MAX_DISPLAY_ENTRIES {
                    let _ = write!(
                        message,
                        "... and {} more",
                        matching_indices.len() - MAX_DISPLAY_ENTRIES
                    );
                }

                ui.set_status_is_error(false);
                ui.set_status_message(message.into());
            }
        }
    });

    // Set up sort passwords callback
    // This is called when the user selects a different sort option
    let ui_weak = ui.as_weak();
    let loaded_entries_clone = loaded_entries.clone();
    ui.on_sort_passwords(move |sort_option| {
        // Record user activity
        SESSION_MANAGER.record_activity();

        if let Some(ui) = ui_weak.upgrade() {
            let mut entries = loaded_entries_clone.lock().unwrap_or_else(|poisoned| {
                warn!("Loaded entries mutex poisoned, recovering");
                poisoned.into_inner()
            });

            let criteria = match sort_option {
                1 => SortCriteria::TitleDescending,
                2 => SortCriteria::DateCreatedNewest,
                3 => SortCriteria::DateCreatedOldest,
                4 => SortCriteria::UsernameAscending,
                _ => SortCriteria::TitleAscending, // 0 or any other value defaults to TitleAscending
            };

            sort_entries(&mut entries, criteria);

            // Update password entries list with sorted results
            let sorted_entries: Vec<_> = entries
                .iter()
                .map(|entry| PasswordEntryData {
                    title: entry.title.clone().into(),
                    username: entry.username.clone().into(),
                    password: entry.password.clone().into(),
                })
                .collect();

            let model = std::rc::Rc::new(slint::VecModel::from(sorted_entries));
            ui.set_password_entries(model.into());

            let count = entries.len();
            let mut message = format!("Sorted {} password(s):\n", count);

            // Display first few entries after sorting
            for entry in entries.iter().take(MAX_DISPLAY_ENTRIES) {
                let _ = write!(message, "- {}", entry.title);
                if !entry.username.is_empty() {
                    let _ = write!(message, " ({})", entry.username);
                }
                message.push('\n');
            }

            if count > MAX_DISPLAY_ENTRIES {
                let _ = write!(message, "... and {} more", count - MAX_DISPLAY_ENTRIES);
            }

            ui.set_status_is_error(false);
            ui.set_status_message(message.into());
        }
    });

    // Set up update check callback (manual check)
    let ui_weak = ui.as_weak();
    ui.on_check_for_updates(move || {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_checking_for_updates(true);
            ui.set_status_is_error(false);
            ui.set_status_message("Checking for updates...".into());

            // Spawn a thread for blocking update check
            let ui_weak_inner = ui.as_weak();
            std::thread::spawn(move || {
                let checker = UpdateChecker::new();

                match checker.check_for_updates() {
                    Ok(Some(update_info)) => {
                        if let Some(ui) = ui_weak_inner.upgrade() {
                            ui.set_update_available(true);
                            ui.set_latest_version(update_info.latest_version.clone().into());
                            ui.set_is_security_update(update_info.security_update);
                            ui.set_download_url(update_info.download_url.clone().into());
                            ui.set_checking_for_updates(false);

                            let message = if update_info.security_update {
                                format!(
                                    "⚠️ Security update available: {}",
                                    update_info.latest_version
                                )
                            } else {
                                format!("New version available: {}", update_info.latest_version)
                            };
                            ui.set_status_is_error(false);
                            ui.set_status_message(message.into());
                        }
                    }
                    Ok(None) => {
                        if let Some(ui) = ui_weak_inner.upgrade() {
                            ui.set_checking_for_updates(false);
                            ui.set_status_is_error(false);
                            ui.set_status_message("You are running the latest version".into());
                        }
                    }
                    Err(e) => {
                        warn!("Failed to check for updates: {}", e);
                        if let Some(ui) = ui_weak_inner.upgrade() {
                            ui.set_checking_for_updates(false);
                            ui.set_status_is_error(true);
                            ui.set_status_message(
                                format!("Failed to check for updates: {}", e).into(),
                            );
                        }
                    }
                }
            });
        }
    });

    // Set up open release page callback
    let ui_weak = ui.as_weak();
    ui.on_open_release_page(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let url = ui.get_download_url();
            if let Err(e) = webbrowser::open(url.as_ref()) {
                warn!("Failed to open browser: {}", e);
                ui.set_status_is_error(true);
                ui.set_status_message(format!("Failed to open browser: {}", e).into());
            }
        }
    });

    // Set up copy recovery codes callback
    let ui_weak = ui.as_weak();
    ui.on_copy_recovery_codes(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let codes = format!(
                "Recovery Code 1: {}\nRecovery Code 2: {}\nRecovery Code 3: {}",
                ui.get_recovery_code_1(),
                ui.get_recovery_code_2(),
                ui.get_recovery_code_3()
            );

            // Initialize clipboard if needed
            let mut clipboard_guard = CLIPBOARD.lock().unwrap_or_else(|poisoned| {
                warn!("Clipboard mutex poisoned, recovering");
                poisoned.into_inner()
            });
            if clipboard_guard.is_none() {
                match SecureClipboard::new(CLIPBOARD_CONFIG.clear_timeout_seconds) {
                    Ok(clipboard) => {
                        *clipboard_guard = Some(clipboard);
                    }
                    Err(e) => {
                        ui.set_status_is_error(true);
                        ui.set_status_message(
                            format!("Failed to initialize clipboard: {}", e).into(),
                        );
                        return;
                    }
                }
            }

            // Copy codes to clipboard (don't auto-clear recovery codes)
            if let Some(clipboard) = clipboard_guard.as_mut() {
                match clipboard.copy_with_autoclear(&codes) {
                    Ok(()) => {
                        ui.set_status_is_error(false);
                        ui.set_status_message("Recovery codes copied to clipboard!".into());
                    }
                    Err(e) => {
                        ui.set_status_is_error(true);
                        ui.set_status_message(format!("Failed to copy codes: {}", e).into());
                    }
                }
            }
        }
    });

    // Set up print recovery codes callback
    let ui_weak = ui.as_weak();
    ui.on_print_recovery_codes(move || {
        if let Some(ui) = ui_weak.upgrade() {
            // For now, just show a message that printing is not yet implemented
            // In a full implementation, this would open a print dialog
            ui.set_status_is_error(false);
            ui.set_status_message(
                "Print functionality: Please copy the codes and print them manually.".into(),
            );
        }
    });

    // Set up recover with code callback
    let ui_weak = ui.as_weak();
    let storage_path_clone = storage_path.clone();
    ui.on_recover_with_code(move |recovery_code| {
        if let Some(ui) = ui_weak.upgrade() {
            // Check rate limit for recovery attempts
            if let Err(e) = RATE_LIMITER.check_and_record_attempt() {
                ui.set_status_is_error(true);
                ui.set_status_message(e.into());
                return;
            }

            let storage = PasswordStorage::new(storage_path_clone.clone());

            // Check if recovery data exists
            match storage.load_recovery_data() {
                Ok(Some((hashes, _encrypted_key))) => {
                    // Hash the provided recovery code
                    let mut hash_computer = Sha256::new();
                    hash_computer.update(recovery_code.as_bytes());
                    let code_hash = hex::encode(hash_computer.finalize());

                    // Check if the hash matches any stored hash
                    let hash_matches = hashes.iter().any(|stored_hash| {
                        stored_hash.as_bytes().ct_eq(code_hash.as_bytes()).into()
                    });

                    if hash_matches {
                        // Success! Clear rate limiter
                        RATE_LIMITER.record_success();

                        // Close recovery login dialog
                        ui.set_show_recovery_login(false);

                        // TODO: In current implementation, recovery codes verify identity but
                        // user still needs to know their master password to decrypt.
                        // Future enhancement: Store encrypted database key with recovery key
                        // to allow full recovery without master password.

                        // Inform user of successful verification
                        ui.set_status_is_error(false);
                        ui.set_status_message(
                            "✅ Recovery code verified! You are authenticated.\nEnter your master password to access passwords, or change it if forgotten.".into()
                        );

                        // Unlock the session UI
                        ui.set_is_locked(false);
                    } else {
                        ui.set_status_is_error(true);
                        ui.set_status_message("❌ Invalid recovery code. Please try again.".into());
                    }
                }
                Ok(None) => {
                    ui.set_status_is_error(false);
                    ui.set_status_message(
                        "No recovery data found. This database was created before recovery was added.".into()
                    );
                }
                Err(e) => {
                    ui.set_status_is_error(true);
                    ui.set_status_message(e.user_message().into());
                    eprintln!("Recovery data load failed: {}", e.debug_message());
                }
            }
        }
    });

    // Check for updates on startup (non-blocking)
    // Give the UI time to fully initialize before checking (2 seconds)
    // This prevents blocking the initial UI render and ensures a smooth startup experience
    let ui_weak = ui.as_weak();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));

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
                // No update available - silently continue
            }
            Err(e) => {
                warn!("Failed to check for updates on startup: {}", e);
                // Don't show error to user on automatic startup check
            }
        }
    });

    // Run the UI event loop
    ui.run()
}
