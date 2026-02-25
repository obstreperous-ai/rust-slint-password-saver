//! # UI Handlers Module
//!
//! This module provides the [`UIHandlers`] struct that encapsulates all UI callback
//! logic extracted from the `main()` function. Each handler corresponds to a Slint
//! UI callback and contains the associated business logic.
//!
//! ## Design
//!
//! `UIHandlers` holds the shared application state (`storage_path`, `loaded_entries`,
//! `rate_limiter`, `session`, `clipboard`, `clipboard_config`) and exposes a handler
//! method for each UI callback. The handlers are registered in `main()` as thin closures
//! that delegate to the appropriate method.
//!
//! ## Example
//!
//! ```no_run
//! use rust_slint_password_saver::ui_handlers::UIHandlers;
//! use std::path::PathBuf;
//!
//! let handlers = UIHandlers::new(PathBuf::from("passwords.enc"));
//! ```

use crate::clipboard::{ClipboardConfig, SecureClipboard};
use crate::password_generator::{
    calculate_charset_size, calculate_entropy, generate_password, CharsetFlags,
    PasswordGeneratorConfig,
};
use crate::password_strength::{
    assess_password_strength, validate_password_strength, PasswordRequirements, PasswordStrength,
};
use crate::rate_limit::RateLimiter;
use crate::recovery::EmergencyRecovery;
use crate::search::{search_entries, sort_entries, SearchConfig, SortCriteria};
use crate::session::{SessionManager, DEFAULT_SESSION_TIMEOUT_MINUTES};
use crate::storage::{PasswordEntry, PasswordStorage};
use crate::update_checker::UpdateChecker;
use crate::validation::{
    validate_master_password, validate_password, validate_title, validate_username,
};
use crate::{AppWindow, PasswordEntryData};
use log::warn;
use sha2::{Digest, Sha256};
use slint::ComponentHandle;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Maximum number of password entries to display in status messages
const MAX_DISPLAY_ENTRIES: usize = 5;

/// Status message shown when a generated password is copied to clipboard
const GENERATED_PASSWORD_COPIED_MESSAGE: &str =
    "Generated password copied to clipboard. Paste it into the Password field.";

// Password strength indicator colors (matching design guide)
/// Color for very weak passwords (Vermillion - error color)
const STRENGTH_COLOR_VERY_WEAK: (u8, u8, u8) = (193, 68, 14);
/// Color for weak to medium passwords (Warning color)
const STRENGTH_COLOR_WEAK_MEDIUM: (u8, u8, u8) = (184, 134, 11);
/// Color for strong to excellent passwords (Forest Green - success color)
const STRENGTH_COLOR_STRONG: (u8, u8, u8) = (45, 80, 22);

/// Holds shared application state and provides handler methods for all UI callbacks.
///
/// Each handler corresponds to one Slint callback registered in `main()`. Handlers
/// are registered as thin closures that upgrade the weak UI reference and delegate
/// to the appropriate method.
///
/// `UIHandlers` is `Clone` so multiple callbacks can hold their own clone of the
/// shared state (which is `Arc`-wrapped where needed).
#[derive(Clone)]
pub struct UIHandlers {
    /// Path to the encrypted password storage file
    pub storage_path: PathBuf,
    /// In-memory cache of loaded password entries for search/filter/sort operations
    pub loaded_entries: Arc<Mutex<Vec<PasswordEntry>>>,
    /// Rate limiter to prevent brute-force attacks on password operations
    pub rate_limiter: Arc<RateLimiter>,
    /// Session manager for auto-lock timeout functionality
    pub session: Arc<SessionManager>,
    /// Shared clipboard instance (lazy-initialized on first use)
    pub clipboard: Arc<Mutex<Option<SecureClipboard>>>,
    /// Clipboard security configuration (auto-clear timeout, etc.)
    pub clipboard_config: ClipboardConfig,
}

// Handler methods take `slint::SharedString` by value, matching the Slint callback signature.
// This is intentional: Slint passes owned SharedStrings to callbacks.
#[allow(clippy::needless_pass_by_value)]
impl UIHandlers {
    /// Creates a new `UIHandlers` instance with the given storage path.
    ///
    /// Initialises all shared state with sensible defaults:
    /// - Empty loaded entries cache
    /// - Rate limiter with persistence at `<storage_dir>/rate_limit.json`
    ///   (5 attempts per 5-minute window, state survives restarts)
    /// - Session manager with 5-minute inactivity timeout
    /// - Uninitialised clipboard (lazy-initialised on first use)
    /// - Default clipboard configuration (30-second auto-clear)
    ///
    /// # Arguments
    ///
    /// * `storage_path` - Path to the encrypted password storage file
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        // Derive the rate limit persistence path from the storage directory
        let rate_limit_path = storage_path.parent().map_or_else(
            || PathBuf::from("rate_limit.json"),
            |parent| parent.join("rate_limit.json"),
        );
        Self {
            storage_path,
            loaded_entries: Arc::new(Mutex::new(Vec::new())),
            rate_limiter: Arc::new(RateLimiter::with_persistence(rate_limit_path)),
            session: Arc::new(SessionManager::new(DEFAULT_SESSION_TIMEOUT_MINUTES)),
            clipboard: Arc::new(Mutex::new(None)),
            clipboard_config: ClipboardConfig::default(),
        }
    }

    /// Handles the save-password callback.
    ///
    /// Validates all inputs, loads existing entries, appends the new entry, and saves.
    /// On first use, also generates and displays emergency recovery codes.
    #[allow(clippy::too_many_lines)]
    pub fn handle_save_password(
        &self,
        ui: &AppWindow,
        master_password: slint::SharedString,
        title: slint::SharedString,
        username: slint::SharedString,
        password: slint::SharedString,
    ) {
        // Record user activity to reset the session timeout
        self.session.record_activity();

        // Wrap in Zeroizing<String> immediately so the master password is securely
        // cleared from memory when this function returns (zeroized on drop).
        let master_password: Zeroizing<String> = Zeroizing::new(master_password.to_string());

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

        let storage = PasswordStorage::new(self.storage_path.clone());

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
                        format!("Master password validation failed: {}", e).into(),
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
            let recovery_key_salt = recovery.get_recovery_key_salt();

            // Save entries with recovery data
            match storage.save_entries_with_recovery(
                &entries,
                &master_password,
                recovery_hashes,
                &recovery_key,
                recovery_key_salt,
            ) {
                Ok(()) => {
                    // Show recovery codes to user
                    ui.set_recovery_code_1(recovery_codes[0].clone().into());
                    ui.set_recovery_code_2(recovery_codes[1].clone().into());
                    ui.set_recovery_code_3(recovery_codes[2].clone().into());
                    ui.set_show_recovery_setup(true);
                    ui.set_status_is_error(false);
                    ui.set_status_message(
                        format!(
                            "Password saved for: {}. Please save your recovery codes!",
                            title
                        )
                        .into(),
                    );
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

    /// Handles the check-password-strength callback.
    ///
    /// Assesses strength of the entered password and updates the strength indicator
    /// text and color in the UI.
    pub fn handle_check_password_strength(&self, ui: &AppWindow, password: slint::SharedString) {
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

    /// Handles the load-passwords callback.
    ///
    /// Validates the master password, checks the rate limiter, loads entries from
    /// storage, and updates the UI list and status message.
    pub fn handle_load_passwords(&self, ui: &AppWindow, master_password: slint::SharedString) {
        // Record user activity to reset the session timeout
        self.session.record_activity();

        // Wrap in Zeroizing<String> immediately so the master password is securely
        // cleared from memory when this function returns (zeroized on drop).
        let master_password: Zeroizing<String> = Zeroizing::new(master_password.to_string());

        // Validate master password
        if let Err(e) = validate_master_password(&master_password) {
            ui.set_status_is_error(true);
            ui.set_status_message(format!("Invalid master password: {}", e).into());
            return;
        }

        // Check rate limit before attempting decryption
        if let Err(e) = self.rate_limiter.check_and_record_attempt() {
            ui.set_status_is_error(true);
            ui.set_status_message(e.into());
            return;
        }

        let storage = PasswordStorage::new(self.storage_path.clone());

        if !storage.exists() {
            ui.set_status_is_error(false);
            ui.set_status_message("No passwords stored yet".into());
            return;
        }

        match storage.load_entries(&master_password) {
            Ok(entries) => {
                // Clear rate limiter on successful authentication
                self.rate_limiter.record_success();

                let count = entries.len();

                // Store entries in memory for search/filter operations
                // We need a full clone to maintain a searchable cache
                {
                    let mut loaded = self.loaded_entries.lock().unwrap_or_else(|poisoned| {
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

    /// Handles the unlock callback.
    ///
    /// Verifies the master password by attempting to decrypt storage, then unlocks
    /// the session UI on success.
    pub fn handle_unlock(&self, ui: &AppWindow, password: slint::SharedString) {
        // Wrap in Zeroizing<String> immediately so the master password is securely
        // cleared from memory when this function returns (zeroized on drop).
        let password: Zeroizing<String> = Zeroizing::new(password.to_string());

        // Validate master password
        if let Err(e) = validate_master_password(&password) {
            ui.set_status_is_error(true);
            ui.set_status_message(format!("Invalid password: {}", e).into());
            return;
        }

        // Check rate limit before attempting unlock
        if let Err(e) = self.rate_limiter.check_and_record_attempt() {
            ui.set_status_is_error(true);
            ui.set_status_message(e.into());
            return;
        }

        let storage = PasswordStorage::new(self.storage_path.clone());

        // Verify password by attempting to load entries
        // This ensures user enters correct master password to unlock
        if storage.exists() {
            match storage.load_entries(&password) {
                Ok(_) => {
                    // Password is correct, unlock session
                    self.rate_limiter.record_success();
                    self.session.record_activity();
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

    /// Handles the copy-password callback.
    ///
    /// Copies the provided password string to the clipboard with auto-clear.
    pub fn handle_copy_password(&self, ui: &AppWindow, password: slint::SharedString) {
        // Record user activity to reset the session timeout
        self.session.record_activity();

        // Initialize clipboard if not already done
        let mut clipboard_guard = self.clipboard.lock().unwrap_or_else(|poisoned| {
            warn!("Clipboard mutex poisoned, recovering");
            poisoned.into_inner()
        });
        if clipboard_guard.is_none() {
            match SecureClipboard::new(self.clipboard_config.clear_timeout_seconds) {
                Ok(clipboard) => {
                    *clipboard_guard = Some(clipboard);
                }
                Err(e) => {
                    ui.set_status_is_error(true);
                    ui.set_status_message(format!("Failed to initialize clipboard: {}", e).into());
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
                            self.clipboard_config.clear_timeout_seconds
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

    /// Handles the copy-entry-password callback.
    ///
    /// Looks up the password entry at the given index in the loaded entries cache
    /// and copies it to the clipboard with auto-clear.
    pub fn handle_copy_entry_password(&self, ui: &AppWindow, index: i32) {
        // Record user activity to reset the session timeout
        self.session.record_activity();

        // Get password from loaded entries at the specified index
        let password = {
            let entries = self.loaded_entries.lock().unwrap_or_else(|poisoned| {
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
            let mut clipboard_guard = self.clipboard.lock().unwrap_or_else(|poisoned| {
                warn!("Clipboard mutex poisoned, recovering");
                poisoned.into_inner()
            });
            if clipboard_guard.is_none() {
                match SecureClipboard::new(self.clipboard_config.clear_timeout_seconds) {
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
                                self.clipboard_config.clear_timeout_seconds
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

    /// Handles the generate-password callback.
    ///
    /// Reads generator configuration from the UI, generates a password, and
    /// updates the generated-password field together with an entropy display.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn handle_generate_password(&self, ui: &AppWindow) {
        // Record user activity to reset the session timeout
        self.session.record_activity();

        // Get configuration from UI
        let mut charset = CharsetFlags::empty();
        if ui.get_generator_use_uppercase() {
            charset |= CharsetFlags::UPPERCASE;
        }
        if ui.get_generator_use_lowercase() {
            charset |= CharsetFlags::LOWERCASE;
        }
        if ui.get_generator_use_digits() {
            charset |= CharsetFlags::DIGITS;
        }
        if ui.get_generator_use_special() {
            charset |= CharsetFlags::SPECIAL;
        }
        let config = PasswordGeneratorConfig {
            length: ui.get_generator_length() as usize,
            charset,
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

    /// Handles the use-generated-password callback.
    ///
    /// Copies the generated password to the clipboard and shows a status message
    /// prompting the user to paste it into the password field.
    pub fn handle_use_generated_password(&self, ui: &AppWindow, password: slint::SharedString) {
        // Record user activity to reset the session timeout
        self.session.record_activity();

        // Find the password input field in the "Add New Password" section
        // We need to set it through a property or find another way
        // For now, we'll just copy to clipboard and show a message
        ui.set_status_is_error(false);
        ui.set_status_message(GENERATED_PASSWORD_COPIED_MESSAGE.into());

        // Copy to clipboard
        let mut clipboard_guard = self.clipboard.lock().unwrap_or_else(|poisoned| {
            warn!("Clipboard mutex poisoned, recovering");
            poisoned.into_inner()
        });
        if clipboard_guard.is_none() {
            match SecureClipboard::new(self.clipboard_config.clear_timeout_seconds) {
                Ok(clipboard) => {
                    *clipboard_guard = Some(clipboard);
                }
                Err(e) => {
                    ui.set_status_is_error(true);
                    ui.set_status_message(format!("Failed to initialize clipboard: {}", e).into());
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

    /// Handles the search-passwords callback.
    ///
    /// Searches the in-memory entries cache with the provided query string and
    /// updates the UI list with matching results.
    pub fn handle_search_passwords(&self, ui: &AppWindow, query: slint::SharedString) {
        // Record user activity to reset the session timeout
        self.session.record_activity();

        let entries = self.loaded_entries.lock().unwrap_or_else(|poisoned| {
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

    /// Handles the sort-passwords callback.
    ///
    /// Sorts the in-memory entries cache by the given criterion and refreshes
    /// the UI list.
    pub fn handle_sort_passwords(&self, ui: &AppWindow, sort_option: i32) {
        // Record user activity to reset the session timeout
        self.session.record_activity();

        let mut entries = self.loaded_entries.lock().unwrap_or_else(|poisoned| {
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

    /// Handles the check-for-updates callback (manual trigger).
    ///
    /// Spawns a background thread to perform the update check and updates the UI
    /// with the result.
    pub fn handle_check_for_updates(&self, ui: &AppWindow) {
        ui.set_checking_for_updates(true);
        ui.set_status_is_error(false);
        ui.set_status_message("Checking for updates...".into());

        // Spawn a thread for blocking update check
        let ui_weak = ui.as_weak();
        std::thread::spawn(move || {
            let checker = UpdateChecker::new();

            match checker.check_for_updates() {
                Ok(Some(update_info)) => {
                    if let Some(ui) = ui_weak.upgrade() {
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
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_checking_for_updates(false);
                        ui.set_status_is_error(false);
                        ui.set_status_message("You are running the latest version".into());
                    }
                }
                Err(e) => {
                    warn!("Failed to check for updates: {}", e);
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_checking_for_updates(false);
                        ui.set_status_is_error(true);
                        ui.set_status_message(format!("Failed to check for updates: {}", e).into());
                    }
                }
            }
        });
    }

    /// Handles the open-release-page callback.
    ///
    /// Opens the download URL stored in the UI in the system's default browser.
    pub fn handle_open_release_page(&self, ui: &AppWindow) {
        let url = ui.get_download_url();
        if let Err(e) = webbrowser::open(url.as_ref()) {
            warn!("Failed to open browser: {}", e);
            ui.set_status_is_error(true);
            ui.set_status_message(format!("Failed to open browser: {}", e).into());
        }
    }

    /// Handles the copy-recovery-codes callback.
    ///
    /// Formats all three recovery codes and copies them to the clipboard.
    pub fn handle_copy_recovery_codes(&self, ui: &AppWindow) {
        let codes = format!(
            "Recovery Code 1: {}\nRecovery Code 2: {}\nRecovery Code 3: {}",
            ui.get_recovery_code_1(),
            ui.get_recovery_code_2(),
            ui.get_recovery_code_3()
        );

        // Initialize clipboard if needed
        let mut clipboard_guard = self.clipboard.lock().unwrap_or_else(|poisoned| {
            warn!("Clipboard mutex poisoned, recovering");
            poisoned.into_inner()
        });
        if clipboard_guard.is_none() {
            match SecureClipboard::new(self.clipboard_config.clear_timeout_seconds) {
                Ok(clipboard) => {
                    *clipboard_guard = Some(clipboard);
                }
                Err(e) => {
                    ui.set_status_is_error(true);
                    ui.set_status_message(format!("Failed to initialize clipboard: {}", e).into());
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

    /// Handles the print-recovery-codes callback.
    ///
    /// Currently shows an informational message. A full print-dialog implementation
    /// is a future enhancement.
    pub fn handle_print_recovery_codes(&self, ui: &AppWindow) {
        // For now, just show a message that printing is not yet implemented
        // In a full implementation, this would open a print dialog
        ui.set_status_is_error(false);
        ui.set_status_message(
            "Print functionality: Please copy the codes and print them manually.".into(),
        );
    }

    /// Handles the recover-with-code callback.
    ///
    /// Validates the recovery code against stored hashes (using constant-time
    /// comparison to prevent timing attacks), then unlocks the UI session on
    /// success.
    pub fn handle_recover_with_code(&self, ui: &AppWindow, recovery_code: slint::SharedString) {
        // Check rate limit for recovery attempts
        if let Err(e) = self.rate_limiter.check_and_record_attempt() {
            ui.set_status_is_error(true);
            ui.set_status_message(e.into());
            return;
        }

        let storage = PasswordStorage::new(self.storage_path.clone());

        // Check if recovery data exists
        match storage.load_recovery_data() {
            Ok(Some((hashes, _encrypted_key, _recovery_key_salt))) => {
                // Hash the provided recovery code
                let mut hash_computer = Sha256::new();
                hash_computer.update(recovery_code.as_bytes());
                let code_hash = hex::encode(hash_computer.finalize());

                // Check if the hash matches any stored hash using constant-time comparison
                let hash_matches = hashes
                    .iter()
                    .any(|stored_hash| stored_hash.as_bytes().ct_eq(code_hash.as_bytes()).into());

                if hash_matches {
                    // Success! Clear rate limiter
                    self.rate_limiter.record_success();

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
                    "No recovery data found. This database was created before recovery was added."
                        .into(),
                );
            }
            Err(e) => {
                ui.set_status_is_error(true);
                ui.set_status_message(e.user_message().into());
                eprintln!("Recovery data load failed: {}", e.debug_message());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Helper that creates a `UIHandlers` instance pointing at a temp directory.
    fn make_handlers() -> (UIHandlers, tempfile::TempDir) {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().join("test_passwords.enc");
        let handlers = UIHandlers::new(path);
        (handlers, dir)
    }

    #[test]
    fn test_new_creates_empty_loaded_entries() {
        let (handlers, _dir) = make_handlers();
        let entries = handlers.loaded_entries.lock().unwrap();
        assert!(entries.is_empty(), "loaded_entries should start empty");
    }

    #[test]
    fn test_clone_shares_loaded_entries() {
        let (handlers, _dir) = make_handlers();
        let clone = handlers.clone();

        // Insert an entry into the original
        {
            let mut entries = handlers.loaded_entries.lock().unwrap();
            entries.push(PasswordEntry {
                title: "Test".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
                created_at: current_timestamp(),
            });
        }

        // The clone should see the same entry (Arc-shared)
        let entries = clone.loaded_entries.lock().unwrap();
        assert_eq!(
            entries.len(),
            1,
            "Clone should share the same loaded_entries Arc"
        );
        assert_eq!(entries[0].title, "Test");
    }

    #[test]
    fn test_new_default_clipboard_config() {
        let (handlers, _dir) = make_handlers();
        assert!(handlers.clipboard_config.auto_clear_enabled);
        assert_eq!(handlers.clipboard_config.clear_timeout_seconds, 30);
    }

    #[test]
    fn test_rate_limiter_blocks_after_max_attempts() {
        let (handlers, _dir) = make_handlers();

        // Exhaust the rate limiter (default: 5 attempts)
        for _ in 0..5 {
            let _ = handlers.rate_limiter.check_and_record_attempt();
        }

        // Next attempt should be rate-limited
        let result = handlers.rate_limiter.check_and_record_attempt();
        assert!(
            result.is_err(),
            "Rate limiter should block after max attempts"
        );
    }

    #[test]
    fn test_rate_limiter_resets_after_success() {
        let (handlers, _dir) = make_handlers();

        // Use some attempts
        for _ in 0..3 {
            let _ = handlers.rate_limiter.check_and_record_attempt();
        }

        // Record a success (clears the attempt history)
        handlers.rate_limiter.record_success();

        // Should be able to attempt again
        let result = handlers.rate_limiter.check_and_record_attempt();
        assert!(
            result.is_ok(),
            "Rate limiter should allow attempts after success"
        );
    }

    #[test]
    fn test_session_records_activity() {
        let (handlers, _dir) = make_handlers();
        // Should not be locked initially
        assert!(!handlers.session.is_locked());
        // Recording activity should keep session unlocked
        handlers.session.record_activity();
        assert!(!handlers.session.is_locked());
    }

    #[test]
    fn test_session_can_lock_and_unlock() {
        let (handlers, _dir) = make_handlers();
        handlers.session.lock();
        assert!(handlers.session.is_locked());
        handlers.session.record_activity();
        assert!(!handlers.session.is_locked());
    }

    #[test]
    fn test_storage_path_stored_correctly() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().join("passwords.enc");
        let handlers = UIHandlers::new(path.clone());
        assert_eq!(handlers.storage_path, path);
    }

    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    #[test]
    fn test_save_and_load_via_storage() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().join("passwords.enc");
        let master_password = "TestMaster999!";

        // Save directly via PasswordStorage (handler logic is tested via integration)
        let storage = PasswordStorage::new(path.clone());
        let entries = vec![PasswordEntry {
            title: "Example".to_string(),
            username: "user@example.com".to_string(),
            password: "entry_pass".to_string(),
            created_at: current_timestamp(),
        }];
        storage.save_entries(&entries, master_password).unwrap();

        // Now a UIHandlers pointing at the same path should be able to load
        let handlers = UIHandlers::new(path);
        let storage2 = PasswordStorage::new(handlers.storage_path.clone());
        let loaded = storage2.load_entries(master_password).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].title, "Example");
    }

    #[test]
    fn test_loaded_entries_population() {
        let (handlers, _dir) = make_handlers();

        // Manually populate loaded_entries as load_passwords handler would
        {
            let mut entries = handlers.loaded_entries.lock().unwrap();
            for i in 0..3 {
                entries.push(PasswordEntry {
                    title: format!("Entry {}", i),
                    username: format!("user{}@example.com", i),
                    password: format!("pass{}", i),
                    created_at: current_timestamp(),
                });
            }
        }

        let entries = handlers.loaded_entries.lock().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].title, "Entry 0");
        assert_eq!(entries[2].title, "Entry 2");
    }

    /// Verify that `Zeroizing<String>` zeroizes memory on drop.
    ///
    /// This test documents the memory-safety pattern used in UI handlers:
    /// master passwords received from the UI as `SharedString` are immediately
    /// converted to `Zeroizing<String>` so they are securely overwritten when
    /// the callback returns.
    #[test]
    fn test_zeroizing_string_clears_on_drop() {
        use zeroize::Zeroizing;

        // codeql[rust/hard-coded-cryptographic-value] // False positive: test fixture only
        let secret = "MasterPassword123!";
        let zeroizing: Zeroizing<String> = Zeroizing::new(secret.to_string());

        // Confirm the value is accessible while in scope
        assert_eq!(zeroizing.as_str(), secret);

        // Drop explicitly; memory is zeroed by Zeroizing on drop
        drop(zeroizing);
        // After drop, the heap memory has been overwritten with zeros.
        // We cannot directly observe this in safe Rust, but the drop occurred
        // and zeroize guarantees the bytes are overwritten before deallocation.
    }
}
