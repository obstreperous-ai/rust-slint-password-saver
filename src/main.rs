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

// Suppress the console window on Windows; has no effect on other platforms.
#![cfg_attr(windows, windows_subsystem = "windows")]

use log::warn;
use rust_slint_password_saver::{
    audit_log::{get_audit_hmac_key_path, get_audit_log_path, AuditEventType, AuditLogger},
    errors,
    storage::PasswordStorage,
    ui_handlers::UIHandlers,
    update_checker::UpdateChecker,
    AppWindow,
};
use slint::ComponentHandle;
use std::path::PathBuf;
use std::time::Duration;

/// Get cross-platform path for storing encrypted passwords.
///
/// This function determines the appropriate location for password storage
/// based on the operating system:
/// - Unix-like systems (macOS, Linux): `~/.password_saver/passwords.enc`
/// - Windows: `%USERPROFILE%/.password_saver/passwords.enc`
///
/// # Returns
///
/// A `Result<PathBuf, SecurityError>` pointing to the storage file location.
/// Parent directory is created if it doesn't exist. On Unix systems, the
/// directory is created with secure permissions (0700) which are then verified.
///
/// # Errors
///
/// Returns `SecurityError::InvalidInput` if directory permissions cannot be
/// set to the required 0700 on Unix systems (e.g., on NFS or network shares).
///
/// # Platform Support
///
/// Works on macOS, Linux, and other Unix-like systems. Uses `HOME` environment
/// variable on Unix and `USERPROFILE` on Windows.
fn get_storage_path() -> Result<PathBuf, errors::SecurityError> {
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

        // Set secure permissions on the directory (0700 on Unix) and verify
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(parent, permissions);

            // Verify permissions were actually set (may silently fail on NFS/network shares)
            let metadata = std::fs::metadata(parent).map_err(|e| {
                log::error!(
                    "Failed to read directory metadata for permission verification: {}",
                    e
                );
                errors::SecurityError::StorageError
            })?;
            let actual_mode = metadata.permissions().mode() & 0o777;
            if actual_mode != 0o700 {
                log::error!(
                    "Failed to set secure directory permissions. Expected 0700, got {:o}",
                    actual_mode
                );
                return Err(errors::SecurityError::InvalidInput(
                    "Cannot secure storage directory with required permissions".to_string(),
                ));
            }
        }

        // Set secure permissions on the directory (ACL on Windows)
        #[cfg(windows)]
        {
            use rust_slint_password_saver::windows_permissions::set_windows_directory_permissions;
            if let Err(e) = set_windows_directory_permissions(parent) {
                log::warn!(
                    "Failed to set Windows ACL on storage directory {:?}: {:?}. \
                     Directory may be accessible to other users.",
                    parent,
                    e
                );
            }
        }
    }

    Ok(path)
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), slint::PlatformError> {
    // Initialise env_logger.
    // On Windows, stderr is unavailable after applying `windows_subsystem = "windows"`, so
    // redirect log output to %LOCALAPPDATA%\PasswordSaver\app.log instead.
    #[cfg(windows)]
    {
        let log_dir = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("PasswordSaver");
        let file_logger_initialised = std::fs::create_dir_all(&log_dir)
            .ok()
            .and_then(|_| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_dir.join("app.log"))
                    .ok()
            })
            .map(|file| {
                env_logger::Builder::new()
                    .target(env_logger::Target::Pipe(Box::new(file)))
                    .filter_level(log::LevelFilter::Warn)
                    .init();
            })
            .is_some();
        if !file_logger_initialised {
            // Fall back to stderr if the log file could not be opened.
            env_logger::init();
        }
    }
    #[cfg(not(windows))]
    {
        env_logger::init();
    }

    // Initialize audit logging
    let audit_logger = AuditLogger::new(get_audit_log_path(), &get_audit_hmac_key_path());
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
    let storage_path = match get_storage_path() {
        Ok(path) => path,
        Err(e) => {
            log::error!(
                "Failed to initialize secure storage path: {}",
                e.debug_message()
            );
            return Err(slint::PlatformError::Other(e.user_message()));
        }
    };

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

    // Create the UI handler that holds all shared state
    let handlers = UIHandlers::new(storage_path);

    // Start background thread to check for session timeout
    let ui_weak_timeout = ui.as_weak();
    let session = handlers.session.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));

            // Check if UI is still alive, exit thread if not
            let Some(ui) = ui_weak_timeout.upgrade() else {
                break; // UI is gone, exit thread
            };

            if session.should_lock() && !session.is_locked() {
                session.lock();
                ui.set_is_locked(true);
            }

            // Update countdown timer (only show when less than 60 seconds remaining)
            let time_left = session.time_until_lock();
            // Safely convert u64 to i32, capping at i32::MAX
            let seconds = time_left.as_secs().try_into().unwrap_or(i32::MAX);
            ui.set_seconds_until_lock(seconds);
        }
    });

    // Set up save password callback
    // This is called when the user clicks "Save Password" button
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_save_password(move |master_password, title, username, password| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_save_password(&ui, master_password, title, username, password);
            }
        });
    }

    // Set up password strength check callback
    // This is called when the user types in the password field
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_check_password_strength(move |password| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_check_password_strength(&ui, password);
            }
        });
    }

    // Set up load passwords callback
    // This is called when the user clicks "Load Passwords" button
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_load_passwords(move |master_password| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_load_passwords(&ui, master_password);
            }
        });
    }

    // Set up unlock callback
    // This is called when the user tries to unlock the session
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_unlock(move |password| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_unlock(&ui, password);
            }
        });
    }

    // Set up copy password callback
    // This is called when the user wants to copy a password to clipboard
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_copy_password(move |password| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_copy_password(&ui, password);
            }
        });
    }

    // Set up copy entry password callback (by index)
    // This is called when user clicks copy button next to a password entry
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_copy_entry_password(move |index| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_copy_entry_password(&ui, index);
            }
        });
    }

    // Set up generate password callback
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_generate_password(move || {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_generate_password(&ui);
            }
        });
    }

    // Set up use generated password callback
    // This copies the generated password to the password input field
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_use_generated_password(move |password| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_use_generated_password(&ui, password);
            }
        });
    }

    // Set up search passwords callback
    // This is called when the user types in the search box or clicks Search
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_search_passwords(move |query| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_search_passwords(&ui, query);
            }
        });
    }

    // Set up sort passwords callback
    // This is called when the user selects a different sort option
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_sort_passwords(move |sort_option| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_sort_passwords(&ui, sort_option);
            }
        });
    }

    // Set up update check callback (manual check)
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_check_for_updates(move || {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_check_for_updates(&ui);
            }
        });
    }

    // Set up open release page callback
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_open_release_page(move || {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_open_release_page(&ui);
            }
        });
    }

    // Set up copy recovery codes callback
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_copy_recovery_codes(move || {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_copy_recovery_codes(&ui);
            }
        });
    }

    // Set up print recovery codes callback
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_print_recovery_codes(move || {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_print_recovery_codes(&ui);
            }
        });
    }

    // Set up recover with code callback
    {
        let h = handlers.clone();
        let ui_weak = ui.as_weak();
        ui.on_recover_with_code(move |recovery_code| {
            if let Some(ui) = ui_weak.upgrade() {
                h.handle_recover_with_code(&ui, recovery_code);
            }
        });
    }

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
