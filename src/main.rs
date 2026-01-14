mod storage;

use storage::{PasswordEntry, PasswordStorage};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

slint::include_modules!();

/// Maximum number of password entries to display in status message
const MAX_DISPLAY_ENTRIES: usize = 5;

/// Get cross-platform path for storing encrypted passwords
/// Works on macOS, Linux, and other Unix-like systems
fn get_storage_path() -> PathBuf {
    // Use home directory for cross-platform compatibility
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| String::from("."));
    
    let mut path = PathBuf::from(home_dir);
    path.push(".password_saver");
    path.push("passwords.enc");
    
    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    
    path
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    // Initialize storage with cross-platform path
    let storage_path = get_storage_path();
    
    // Set up save password callback
    let ui_weak = ui.as_weak();
    let storage_path_clone = storage_path.clone();
    ui.on_save_password(move |master_password, title, username, password| {
        if let Some(ui) = ui_weak.upgrade() {
            // Validate inputs
            if master_password.is_empty() {
                ui.set_status_message("Error: Master password is required".into());
                return;
            }
            
            if title.is_empty() || password.is_empty() {
                ui.set_status_message("Error: Title and password are required".into());
                return;
            }

            let storage = PasswordStorage::new(storage_path_clone.clone());
            
            // Load existing entries or create new list
            let mut entries = if storage.exists() {
                match storage.load_entries(&master_password) {
                    Ok(entries) => entries,
                    Err(e) => {
                        ui.set_status_message(format!("Error loading entries: {}", e).into());
                        return;
                    }
                }
            } else {
                Vec::new()
            };
            
            // Create new entry
            let new_entry = PasswordEntry {
                title: title.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            
            // Add entry to list
            entries.push(new_entry);
            
            // Save encrypted entries
            match storage.save_entries(&entries, &master_password) {
                Ok(()) => {
                    ui.set_status_message(format!("Password saved for: {}", title).into());
                }
                Err(e) => {
                    ui.set_status_message(format!("Error saving password: {}", e).into());
                }
            }
        }
    });

    // Set up load passwords callback
    let ui_weak = ui.as_weak();
    ui.on_load_passwords(move |master_password| {
        if let Some(ui) = ui_weak.upgrade() {
            if master_password.is_empty() {
                ui.set_status_message("Error: Master password is required".into());
                return;
            }

            let storage = PasswordStorage::new(storage_path.clone());
            
            if !storage.exists() {
                ui.set_status_message("No passwords stored yet".into());
                return;
            }
            
            match storage.load_entries(&master_password) {
                Ok(entries) => {
                    let count = entries.len();
                    let mut message = format!("Loaded {} password(s):\n", count);
                    for entry in entries.iter().take(MAX_DISPLAY_ENTRIES) {
                        let _ = write!(message, "- {}", entry.title);
                        if !entry.username.is_empty() {
                            let _ = write!(message, " ({})", entry.username);
                        }
                        message.push('\n');
                    }
                    if entries.len() > MAX_DISPLAY_ENTRIES {
                        let _ = write!(message, "... and {} more", entries.len() - MAX_DISPLAY_ENTRIES);
                    }
                    ui.set_status_message(message.into());
                }
                Err(e) => {
                    ui.set_status_message(format!("Error loading passwords: {}. Check your master password.", e).into());
                }
            }
        }
    });

    ui.run()
}
