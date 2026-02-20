//! # Clipboard Security Module
//!
//! Provides secure clipboard operations with automatic clearing after a timeout.
//!
//! This module implements clipboard functionality with security features:
//! - Copy text to clipboard with automatic clearing after timeout
//! - Only clears clipboard if content hasn't changed (prevents clearing user's subsequent operations)
//! - Configurable timeout period
//! - Manual clipboard clear functionality
//!
//! ## Security Features
//!
//! - **Auto-clear**: Clipboard is automatically cleared after configured timeout
//! - **Smart clearing**: Only clears if clipboard still contains the original text
//! - **Cross-platform**: Works on macOS, Linux, and Windows
//!
//! ## Example
//!
//! ```no_run
//! use rust_slint_password_saver::clipboard::{SecureClipboard, ClipboardConfig};
//!
//! let config = ClipboardConfig::default();
//! let mut clipboard = SecureClipboard::new(config.clear_timeout_seconds).unwrap();
//!
//! // Copy password with auto-clear after 30 seconds
//! clipboard.copy_with_autoclear("MySecretPassword123!").unwrap();
//! ```

use arboard::Clipboard;
use std::thread;
use std::time::Duration;

/// Secure clipboard manager with auto-clear functionality
pub struct SecureClipboard {
    clipboard: Clipboard,
    clear_timeout: Duration,
}

impl SecureClipboard {
    /// Create a new secure clipboard instance
    ///
    /// # Arguments
    ///
    /// * `clear_timeout_seconds` - Number of seconds before clipboard is automatically cleared
    ///
    /// # Returns
    ///
    /// Returns `Ok(SecureClipboard)` on success, or `Err(String)` if clipboard initialization fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::clipboard::SecureClipboard;
    ///
    /// let clipboard = SecureClipboard::new(30).unwrap();
    /// ```
    pub fn new(clear_timeout_seconds: u64) -> Result<Self, String> {
        Ok(Self {
            clipboard: Clipboard::new()
                .map_err(|e| format!("Failed to initialize clipboard: {}", e))?,
            clear_timeout: Duration::from_secs(clear_timeout_seconds),
        })
    }

    /// Copy text to clipboard and automatically clear after timeout
    ///
    /// This method copies the provided text to the system clipboard and spawns
    /// a background thread to automatically clear it after the configured timeout.
    /// The clipboard is only cleared if it still contains the original text,
    /// preventing interference with user's subsequent clipboard operations.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to copy to clipboard
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Err(String)` if clipboard operation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::clipboard::SecureClipboard;
    ///
    /// let mut clipboard = SecureClipboard::new(30).unwrap();
    /// clipboard.copy_with_autoclear("MyPassword123!").unwrap();
    /// // Clipboard will be cleared after 30 seconds if content hasn't changed
    /// ```
    pub fn copy_with_autoclear(&mut self, text: &str) -> Result<(), String> {
        // Copy to clipboard
        self.clipboard
            .set_text(text)
            .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;

        // Spawn thread to clear clipboard after timeout
        let clear_timeout = self.clear_timeout;
        let text_to_clear = text.to_string();

        thread::spawn(move || {
            thread::sleep(clear_timeout);

            // Clear clipboard only if it still contains our text
            // This prevents clearing user's subsequent clipboard operations
            if let Ok(mut clipboard) = Clipboard::new() {
                if let Ok(current_content) = clipboard.get_text() {
                    if current_content == text_to_clear {
                        let _ = clipboard.set_text(""); // Clear clipboard
                    }
                }
            }
        });

        Ok(())
    }

    /// Immediately clear clipboard
    ///
    /// This method clears the clipboard immediately by setting it to an empty string.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Err(String)` if clipboard operation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::clipboard::SecureClipboard;
    ///
    /// let mut clipboard = SecureClipboard::new(30).unwrap();
    /// clipboard.clear().unwrap();
    /// ```
    #[allow(dead_code)] // Part of public API, may be used in future
    pub fn clear(&mut self) -> Result<(), String> {
        self.clipboard
            .set_text("")
            .map_err(|e| format!("Failed to clear clipboard: {}", e))
    }
}

/// Configuration for clipboard security
#[allow(dead_code)] // Part of public API, may be used in future
#[derive(Clone, Copy)]
pub struct ClipboardConfig {
    /// Whether auto-clear is enabled
    pub auto_clear_enabled: bool,
    /// Number of seconds before clipboard is automatically cleared
    pub clear_timeout_seconds: u64,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            auto_clear_enabled: true,
            clear_timeout_seconds: 30, // Clear after 30 seconds
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_config_default() {
        let config = ClipboardConfig::default();
        assert!(config.auto_clear_enabled);
        assert_eq!(config.clear_timeout_seconds, 30);
    }

    #[test]
    fn test_clipboard_config_custom() {
        let config = ClipboardConfig {
            auto_clear_enabled: false,
            clear_timeout_seconds: 60,
        };
        assert!(!config.auto_clear_enabled);
        assert_eq!(config.clear_timeout_seconds, 60);
    }

    // Note: We cannot fully test clipboard operations in a headless CI environment
    // as clipboard access requires a display server. Integration tests should be
    // run manually on systems with clipboard support.
}
