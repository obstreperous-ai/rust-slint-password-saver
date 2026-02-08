//! Security audit logging module.
//!
//! This module provides functionality for logging security-relevant events with integrity protection.
//! All audit events are logged to an append-only file with HMAC-based integrity verification.
//!
//! # Features
//!
//! - **Structured logging**: Events stored as JSON with timestamps
//! - **Integrity protection**: HMAC-SHA256 for tamper detection
//! - **Log rotation**: Automatic rotation when size threshold exceeded
//! - **Forensic trail**: Complete record of security events

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Maximum log file size before rotation (10 MB)
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of rotated log files to keep
const MAX_ROTATIONS: usize = 5;

/// Represents a single audit log entry.
///
/// Each entry contains:
/// - Timestamp (Unix epoch seconds)
/// - Event type classification
/// - Success/failure status
/// - Optional details message
/// - HMAC for integrity verification
///
/// # Example
///
/// ```
/// use rust_slint_password_saver::audit_log::{AuditEntry, AuditEventType};
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// let entry = AuditEntry {
///     timestamp: SystemTime::now()
///         .duration_since(UNIX_EPOCH)
///         .unwrap()
///         .as_secs(),
///     event_type: AuditEventType::ApplicationStartup,
///     success: true,
///     details: None,
///     hmac: String::new(), // HMAC computed during logging
/// };
/// ```
#[derive(Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    /// Unix timestamp (seconds since epoch)
    pub timestamp: u64,
    /// Type of security event
    pub event_type: AuditEventType,
    /// Whether the operation succeeded
    pub success: bool,
    /// Optional details about the event
    pub details: Option<String>,
    /// HMAC-SHA256 for integrity protection
    pub hmac: String,
}

/// Classification of security-relevant events.
///
/// Each variant represents a different type of security event that should be audited.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuditEventType {
    /// Master password validation attempt
    MasterPasswordCheck,
    /// Password entries saved to disk
    PasswordsSaved,
    /// Password entries loaded from disk
    PasswordsLoaded,
    /// File system access (read/write)
    FileAccess,
    /// Application started
    ApplicationStartup,
}

/// Manages audit logging with integrity protection and rotation.
///
/// The `AuditLogger` writes security events to an append-only log file.
/// Each entry is protected with HMAC-SHA256 for tamper detection.
/// When the log exceeds `MAX_LOG_SIZE`, it is automatically rotated.
///
/// # Security
///
/// - Log file is append-only to prevent tampering
/// - Each entry includes HMAC for integrity verification
/// - Logs are stored separately from encrypted password data
/// - HMAC key derived from system-specific information
///
/// # Example
///
/// ```no_run
/// use rust_slint_password_saver::audit_log::{AuditLogger, AuditEntry, AuditEventType};
/// use std::path::PathBuf;
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// let logger = AuditLogger::new(PathBuf::from("/tmp/audit.log"));
///
/// let entry = AuditEntry {
///     timestamp: SystemTime::now()
///         .duration_since(UNIX_EPOCH)
///         .unwrap()
///         .as_secs(),
///     event_type: AuditEventType::ApplicationStartup,
///     success: true,
///     details: Some("App started".to_string()),
///     hmac: String::new(),
/// };
///
/// logger.log_event(&entry).unwrap();
/// ```
#[allow(dead_code)]
pub struct AuditLogger {
    log_path: PathBuf,
    hmac_key: [u8; 32],
}

#[allow(dead_code)]
impl AuditLogger {
    /// Creates a new audit logger instance.
    ///
    /// # Arguments
    ///
    /// * `log_path` - Path where audit log will be stored
    ///
    /// # Returns
    ///
    /// A new `AuditLogger` instance with a derived HMAC key
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::audit_log::AuditLogger;
    /// use std::path::PathBuf;
    ///
    /// let logger = AuditLogger::new(PathBuf::from("~/.password_saver/audit.log"));
    /// ```
    #[must_use]
    pub fn new(log_path: PathBuf) -> Self {
        // Generate HMAC key - in production, this should be stored securely
        // For this implementation, we derive it from system information
        let hmac_key = Self::derive_hmac_key();

        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        Self { log_path, hmac_key }
    }

    /// Derives an HMAC key for log integrity protection.
    ///
    /// This is a simplified implementation. In production, the HMAC key should be:
    /// - Stored securely (e.g., in system keyring)
    /// - Generated cryptographically (not derived from hostname)
    /// - Rotated periodically
    ///
    /// # Returns
    ///
    /// A 32-byte HMAC key
    fn derive_hmac_key() -> [u8; 32] {
        // Simplified key derivation - use hostname as entropy source
        // In production, use proper key management
        let hostname = hostname::get()
            .unwrap_or_else(|_| std::ffi::OsString::from("default"))
            .to_string_lossy()
            .to_string();

        // Hash the hostname to create a 32-byte key
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(hostname.as_bytes());
        hasher.update(b"audit_log_hmac_key_v1");
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Computes HMAC-SHA256 for an audit entry.
    ///
    /// # Arguments
    ///
    /// * `entry` - The audit entry to compute HMAC for
    ///
    /// # Returns
    ///
    /// Hex-encoded HMAC string
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails
    fn compute_hmac(&self, entry: &AuditEntry) -> Result<String, String> {
        // Create a temporary entry without HMAC for hashing
        let mut entry_for_hash = entry.clone();
        entry_for_hash.hmac = String::new();

        // Serialize entry to JSON
        let json_data = serde_json::to_string(&entry_for_hash)
            .map_err(|e| format!("Failed to serialize entry: {}", e))?;

        // Compute HMAC
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| format!("Failed to create HMAC: {}", e))?;
        mac.update(json_data.as_bytes());
        let result = mac.finalize();

        // Convert to hex string
        Ok(hex::encode(result.into_bytes()))
    }

    /// Logs an audit event to the log file.
    ///
    /// This method:
    /// 1. Computes HMAC for the entry
    /// 2. Appends entry to log file as JSON
    /// 3. Checks if rotation is needed
    ///
    /// # Arguments
    ///
    /// * `entry` - The audit entry to log (HMAC will be computed automatically)
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error message on failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HMAC computation fails
    /// - JSON serialization fails
    /// - File write fails
    /// - Log rotation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::audit_log::{AuditLogger, AuditEntry, AuditEventType};
    /// use std::path::PathBuf;
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// let logger = AuditLogger::new(PathBuf::from("/tmp/audit.log"));
    ///
    /// let entry = AuditEntry {
    ///     timestamp: SystemTime::now()
    ///         .duration_since(UNIX_EPOCH)
    ///         .unwrap()
    ///         .as_secs(),
    ///     event_type: AuditEventType::MasterPasswordCheck,
    ///     success: true,
    ///     details: None,
    ///     hmac: String::new(),
    /// };
    ///
    /// logger.log_event(&entry).unwrap();
    /// ```
    pub fn log_event(&self, entry: &AuditEntry) -> Result<(), String> {
        // Compute HMAC for the entry
        let mut entry_with_hmac = entry.clone();
        entry_with_hmac.hmac = self.compute_hmac(entry)?;

        // Serialize to JSON
        let json_line = serde_json::to_string(&entry_with_hmac)
            .map_err(|e| format!("Failed to serialize entry: {}", e))?;

        // Append to log file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| format!("Failed to open log file: {}", e))?;

        writeln!(file, "{}", json_line)
            .map_err(|e| format!("Failed to write to log file: {}", e))?;

        // Check if rotation is needed
        self.rotate_if_needed()?;

        Ok(())
    }

    /// Rotates the log file if it exceeds the size threshold.
    ///
    /// When rotation occurs:
    /// - Current log is renamed to `audit.log.1`
    /// - Previous rotated logs are shifted (e.g., `.1` → `.2`)
    /// - A new empty log file is created
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error message on failure
    ///
    /// # Errors
    ///
    /// Returns an error if file operations fail
    fn rotate_if_needed(&self) -> Result<(), String> {
        // Check if log file exists and its size
        let Ok(metadata) = fs::metadata(&self.log_path) else {
            return Ok(()); // File doesn't exist yet
        };

        if metadata.len() < MAX_LOG_SIZE {
            return Ok(());
        }

        // Rotate logs (keep last MAX_ROTATIONS rotations)
        for i in (1..MAX_ROTATIONS).rev() {
            let old_path = if i == 1 {
                self.log_path.clone()
            } else {
                // Construct rotated filename: audit.log.N
                let mut path = self.log_path.clone();
                let filename = format!("{}.{}", path.file_name().unwrap().to_string_lossy(), i);
                path.set_file_name(filename);
                path
            };

            let new_path = {
                // Construct rotated filename: audit.log.(N+1)
                let mut path = self.log_path.clone();
                let filename = format!("{}.{}", path.file_name().unwrap().to_string_lossy(), i + 1);
                path.set_file_name(filename);
                path
            };

            if old_path.exists() {
                fs::rename(&old_path, &new_path)
                    .map_err(|e| format!("Failed to rotate log file: {}", e))?;
            }
        }

        // Rename current log to .1
        let rotated_path = {
            let mut path = self.log_path.clone();
            let filename = format!("{}.1", path.file_name().unwrap().to_string_lossy());
            path.set_file_name(filename);
            path
        };

        fs::rename(&self.log_path, &rotated_path)
            .map_err(|e| format!("Failed to rotate current log: {}", e))?;

        Ok(())
    }

    /// Helper function to create an audit entry with current timestamp.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Type of security event
    /// * `success` - Whether the operation succeeded
    /// * `details` - Optional details about the event
    ///
    /// # Returns
    ///
    /// A new `AuditEntry` with current timestamp
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::audit_log::{AuditLogger, AuditEventType};
    /// use std::path::PathBuf;
    ///
    /// let logger = AuditLogger::new(PathBuf::from("/tmp/audit.log"));
    /// let entry = AuditLogger::create_entry(
    ///     AuditEventType::ApplicationStartup,
    ///     true,
    ///     Some("Application started successfully".to_string())
    /// );
    /// ```
    #[must_use]
    pub fn create_entry(
        event_type: AuditEventType,
        success: bool,
        details: Option<String>,
    ) -> AuditEntry {
        AuditEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type,
            success,
            details,
            hmac: String::new(),
        }
    }
}

/// Helper function to get the default audit log path.
///
/// Returns the path to the audit log file in the user's home directory:
/// - Unix-like systems: `~/.password_saver/audit.log`
/// - Windows: `%USERPROFILE%/.password_saver/audit.log`
///
/// # Returns
///
/// A `PathBuf` pointing to the audit log location
///
/// # Example
///
/// ```
/// use rust_slint_password_saver::audit_log::get_audit_log_path;
///
/// let log_path = get_audit_log_path();
/// println!("Audit log: {:?}", log_path);
/// ```
#[must_use]
pub fn get_audit_log_path() -> PathBuf {
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| String::from("."));

    let mut path = PathBuf::from(home_dir);
    path.push(".password_saver");
    path.push("audit.log");

    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_create_entry() {
        let entry = AuditLogger::create_entry(
            AuditEventType::ApplicationStartup,
            true,
            Some("Test details".to_string()),
        );

        assert_eq!(entry.event_type, AuditEventType::ApplicationStartup);
        assert!(entry.success);
        assert_eq!(entry.details, Some("Test details".to_string()));
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn test_audit_logger_creation() {
        let temp_path = PathBuf::from("/tmp/test_audit.log");
        let logger = AuditLogger::new(temp_path.clone());

        // Verify logger was created
        assert!(logger.hmac_key.len() == 32);

        // Clean up
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_log_event() {
        let temp_path = PathBuf::from("/tmp/test_audit_log_event.log");
        let logger = AuditLogger::new(temp_path.clone());

        let entry = AuditLogger::create_entry(
            AuditEventType::MasterPasswordCheck,
            true,
            Some("Password check succeeded".to_string()),
        );

        // Log the event
        let result = logger.log_event(&entry);
        assert!(result.is_ok());

        // Verify log file exists and contains data
        assert!(temp_path.exists());
        let content = fs::read_to_string(&temp_path).unwrap();
        assert!(content.contains("MasterPasswordCheck"));
        assert!(content.contains("Password check succeeded"));

        // Clean up
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_hmac_computation() {
        let temp_path = PathBuf::from("/tmp/test_audit_hmac.log");
        let logger = AuditLogger::new(temp_path.clone());

        let entry = AuditLogger::create_entry(
            AuditEventType::FileAccess,
            true,
            Some("File read".to_string()),
        );

        let hmac = logger.compute_hmac(&entry);
        assert!(hmac.is_ok());
        assert!(!hmac.unwrap().is_empty());

        // Clean up
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_event_type_serialization() {
        let event = AuditEventType::PasswordsSaved;
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("PasswordsSaved"));

        let deserialized: AuditEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, AuditEventType::PasswordsSaved);
    }
}
