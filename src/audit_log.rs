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
use std::path::{Path, PathBuf};
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
/// - HMAC key is a cryptographically random persistent key stored with 0600 permissions
///
/// # Example
///
/// ```no_run
/// use rust_slint_password_saver::audit_log::{AuditLogger, AuditEntry, AuditEventType};
/// use std::path::PathBuf;
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// let logger = AuditLogger::new(PathBuf::from("/tmp/audit.log"), &PathBuf::from("/tmp/audit_hmac.key"));
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
    /// * `hmac_key_path` - Path where the persistent HMAC key is stored (created on first use)
    ///
    /// # Returns
    ///
    /// A new `AuditLogger` instance with a persistent cryptographically random HMAC key
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::audit_log::AuditLogger;
    /// use std::path::PathBuf;
    ///
    /// let logger = AuditLogger::new(
    ///     PathBuf::from("/tmp/audit.log"),
    ///     &PathBuf::from("/tmp/audit_hmac.key"),
    /// );
    /// ```
    #[must_use]
    pub fn new(log_path: PathBuf, hmac_key_path: &Path) -> Self {
        let hmac_key = Self::load_or_create_hmac_key(hmac_key_path);

        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        Self { log_path, hmac_key }
    }

    /// Loads an existing HMAC key from `key_path`, or generates and persists a new one.
    ///
    /// On first launch, generates a 32-byte cryptographically random key using `OsRng`
    /// and writes it to `key_path` with 0600 permissions. On subsequent launches, reads
    /// the key from the file.
    ///
    /// # Arguments
    ///
    /// * `key_path` - Path to the persistent HMAC key file
    ///
    /// # Returns
    ///
    /// A 32-byte HMAC key
    #[must_use]
    pub fn load_or_create_hmac_key(key_path: &Path) -> [u8; 32] {
        if key_path.exists() {
            if let Ok(bytes) = fs::read(key_path) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return key;
                }
            }
        }
        // Generate new random key
        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut key);
        // Persist with secure permissions
        if let Err(e) = fs::write(key_path, key) {
            log::warn!(
                "Failed to persist audit HMAC key to {}: {}. \
                 HMAC integrity will not survive restarts.",
                key_path.display(),
                e
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            if let Err(e) = fs::set_permissions(key_path, permissions) {
                log::warn!(
                    "Failed to set 0600 permissions on audit HMAC key {}: {}. \
                     Key file may be world-readable.",
                    key_path.display(),
                    e
                );
            }
        }
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
    /// let logger = AuditLogger::new(
    ///     PathBuf::from("/tmp/audit.log"),
    ///     &PathBuf::from("/tmp/audit_hmac.key"),
    /// );
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
    /// let logger = AuditLogger::new(
    ///     PathBuf::from("/tmp/audit.log"),
    ///     &PathBuf::from("/tmp/audit_hmac.key"),
    /// );
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

/// Helper function to get the default audit HMAC key path.
///
/// Returns the path to the persistent HMAC key file used for audit log integrity:
/// - Unix-like systems: `~/.password_saver/audit_hmac.key`
/// - Windows: `%USERPROFILE%/.password_saver/audit_hmac.key`
///
/// # Returns
///
/// A `PathBuf` pointing to the audit HMAC key location
///
/// # Example
///
/// ```
/// use rust_slint_password_saver::audit_log::get_audit_hmac_key_path;
///
/// let key_path = get_audit_hmac_key_path();
/// println!("HMAC key: {:?}", key_path);
/// ```
#[must_use]
pub fn get_audit_hmac_key_path() -> PathBuf {
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| String::from("."));

    let mut path = PathBuf::from(home_dir);
    path.push(".password_saver");
    path.push("audit_hmac.key");

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
        let temp_key_path = PathBuf::from("/tmp/test_audit_key.key");
        let logger = AuditLogger::new(temp_path.clone(), &temp_key_path);

        // Verify logger was created
        assert!(logger.hmac_key.len() == 32);

        // Clean up
        let _ = fs::remove_file(temp_path);
        let _ = fs::remove_file(temp_key_path);
    }

    #[test]
    fn test_log_event() {
        let temp_path = PathBuf::from("/tmp/test_audit_log_event.log");
        let temp_key_path = PathBuf::from("/tmp/test_audit_log_event.key");
        let logger = AuditLogger::new(temp_path.clone(), &temp_key_path);

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
        let _ = fs::remove_file(temp_key_path);
    }

    #[test]
    fn test_hmac_computation() {
        let temp_path = PathBuf::from("/tmp/test_audit_hmac.log");
        let temp_key_path = PathBuf::from("/tmp/test_audit_hmac.key");
        let logger = AuditLogger::new(temp_path.clone(), &temp_key_path);

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
        let _ = fs::remove_file(temp_key_path);
    }

    #[test]
    fn test_event_type_serialization() {
        let event = AuditEventType::PasswordsSaved;
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("PasswordsSaved"));

        let deserialized: AuditEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, AuditEventType::PasswordsSaved);
    }

    #[test]
    fn test_hmac_key_persistence() {
        let temp_key_path = PathBuf::from("/tmp/test_persist_key.key");
        let _ = fs::remove_file(&temp_key_path);

        // First call: key does not exist, should be generated and saved
        let key1 = AuditLogger::load_or_create_hmac_key(&temp_key_path);
        assert!(temp_key_path.exists(), "Key file should be created");
        assert_eq!(key1.len(), 32);

        // Second call: key exists, should be loaded (same value)
        let key2 = AuditLogger::load_or_create_hmac_key(&temp_key_path);
        assert_eq!(key1, key2, "Same key should be loaded on subsequent calls");

        // Clean up
        let _ = fs::remove_file(temp_key_path);
    }

    #[test]
    #[cfg(unix)]
    fn test_hmac_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_key_path = PathBuf::from("/tmp/test_perm_key.key");
        let _ = fs::remove_file(&temp_key_path);

        let _ = AuditLogger::load_or_create_hmac_key(&temp_key_path);
        assert!(temp_key_path.exists());

        let metadata = fs::metadata(&temp_key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Key file should have 0600 permissions");

        // Clean up
        let _ = fs::remove_file(temp_key_path);
    }

    #[test]
    fn test_different_keys_fail_hmac_verification() {
        let log_path = PathBuf::from("/tmp/test_tamper_audit.log");
        let key_path1 = PathBuf::from("/tmp/test_tamper_key1.key");
        let key_path2 = PathBuf::from("/tmp/test_tamper_key2.key");
        let _ = fs::remove_file(&key_path1);
        let _ = fs::remove_file(&key_path2);

        // Create a logger with key1 and log an event
        let logger1 = AuditLogger::new(log_path.clone(), &key_path1);
        let entry = AuditLogger::create_entry(AuditEventType::ApplicationStartup, true, None);
        logger1.log_event(&entry).unwrap();

        // Read the logged entry's HMAC
        let content = fs::read_to_string(&log_path).unwrap();
        let logged_entry: AuditEntry = serde_json::from_str(content.trim()).unwrap();
        let original_hmac = logged_entry.hmac.clone();

        // Create a logger with a different key and compute HMAC for the same entry
        let logger2 = AuditLogger::new(log_path.clone(), &key_path2);
        let hmac2 = logger2.compute_hmac(&logged_entry).unwrap();

        // The HMACs should differ because the keys are different
        assert_ne!(
            original_hmac, hmac2,
            "HMAC from a different key should not match"
        );

        // Clean up
        let _ = fs::remove_file(log_path);
        let _ = fs::remove_file(key_path1);
        let _ = fs::remove_file(key_path2);
    }
}
