//! Database integrity verification module.
//!
//! This module provides functionality to detect database corruption, verify data integrity,
//! and calculate checksums for the encrypted password storage file. It helps identify
//! issues like filesystem errors, incomplete writes, or malicious tampering before
//! attempting to decrypt data.
//!
//! # Security Considerations
//!
//! - SHA-256 checksums detect accidental corruption and tampering
//! - AES-GCM authentication provides additional tamper detection for encrypted data
//! - Early corruption detection prevents data loss and security issues
//! - Comprehensive checks for common corruption patterns
//!
//! # Example
//!
//! ```no_run
//! use rust_slint_password_saver::integrity::IntegrityChecker;
//! use std::path::PathBuf;
//!
//! let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
//!
//! // Check for corruption
//! let report = checker.check_corruption().unwrap();
//! if report.is_healthy() {
//!     println!("Database is healthy");
//! } else {
//!     println!("Issues found: {:?}", report.issues());
//! }
//!
//! // Calculate checksum
//! let checksum = checker.calculate_checksum().unwrap();
//! println!("Database checksum: {}", checksum);
//! ```

use crate::errors::SecurityError;
use log::warn;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

/// Database integrity checker that verifies file integrity and detects corruption.
///
/// This structure provides methods to calculate checksums, verify integrity,
/// and check for common corruption patterns in the encrypted storage file.
///
/// # Example
///
/// ```no_run
/// use rust_slint_password_saver::integrity::IntegrityChecker;
/// use std::path::PathBuf;
///
/// let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
/// let report = checker.check_corruption().unwrap();
///
/// if !report.is_healthy() {
///     eprintln!("Corruption detected: {:?}", report.issues());
/// }
/// ```
#[allow(dead_code)]
pub struct IntegrityChecker {
    path: PathBuf,
}

impl IntegrityChecker {
    /// Creates a new integrity checker for the specified file path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database file to check
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::integrity::IntegrityChecker;
    /// use std::path::PathBuf;
    ///
    /// let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
    /// ```
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Calculates SHA-256 checksum of the database file.
    ///
    /// This method reads the entire file and computes a SHA-256 hash,
    /// which can be used to detect any changes to the file contents.
    ///
    /// # Returns
    ///
    /// Hex-encoded SHA-256 checksum string on success, or a `SecurityError` on failure
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::StorageError` if the file cannot be read
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::integrity::IntegrityChecker;
    /// use std::path::PathBuf;
    ///
    /// let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
    /// let checksum = checker.calculate_checksum().unwrap();
    /// println!("Checksum: {}", checksum);
    /// ```
    #[allow(dead_code)]
    pub fn calculate_checksum(&self) -> Result<String, SecurityError> {
        let data = fs::read(&self.path).map_err(|e| {
            warn!("Failed to read file for checksum: {}", e);
            SecurityError::StorageError
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();

        Ok(hex::encode(result))
    }

    /// Verifies file integrity against an expected checksum.
    ///
    /// This method calculates the current checksum and compares it to the
    /// expected value to detect any modifications to the file.
    ///
    /// # Arguments
    ///
    /// * `expected_checksum` - Hex-encoded SHA-256 checksum to compare against
    ///
    /// # Returns
    ///
    /// `true` if checksums match, `false` otherwise, or a `SecurityError` on failure
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::StorageError` if the file cannot be read
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::integrity::IntegrityChecker;
    /// use std::path::PathBuf;
    ///
    /// let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
    /// let checksum = checker.calculate_checksum().unwrap();
    ///
    /// // Later, verify the file hasn't changed
    /// assert!(checker.verify_integrity(&checksum).unwrap());
    /// ```
    #[allow(dead_code)]
    pub fn verify_integrity(&self, expected_checksum: &str) -> Result<bool, SecurityError> {
        let actual_checksum = self.calculate_checksum()?;
        Ok(actual_checksum == expected_checksum)
    }

    /// Checks for common corruption patterns in the database file.
    ///
    /// This method performs comprehensive checks for various corruption indicators:
    /// - Validates JSON structure
    /// - Checks for required fields (salt, nonce, `encrypted_data`)
    /// - Detects file truncation (suspiciously small files)
    /// - Checks for null bytes (corruption indicator)
    ///
    /// # Returns
    ///
    /// A `CorruptionReport` containing detailed information about the file's health
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::StorageError` if the file cannot be read
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::integrity::IntegrityChecker;
    /// use std::path::PathBuf;
    ///
    /// let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
    /// let report = checker.check_corruption().unwrap();
    ///
    /// if !report.is_healthy() {
    ///     for issue in report.issues() {
    ///         eprintln!("Issue: {}", issue);
    ///     }
    /// }
    /// ```
    pub fn check_corruption(&self) -> Result<CorruptionReport, SecurityError> {
        let data = fs::read(&self.path).map_err(|e| {
            warn!("Failed to read file for corruption check: {}", e);
            SecurityError::StorageError
        })?;

        // Check if file is valid JSON
        let valid_json = serde_json::from_slice::<serde_json::Value>(&data).is_ok();

        // Check if file has expected structure
        let (has_salt, has_nonce, has_encrypted_data) =
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
                (
                    json.get("salt").is_some(),
                    json.get("nonce").is_some(),
                    json.get("encrypted_data").is_some(),
                )
            } else {
                (false, false, false)
            };

        // Check for truncation (incomplete write)
        let file_size = data.len();
        let appears_truncated = data.len() < 100; // Suspiciously small

        // Check for null bytes (corruption indicator)
        let has_null_bytes = data.contains(&0);

        Ok(CorruptionReport {
            valid_json,
            has_salt,
            has_nonce,
            has_encrypted_data,
            file_size,
            appears_truncated,
            has_null_bytes,
        })
    }
}

/// Report detailing the health status of a database file.
///
/// This structure contains the results of corruption detection checks,
/// including whether the file is valid JSON, has required fields,
/// appears truncated, or contains suspicious null bytes.
///
/// # Example
///
/// ```no_run
/// use rust_slint_password_saver::integrity::IntegrityChecker;
/// use std::path::PathBuf;
///
/// let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
/// let report = checker.check_corruption().unwrap();
///
/// if report.is_healthy() {
///     println!("Database is healthy!");
/// } else {
///     println!("Corruption detected!");
///     for issue in report.issues() {
///         println!("  - {}", issue);
///     }
/// }
/// ```
#[derive(Default, Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct CorruptionReport {
    /// Whether the file contains valid JSON
    pub valid_json: bool,
    /// Whether the file has a salt field
    pub has_salt: bool,
    /// Whether the file has a nonce field
    pub has_nonce: bool,
    /// Whether the file has an `encrypted_data` field
    pub has_encrypted_data: bool,
    /// Size of the file in bytes
    pub file_size: usize,
    /// Whether the file appears to be truncated (too small)
    pub appears_truncated: bool,
    /// Whether the file contains unexpected null bytes
    pub has_null_bytes: bool,
}

impl CorruptionReport {
    /// Returns whether the database file appears to be healthy.
    ///
    /// A file is considered healthy if:
    /// - It is valid JSON
    /// - It has all required fields (salt, nonce, `encrypted_data`)
    /// - It doesn't appear truncated
    /// - It doesn't contain null bytes
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::integrity::IntegrityChecker;
    /// use std::path::PathBuf;
    ///
    /// let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
    /// let report = checker.check_corruption().unwrap();
    ///
    /// if report.is_healthy() {
    ///     println!("All checks passed!");
    /// }
    /// ```
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.valid_json
            && self.has_salt
            && self.has_nonce
            && self.has_encrypted_data
            && !self.appears_truncated
            && !self.has_null_bytes
    }

    /// Returns a list of specific issues found during corruption checks.
    ///
    /// This method generates human-readable descriptions of each problem
    /// detected in the database file.
    ///
    /// # Returns
    ///
    /// A vector of strings describing detected issues, or an empty vector
    /// if the file is healthy.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::integrity::IntegrityChecker;
    /// use std::path::PathBuf;
    ///
    /// let checker = IntegrityChecker::new(PathBuf::from("passwords.enc"));
    /// let report = checker.check_corruption().unwrap();
    ///
    /// for issue in report.issues() {
    ///     eprintln!("Problem: {}", issue);
    /// }
    /// ```
    #[must_use]
    pub fn issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if !self.valid_json {
            issues.push("File is not valid JSON".to_string());
        }
        if !self.has_salt {
            issues.push("Missing salt field".to_string());
        }
        if !self.has_nonce {
            issues.push("Missing nonce field".to_string());
        }
        if !self.has_encrypted_data {
            issues.push("Missing encrypted_data field".to_string());
        }
        if self.appears_truncated {
            issues.push(format!(
                "File appears truncated (only {} bytes)",
                self.file_size
            ));
        }
        if self.has_null_bytes {
            issues.push("File contains unexpected null bytes".to_string());
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_integrity_checker_creation() {
        let checker = IntegrityChecker::new(PathBuf::from("test.enc"));
        assert_eq!(checker.path, PathBuf::from("test.enc"));
    }

    #[test]
    fn test_calculate_checksum_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");

        let test_data = b"test data for checksum";
        fs::write(&file_path, test_data).unwrap();

        let checker = IntegrityChecker::new(file_path);
        let checksum = checker.calculate_checksum().unwrap();

        // Verify checksum is a valid hex string of correct length (64 chars for SHA-256)
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_calculate_checksum_nonexistent_file() {
        let checker = IntegrityChecker::new(PathBuf::from("/nonexistent/file.enc"));
        let result = checker.calculate_checksum();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SecurityError::StorageError));
    }

    #[test]
    fn test_verify_integrity_match() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");

        fs::write(&file_path, b"test data").unwrap();

        let checker = IntegrityChecker::new(file_path);
        let checksum = checker.calculate_checksum().unwrap();

        // Verify against itself
        assert!(checker.verify_integrity(&checksum).unwrap());
    }

    #[test]
    fn test_verify_integrity_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");

        fs::write(&file_path, b"test data").unwrap();

        let checker = IntegrityChecker::new(file_path);

        // Use an incorrect checksum
        let wrong_checksum = "0".repeat(64);
        assert!(!checker.verify_integrity(&wrong_checksum).unwrap());
    }

    #[test]
    fn test_corruption_report_healthy() {
        let report = CorruptionReport {
            valid_json: true,
            has_salt: true,
            has_nonce: true,
            has_encrypted_data: true,
            file_size: 1000,
            appears_truncated: false,
            has_null_bytes: false,
        };

        assert!(report.is_healthy());
        assert!(report.issues().is_empty());
    }

    #[test]
    fn test_corruption_report_invalid_json() {
        let report = CorruptionReport {
            valid_json: false,
            has_salt: true,
            has_nonce: true,
            has_encrypted_data: true,
            file_size: 1000,
            appears_truncated: false,
            has_null_bytes: false,
        };

        assert!(!report.is_healthy());
        let issues = report.issues();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0], "File is not valid JSON");
    }

    #[test]
    fn test_corruption_report_missing_fields() {
        let report = CorruptionReport {
            valid_json: true,
            has_salt: false,
            has_nonce: false,
            has_encrypted_data: false,
            file_size: 1000,
            appears_truncated: false,
            has_null_bytes: false,
        };

        assert!(!report.is_healthy());
        let issues = report.issues();
        assert_eq!(issues.len(), 3);
        assert!(issues.contains(&"Missing salt field".to_string()));
        assert!(issues.contains(&"Missing nonce field".to_string()));
        assert!(issues.contains(&"Missing encrypted_data field".to_string()));
    }

    #[test]
    fn test_corruption_report_truncated() {
        let report = CorruptionReport {
            valid_json: true,
            has_salt: true,
            has_nonce: true,
            has_encrypted_data: true,
            file_size: 50,
            appears_truncated: true,
            has_null_bytes: false,
        };

        assert!(!report.is_healthy());
        let issues = report.issues();
        assert!(issues.iter().any(|i| i.contains("truncated")));
    }

    #[test]
    fn test_corruption_report_null_bytes() {
        let report = CorruptionReport {
            valid_json: true,
            has_salt: true,
            has_nonce: true,
            has_encrypted_data: true,
            file_size: 1000,
            appears_truncated: false,
            has_null_bytes: true,
        };

        assert!(!report.is_healthy());
        let issues = report.issues();
        assert!(issues.iter().any(|i| i.contains("unexpected null bytes")));
    }

    #[test]
    fn test_check_corruption_healthy_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");

        let test_data = r#"{
            "salt": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            "nonce": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            "encrypted_data": [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200]
        }"#;
        fs::write(&file_path, test_data).unwrap();

        let checker = IntegrityChecker::new(file_path);
        let report = checker.check_corruption().unwrap();

        assert!(report.is_healthy());
        assert!(report.valid_json);
        assert!(report.has_salt);
        assert!(report.has_nonce);
        assert!(report.has_encrypted_data);
        assert!(!report.appears_truncated);
        assert!(!report.has_null_bytes);
    }

    #[test]
    fn test_check_corruption_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");

        fs::write(&file_path, b"not valid json {{{").unwrap();

        let checker = IntegrityChecker::new(file_path);
        let report = checker.check_corruption().unwrap();

        assert!(!report.is_healthy());
        assert!(!report.valid_json);
    }

    #[test]
    fn test_check_corruption_truncated_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");

        // Write a very small file (< 100 bytes)
        fs::write(&file_path, b"tiny").unwrap();

        let checker = IntegrityChecker::new(file_path);
        let report = checker.check_corruption().unwrap();

        assert!(!report.is_healthy());
        assert!(report.appears_truncated);
        assert_eq!(report.file_size, 4);
    }

    #[test]
    fn test_check_corruption_null_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");

        let mut data = vec![b'a'; 200];
        data[50] = 0; // Insert null byte
        fs::write(&file_path, data).unwrap();

        let checker = IntegrityChecker::new(file_path);
        let report = checker.check_corruption().unwrap();

        assert!(!report.is_healthy());
        assert!(report.has_null_bytes);
    }

    #[test]
    fn test_check_corruption_missing_fields() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.enc");

        let test_data = r#"{
            "salt": [1, 2, 3],
            "other_field": "value"
        }"#;
        fs::write(&file_path, test_data).unwrap();

        let checker = IntegrityChecker::new(file_path);
        let report = checker.check_corruption().unwrap();

        assert!(!report.is_healthy());
        assert!(report.valid_json);
        assert!(report.has_salt);
        assert!(!report.has_nonce);
        assert!(!report.has_encrypted_data);
    }
}
