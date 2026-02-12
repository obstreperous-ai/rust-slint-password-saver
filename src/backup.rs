//! Encrypted backup and export functionality for password storage.
//!
//! This module provides secure backup, export, and import capabilities for password entries.
//! All operations maintain security by encrypting data with passwords using the same
//! encryption methods as the main storage (Argon2 + AES-256-GCM).
//!
//! # Features
//!
//! - **Encrypted Backups**: Create encrypted backups with the master password
//! - **Export with Different Password**: Export data with a different password for secure sharing
//! - **Import with Merging**: Import entries from backup files with duplicate detection
//! - **Backup Listing**: List available backup files in a directory
//!
//! # Security
//!
//! - All backups and exports are encrypted using Argon2 + AES-256-GCM
//! - Supports different passwords for export (secure sharing)
//! - Import operations detect and skip duplicate entries
//! - Uses same security measures as main storage
//!
//! # Example
//!
//! ```no_run
//! use rust_slint_password_saver::backup::BackupManager;
//! use rust_slint_password_saver::storage::PasswordStorage;
//! use std::path::{Path, PathBuf};
//!
//! let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
//! let backup_manager = BackupManager::new(storage);
//!
//! // Create a backup
//! backup_manager.create_backup("master_password", Path::new("backup.bak")).unwrap();
//!
//! // Export with different password
//! backup_manager.export_encrypted(
//!     "master_password",
//!     "export_password",
//!     Path::new("export.enc")
//! ).unwrap();
//!
//! // Import from backup
//! let count = backup_manager.import_from_file(
//!     Path::new("backup.bak"),
//!     "master_password",
//!     "master_password"
//! ).unwrap();
//! println!("Imported {} entries", count);
//! ```

use crate::errors::SecurityError;
use crate::storage::PasswordStorage;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(test)]
use crate::storage::PasswordEntry;

/// Manages encrypted backup, export, and import operations for password entries.
///
/// This structure provides methods to create encrypted backups, export with different
/// passwords, and import entries from backup files. All operations maintain the same
/// security level as the main storage.
///
/// # Example
///
/// ```no_run
/// use rust_slint_password_saver::backup::BackupManager;
/// use rust_slint_password_saver::storage::PasswordStorage;
/// use std::path::PathBuf;
///
/// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
/// let backup_manager = BackupManager::new(storage);
/// ```
pub struct BackupManager {
    storage: PasswordStorage,
}

impl BackupManager {
    /// Creates a new `BackupManager` instance.
    ///
    /// # Arguments
    ///
    /// * `storage` - The `PasswordStorage` instance to backup or import to
    ///
    /// # Returns
    ///
    /// A new `BackupManager` instance
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::backup::BackupManager;
    /// use rust_slint_password_saver::storage::PasswordStorage;
    /// use std::path::PathBuf;
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    /// let backup_manager = BackupManager::new(storage);
    /// ```
    #[must_use]
    pub fn new(storage: PasswordStorage) -> Self {
        Self { storage }
    }

    /// Creates an encrypted backup of all password entries.
    ///
    /// This method loads all entries from the main storage and saves them to a backup
    /// file using the same encryption (Argon2 + AES-256-GCM). The backup is encrypted
    /// with the master password.
    ///
    /// # Arguments
    ///
    /// * `master_password` - The master password to decrypt current entries and encrypt the backup
    /// * `backup_path` - Path where the backup file will be created
    ///
    /// # Returns
    ///
    /// - `Ok(())` if backup was created successfully
    /// - `Err(SecurityError)` if operation failed (wrong password, I/O error, etc.)
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::AuthenticationFailed` if the master password is incorrect.
    /// Returns `SecurityError::StorageError` if file operations fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::backup::BackupManager;
    /// use rust_slint_password_saver::storage::PasswordStorage;
    /// use std::path::{Path, PathBuf};
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    /// let backup_manager = BackupManager::new(storage);
    ///
    /// backup_manager.create_backup("master_password", Path::new("backup.bak")).unwrap();
    /// ```
    pub fn create_backup(
        &self,
        master_password: &str,
        backup_path: &Path,
    ) -> Result<(), SecurityError> {
        // Load current entries with master password
        let entries = self.storage.load_entries(master_password)?;

        // Create backup using same encryption as main storage
        let backup_storage = PasswordStorage::new(backup_path.to_path_buf());
        backup_storage.save_entries(&entries, master_password)?;

        Ok(())
    }

    /// Exports password entries encrypted with a different password.
    ///
    /// This method allows exporting entries with a different password than the master
    /// password. This is useful for secure sharing or migration to other devices.
    ///
    /// # Arguments
    ///
    /// * `master_password` - The current master password to decrypt entries
    /// * `export_password` - The password to encrypt the export file with
    /// * `export_path` - Path where the export file will be created
    ///
    /// # Returns
    ///
    /// - `Ok(())` if export was created successfully
    /// - `Err(SecurityError)` if operation failed
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::AuthenticationFailed` if the master password is incorrect.
    /// Returns `SecurityError::StorageError` if file operations fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::backup::BackupManager;
    /// use rust_slint_password_saver::storage::PasswordStorage;
    /// use std::path::{Path, PathBuf};
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    /// let backup_manager = BackupManager::new(storage);
    ///
    /// backup_manager.export_encrypted(
    ///     "master_password",
    ///     "export_password",
    ///     Path::new("export.enc")
    /// ).unwrap();
    /// ```
    pub fn export_encrypted(
        &self,
        master_password: &str,
        export_password: &str,
        export_path: &Path,
    ) -> Result<(), SecurityError> {
        // Load entries with master password
        let entries = self.storage.load_entries(master_password)?;

        // Export encrypted with different password (allows secure sharing)
        let export_storage = PasswordStorage::new(export_path.to_path_buf());
        export_storage.save_entries(&entries, export_password)?;

        Ok(())
    }

    /// Imports entries from a backup or export file and merges them with existing entries.
    ///
    /// This method loads entries from an import file and merges them with the current
    /// storage. Duplicate entries (based on title) are automatically skipped. The import
    /// file can be encrypted with a different password than the master password.
    ///
    /// # Arguments
    ///
    /// * `import_path` - Path to the backup or export file to import from
    /// * `import_password` - Password to decrypt the import file
    /// * `master_password` - Master password to access and update current storage
    ///
    /// # Returns
    ///
    /// - `Ok(count)` with the number of newly imported entries (excluding duplicates)
    /// - `Err(SecurityError)` if operation failed
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::AuthenticationFailed` if either password is incorrect.
    /// Returns `SecurityError::StorageError` if file operations fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::backup::BackupManager;
    /// use rust_slint_password_saver::storage::PasswordStorage;
    /// use std::path::{Path, PathBuf};
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    /// let backup_manager = BackupManager::new(storage);
    ///
    /// let count = backup_manager.import_from_file(
    ///     Path::new("backup.bak"),
    ///     "backup_password",
    ///     "master_password"
    /// ).unwrap();
    /// println!("Imported {} new entries", count);
    /// ```
    pub fn import_from_file(
        &self,
        import_path: &Path,
        import_password: &str,
        master_password: &str,
    ) -> Result<usize, SecurityError> {
        // Load entries from import file
        let import_storage = PasswordStorage::new(import_path.to_path_buf());
        let imported_entries = import_storage.load_entries(import_password)?;

        // Load current entries (if any)
        let mut current_entries = if self.storage.exists() {
            self.storage.load_entries(master_password)?
        } else {
            Vec::new()
        };

        // Merge imported entries (check for duplicates by title)
        let mut import_count = 0;
        for entry in imported_entries {
            if !current_entries.iter().any(|e| e.title == entry.title) {
                current_entries.push(entry);
                import_count += 1;
            }
        }

        // Save merged entries
        self.storage
            .save_entries(&current_entries, master_password)?;

        Ok(import_count)
    }

    /// Lists all backup files in a directory.
    ///
    /// This method scans a directory for backup files (files with `.bak` extension)
    /// and returns them sorted by modification time (newest first).
    ///
    /// # Arguments
    ///
    /// * `backup_dir` - Path to the directory containing backup files
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<PathBuf>)` with paths to backup files, sorted newest first
    /// - `Err(SecurityError)` if directory cannot be read
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::StorageError` if the directory cannot be read or
    /// if there are issues reading directory entries.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::backup::BackupManager;
    /// use std::path::PathBuf;
    ///
    /// let backup_dir = PathBuf::from("/home/user/.password_saver/backups");
    /// let backups = BackupManager::list_backups(&backup_dir).unwrap();
    /// for backup in backups {
    ///     println!("Backup: {}", backup.display());
    /// }
    /// ```
    pub fn list_backups(backup_dir: &Path) -> Result<Vec<PathBuf>, SecurityError> {
        let mut backups = Vec::new();

        if !backup_dir.exists() {
            return Ok(backups);
        }

        for entry in fs::read_dir(backup_dir).map_err(|e| {
            SecurityError::InvalidInput(format!("Failed to read backup directory: {e}"))
        })? {
            let entry = entry.map_err(|e| {
                SecurityError::InvalidInput(format!("Failed to read directory entry: {e}"))
            })?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("bak") {
                backups.push(path);
            }
        }

        // Sort by modification time (newest first)
        backups.sort_by(|a, b| {
            let a_time = fs::metadata(a).and_then(|m| m.modified()).ok();
            let b_time = fs::metadata(b).and_then(|m| m.modified()).ok();
            b_time.cmp(&a_time)
        });

        Ok(backups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_backup_manager_creation() {
        let temp_dir = std::env::temp_dir();
        let storage_path = temp_dir.join("test_backup_manager.enc");
        let storage = PasswordStorage::new(storage_path.clone());
        let _manager = BackupManager::new(storage);

        // Cleanup
        let _ = fs::remove_file(storage_path);
    }

    #[test]
    fn test_create_and_restore_backup() {
        let temp_dir = std::env::temp_dir();
        let storage_path = temp_dir.join("test_backup_storage.enc");
        let backup_path = temp_dir.join("test_backup.bak");

        // Create and save some test entries
        let storage = PasswordStorage::new(storage_path.clone());
        let entries = vec![
            PasswordEntry {
                title: "Test1".to_string(),
                username: "user1".to_string(),
                password: "pass1".to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            PasswordEntry {
                title: "Test2".to_string(),
                username: "user2".to_string(),
                password: "pass2".to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        ];
        storage.save_entries(&entries, "TestPass123").unwrap();

        // Create backup
        let manager = BackupManager::new(storage);
        manager.create_backup("TestPass123", &backup_path).unwrap();

        // Verify backup file exists
        assert!(backup_path.exists());

        // Load from backup
        let backup_storage = PasswordStorage::new(backup_path.clone());
        let loaded_entries = backup_storage.load_entries("TestPass123").unwrap();

        // Verify entries match
        assert_eq!(loaded_entries.len(), 2);
        assert_eq!(loaded_entries[0].title, "Test1");
        assert_eq!(loaded_entries[1].title, "Test2");

        // Cleanup
        let _ = fs::remove_file(storage_path);
        let _ = fs::remove_file(backup_path);
    }

    #[test]
    fn test_export_with_different_password() {
        let temp_dir = std::env::temp_dir();
        let storage_path = temp_dir.join("test_export_storage.enc");
        let export_path = temp_dir.join("test_export.enc");

        // Create and save test entries
        let storage = PasswordStorage::new(storage_path.clone());
        let entries = vec![PasswordEntry {
            title: "ExportTest".to_string(),
            username: "export_user".to_string(),
            password: "export_pass".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }];
        storage.save_entries(&entries, "MasterPass123").unwrap();

        // Export with different password
        let manager = BackupManager::new(storage);
        manager
            .export_encrypted("MasterPass123", "ExportPass456", &export_path)
            .unwrap();

        // Verify export file exists
        assert!(export_path.exists());

        // Load with export password (not master password)
        let export_storage = PasswordStorage::new(export_path.clone());
        let loaded_entries = export_storage.load_entries("ExportPass456").unwrap();

        // Verify entries match
        assert_eq!(loaded_entries.len(), 1);
        assert_eq!(loaded_entries[0].title, "ExportTest");

        // Verify master password doesn't work on export
        assert!(export_storage.load_entries("MasterPass123").is_err());

        // Cleanup
        let _ = fs::remove_file(storage_path);
        let _ = fs::remove_file(export_path);
    }

    #[test]
    fn test_import_merges_entries() {
        let temp_dir = std::env::temp_dir();
        let storage_path = temp_dir.join("test_import_main.enc");
        let import_path = temp_dir.join("test_import_source.enc");

        // Create main storage with existing entries
        let storage = PasswordStorage::new(storage_path.clone());
        let existing_entries = vec![PasswordEntry {
            title: "Existing".to_string(),
            username: "existing_user".to_string(),
            password: "existing_pass".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }];
        storage
            .save_entries(&existing_entries, "TestPass123")
            .unwrap();

        // Create import source with new entries
        let import_storage = PasswordStorage::new(import_path.clone());
        let import_entries = vec![
            PasswordEntry {
                title: "New1".to_string(),
                username: "new1_user".to_string(),
                password: "new1_pass".to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            PasswordEntry {
                title: "New2".to_string(),
                username: "new2_user".to_string(),
                password: "new2_pass".to_string(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        ];
        import_storage
            .save_entries(&import_entries, "ImportPass456")
            .unwrap();

        // Import entries
        let manager = BackupManager::new(storage);
        let count = manager
            .import_from_file(&import_path, "ImportPass456", "TestPass123")
            .unwrap();

        // Verify import count
        assert_eq!(count, 2);

        // Verify merged entries
        let main_storage = PasswordStorage::new(storage_path.clone());
        let merged_entries = main_storage.load_entries("TestPass123").unwrap();
        assert_eq!(merged_entries.len(), 3);

        // Cleanup
        let _ = fs::remove_file(storage_path);
        let _ = fs::remove_file(import_path);
    }

    #[test]
    fn test_import_skips_duplicates() {
        let temp_dir = std::env::temp_dir();
        let storage_path = temp_dir.join("test_duplicate_main.enc");
        let import_path = temp_dir.join("test_duplicate_source.enc");

        // Create main storage with existing entries
        let storage = PasswordStorage::new(storage_path.clone());
        let existing_entries = vec![PasswordEntry {
            title: "Duplicate".to_string(),
            username: "user1".to_string(),
            password: "pass1".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }];
        storage
            .save_entries(&existing_entries, "TestPass123")
            .unwrap();

        // Create import source with same title (different credentials)
        let import_storage = PasswordStorage::new(import_path.clone());
        let import_entries = vec![PasswordEntry {
            title: "Duplicate".to_string(), // Same title - should be skipped
            username: "user2".to_string(),
            password: "pass2".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }];
        import_storage
            .save_entries(&import_entries, "ImportPass456")
            .unwrap();

        // Import entries
        let manager = BackupManager::new(storage);
        let count = manager
            .import_from_file(&import_path, "ImportPass456", "TestPass123")
            .unwrap();

        // Verify no new entries were imported
        assert_eq!(count, 0);

        // Verify original entry unchanged
        let main_storage = PasswordStorage::new(storage_path.clone());
        let merged_entries = main_storage.load_entries("TestPass123").unwrap();
        assert_eq!(merged_entries.len(), 1);
        assert_eq!(merged_entries[0].username, "user1"); // Original not changed

        // Cleanup
        let _ = fs::remove_file(storage_path);
        let _ = fs::remove_file(import_path);
    }

    #[test]
    fn test_list_backups() {
        let temp_dir = std::env::temp_dir().join("test_backups_list");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create some test backup files
        fs::write(temp_dir.join("backup1.bak"), "test1").unwrap();
        fs::write(temp_dir.join("backup2.bak"), "test2").unwrap();
        fs::write(temp_dir.join("not_backup.txt"), "test3").unwrap(); // Should be ignored

        // List backups
        let backups = BackupManager::list_backups(&temp_dir).unwrap();

        // Verify only .bak files are listed
        assert_eq!(backups.len(), 2);
        assert!(backups.iter().all(|p| p.extension().unwrap() == "bak"));

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_list_backups_nonexistent_directory() {
        let temp_dir = std::env::temp_dir().join("nonexistent_backup_dir_12345");

        // Should return empty list for nonexistent directory
        let backups = BackupManager::list_backups(&temp_dir).unwrap();
        assert_eq!(backups.len(), 0);
    }
}
