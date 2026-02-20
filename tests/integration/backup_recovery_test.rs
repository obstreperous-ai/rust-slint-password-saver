//! Backup and recovery integration tests.
//!
//! # Security Note
//! This file contains hardcoded passwords for testing purposes only.
//! These are NOT real passwords and are used solely for testing backup scenarios.

// Allow hardcoded credentials in test code - these are intentional test fixtures
#![allow(clippy::identity_op)]

use rust_slint_password_saver::backup::BackupManager;
use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

// NOTE: Test contains hardcoded password - TESTING_SECURITY_NOTE.md
const MASTER_PASSWORD: &str = "BackupTest123!";

/// Helper to create a `PasswordEntry`.
fn make_entry(title: &str, username: &str, password: &str) -> PasswordEntry {
    PasswordEntry {
        title: title.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

/// Test the basic backup creation and restoration flow:
/// 1. Create a database with entries.
/// 2. Create an encrypted backup.
/// 3. Verify the backup file can be read independently.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_create_and_verify_backup() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let backup_path = temp_dir.path().join("backup.bak");

    let storage = PasswordStorage::new(storage_path.clone());
    let entries = vec![
        make_entry("Gmail", "user@gmail.com", "secret1"),
        make_entry("GitHub", "user@github.com", "secret2"),
    ];
    storage
        .save_entries(&entries, MASTER_PASSWORD)
        .expect("Failed to save entries");

    // Create backup.
    let manager = BackupManager::new(PasswordStorage::new(storage_path));
    manager
        .create_backup(MASTER_PASSWORD, &backup_path)
        .expect("Failed to create backup");

    // Verify backup file exists and is loadable.
    assert!(backup_path.exists(), "Backup file should exist");
    let backup_storage = PasswordStorage::new(backup_path.clone());
    let loaded = backup_storage
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load from backup");
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].title, "Gmail");
    assert_eq!(loaded[1].title, "GitHub");
}

/// Test restoring from backup after the primary database is corrupted:
/// 1. Create a database with entries.
/// 2. Create a backup.
/// 3. Corrupt the primary database file.
/// 4. Delete the corrupted primary file.
/// 5. Import from backup and verify all entries are restored.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_restore_from_backup_after_corruption() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let backup_path = temp_dir.path().join("backup.bak");

    // Step 1: Create a database with entries.
    let storage = PasswordStorage::new(storage_path.clone());
    let entries = vec![
        make_entry("Twitter", "user@twitter.com", "twpass"),
        make_entry("LinkedIn", "user@linkedin.com", "lipass"),
    ];
    storage
        .save_entries(&entries, MASTER_PASSWORD)
        .expect("Failed to save entries");

    // Step 2: Create a backup.
    let manager = BackupManager::new(PasswordStorage::new(storage_path.clone()));
    manager
        .create_backup(MASTER_PASSWORD, &backup_path)
        .expect("Failed to create backup");

    // Step 3: Corrupt the primary database file.
    fs::write(&storage_path, b"this is corrupted data").expect("Failed to corrupt file");

    // Step 4: Delete the corrupted file to simulate starting fresh.
    fs::remove_file(&storage_path).expect("Failed to remove corrupted file");

    // Step 5: Import from backup into a new storage at the same path.
    let restore_manager = BackupManager::new(PasswordStorage::new(storage_path.clone()));
    let count = restore_manager
        .import_from_file(&backup_path, MASTER_PASSWORD, MASTER_PASSWORD)
        .expect("Failed to import from backup");
    assert_eq!(count, 2, "Should have imported 2 entries");

    // Verify all entries are accessible after restoration.
    let restored = PasswordStorage::new(storage_path);
    let loaded = restored
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load restored entries");
    assert_eq!(loaded.len(), 2);
    let titles: Vec<&str> = loaded.iter().map(|e| e.title.as_str()).collect();
    assert!(titles.contains(&"Twitter"));
    assert!(titles.contains(&"LinkedIn"));
}

/// Test that importing from a backup skips entries that already exist
/// (duplicate detection by title).
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_import_does_not_duplicate_existing_entries() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("primary.enc");
    let backup_path = temp_dir.path().join("backup.bak");

    // Create initial primary with one entry.
    let primary = PasswordStorage::new(storage_path.clone());
    let entry_a = make_entry("ServiceA", "a@example.com", "passA");
    primary
        .save_entries(std::slice::from_ref(&entry_a), MASTER_PASSWORD)
        .expect("Failed to save primary entry");

    // Create backup that also contains ServiceA plus a new ServiceB.
    let backup_entries = vec![entry_a, make_entry("ServiceB", "b@example.com", "passB")];
    let backup_storage = PasswordStorage::new(backup_path.clone());
    backup_storage
        .save_entries(&backup_entries, MASTER_PASSWORD)
        .expect("Failed to save backup entries");

    // Import from backup into primary.
    let manager = BackupManager::new(PasswordStorage::new(storage_path.clone()));
    let imported = manager
        .import_from_file(&backup_path, MASTER_PASSWORD, MASTER_PASSWORD)
        .expect("Failed to import");

    // Only ServiceB is new; ServiceA should be skipped.
    assert_eq!(imported, 1, "Should have imported exactly 1 new entry");

    let result = PasswordStorage::new(storage_path)
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load after import");
    assert_eq!(result.len(), 2, "Primary should now have 2 entries total");
}

/// Test listing backup files in a directory.
#[test]
fn test_list_backups_in_directory() {
    let temp_dir = tempdir().unwrap();
    let backup_dir = temp_dir.path();

    // No backups initially.
    let empty = BackupManager::list_backups(backup_dir).expect("Failed to list empty dir");
    assert!(empty.is_empty(), "No backups should exist initially");

    // Create two .bak files.
    let storage1 = PasswordStorage::new(temp_dir.path().join("src.enc"));
    let entry = make_entry("ListTest", "user", "pass");
    storage1
        .save_entries(&[entry], MASTER_PASSWORD)
        .expect("Failed to save entries");

    let manager1 = BackupManager::new(PasswordStorage::new(temp_dir.path().join("src.enc")));
    manager1
        .create_backup(MASTER_PASSWORD, &backup_dir.join("backup1.bak"))
        .expect("Failed to create backup1");
    manager1
        .create_backup(MASTER_PASSWORD, &backup_dir.join("backup2.bak"))
        .expect("Failed to create backup2");

    let backups = BackupManager::list_backups(backup_dir).expect("Failed to list backups");
    assert_eq!(backups.len(), 2, "Should list exactly 2 backup files");
}
