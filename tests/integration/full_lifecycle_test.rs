//! Full lifecycle integration tests for the password manager.
//!
//! # Security Note
//! This file contains hardcoded passwords for testing purposes only.
//! These are NOT real passwords and are used solely for testing lifecycle scenarios.

// Allow hardcoded credentials in test code - these are intentional test fixtures
#![allow(clippy::identity_op)]

use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

// NOTE: Test contains hardcoded password - TESTING_SECURITY_NOTE.md
const MASTER_PASSWORD: &str = "TestLifecycle123!";

/// Helper to create a `PasswordEntry` with the current timestamp.
fn make_entry(title: &str, username: &str, password: &str, timestamp: u64) -> PasswordEntry {
    PasswordEntry {
        title: title.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        created_at: timestamp,
    }
}

/// Helper to get the current Unix timestamp.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Test the complete password management lifecycle:
/// 1. Create a new encrypted database.
/// 2. Save an initial entry and verify it loads correctly.
/// 3. Add a second entry and verify both entries load.
/// 4. Delete one entry (save without it) and verify only the remaining entry persists.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_complete_password_lifecycle() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    let entry1 = make_entry("Gmail", "user@gmail.com", "secret1", 1000);
    let entry2 = make_entry("GitHub", "user@github.com", "secret2", 2000);

    // 1. Save a single entry.
    storage
        .save_entries(std::slice::from_ref(&entry1), MASTER_PASSWORD)
        .expect("Failed to save initial entry");

    // 2. Load and verify.
    let loaded = storage
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load entries");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].title, "Gmail");
    assert_eq!(loaded[0].username, "user@gmail.com");
    assert_eq!(loaded[0].password, "secret1");

    // 3. Add a second entry by saving both.
    storage
        .save_entries(&[entry1.clone(), entry2.clone()], MASTER_PASSWORD)
        .expect("Failed to save two entries");

    let loaded = storage
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load two entries");
    assert_eq!(loaded.len(), 2);

    // 4. Delete the first entry (save only entry2).
    storage
        .save_entries(std::slice::from_ref(&entry2), MASTER_PASSWORD)
        .expect("Failed to save after deletion");

    let loaded = storage
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load after deletion");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].title, "GitHub");
}

/// Test that the master password can be changed and the new password grants access
/// while the old password no longer works.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_master_password_change() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    let new_password = "NewPassword456!";
    let entry = make_entry("TestSite", "user@example.com", "mypassword", now());

    // Save with original master password.
    storage
        .save_entries(std::slice::from_ref(&entry), MASTER_PASSWORD)
        .expect("Failed to save entries");

    // Change the master password.
    storage
        .change_master_password(MASTER_PASSWORD, new_password)
        .expect("Failed to change master password");

    // Old password must no longer work.
    assert!(
        storage.load_entries(MASTER_PASSWORD).is_err(),
        "Old password should be rejected after change"
    );

    // New password must load the entry correctly.
    let loaded = storage
        .load_entries(new_password)
        .expect("Failed to load with new password");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].title, "TestSite");
    assert_eq!(loaded[0].password, "mypassword");
}

/// Test that saving entries with recovery data persists both the entries and the
/// recovery metadata, and that they can be retrieved independently.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_lifecycle_with_recovery_codes() {
    use rust_slint_password_saver::recovery::EmergencyRecovery;

    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    // Generate recovery codes.
    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);
    let hashes = recovery.get_code_hashes();
    let recovery_key = recovery.get_recovery_key();

    let entry = make_entry("RecoveryTest", "admin@example.com", "adminpass", now());

    // Save entries together with recovery metadata.
    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            MASTER_PASSWORD,
            hashes.clone(),
            &recovery_key,
        )
        .expect("Failed to save with recovery data");

    // Verify regular load still works.
    let loaded = storage
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load entries after save_with_recovery");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].title, "RecoveryTest");

    // Verify recovery metadata was persisted.
    let recovery_data = storage
        .load_recovery_data()
        .expect("Failed to load recovery metadata");
    assert!(
        recovery_data.is_some(),
        "Recovery data should be present after save_with_recovery"
    );
}

/// Test that wrong password returns an authentication error.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_wrong_password_returns_error() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    let entry = make_entry("SomeService", "user", "pass", now());
    storage
        .save_entries(&[entry], MASTER_PASSWORD)
        .expect("Failed to save entries");

    let result = storage.load_entries("WrongPassword999!");
    assert!(result.is_err(), "Loading with wrong password must fail");
}

/// Test that updating an entry (overwriting with modified data) round-trips correctly.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_update_entry() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    let original = make_entry("MyService", "user@example.com", "oldpassword", 1000);
    storage
        .save_entries(std::slice::from_ref(&original), MASTER_PASSWORD)
        .expect("Failed to save original entry");

    // Simulate update: replace entry with updated password.
    let updated = make_entry("MyService", "user@example.com", "newpassword", 2000);
    storage
        .save_entries(std::slice::from_ref(&updated), MASTER_PASSWORD)
        .expect("Failed to save updated entry");

    let loaded = storage
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load after update");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].title, "MyService");
    assert_eq!(loaded[0].password, "newpassword");
    assert_eq!(loaded[0].created_at, 2000);
}

/// Test that saving an empty list of entries produces a loadable (empty) database.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_save_and_load_empty_entries() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    storage
        .save_entries(&[], MASTER_PASSWORD)
        .expect("Failed to save empty entries");

    let loaded = storage
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load empty entries");
    assert_eq!(loaded.len(), 0);
}
