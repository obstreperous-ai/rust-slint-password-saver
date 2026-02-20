//! Integration tests for cross-platform functionality
//!
//! # Security Note
//! This file contains hardcoded passwords for testing purposes only.
//! These are NOT real passwords and are used solely for testing integration scenarios.

// Allow hardcoded credentials in test code - these are intentional test fixtures
#![allow(clippy::identity_op)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimum timestamp for year 2020 (Jan 1, 2020 00:00:00 UTC)
const JAN_1_2020_TIMESTAMP: u64 = 1_577_836_800;

#[test]
fn test_cross_platform_path_creation() {
    // Test that we can create a path structure
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| String::from("."));

    let mut path = PathBuf::from(home_dir);
    path.push(".password_saver_test");
    path.push("test_passwords.enc");

    // Create parent directory
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("Failed to create test directory");
    }

    // Verify directory was created
    assert!(path.parent().unwrap().exists());

    // Clean up
    let _ = fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn test_timestamp_generation() {
    // Test that we can generate timestamps correctly
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Timestamp should be reasonable (after 2020)
    assert!(timestamp > JAN_1_2020_TIMESTAMP);
}

#[test]
fn test_basic_functionality() {
    // This is a placeholder test to ensure the test infrastructure works
    assert_eq!(2 + 2, 4);
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_password_change_integration() {
    use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};

    let test_path = std::env::temp_dir().join("test_integration_password_change.enc");

    // Clean up any existing test file
    let _ = fs::remove_file(&test_path);

    let storage = PasswordStorage::new(test_path.clone());
    let old_password = "OldSecure123";
    let new_password = "NewSecure456";

    // Create initial test data
    let entries = vec![
        PasswordEntry {
            title: "TestAccount1".to_string(),
            username: "user1@example.com".to_string(),
            password: "secret123".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        },
        PasswordEntry {
            title: "TestAccount2".to_string(),
            username: "user2@example.com".to_string(),
            password: "password456".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        },
    ];

    // Step 1: Save with old password
    storage
        .save_entries(&entries, old_password)
        .expect("Failed to save with old password");

    // Step 2: Verify we can load with old password
    let loaded = storage
        .load_entries(old_password)
        .expect("Failed to load with old password");
    assert_eq!(loaded.len(), 2);

    // Step 3: Change the master password
    storage
        .change_master_password(old_password, new_password)
        .expect("Failed to change master password");

    // Step 4: Verify old password no longer works
    let old_result = storage.load_entries(old_password);
    assert!(
        old_result.is_err(),
        "Old password should not work after change"
    );

    // Step 5: Verify new password works and data is intact
    let new_loaded = storage
        .load_entries(new_password)
        .expect("Failed to load with new password");
    assert_eq!(new_loaded.len(), 2);
    assert_eq!(new_loaded[0].title, "TestAccount1");
    assert_eq!(new_loaded[0].username, "user1@example.com");
    assert_eq!(new_loaded[0].password, "secret123");
    assert_eq!(new_loaded[1].title, "TestAccount2");
    assert_eq!(new_loaded[1].username, "user2@example.com");
    assert_eq!(new_loaded[1].password, "password456");

    // Clean up
    let _ = fs::remove_file(&test_path);
}

/// Verify that a newly created directory has secure 0700 permissions (Unix only).
///
/// This test validates the happy path: after creating a directory and setting
/// permissions to 0700, `fs::metadata()` should confirm the mode is exactly 0700.
#[cfg(unix)]
#[test]
fn test_directory_permissions_verification() {
    use std::os::unix::fs::PermissionsExt;

    let test_dir =
        std::env::temp_dir().join(format!("test_permission_verify_dir_{}", std::process::id()));

    // Clean up any previous run
    let _ = fs::remove_dir_all(&test_dir);

    // Create the directory
    fs::create_dir_all(&test_dir).expect("Failed to create test directory");

    // Set permissions to 0700
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&test_dir, permissions).expect("Failed to set permissions");

    // Verify permissions were actually set (the happy path)
    let metadata = fs::metadata(&test_dir).expect("Failed to read metadata");
    let actual_mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        actual_mode, 0o700,
        "Directory permissions should be 0700, got {:o}",
        actual_mode
    );

    // Clean up
    let _ = fs::remove_dir_all(&test_dir);
}
