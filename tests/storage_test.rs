use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper function to generate current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn test_full_encryption_flow() {
    // Create a temporary test file
    let test_path = std::env::temp_dir().join("test_passwords_full.enc");

    // Clean up any existing test file
    let _ = fs::remove_file(&test_path);

    let storage = PasswordStorage::new(test_path.clone());
    let master_password = "test_master_password_123";

    // Create test entries
    let entries = vec![
        PasswordEntry {
            title: "GitHub".to_string(),
            username: "testuser".to_string(),
            password: "github_password_123".to_string(),
            created_at: current_timestamp(),
        },
        PasswordEntry {
            title: "Gmail".to_string(),
            username: "test@example.com".to_string(),
            password: "gmail_password_456".to_string(),
            created_at: current_timestamp(),
        },
    ];

    // Save entries
    storage
        .save_entries(&entries, master_password)
        .expect("Failed to save entries");

    // Verify file exists
    assert!(storage.exists());

    // Load entries back
    let loaded_entries = storage
        .load_entries(master_password)
        .expect("Failed to load entries");

    // Verify loaded entries match original
    assert_eq!(loaded_entries.len(), 2);
    assert_eq!(loaded_entries[0].title, "GitHub");
    assert_eq!(loaded_entries[0].username, "testuser");
    assert_eq!(loaded_entries[0].password, "github_password_123");
    assert_eq!(loaded_entries[1].title, "Gmail");
    assert_eq!(loaded_entries[1].username, "test@example.com");
    assert_eq!(loaded_entries[1].password, "gmail_password_456");

    // Clean up
    let _ = fs::remove_file(&test_path);
}

#[test]
fn test_wrong_master_password() {
    // Create a temporary test file
    let test_path = std::env::temp_dir().join("test_passwords_wrong.enc");

    // Clean up any existing test file
    let _ = fs::remove_file(&test_path);

    let storage = PasswordStorage::new(test_path.clone());
    let master_password = "correct_password";
    let wrong_password = "wrong_password";

    // Create and save test entry
    let entries = vec![PasswordEntry {
        title: "Test".to_string(),
        username: "user".to_string(),
        password: "pass".to_string(),
        created_at: current_timestamp(),
    }];

    storage
        .save_entries(&entries, master_password)
        .expect("Failed to save entries");

    // Try to load with wrong password
    let result = storage.load_entries(wrong_password);
    assert!(result.is_err(), "Should fail with wrong password");

    // Verify correct password works
    let loaded = storage.load_entries(master_password);
    assert!(loaded.is_ok(), "Should work with correct password");

    // Clean up
    let _ = fs::remove_file(&test_path);
}

#[test]
fn test_multiple_save_and_load_cycles() {
    let test_path = std::env::temp_dir().join("test_passwords_cycles.enc");

    // Clean up any existing test file
    let _ = fs::remove_file(&test_path);

    let storage = PasswordStorage::new(test_path.clone());
    let master_password = "test_password";

    // First cycle: Save and load
    let mut entries = vec![PasswordEntry {
        title: "Entry1".to_string(),
        username: "user1".to_string(),
        password: "pass1".to_string(),
        created_at: current_timestamp(),
    }];

    storage
        .save_entries(&entries, master_password)
        .expect("Failed to save in cycle 1");
    let loaded = storage
        .load_entries(master_password)
        .expect("Failed to load in cycle 1");
    assert_eq!(loaded.len(), 1);

    // Second cycle: Add more entries
    entries.push(PasswordEntry {
        title: "Entry2".to_string(),
        username: "user2".to_string(),
        password: "pass2".to_string(),
        created_at: current_timestamp(),
    });

    storage
        .save_entries(&entries, master_password)
        .expect("Failed to save in cycle 2");
    let loaded = storage
        .load_entries(master_password)
        .expect("Failed to load in cycle 2");
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].title, "Entry1");
    assert_eq!(loaded[1].title, "Entry2");

    // Clean up
    let _ = fs::remove_file(&test_path);
}

#[test]
fn test_empty_entries() {
    let test_path = std::env::temp_dir().join("test_passwords_empty.enc");

    // Clean up any existing test file
    let _ = fs::remove_file(&test_path);

    let storage = PasswordStorage::new(test_path.clone());
    let master_password = "test_password";

    // Save empty entries
    let entries: Vec<PasswordEntry> = vec![];
    storage
        .save_entries(&entries, master_password)
        .expect("Failed to save empty entries");

    // Load and verify
    let loaded = storage
        .load_entries(master_password)
        .expect("Failed to load empty entries");
    assert_eq!(loaded.len(), 0);

    // Clean up
    let _ = fs::remove_file(&test_path);
}
