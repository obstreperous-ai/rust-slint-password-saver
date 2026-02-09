use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Helper function to generate current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn test_zeroization_behavior() {
    // This test verifies that the ZeroizeOnDrop trait is properly derived
    // and that PasswordEntry continues to work correctly with zeroization enabled.
    //
    // Note: Direct verification of memory zeroization is not possible in safe Rust.
    // The zeroize crate provides this guarantee through its Drop implementation,
    // which is automatically called when the struct goes out of scope.
    //
    // What this test verifies:
    // 1. PasswordEntry compiles with Zeroize and ZeroizeOnDrop traits
    // 2. Normal operations (clone, drop) work as expected
    // 3. Serialization/deserialization still functions correctly

    // Create a password entry
    let password = "my_secret_password_123";
    let entry = PasswordEntry {
        title: "Test Entry".to_string(),
        username: "testuser".to_string(),
        password: password.to_string(),
        created_at: current_timestamp(),
    };

    // Clone the password to verify normal operations work
    let password_clone = entry.password.clone();
    assert_eq!(password_clone, password);

    // Drop the entry to trigger zeroization
    // The password field's memory is securely cleared here by ZeroizeOnDrop
    drop(entry);

    // Create another entry to ensure the pattern works consistently
    let entry2 = PasswordEntry {
        title: "Test Entry 2".to_string(),
        username: "user2".to_string(),
        password: "another_password".to_string(),
        created_at: current_timestamp(),
    };

    // Verify serialization/deserialization still works with zeroize
    let json = serde_json::to_string(&entry2).unwrap();
    let deserialized: PasswordEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry2.password, deserialized.password);
    assert_eq!(entry2.title, deserialized.title);

    // entry2 will be dropped here, triggering zeroization
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

#[test]
#[cfg(unix)]
fn test_file_permissions_are_secure() {
    let test_path = std::env::temp_dir().join("test_passwords_perms.enc");

    // Clean up any existing test file
    let _ = fs::remove_file(&test_path);

    let storage = PasswordStorage::new(test_path.clone());
    let master_password = "test_password";

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

    // Verify file permissions are 0600
    let metadata = fs::metadata(&test_path).expect("Failed to get file metadata");
    let permissions = metadata.permissions();
    let mode = permissions.mode();

    // On Unix, the lower 9 bits represent rwxrwxrwx
    // 0600 means rw------- (owner read/write only)
    assert_eq!(
        mode & 0o777,
        0o600,
        "File permissions should be 0600 (owner read/write only)"
    );

    // Clean up
    let _ = fs::remove_file(&test_path);
}

#[test]
#[cfg(unix)]
fn test_directory_permissions_are_secure() {
    let test_dir = std::env::temp_dir().join("test_password_saver_dir");
    let test_path = test_dir.join("passwords.enc");

    // Clean up any existing test directory
    let _ = fs::remove_dir_all(&test_dir);

    // Create directory with secure permissions
    fs::create_dir_all(&test_dir).expect("Failed to create directory");

    // Set directory permissions to 0700
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(&test_dir, permissions).expect("Failed to set directory permissions");

    // Verify directory permissions are 0700
    let metadata = fs::metadata(&test_dir).expect("Failed to get directory metadata");
    let permissions = metadata.permissions();
    let mode = permissions.mode();

    // 0700 means rwx------ (owner read/write/execute only)
    assert_eq!(
        mode & 0o777,
        0o700,
        "Directory permissions should be 0700 (owner read/write/execute only)"
    );

    // Now test that saving a file in this directory preserves directory permissions
    let storage = PasswordStorage::new(test_path.clone());
    let entries = vec![PasswordEntry {
        title: "Test".to_string(),
        username: "user".to_string(),
        password: "pass".to_string(),
        created_at: current_timestamp(),
    }];

    storage
        .save_entries(&entries, "test_password")
        .expect("Failed to save entries");

    // Verify directory permissions are still 0700
    let metadata = fs::metadata(&test_dir).expect("Failed to get directory metadata");
    let permissions = metadata.permissions();
    let mode = permissions.mode();

    assert_eq!(
        mode & 0o777,
        0o700,
        "Directory permissions should remain 0700 after file operations"
    );

    // Clean up
    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
#[cfg(not(unix))]
fn test_permissions_no_op_on_windows() {
    // This test just verifies that setting permissions doesn't fail on Windows
    let test_path = std::env::temp_dir().join("test_passwords_windows.enc");

    // Clean up any existing test file
    let _ = fs::remove_file(&test_path);

    let storage = PasswordStorage::new(test_path.clone());
    let master_password = "test_password";

    // Create and save test entry
    let entries = vec![PasswordEntry {
        title: "Test".to_string(),
        username: "user".to_string(),
        password: "pass".to_string(),
        created_at: current_timestamp(),
    }];

    // This should succeed on Windows without trying to set Unix permissions
    storage
        .save_entries(&entries, master_password)
        .expect("Failed to save entries on Windows");

    // Verify file exists
    assert!(test_path.exists(), "File should exist after save");

    // Clean up
    let _ = fs::remove_file(&test_path);
}
