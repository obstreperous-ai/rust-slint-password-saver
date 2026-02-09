use rust_slint_password_saver::errors::SecurityError;
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
fn test_authentication_error_is_sanitized() {
    // Create a temporary test file
    let test_path = std::env::temp_dir().join("test_auth_error.enc");
    let _ = fs::remove_file(&test_path);

    let storage = PasswordStorage::new(test_path.clone());
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";

    // Create and save test entry
    let entries = vec![PasswordEntry {
        title: "Test".to_string(),
        username: "user".to_string(),
        password: "pass".to_string(),
        created_at: current_timestamp(),
    }];

    storage
        .save_entries(&entries, correct_password)
        .expect("Failed to save entries");

    // Try to load with wrong password
    let result = storage.load_entries(wrong_password);
    assert!(result.is_err(), "Should fail with wrong password");

    let error = result.unwrap_err();
    let user_msg = error.user_message();

    // Verify user message is generic
    assert_eq!(user_msg, "Incorrect master password. Please try again.");

    // Verify user message does NOT contain sensitive information
    assert!(!user_msg.contains("AES"));
    assert!(!user_msg.contains("GCM"));
    assert!(!user_msg.contains("decrypt"));
    assert!(!user_msg.contains("cipher"));
    assert!(!user_msg.contains("key"));
    assert!(!user_msg.to_lowercase().contains("auth tag"));

    // Clean up
    let _ = fs::remove_file(&test_path);
}

#[test]
fn test_storage_error_is_sanitized() {
    // Try to read from a non-existent file
    let test_path = std::env::temp_dir().join("nonexistent_file_xyz123.enc");
    let storage = PasswordStorage::new(test_path);

    let result = storage.load_entries("any_password");
    assert!(result.is_err(), "Should fail reading non-existent file");

    let error = result.unwrap_err();
    let user_msg = error.user_message();

    // Verify user message is generic
    assert_eq!(
        user_msg,
        "Unable to access password storage. Check file permissions."
    );

    // Verify user message does NOT contain sensitive information
    assert!(!user_msg.contains("No such file"));
    assert!(!user_msg.contains("/tmp/"));
    assert!(!user_msg.contains("nonexistent_file"));
    assert!(!user_msg.to_lowercase().contains("io error"));
    assert!(!user_msg.to_lowercase().contains("errno"));
}

#[test]
fn test_cryptographic_error_variants() {
    // Test all error variants to ensure messages are safe
    let test_cases = vec![
        (
            SecurityError::AuthenticationFailed,
            "Incorrect master password. Please try again.",
        ),
        (
            SecurityError::InvalidInput("password".to_string()),
            "Invalid password",
        ),
        (
            SecurityError::StorageError,
            "Unable to access password storage. Check file permissions.",
        ),
        (
            SecurityError::CryptographicError,
            "Encryption error occurred. Data may be corrupted.",
        ),
        (
            SecurityError::PermissionDenied,
            "Permission denied. Check file permissions.",
        ),
        (
            SecurityError::RateLimitExceeded,
            "Too many attempts. Please try again later.",
        ),
    ];

    for (error, expected_msg) in test_cases {
        let user_msg = error.user_message();
        assert_eq!(
            user_msg, expected_msg,
            "User message should be generic for {:?}",
            error
        );

        // Verify no sensitive cryptographic terms in user messages
        assert!(
            !user_msg.contains("Argon2"),
            "Should not expose Argon2 details"
        );
        assert!(!user_msg.contains("AES"), "Should not expose AES details");
        assert!(
            !user_msg.contains("GCM"),
            "Should not expose GCM mode details"
        );
        assert!(!user_msg.contains("nonce"), "Should not expose nonce info");
        assert!(!user_msg.contains("salt"), "Should not expose salt info");
        assert!(!user_msg.contains("hash"), "Should not expose hash details");
    }
}

#[test]
fn test_debug_messages_contain_details() {
    // Debug messages should contain the variant name for developers
    let error = SecurityError::AuthenticationFailed;
    let debug_msg = error.debug_message();

    assert!(
        debug_msg.contains("AuthenticationFailed"),
        "Debug message should contain variant name"
    );
}

#[test]
fn test_display_trait_uses_user_message() {
    // Display trait should use user_message, not debug representation
    let error = SecurityError::AuthenticationFailed;
    let displayed = format!("{}", error);

    assert_eq!(displayed, "Incorrect master password. Please try again.");
    assert!(!displayed.contains("AuthenticationFailed"));
}

#[test]
fn test_error_trait_implementation() {
    // Verify SecurityError implements std::error::Error
    let error = SecurityError::CryptographicError;
    let _: &dyn std::error::Error = &error;
    // If this compiles, the trait is implemented correctly
}
