//! Integration tests for emergency recovery functionality
//!
//! These tests verify the complete recovery workflow from generation
//! to verification and access recovery.

use rust_slint_password_saver::recovery::{EmergencyRecovery, RecoveryCode};
use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

// NOTE: Test contains hardcoded password - TESTING_SECURITY_NOTE.md
const TEST_PASSWORD: &str = "TestPassword123!";
// NOTE: Test contains hardcoded password - TESTING_SECURITY_NOTE.md
const TEST_PASSWORD_2: &str = "AnotherTest456!";

#[test]
fn test_recovery_code_format() {
    let code = RecoveryCode::generate();

    // Check format: XXXX-XXXX-XXXX-XXXX
    assert_eq!(code.code.len(), 19, "Recovery code should be 19 characters");
    assert_eq!(
        code.code.matches('-').count(),
        3,
        "Recovery code should have 3 dashes"
    );

    // Check that each segment is 4 characters
    let parts: Vec<&str> = code.code.split('-').collect();
    assert_eq!(parts.len(), 4, "Recovery code should have 4 parts");
    for part in parts {
        assert_eq!(part.len(), 4, "Each part should be 4 characters");
    }
}

#[test]
fn test_recovery_codes_are_unique() {
    let mut codes = Vec::new();
    for _ in 0..10 {
        let code = RecoveryCode::generate();
        assert!(!codes.contains(&code.code), "Generated duplicate code");
        codes.push(code.code.clone());
    }
}

#[test]
fn test_emergency_recovery_generates_three_codes() {
    let recovery = EmergencyRecovery::create(TEST_PASSWORD);
    let codes = recovery.get_codes();

    assert_eq!(codes.len(), 3, "Should generate exactly 3 recovery codes");

    // Ensure all codes are unique
    assert_ne!(codes[0], codes[1]);
    assert_ne!(codes[0], codes[2]);
    assert_ne!(codes[1], codes[2]);
}

#[test]
fn test_recovery_key_derivation_is_deterministic() {
    let recovery1 = EmergencyRecovery::create(TEST_PASSWORD);
    let codes = recovery1.get_codes();

    // The key derivation should be deterministic for same codes + password
    // Test that the recovery key is consistently retrievable
    let key1 = recovery1.get_recovery_key();

    for code in codes {
        let result = recovery1.recover_access(&code);
        assert!(result.is_ok(), "Should be able to recover with valid code");
        assert_eq!(result.unwrap(), key1, "Should get same key each time");
    }
}

#[test]
fn test_save_and_load_with_recovery() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("test_recovery.enc");
    let storage = PasswordStorage::new(storage_path.clone());

    // Create test entry
    let entry = PasswordEntry {
        title: "Test Entry".to_string(),
        username: "test@example.com".to_string(),
        password: "secret123".to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Generate recovery
    let recovery = EmergencyRecovery::create(TEST_PASSWORD);
    let recovery_hashes = recovery.get_code_hashes();
    let recovery_key = recovery.get_recovery_key();

    // Save with recovery
    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            TEST_PASSWORD,
            recovery_hashes,
            &recovery_key,
        )
        .expect("Should save entries with recovery");

    // Load recovery data
    let loaded_recovery = storage
        .load_recovery_data()
        .expect("Should load recovery data");

    assert!(loaded_recovery.is_some(), "Recovery data should be present");

    let (loaded_hashes, _encrypted_key) = loaded_recovery.unwrap();
    assert_eq!(loaded_hashes.len(), 3, "Should have 3 recovery code hashes");
}

#[test]
fn test_recovery_with_valid_code() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("test_valid_recovery.enc");
    let storage = PasswordStorage::new(storage_path.clone());

    // Create test entry
    let entry = PasswordEntry {
        title: "Test Entry".to_string(),
        username: "test@example.com".to_string(),
        password: "secret123".to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Generate recovery
    let recovery = EmergencyRecovery::create(TEST_PASSWORD);
    let codes = recovery.get_codes();
    let recovery_hashes = recovery.get_code_hashes();
    let recovery_key = recovery.get_recovery_key();

    // Save with recovery
    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            TEST_PASSWORD,
            recovery_hashes.clone(),
            &recovery_key,
        )
        .expect("Should save entries with recovery");

    // Test recovery with each valid code
    for (i, code) in codes.iter().enumerate() {
        // Hash the code
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let code_hash = hex::encode(hasher.finalize());

        let result = storage.verify_recovery_code(&code_hash, TEST_PASSWORD);
        assert!(
            result.is_ok(),
            "Should successfully verify recovery code {}",
            i
        );

        let recovered_key = result.unwrap();
        assert!(
            recovered_key.is_some(),
            "Should return recovery key for valid code {}",
            i
        );
        assert_eq!(
            recovered_key.unwrap(),
            recovery_key,
            "Recovered key should match original for code {}",
            i
        );
    }
}

#[test]
fn test_recovery_with_invalid_code() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("test_invalid_recovery.enc");
    let storage = PasswordStorage::new(storage_path.clone());

    // Create test entry
    let entry = PasswordEntry {
        title: "Test Entry".to_string(),
        username: "test@example.com".to_string(),
        password: "secret123".to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Generate recovery
    let recovery = EmergencyRecovery::create(TEST_PASSWORD);
    let recovery_hashes = recovery.get_code_hashes();
    let recovery_key = recovery.get_recovery_key();

    // Save with recovery
    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            TEST_PASSWORD,
            recovery_hashes,
            &recovery_key,
        )
        .expect("Should save entries with recovery");

    // Try with an invalid code
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"INVALID-CODE-XXXX-YYYY");
    let invalid_hash = hex::encode(hasher.finalize());

    let result = storage.verify_recovery_code(&invalid_hash, TEST_PASSWORD);
    assert!(result.is_ok(), "Should not error on invalid code");
    assert!(
        result.unwrap().is_none(),
        "Should return None for invalid code"
    );
}

#[test]
fn test_backward_compatibility_no_recovery_data() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("test_no_recovery.enc");
    let storage = PasswordStorage::new(storage_path.clone());

    // Create test entry
    let entry = PasswordEntry {
        title: "Test Entry".to_string(),
        username: "test@example.com".to_string(),
        password: "secret123".to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Save WITHOUT recovery (old behavior)
    storage
        .save_entries(std::slice::from_ref(&entry), TEST_PASSWORD)
        .expect("Should save entries without recovery");

    // Try to load recovery data
    let loaded_recovery = storage
        .load_recovery_data()
        .expect("Should load successfully");

    assert!(
        loaded_recovery.is_none(),
        "Should return None when no recovery data exists"
    );
}

#[test]
fn test_recovery_codes_are_properly_hashed() {
    let recovery = EmergencyRecovery::create(TEST_PASSWORD);
    let codes = recovery.get_codes();
    let hashes = recovery.get_code_hashes();

    assert_eq!(
        codes.len(),
        hashes.len(),
        "Should have same number of codes and hashes"
    );

    // Verify each hash corresponds to its code
    for (code, hash) in codes.iter().zip(hashes.iter()) {
        use sha2::{Digest, Sha256};
        let mut hash_computer = Sha256::new();
        hash_computer.update(code.as_bytes());
        let computed_hash = hex::encode(hash_computer.finalize());

        assert_eq!(&computed_hash, hash, "Hash should match for code: {}", code);
    }
}

#[test]
fn test_recovery_key_differs_for_different_passwords() {
    let recovery1 = EmergencyRecovery::create(TEST_PASSWORD);
    let recovery2 = EmergencyRecovery::create(TEST_PASSWORD_2);

    let key1 = recovery1.get_recovery_key();
    let key2 = recovery2.get_recovery_key();

    assert_ne!(
        key1, key2,
        "Recovery keys should differ for different master passwords"
    );
}

#[test]
fn test_full_recovery_workflow() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("test_full_workflow.enc");
    let storage = PasswordStorage::new(storage_path.clone());

    // Step 1: Create initial entry with recovery
    let entry = PasswordEntry {
        title: "Important Account".to_string(),
        username: "user@example.com".to_string(),
        password: "MySecretPassword!".to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let recovery = EmergencyRecovery::create(TEST_PASSWORD);
    let codes = recovery.get_codes();
    let recovery_hashes = recovery.get_code_hashes();
    let recovery_key = recovery.get_recovery_key();

    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            TEST_PASSWORD,
            recovery_hashes,
            &recovery_key,
        )
        .expect("Should save with recovery");

    // Step 2: User "forgets" password, uses recovery code
    let recovery_code = codes[0].clone();

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(recovery_code.as_bytes());
    let code_hash = hex::encode(hasher.finalize());

    let recovered_key = storage
        .verify_recovery_code(&code_hash, TEST_PASSWORD)
        .expect("Should verify recovery code")
        .expect("Should return recovery key");

    // Step 3: Verify recovered key matches
    assert_eq!(recovered_key, recovery_key, "Recovered key should match");

    // Step 4: User should still be able to load passwords with master password
    let loaded_entries = storage
        .load_entries(TEST_PASSWORD)
        .expect("Should load entries with master password");

    assert_eq!(loaded_entries.len(), 1, "Should load 1 entry");
    assert_eq!(loaded_entries[0].title, entry.title);
}

#[test]
fn test_recovery_codes_have_no_ambiguous_characters() {
    // Generate many codes and verify they don't contain ambiguous characters
    for _ in 0..100 {
        let code = RecoveryCode::generate();
        let code_chars = code.code.replace('-', "");

        // Should not contain: 0, O, 1, I, l
        assert!(
            !code_chars.contains('0'),
            "Code should not contain '0': {}",
            code.code
        );
        assert!(
            !code_chars.contains('O'),
            "Code should not contain 'O': {}",
            code.code
        );
        assert!(
            !code_chars.contains('1'),
            "Code should not contain '1': {}",
            code.code
        );
        assert!(
            !code_chars.contains('I'),
            "Code should not contain 'I': {}",
            code.code
        );
        assert!(
            !code_chars.contains('l'),
            "Code should not contain 'l': {}",
            code.code
        );
    }
}
