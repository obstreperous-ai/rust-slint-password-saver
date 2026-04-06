//! Full end-to-end recovery workflow integration tests.
//!
//! Verifies that a user who has forgotten their master password can recover
//! full read access to the password database using only recovery codes —
//! with no master password involved in the decryption step.
//!
//! # Security Note
//! This file contains hardcoded passwords for testing purposes only.
//! These are NOT real passwords and are used solely for testing recovery scenarios.

// Allow hardcoded credentials in test code - these are intentional test fixtures
#![allow(clippy::identity_op)]

use rust_slint_password_saver::rate_limit::RateLimiter;
use rust_slint_password_saver::recovery::EmergencyRecovery;
use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

// NOTE: Test contains hardcoded password - TESTING_SECURITY_NOTE.md
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
const MASTER_PASSWORD: &str = "RecoveryWorkflow123!";

/// Helper to create a `PasswordEntry` with a fixed timestamp for determinism.
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded entry password
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

// ---------------------------------------------------------------------------
// Full password-less recovery workflow
// ---------------------------------------------------------------------------

/// Verify that a user with only recovery codes (no master password) can
/// decrypt the password database end-to-end.
///
/// Scenario:
/// 1. During normal setup the database is saved with recovery metadata.
/// 2. The user "forgets" their master password.
/// 3. The user enters a valid recovery code → receives the recovery master key.
/// 4. The recovery master key is used to decrypt the database — no master
///    password is required at any point in steps 3-4.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_full_end_to_end_passwordless_recovery() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("passwords_recovery.enc");
    let storage = PasswordStorage::new(storage_path);

    // --- SETUP: Save database with recovery metadata ---

    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    let entry = make_entry("BankAccount", "alice@example.com", "Sup3rS3cret!");
    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);
    let codes = recovery.get_codes();
    let recovery_hashes = recovery.get_code_hashes();
    let recovery_key = recovery.get_recovery_key();
    let recovery_key_salt = recovery.get_recovery_key_salt();

    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            MASTER_PASSWORD,
            recovery_hashes,
            &recovery_key,
            recovery_key_salt,
        )
        .expect("Should save entries with recovery metadata");

    // --- RECOVERY: User has only a recovery code (no master password) ---

    // Present the first recovery code to the in-memory recovery system.
    // In a real scenario the EmergencyRecovery would be re-constructed from the
    // stored hashes via `EmergencyRecovery::from_hashes`; here we use the
    // original instance because we need the pre-computed recovery master key.
    let rate_limiter = RateLimiter::new();
    let recovered_master_key = recovery
        .recover_access(&codes[0], &rate_limiter)
        .expect("Recovery code should be accepted");

    // Decrypt the database using ONLY the recovery master key — no master password.
    let loaded_entries = storage
        .load_entries_with_recovery_key(&recovered_master_key)
        .expect("Should decrypt database with recovery key alone");

    // Verify the decrypted data matches the original entry.
    assert_eq!(loaded_entries.len(), 1, "Should load exactly 1 entry");
    assert_eq!(
        loaded_entries[0].title, entry.title,
        "Entry title should match"
    );
    assert_eq!(
        loaded_entries[0].username, entry.username,
        "Entry username should match"
    );
    assert_eq!(
        loaded_entries[0].password, entry.password,
        "Entry password should match"
    );
}

/// Verify that every recovery code independently unlocks the database.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_each_recovery_code_independently_decrypts_database() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("passwords_each_code.enc");
    let storage = PasswordStorage::new(storage_path);

    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    let entry = make_entry("EmailAccount", "bob@example.com", "Email@Pass1");
    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);
    let codes = recovery.get_codes();
    let recovery_key = recovery.get_recovery_key();

    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            MASTER_PASSWORD,
            recovery.get_code_hashes(),
            &recovery_key,
            recovery.get_recovery_key_salt(),
        )
        .expect("Should save entries with recovery metadata");

    // Each of the 3 recovery codes should independently decrypt the database.
    for (i, code) in codes.iter().enumerate() {
        let rate_limiter = RateLimiter::new();
        let key = recovery
            .recover_access(code, &rate_limiter)
            .unwrap_or_else(|_| panic!("Recovery code {} should be valid", i));

        let loaded = storage
            .load_entries_with_recovery_key(&key)
            .unwrap_or_else(|_| panic!("Database should decrypt with code {}", i));

        assert_eq!(loaded.len(), 1, "Code {}: expected 1 entry", i);
        assert_eq!(
            loaded[0].title, entry.title,
            "Code {}: title should match",
            i
        );
    }
}

/// Verify that a wrong (fabricated) recovery key cannot decrypt the database.
#[test]
fn test_wrong_recovery_key_cannot_decrypt_database() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("passwords_wrong_key.enc");
    let storage = PasswordStorage::new(storage_path);

    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    let entry = make_entry("Social", "carol@example.com", "Social@Pass99");
    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);

    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            MASTER_PASSWORD,
            recovery.get_code_hashes(),
            &recovery.get_recovery_key(),
            recovery.get_recovery_key_salt(),
        )
        .expect("Should save entries with recovery metadata");

    // A fabricated 32-byte key should not decrypt the database.
    // codeql[rust/hardcoded-credentials] // False positive: test fixture — wrong key intentionally used to verify rejection
    let wrong_key = vec![0xABu8; 32];
    let result = storage.load_entries_with_recovery_key(&wrong_key);
    assert!(
        result.is_err(),
        "A wrong recovery key must not decrypt the database"
    );
}

/// Verify that `load_entries_with_recovery_key` fails gracefully for databases
/// saved without recovery metadata (i.e. via `save_entries`).
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_recovery_key_load_fails_when_no_recovery_data_present() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("passwords_no_recovery.enc");
    let storage = PasswordStorage::new(storage_path);

    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    let entry = make_entry("LegacyService", "dave@example.com", "Legacy!Pass1");

    // Save WITHOUT recovery data (simulates legacy / non-recovery databases).
    storage
        .save_entries(std::slice::from_ref(&entry), MASTER_PASSWORD)
        .expect("Should save entries without recovery");

    // Any recovery key should fail because there is no encrypted_db_key_for_recovery field.
    // codeql[rust/hardcoded-credentials] // False positive: test fixture — key value irrelevant, testing absence of recovery data
    let any_key = vec![0x11u8; 32];
    let result = storage.load_entries_with_recovery_key(&any_key);
    assert!(
        result.is_err(),
        "load_entries_with_recovery_key should fail for databases without recovery data"
    );
}

/// Full scenario with multiple entries — confirm all are recovered correctly.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_full_recovery_preserves_all_entries() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("passwords_multi.enc");
    let storage = PasswordStorage::new(storage_path);

    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    let entries = vec![
        make_entry("Gmail", "eve@gmail.com", "Gmail@Pass1!"),
        make_entry("GitHub", "eve@github.com", "Github@Pass2!"),
        make_entry("LinkedIn", "eve@linkedin.com", "LinkedIn@Pass3!"),
    ];

    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);
    let codes = recovery.get_codes();
    let recovery_key = recovery.get_recovery_key();

    storage
        .save_entries_with_recovery(
            &entries,
            MASTER_PASSWORD,
            recovery.get_code_hashes(),
            &recovery_key,
            recovery.get_recovery_key_salt(),
        )
        .expect("Should save multiple entries with recovery metadata");

    let rate_limiter = RateLimiter::new();
    let key = recovery
        .recover_access(&codes[0], &rate_limiter)
        .expect("Recovery code should be valid");

    let loaded = storage
        .load_entries_with_recovery_key(&key)
        .expect("Should decrypt database with recovery key");

    assert_eq!(loaded.len(), 3, "All 3 entries should be recovered");
    let titles: Vec<&str> = loaded.iter().map(|e| e.title.as_str()).collect();
    assert!(titles.contains(&"Gmail"), "Gmail entry should be present");
    assert!(titles.contains(&"GitHub"), "GitHub entry should be present");
    assert!(
        titles.contains(&"LinkedIn"),
        "LinkedIn entry should be present"
    );
}

/// Confirm that the master password path and recovery key path are independent:
/// both must produce the same entries (the database is the single source of truth).
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_master_password_and_recovery_key_load_identical_entries() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().join("passwords_parity.enc");
    let storage = PasswordStorage::new(storage_path);

    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    let entry = make_entry("Parity Service", "frank@example.com", "Parity@Test1!");
    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);
    let codes = recovery.get_codes();
    let recovery_key = recovery.get_recovery_key();

    storage
        .save_entries_with_recovery(
            std::slice::from_ref(&entry),
            MASTER_PASSWORD,
            recovery.get_code_hashes(),
            &recovery_key,
            recovery.get_recovery_key_salt(),
        )
        .expect("Should save entries");

    // Load via master password (existing path).
    let by_password = storage
        .load_entries(MASTER_PASSWORD)
        .expect("Should load with master password");

    // Load via recovery key (new password-less path).
    let rate_limiter = RateLimiter::new();
    let key = recovery
        .recover_access(&codes[0], &rate_limiter)
        .expect("Recovery code should succeed");
    let by_recovery = storage
        .load_entries_with_recovery_key(&key)
        .expect("Should load with recovery key");

    assert_eq!(
        by_password.len(),
        by_recovery.len(),
        "Both paths must return the same number of entries"
    );
    assert_eq!(
        by_password[0].title, by_recovery[0].title,
        "Entry titles must match between paths"
    );
    assert_eq!(
        by_password[0].username, by_recovery[0].username,
        "Entry usernames must match between paths"
    );
    assert_eq!(
        by_password[0].password, by_recovery[0].password,
        "Entry passwords must match between paths"
    );
}
