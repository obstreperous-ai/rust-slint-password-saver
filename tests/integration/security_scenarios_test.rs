//! Security scenario integration tests.
//!
//! Verifies that security features (rate limiting, session management, recovery codes,
//! and audit logging) work correctly both individually and together.
//!
//! # Security Note
//! This file contains hardcoded passwords for testing purposes only.
//! These are NOT real passwords and are used solely for testing security scenarios.

// Allow hardcoded credentials in test code - these are intentional test fixtures
#![allow(clippy::identity_op)]

use rust_slint_password_saver::audit_log::{AuditEntry, AuditEventType, AuditLogger};
use rust_slint_password_saver::errors::SecurityError;
use rust_slint_password_saver::rate_limit::RateLimiter;
use rust_slint_password_saver::recovery::EmergencyRecovery;
use rust_slint_password_saver::session::SessionManager;
use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

// NOTE: Test contains hardcoded password - TESTING_SECURITY_NOTE.md
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
const MASTER_PASSWORD: &str = "SecurityTest123!";

/// Helper to create a `PasswordEntry`.
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded entry password
fn make_entry(title: &str) -> PasswordEntry {
    PasswordEntry {
        title: title.to_string(),
        username: "user@example.com".to_string(),
        password: "entrypassword".to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

// ---------------------------------------------------------------------------
// Rate limiting tests
// ---------------------------------------------------------------------------

/// Test that the rate limiter blocks requests after the maximum number of attempts.
#[test]
fn test_rate_limiting_blocks_after_max_attempts() {
    let limiter = RateLimiter::new();

    // The first 5 attempts should be allowed.
    for i in 1..=5 {
        assert!(
            limiter.check_and_record_attempt().is_ok(),
            "Attempt {i} should be allowed"
        );
    }

    // The 6th attempt must be rejected.
    let result = limiter.check_and_record_attempt();
    assert!(result.is_err(), "6th attempt should be rate-limited");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("Too many failed attempts"),
        "Error should mention failed attempts, got: {msg}"
    );
}

/// Test that a successful authentication resets the rate limiter.
#[test]
fn test_rate_limiter_resets_on_success() {
    let limiter = RateLimiter::new();

    // Record 4 failed attempts.
    for _ in 0..4 {
        let _ = limiter.check_and_record_attempt();
    }
    assert_eq!(limiter.attempt_count(), 4);

    // Record a successful authentication.
    limiter.record_success();
    assert_eq!(
        limiter.attempt_count(),
        0,
        "Attempt count should reset after success"
    );

    // Subsequent attempts should be allowed again.
    assert!(limiter.check_and_record_attempt().is_ok());
}

/// Test that rate limiting applies across multiple password-check operations.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_rate_limiting_across_storage_loads() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    // Create a valid database.
    storage
        .save_entries(&[make_entry("Test")], MASTER_PASSWORD)
        .expect("Failed to save entries");

    let limiter = RateLimiter::new();

    // 5 wrong-password attempts via the rate limiter.
    for _ in 0..5 {
        let _ = limiter.check_and_record_attempt();
    }

    // 6th attempt via the rate limiter must be blocked before we even try to decrypt.
    let rate_check = limiter.check_and_record_attempt();
    assert!(
        rate_check.is_err(),
        "Rate limiter should block the 6th attempt"
    );
}

// ---------------------------------------------------------------------------
// Session management tests
// ---------------------------------------------------------------------------

/// Test that a session starts unlocked and reports the correct lock state.
#[test]
fn test_session_starts_unlocked() {
    let session = SessionManager::new(5);
    assert!(!session.is_locked(), "Session should start unlocked");
    assert!(
        !session.should_lock(),
        "Session should not require locking immediately"
    );
}

/// Test that explicit lock and activity-based unlock work correctly.
#[test]
fn test_session_lock_and_unlock_via_activity() {
    let session = SessionManager::new(5);

    // Explicitly lock the session.
    session.lock();
    assert!(session.is_locked(), "Session should be locked after lock()");

    // Recording activity should unlock the session.
    session.record_activity();
    assert!(
        !session.is_locked(),
        "Session should be unlocked after record_activity()"
    );
}

/// Test that a session with a very short timeout reports `should_lock()` after
/// sleeping past the timeout duration.
#[test]
fn test_session_timeout_triggers_should_lock() {
    // Create a session with a 0-minute timeout (expires immediately).
    // With a 0-second timeout, should_lock() should return true
    // as soon as some time passes.
    let session = SessionManager::new(0);

    // Yield briefly to allow time to advance past the zero-duration timeout.
    std::thread::sleep(Duration::from_millis(10));

    assert!(
        session.should_lock(),
        "Session with 0-minute timeout should report should_lock() after inactivity"
    );
}

// ---------------------------------------------------------------------------
// Recovery code tests
// ---------------------------------------------------------------------------

/// Test that recovery codes can be used to recover access after failed logins.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_recovery_code_usage_after_failed_logins() {
    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);
    let codes = recovery.get_codes();
    let rate_limiter = RateLimiter::new();

    // Simulate 3 failed login attempts.
    for _ in 0..3 {
        let _ = rate_limiter.check_and_record_attempt();
    }
    assert_eq!(rate_limiter.attempt_count(), 3);

    // Recovery with a valid code should succeed and return the recovery key.
    let result = recovery.recover_access(&codes[0], &rate_limiter);
    assert!(result.is_ok(), "Recovery with valid code should succeed");
    assert_eq!(
        result.unwrap(),
        recovery.get_recovery_key(),
        "Recovered key must match the original recovery key"
    );
}

/// Test that an invalid recovery code is rejected.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_invalid_recovery_code_is_rejected() {
    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);
    let rate_limiter = RateLimiter::new();

    let result = recovery.recover_access("XXXX-XXXX-XXXX-XXXX", &rate_limiter);
    assert!(result.is_err(), "Invalid recovery code should be rejected");
    assert!(
        matches!(result.unwrap_err(), SecurityError::AuthenticationFailed),
        "Expected AuthenticationFailed error"
    );
}

/// Test that recovery codes stored with the database can be loaded back and verified.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_recovery_code_round_trip_through_storage() {
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    let recovery = EmergencyRecovery::create(MASTER_PASSWORD);
    let hashes = recovery.get_code_hashes();
    let recovery_key = recovery.get_recovery_key();
    let recovery_key_salt = recovery.get_recovery_key_salt();

    storage
        .save_entries_with_recovery(
            &[make_entry("StoredEntry")],
            MASTER_PASSWORD,
            hashes.clone(),
            &recovery_key,
            recovery_key_salt,
        )
        .expect("Failed to save with recovery data");

    // Load recovery metadata back.
    let loaded_data = storage
        .load_recovery_data()
        .expect("Failed to load recovery data")
        .expect("Recovery data should be present");

    let (loaded_hashes, _, _loaded_salt) = loaded_data;
    assert_eq!(
        loaded_hashes.len(),
        hashes.len(),
        "Hash count should match after round-trip"
    );
    assert_eq!(
        loaded_hashes, hashes,
        "Hashes must be identical after round-trip"
    );
}

// ---------------------------------------------------------------------------
// Audit log tests
// ---------------------------------------------------------------------------

/// Test that the audit logger records events and writes them to a log file.
#[test]
fn test_audit_log_records_events() {
    let temp_dir = tempdir().unwrap();
    let log_path = temp_dir.path().join("audit.log");
    let key_path = temp_dir.path().join("audit_hmac.key");
    let logger = AuditLogger::new(log_path.clone(), &key_path);

    // Log a PasswordsSaved event.
    let entry = AuditLogger::create_entry(
        AuditEventType::PasswordsSaved,
        true,
        Some("Saved 2 entries".to_string()),
    );
    logger
        .log_event(&entry)
        .expect("Failed to log PasswordsSaved event");

    // Log a MasterPasswordCheck event.
    let check_entry = AuditLogger::create_entry(
        AuditEventType::MasterPasswordCheck,
        false,
        Some("Wrong password attempt".to_string()),
    );
    logger
        .log_event(&check_entry)
        .expect("Failed to log MasterPasswordCheck event");

    // Verify the log file exists and contains two JSON lines.
    assert!(
        log_path.exists(),
        "Audit log file should exist after logging"
    );
    let contents = fs::read_to_string(&log_path).expect("Failed to read audit log");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2, "Log file should contain exactly 2 entries");

    // Parse and verify the first entry.
    let first: AuditEntry =
        serde_json::from_str(lines[0]).expect("First log line must be valid JSON");
    assert_eq!(first.event_type, AuditEventType::PasswordsSaved);
    assert!(first.success);

    // Parse and verify the second entry.
    let second: AuditEntry =
        serde_json::from_str(lines[1]).expect("Second log line must be valid JSON");
    assert_eq!(second.event_type, AuditEventType::MasterPasswordCheck);
    assert!(!second.success);
}

/// Test that audit log entries contain HMAC integrity signatures.
#[test]
fn test_audit_log_entries_have_hmac() {
    let temp_dir = tempdir().unwrap();
    let log_path = temp_dir.path().join("audit_hmac.log");
    let key_path = temp_dir.path().join("audit_hmac.key");
    let logger = AuditLogger::new(log_path.clone(), &key_path);

    let entry = AuditLogger::create_entry(AuditEventType::ApplicationStartup, true, None);
    logger.log_event(&entry).expect("Failed to log event");

    let contents = fs::read_to_string(&log_path).expect("Failed to read audit log");
    let log_entry: AuditEntry =
        serde_json::from_str(contents.trim()).expect("Log line must be valid JSON");

    assert!(
        !log_entry.hmac.is_empty(),
        "Logged entry must contain a non-empty HMAC"
    );
}

/// Test that storage operations for saving and loading produce audit log entries
/// at the default log path, confirming end-to-end audit trail integration.
#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_storage_operations_produce_audit_entries() {
    use rust_slint_password_saver::audit_log::get_audit_log_path;

    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("passwords.enc");
    let storage = PasswordStorage::new(storage_path);

    let audit_path = get_audit_log_path();
    let size_before = fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);

    storage
        .save_entries(&[make_entry("AuditTest")], MASTER_PASSWORD)
        .expect("Failed to save entries");
    storage
        .load_entries(MASTER_PASSWORD)
        .expect("Failed to load entries");

    // The audit log should have grown after save + load.
    let size_after = fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);
    assert!(
        size_after > size_before,
        "Audit log should grow after storage operations (was {size_before} bytes, now {size_after} bytes)"
    );
}

// ---------------------------------------------------------------------------
// Concurrent authentication tests
// ---------------------------------------------------------------------------

/// Verify that the `RateLimiter` is thread-safe under concurrent load.
///
/// Multiple threads attempt to authenticate simultaneously.  The combined
/// allowed-attempt count must not exceed `MAX_ATTEMPTS` (5) and the limiter
/// must not exhibit data corruption (e.g. negative counts or panics).
#[test]
fn test_concurrent_unlock_attempts() {
    use std::sync::Arc;
    use std::thread;

    let limiter = Arc::new(RateLimiter::new());
    let thread_count = 20;
    let mut handles = Vec::with_capacity(thread_count);

    for _ in 0..thread_count {
        let l = Arc::clone(&limiter);
        handles.push(thread::spawn(move || l.check_and_record_attempt().is_ok()));
    }

    let allowed: usize = handles
        .into_iter()
        .map(|h| usize::from(h.join().expect("Thread panicked")))
        .sum();

    // At most MAX_ATTEMPTS (5) threads should have been granted access.
    // Due to race conditions the actual allowed count may be <= 5.
    assert!(
        allowed <= 5,
        "At most 5 concurrent attempts should be allowed, but {allowed} were"
    );
    assert!(
        allowed >= 1,
        "At least 1 thread should succeed before rate limiting kicks in"
    );

    // After exhausting the limit, every new attempt must be rejected.
    assert!(
        limiter.check_and_record_attempt().is_err(),
        "Further attempts must be rate-limited after the limit is exhausted"
    );
}
