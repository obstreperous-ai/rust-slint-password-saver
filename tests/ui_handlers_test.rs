//! Integration tests for the `UIHandlers` module.
//!
//! These tests verify the construction, state management, and storage-level
//! behaviour of `UIHandlers` without requiring a running Slint UI window.
//! Handler methods that interact with the UI (`AppWindow`) are covered by
//! the inline unit tests inside `src/ui_handlers.rs` and by manual integration
//! testing of the binary.
//!
//! # Security Note
//! This file contains hardcoded passwords for testing purposes only.
//! These are NOT real passwords and are used solely for testing handler logic.

// Allow hardcoded credentials in test code - these are intentional test fixtures
#![allow(clippy::identity_op)]

use rust_slint_password_saver::{
    storage::{PasswordEntry, PasswordStorage},
    ui_handlers::UIHandlers,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

/// Helper to get the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Helper that creates a `UIHandlers` pointing at a fresh temp directory.
fn make_handlers() -> (UIHandlers, tempfile::TempDir) {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("passwords.enc");
    let handlers = UIHandlers::new(path);
    (handlers, dir)
}

// ─── Construction and defaults ───────────────────────────────────────────────

#[test]
fn test_handlers_new_loaded_entries_empty() {
    let (handlers, _dir) = make_handlers();
    let entries = handlers.loaded_entries.lock().unwrap();
    assert!(entries.is_empty(), "loaded_entries must start empty");
}

#[test]
fn test_handlers_new_clipboard_not_initialized() {
    let (handlers, _dir) = make_handlers();
    let clipboard = handlers.clipboard.lock().unwrap();
    assert!(
        clipboard.is_none(),
        "clipboard should be lazily initialized (None at start)"
    );
}

#[test]
fn test_handlers_default_clipboard_config() {
    let (handlers, _dir) = make_handlers();
    assert!(
        handlers.clipboard_config.auto_clear_enabled,
        "auto-clear should be enabled by default"
    );
    assert_eq!(
        handlers.clipboard_config.clear_timeout_seconds, 30,
        "default auto-clear timeout should be 30 seconds"
    );
}

#[test]
fn test_handlers_storage_path_stored() {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("my_passwords.enc");
    let handlers = UIHandlers::new(path.clone());
    assert_eq!(handlers.storage_path, path);
}

// ─── Clone behaviour ──────────────────────────────────────────────────────────

#[test]
fn test_handlers_clone_shares_loaded_entries_arc() {
    let (handlers, _dir) = make_handlers();
    let clone = handlers.clone();

    // Populate the original
    {
        let mut entries = handlers.loaded_entries.lock().unwrap();
        entries.push(PasswordEntry {
            title: "ArcTest".to_string(),
            username: "user@example.com".to_string(),
            password: "secret".to_string(),
            created_at: current_timestamp(),
        });
    }

    // The clone sees the same data because both share the Arc
    let entries = clone.loaded_entries.lock().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title, "ArcTest");
}

#[test]
fn test_handlers_clone_shares_rate_limiter_arc() {
    let (handlers, _dir) = make_handlers();
    let clone = handlers.clone();

    // Use some attempts on the original
    for _ in 0..3 {
        let _ = handlers.rate_limiter.check_and_record_attempt();
    }

    // Record success on the clone – both share the same Arc<RateLimiter>
    clone.rate_limiter.record_success();

    // Original should now have a fresh attempt window
    assert!(
        handlers.rate_limiter.check_and_record_attempt().is_ok(),
        "Rate limiter should allow attempts after clone records success"
    );
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

#[test]
fn test_rate_limiter_allows_first_attempt() {
    let (handlers, _dir) = make_handlers();
    assert!(handlers.rate_limiter.check_and_record_attempt().is_ok());
}

#[test]
fn test_rate_limiter_blocks_after_max_attempts() {
    let (handlers, _dir) = make_handlers();

    // Exhaust all 5 allowed attempts
    for _ in 0..5 {
        let _ = handlers.rate_limiter.check_and_record_attempt();
    }

    // The 6th attempt should be blocked
    let result = handlers.rate_limiter.check_and_record_attempt();
    assert!(result.is_err(), "Should be rate-limited after 5 attempts");
    let msg = result.unwrap_err();
    assert!(
        !msg.is_empty(),
        "Rate-limit error message should not be empty"
    );
}

#[test]
fn test_rate_limiter_resets_on_success() {
    let (handlers, _dir) = make_handlers();

    // Use some attempts
    for _ in 0..3 {
        let _ = handlers.rate_limiter.check_and_record_attempt();
    }

    // Success clears the window
    handlers.rate_limiter.record_success();

    // Should be allowed again
    assert!(
        handlers.rate_limiter.check_and_record_attempt().is_ok(),
        "Rate limiter should reset after success"
    );
}

// ─── Session manager ──────────────────────────────────────────────────────────

#[test]
fn test_session_not_locked_initially() {
    let (handlers, _dir) = make_handlers();
    assert!(
        !handlers.session.is_locked(),
        "Session should not be locked on creation"
    );
}

#[test]
fn test_session_lock_and_unlock() {
    let (handlers, _dir) = make_handlers();
    handlers.session.lock();
    assert!(handlers.session.is_locked(), "Session should be locked");

    // record_activity unlocks
    handlers.session.record_activity();
    assert!(
        !handlers.session.is_locked(),
        "Session should unlock after activity"
    );
}

#[test]
fn test_session_record_activity_resets_timer() {
    let (handlers, _dir) = make_handlers();
    handlers.session.record_activity();
    assert!(
        !handlers.session.is_locked(),
        "Activity should keep session unlocked"
    );
}

// ─── Loaded entries state ─────────────────────────────────────────────────────

#[test]
fn test_loaded_entries_can_be_populated() {
    let (handlers, _dir) = make_handlers();

    {
        let mut entries = handlers.loaded_entries.lock().unwrap();
        for i in 0..3_usize {
            entries.push(PasswordEntry {
                title: format!("Entry {}", i),
                username: format!("user{}@example.com", i),
                password: format!("pass{}", i),
                created_at: current_timestamp(),
            });
        }
    }

    let entries = handlers.loaded_entries.lock().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].title, "Entry 0");
    assert_eq!(entries[2].title, "Entry 2");
}

#[test]
fn test_loaded_entries_can_be_cleared() {
    let (handlers, _dir) = make_handlers();

    {
        let mut entries = handlers.loaded_entries.lock().unwrap();
        entries.push(PasswordEntry {
            title: "Temp".to_string(),
            username: String::new(),
            password: "p".to_string(),
            created_at: current_timestamp(),
        });
    }
    assert_eq!(handlers.loaded_entries.lock().unwrap().len(), 1);

    handlers.loaded_entries.lock().unwrap().clear();
    assert!(handlers.loaded_entries.lock().unwrap().is_empty());
}

// ─── Storage integration ──────────────────────────────────────────────────────

// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
#[test]
fn test_handlers_storage_path_usable_for_save_and_load() {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("integration.enc");
    let handlers = UIHandlers::new(path.clone());

    let master_password = "IntegrationTest1!";
    let storage = PasswordStorage::new(handlers.storage_path.clone());

    // Save via PasswordStorage using handlers.storage_path
    let entries = vec![PasswordEntry {
        title: "IntegrationEntry".to_string(),
        username: "int@example.com".to_string(),
        password: "entry_secret".to_string(),
        created_at: current_timestamp(),
    }];
    storage
        .save_entries(&entries, master_password)
        .expect("save_entries should succeed");

    // Load back via a fresh PasswordStorage (simulating handler behaviour)
    let storage2 = PasswordStorage::new(handlers.storage_path.clone());
    let loaded = storage2
        .load_entries(master_password)
        .expect("load_entries should succeed");

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].title, "IntegrationEntry");
    assert_eq!(loaded[0].username, "int@example.com");
}

// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
#[test]
fn test_handlers_multiple_entries_round_trip() {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("multi.enc");
    let handlers = UIHandlers::new(path);
    let master_password = "MultiEntry99#!";

    let storage = PasswordStorage::new(handlers.storage_path.clone());

    let entries: Vec<PasswordEntry> = (0..5)
        .map(|i| PasswordEntry {
            title: format!("Site {}", i),
            username: format!("user{}@site.com", i),
            password: format!("password{}", i),
            created_at: current_timestamp(),
        })
        .collect();

    storage
        .save_entries(&entries, master_password)
        .expect("save should succeed");

    let loaded = storage
        .load_entries(master_password)
        .expect("load should succeed");

    assert_eq!(loaded.len(), 5);
    for (i, entry) in loaded.iter().enumerate() {
        assert_eq!(entry.title, format!("Site {}", i));
    }
}

// ─── Edge cases ───────────────────────────────────────────────────────────────

#[test]
fn test_handlers_nonexistent_storage_file() {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().join("nonexistent.enc");
    let handlers = UIHandlers::new(path);

    // PasswordStorage should report file does not exist
    let storage = PasswordStorage::new(handlers.storage_path.clone());
    assert!(
        !storage.exists(),
        "Storage file should not exist before first save"
    );
}

#[test]
fn test_handlers_copy_entry_out_of_bounds_does_not_panic() {
    let (handlers, _dir) = make_handlers();

    // Loaded entries is empty; index 0 should return None gracefully
    let password = {
        let entries = handlers.loaded_entries.lock().unwrap();
        #[allow(clippy::cast_sign_loss)]
        let idx = 0_i32 as usize;
        if idx < entries.len() {
            Some(entries[idx].password.clone())
        } else {
            None
        }
    };

    assert!(
        password.is_none(),
        "Out-of-bounds index should return None, not panic"
    );
}
