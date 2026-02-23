use rust_slint_password_saver::rate_limit::RateLimiter;
use tempfile::tempdir;

#[test]
fn test_rate_limiter_integration() {
    let limiter = RateLimiter::new();

    // Simulate 5 failed login attempts (max allowed)
    for i in 1..=5 {
        let result = limiter.check_and_record_attempt();
        assert!(
            result.is_ok(),
            "Attempt {} should be allowed (got: {:?})",
            i,
            result
        );
    }

    // 6th attempt should be rate limited
    let result = limiter.check_and_record_attempt();
    assert!(
        result.is_err(),
        "6th attempt should be rate limited, but got Ok"
    );

    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("Too many failed attempts"),
        "Error message should mention failed attempts, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("wait"),
        "Error message should mention waiting, got: {}",
        err_msg
    );
}

#[test]
fn test_successful_login_resets_rate_limit() {
    let limiter = RateLimiter::new();

    // Make 4 failed attempts
    for _ in 0..4 {
        let _ = limiter.check_and_record_attempt();
    }

    // Simulate successful login
    limiter.record_success();

    // Should now be able to make new attempts
    for i in 1..=5 {
        let result = limiter.check_and_record_attempt();
        assert!(
            result.is_ok(),
            "Attempt {} after successful login should be allowed",
            i
        );
    }
}

#[test]
fn test_rate_limit_prevents_brute_force() {
    let limiter = RateLimiter::new();

    // Attacker tries to brute force
    let mut allowed_attempts = 0;
    let mut blocked_attempts = 0;

    // Try 20 attempts
    for _ in 0..20 {
        match limiter.check_and_record_attempt() {
            Ok(()) => allowed_attempts += 1,
            Err(_) => blocked_attempts += 1,
        }
    }

    // Should allow exactly 5 attempts and block the rest
    assert_eq!(
        allowed_attempts, 5,
        "Should allow exactly 5 attempts, got {}",
        allowed_attempts
    );
    assert_eq!(
        blocked_attempts, 15,
        "Should block 15 attempts, got {}",
        blocked_attempts
    );
}

#[test]
fn test_error_message_includes_wait_time() {
    let limiter = RateLimiter::new();

    // Exhaust allowed attempts
    for _ in 0..5 {
        let _ = limiter.check_and_record_attempt();
    }

    // Get the rate limit error
    let result = limiter.check_and_record_attempt();
    assert!(result.is_err());

    let err_msg = result.unwrap_err();

    // Should include a numeric wait time
    assert!(
        err_msg.chars().any(|c| c.is_ascii_digit()),
        "Error message should include wait time in seconds, got: {}",
        err_msg
    );

    // Should mention "seconds"
    assert!(
        err_msg.contains("second"),
        "Error message should mention seconds, got: {}",
        err_msg
    );
}

#[test]
fn test_time_window_cleanup() {
    // This test verifies that attempts are properly tracked.
    // Actual cleanup happens automatically in check_and_record_attempt
    // when attempts outside the time window are removed.
    let limiter = RateLimiter::new();

    // Make 3 attempts
    for _ in 0..3 {
        let _ = limiter.check_and_record_attempt();
    }

    // Verify attempts are tracked
    assert_eq!(limiter.attempt_count(), 3);
}

// ─── Persistence tests ───────────────────────────────────────────────────────

/// Simulates application restart by creating a second `RateLimiter` pointing to
/// the same file.  The second limiter should inherit the attempt count from the
/// first, so the rate limit cannot be bypassed by restarting.
#[test]
fn test_persistence_survives_restart() {
    let dir = tempdir().expect("Failed to create temp dir");
    let persist_path = dir.path().join("rate_limit.json");

    // First "session": make 3 attempts
    {
        let limiter = RateLimiter::with_persistence(persist_path.clone());
        for _ in 0..3 {
            assert!(limiter.check_and_record_attempt().is_ok());
        }
        // attempt_count should be 3
        assert_eq!(limiter.attempt_count(), 3);
    }

    // Second "session" (simulated restart): load from the same file
    {
        let limiter = RateLimiter::with_persistence(persist_path.clone());
        // Should restore the 3 attempts from the previous session
        assert_eq!(
            limiter.attempt_count(),
            3,
            "Attempt count should be restored after restart"
        );

        // 2 more attempts should still be allowed
        assert!(limiter.check_and_record_attempt().is_ok());
        assert!(limiter.check_and_record_attempt().is_ok());

        // Now we have 5 — next one should be blocked
        assert!(
            limiter.check_and_record_attempt().is_err(),
            "Should be rate limited after restoring persistent state"
        );
    }
}

/// Expired attempt timestamps must be pruned when the file is loaded so that
/// old data does not carry over beyond the rate-limit window.
#[test]
fn test_persistence_expired_attempts_pruned() {
    let dir = tempdir().expect("Failed to create temp dir");
    let persist_path = dir.path().join("rate_limit.json");

    // Write a file containing timestamps that are well in the past (> 5 min ago)
    let old_ts: Vec<u64> = vec![1, 2, 3]; // Unix epoch seconds — definitely expired
    let json = serde_json::to_string(&old_ts).unwrap();
    std::fs::write(&persist_path, json).unwrap();

    // Loading the file should discard all expired timestamps
    let limiter = RateLimiter::with_persistence(persist_path);
    assert_eq!(
        limiter.attempt_count(),
        0,
        "Expired attempts should be pruned on load"
    );
}

/// A successful authentication should clear the persist file so that the next
/// session starts with zero failed attempts.
#[test]
fn test_persistence_success_clears_state() {
    let dir = tempdir().expect("Failed to create temp dir");
    let persist_path = dir.path().join("rate_limit.json");

    // Make some attempts and then record success
    {
        let limiter = RateLimiter::with_persistence(persist_path.clone());
        for _ in 0..3 {
            let _ = limiter.check_and_record_attempt();
        }
        limiter.record_success();
    }

    // Simulate a restart — should start with zero attempts
    {
        let limiter = RateLimiter::with_persistence(persist_path);
        assert_eq!(
            limiter.attempt_count(),
            0,
            "Attempt count should be 0 after successful auth cleared state"
        );
    }
}

/// A corrupted rate limit file must be handled gracefully — the limiter should
/// start with an empty attempt list rather than panicking.
#[test]
fn test_persistence_corrupted_file_handled_gracefully() {
    let dir = tempdir().expect("Failed to create temp dir");
    let persist_path = dir.path().join("rate_limit.json");

    // Write invalid JSON to simulate a corrupted file
    std::fs::write(&persist_path, b"not valid json{{{{").unwrap();

    // Should not panic and should start with zero attempts
    let limiter = RateLimiter::with_persistence(persist_path);
    assert_eq!(
        limiter.attempt_count(),
        0,
        "Corrupted persist file should reset to zero attempts"
    );
    // Normal operation should still work
    assert!(limiter.check_and_record_attempt().is_ok());
}

/// The rate limit file must be created with 0600 permissions on Unix to prevent
/// other users on the same system from reading or modifying it.
#[cfg(unix)]
#[test]
fn test_persistence_file_has_secure_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("Failed to create temp dir");
    let persist_path = dir.path().join("rate_limit.json");

    let limiter = RateLimiter::with_persistence(persist_path.clone());
    // Trigger a write by recording one attempt
    let _ = limiter.check_and_record_attempt();

    let metadata = std::fs::metadata(&persist_path).expect("Failed to read persist file metadata");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Rate limit file must have 0600 permissions, got {:o}",
        mode
    );
}
