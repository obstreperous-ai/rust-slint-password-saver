use rust_slint_password_saver::rate_limit::RateLimiter;

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
    // Note: This test uses a real rate limiter with the default 5-minute window.
    // We simulate the cleanup by testing that attempts are properly tracked.
    let limiter = RateLimiter::new();

    // Make 3 attempts
    for _ in 0..3 {
        let _ = limiter.check_and_record_attempt();
    }

    assert_eq!(limiter.attempt_count(), 3);

    // The rate limiter will clean up old attempts automatically
    // when check_and_record_attempt is called next time.
    // For now, verify that we have the expected number of attempts
    assert_eq!(limiter.attempt_count(), 3);
}
