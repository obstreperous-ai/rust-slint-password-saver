//! Integration tests for session management and auto-lock functionality

use rust_slint_password_saver::session::SessionManager;
use std::thread;
use std::time::Duration;

#[test]
fn test_session_manager_basic_functionality() {
    let session = SessionManager::new(5); // 5 minutes

    // Initially not locked
    assert!(!session.is_locked());

    // Should not timeout immediately
    assert!(!session.should_lock());

    // Can be manually locked
    session.lock();
    assert!(session.is_locked());

    // Record activity unlocks
    session.record_activity();
    assert!(!session.is_locked());
}

#[test]
fn test_session_timeout_behavior() {
    // Use very short timeout for testing (1 second)
    let session = SessionManager::new(0); // 0 minutes = immediate timeout

    // Wait for timeout to trigger
    thread::sleep(Duration::from_millis(200));

    // Should be ready to lock
    assert!(session.should_lock());
}

#[test]
fn test_activity_resets_timeout() {
    let session = SessionManager::new(1); // 1 minute

    // Get initial time remaining
    let initial_time = session.time_until_lock();

    // Wait a bit
    thread::sleep(Duration::from_millis(200));

    // Time should have decreased
    let after_wait = session.time_until_lock();
    assert!(after_wait < initial_time);

    // Record activity
    session.record_activity();

    // Time should be reset (increased)
    let after_activity = session.time_until_lock();
    assert!(after_activity > after_wait);
}

#[test]
fn test_time_until_lock_countdown() {
    let session = SessionManager::new(5); // 5 minutes

    let initial = session.time_until_lock();

    // Should be approximately 5 minutes (300 seconds)
    assert!(initial.as_secs() >= 299 && initial.as_secs() <= 300);

    // Wait a bit
    thread::sleep(Duration::from_millis(500));

    let after_wait = session.time_until_lock();

    // Time should have decreased
    assert!(after_wait < initial);
}

#[test]
fn test_time_until_lock_zero_when_expired() {
    let session = SessionManager::new(0); // Immediate timeout

    // Wait for timeout
    thread::sleep(Duration::from_millis(200));

    // Time should be zero
    assert_eq!(session.time_until_lock().as_secs(), 0);
}

#[test]
fn test_manual_lock_and_unlock_flow() {
    let session = SessionManager::new(5);

    // Start unlocked
    assert!(!session.is_locked());

    // Manually lock
    session.lock();
    assert!(session.is_locked());

    // Should stay locked even if timeout hasn't occurred
    assert!(session.is_locked());

    // Record activity to unlock
    session.record_activity();
    assert!(!session.is_locked());
}

#[test]
fn test_should_lock_does_not_auto_lock() {
    let session = SessionManager::new(0); // Immediate timeout

    // Wait for timeout
    thread::sleep(Duration::from_millis(200));

    // Should be ready to lock
    assert!(session.should_lock());

    // But not actually locked yet (requires explicit lock() call)
    assert!(!session.is_locked());

    // Manually lock
    session.lock();
    assert!(session.is_locked());
}

#[test]
fn test_multiple_activity_recordings() {
    let session = SessionManager::new(1); // 1 minute

    // Record multiple activities
    for _ in 0..5 {
        thread::sleep(Duration::from_millis(100));
        session.record_activity();

        // Should not timeout after each activity
        assert!(!session.should_lock());
    }
}

#[test]
fn test_lock_while_already_locked() {
    let session = SessionManager::new(5);

    session.lock();
    assert!(session.is_locked());

    // Lock again (should be idempotent)
    session.lock();
    assert!(session.is_locked());

    // Still locked
    assert!(session.is_locked());
}

#[test]
fn test_activity_while_locked() {
    let session = SessionManager::new(5);

    // Lock the session
    session.lock();
    assert!(session.is_locked());

    // Record activity (simulates successful unlock)
    session.record_activity();

    // Should now be unlocked
    assert!(!session.is_locked());
}

#[test]
fn test_timeout_configuration() {
    // Test different timeout values
    let one_min = SessionManager::new(1);
    let five_min = SessionManager::new(5);
    let ten_min = SessionManager::new(10);

    // Check initial time remaining is approximately correct
    assert!(one_min.time_until_lock().as_secs() >= 59);
    assert!(five_min.time_until_lock().as_secs() >= 299);
    assert!(ten_min.time_until_lock().as_secs() >= 599);
}
