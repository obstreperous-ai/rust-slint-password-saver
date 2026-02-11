//! Session management and automatic timeout functionality.
//!
//! This module provides the [`SessionManager`] which tracks user activity and
//! automatically locks the application after a configured period of inactivity.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Manages session state and automatic timeout functionality.
///
/// The `SessionManager` tracks the last user activity and determines when the
/// session should be locked due to inactivity. It uses thread-safe interior
/// mutability to allow access from multiple threads (UI thread and timeout checker).
///
/// # Examples
///
/// ```
/// use rust_slint_password_saver::session::SessionManager;
/// use std::time::Duration;
///
/// let session = SessionManager::new(5); // 5 minute timeout
///
/// // Record user activity
/// session.record_activity();
///
/// // Check if session should lock
/// if session.should_lock() {
///     session.lock();
/// }
/// ```
pub struct SessionManager {
    /// Last recorded activity timestamp
    last_activity: Arc<Mutex<Instant>>,
    /// Duration of inactivity before auto-lock triggers
    timeout_duration: Duration,
    /// Current lock state
    is_locked: Arc<Mutex<bool>>,
}

impl SessionManager {
    /// Creates a new `SessionManager` with the specified timeout duration.
    ///
    /// # Arguments
    ///
    /// * `timeout_minutes` - Number of minutes of inactivity before auto-lock
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_slint_password_saver::session::SessionManager;
    ///
    /// let session = SessionManager::new(5); // 5 minute timeout
    /// ```
    #[must_use]
    pub fn new(timeout_minutes: u64) -> Self {
        Self {
            last_activity: Arc::new(Mutex::new(Instant::now())),
            timeout_duration: Duration::from_secs(timeout_minutes * 60),
            is_locked: Arc::new(Mutex::new(false)),
        }
    }

    /// Records user activity, resetting the timeout timer.
    ///
    /// This should be called whenever the user interacts with the application
    /// (clicks buttons, types, etc.). It also unlocks the session if it was locked.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_slint_password_saver::session::SessionManager;
    ///
    /// let session = SessionManager::new(5);
    /// session.record_activity(); // Reset timer
    /// ```
    pub fn record_activity(&self) {
        let mut last_activity = self.last_activity.lock().unwrap();
        *last_activity = Instant::now();

        // Unlock if locked (activity implies successful unlock)
        let mut is_locked = self.is_locked.lock().unwrap();
        *is_locked = false;
    }

    /// Checks if the session should be locked due to inactivity.
    ///
    /// Returns `true` if the time since last activity exceeds the timeout duration.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_slint_password_saver::session::SessionManager;
    ///
    /// let session = SessionManager::new(5);
    /// assert!(!session.should_lock()); // Just created, not timed out
    /// ```
    #[must_use]
    pub fn should_lock(&self) -> bool {
        let last_activity = self.last_activity.lock().unwrap();
        let elapsed = Instant::now().duration_since(*last_activity);
        elapsed >= self.timeout_duration
    }

    /// Locks the session.
    ///
    /// This sets the session state to locked. The UI should respond by showing
    /// the lock screen and preventing access to password data.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_slint_password_saver::session::SessionManager;
    ///
    /// let session = SessionManager::new(5);
    /// session.lock();
    /// assert!(session.is_locked());
    /// ```
    pub fn lock(&self) {
        let mut is_locked = self.is_locked.lock().unwrap();
        *is_locked = true;
    }

    /// Checks if the session is currently locked.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_slint_password_saver::session::SessionManager;
    ///
    /// let session = SessionManager::new(5);
    /// assert!(!session.is_locked()); // Initially unlocked
    ///
    /// session.lock();
    /// assert!(session.is_locked()); // Now locked
    /// ```
    #[must_use]
    pub fn is_locked(&self) -> bool {
        *self.is_locked.lock().unwrap()
    }

    /// Gets the remaining time before auto-lock triggers.
    ///
    /// Returns a `Duration` representing the time remaining. If the timeout
    /// has already elapsed, returns `Duration::from_secs(0)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_slint_password_saver::session::SessionManager;
    /// use std::time::Duration;
    ///
    /// let session = SessionManager::new(5);
    /// let remaining = session.time_until_lock();
    /// assert!(remaining.as_secs() > 0); // Some time remaining
    /// ```
    #[must_use]
    pub fn time_until_lock(&self) -> Duration {
        let last_activity = self.last_activity.lock().unwrap();
        let elapsed = Instant::now().duration_since(*last_activity);

        if elapsed >= self.timeout_duration {
            Duration::from_secs(0)
        } else {
            self.timeout_duration
                .checked_sub(elapsed)
                .unwrap_or_else(|| Duration::from_secs(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_session_not_locked() {
        let session = SessionManager::new(5);
        assert!(!session.is_locked());
    }

    #[test]
    fn test_new_session_not_timed_out() {
        let session = SessionManager::new(5);
        assert!(!session.should_lock());
    }

    #[test]
    fn test_lock_sets_locked_state() {
        let session = SessionManager::new(5);
        session.lock();
        assert!(session.is_locked());
    }

    #[test]
    fn test_record_activity_unlocks() {
        let session = SessionManager::new(5);
        session.lock();
        assert!(session.is_locked());

        session.record_activity();
        assert!(!session.is_locked());
    }

    #[test]
    fn test_timeout_triggers_after_duration() {
        // Use 1 second timeout for faster testing
        let session = SessionManager::new(0); // 0 minutes = immediate timeout
        thread::sleep(Duration::from_millis(100)); // Wait a bit
        assert!(session.should_lock());
    }

    #[test]
    fn test_record_activity_resets_timer() {
        let session = SessionManager::new(1); // 1 minute timeout

        // Wait a bit
        thread::sleep(Duration::from_millis(100));

        // Record activity to reset timer
        session.record_activity();

        // Should not be locked immediately after activity
        assert!(!session.should_lock());
    }

    #[test]
    fn test_time_until_lock_decreases() {
        let session = SessionManager::new(5);

        let initial_time = session.time_until_lock();
        thread::sleep(Duration::from_millis(100));
        let later_time = session.time_until_lock();

        assert!(later_time < initial_time);
    }

    #[test]
    fn test_time_until_lock_zero_when_expired() {
        let session = SessionManager::new(0); // Immediate timeout
        thread::sleep(Duration::from_millis(100));
        assert_eq!(session.time_until_lock().as_secs(), 0);
    }

    #[test]
    fn test_record_activity_updates_time_until_lock() {
        let session = SessionManager::new(5);

        thread::sleep(Duration::from_millis(100));
        let before_activity = session.time_until_lock();

        session.record_activity();
        let after_activity = session.time_until_lock();

        assert!(after_activity > before_activity);
    }
}
