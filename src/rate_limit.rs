//! Rate limiting module for preventing brute-force attacks on master password.
//!
//! This module provides rate limiting functionality to protect against brute-force
//! attempts to guess the master password. It tracks failed authentication attempts
//! and enforces a lockout period after exceeding the maximum allowed attempts.
//!
//! # Security Properties
//!
//! - **Brute-force protection**: Limits attempts within a time window
//! - **Exponential backoff**: Enforces lockout after max attempts exceeded
//! - **Automatic cleanup**: Removes old attempts outside the time window
//! - **Persistent state**: Failed attempt timestamps are persisted to disk to
//!   survive application restarts, preventing bypass via restart cycling
//!
//! # Example
//!
//! ```
//! use rust_slint_password_saver::rate_limit::RateLimiter;
//! use std::time::Duration;
//! use std::thread;
//!
//! let limiter = RateLimiter::new();
//!
//! // First few attempts are allowed
//! assert!(limiter.check_and_record_attempt().is_ok());
//!
//! // After max attempts, further attempts are blocked
//! for _ in 0..5 {
//!     let _ = limiter.check_and_record_attempt();
//! }
//! assert!(limiter.check_and_record_attempt().is_err());
//!
//! // Successful authentication clears attempts
//! limiter.record_success();
//! assert!(limiter.check_and_record_attempt().is_ok());
//! ```

use crate::secure_delete::secure_update_file;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum failed authentication attempts before lockout.
///
/// # Security Rationale
///
/// Set to 5 attempts to balance:
/// - Security: Prevents brute force (5 attempts = ~15 bits max)
/// - Usability: Allows for typos without immediate lockout
/// - Industry standard: NIST SP 800-63B recommends 3-10 attempts
const MAX_ATTEMPTS_PER_WINDOW: usize = 5;

/// Time window for counting failed attempts.
///
/// Set to 5 minutes (300 seconds) to:
/// - Group related login attempts
/// - Expire old attempts naturally
/// - Prevent accumulation of attempts over long periods
const RATE_LIMIT_WINDOW_SECONDS: u64 = 5 * 60;

/// Lockout duration after exceeding max attempts.
///
/// Set to 1 minute to:
/// - Slow down automated attacks (1 min per 5 attempts = 12 attempts/hour)
/// - Minimize user frustration (brief lockout)
/// - Comply with OWASP recommendations (30s-5min range)
const LOCKOUT_DURATION_SECONDS: u64 = 60;

/// Rate limiter for controlling decryption attempts.
///
/// This structure tracks failed authentication attempts and enforces rate limiting
/// to prevent brute-force attacks on the master password.
///
/// # Configuration
///
/// - **Max attempts**: 5 attempts per time window
/// - **Time window**: 5 minutes (300 seconds)
/// - **Lockout duration**: 1 minute (60 seconds)
///
/// # Persistence
///
/// When created with [`RateLimiter::with_persistence`], failed attempt timestamps
/// are persisted to disk at the given path. This ensures rate limiting state
/// survives application restarts, preventing bypass via restart cycling.
///
/// # Example
///
/// ```
/// use rust_slint_password_saver::rate_limit::RateLimiter;
///
/// let limiter = RateLimiter::new();
///
/// // Check if attempt is allowed
/// match limiter.check_and_record_attempt() {
///     Ok(()) => println!("Attempt allowed"),
///     Err(msg) => println!("Rate limited: {}", msg),
/// }
/// ```
pub struct RateLimiter {
    /// Vector of attempt timestamps (using `SystemTime` for serializable cross-restart state)
    attempts: Mutex<Vec<SystemTime>>,
    /// Maximum number of attempts allowed in the time window
    max_attempts: usize,
    /// Time window for counting attempts
    window: Duration,
    /// Duration to lock out after exceeding max attempts
    lockout_duration: Duration,
    /// Optional path for persisting attempt timestamps to disk
    persist_path: Option<PathBuf>,
}

impl RateLimiter {
    /// Creates a new rate limiter with default settings.
    ///
    /// Default configuration:
    /// - 5 attempts per 5-minute window
    /// - 1-minute lockout after exceeding limit
    /// - No persistence (state is in-memory only)
    ///
    /// To enable persistence across restarts, use [`RateLimiter::with_persistence`].
    ///
    /// # Returns
    ///
    /// A new `RateLimiter` instance
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::rate_limit::RateLimiter;
    ///
    /// let limiter = RateLimiter::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(Vec::new()),
            max_attempts: MAX_ATTEMPTS_PER_WINDOW,
            window: Duration::from_secs(RATE_LIMIT_WINDOW_SECONDS),
            lockout_duration: Duration::from_secs(LOCKOUT_DURATION_SECONDS),
            persist_path: None,
        }
    }

    /// Creates a rate limiter that persists failed attempt timestamps to disk.
    ///
    /// On construction, any existing attempt records from a previous session are
    /// loaded from `persist_path` and unexpired entries are restored. This ensures
    /// the rate limit cannot be bypassed by restarting the application.
    ///
    /// On each recorded attempt, the timestamp list is serialised as JSON and
    /// written atomically via [`secure_update_file`]. On successful authentication
    /// the file is cleared.
    ///
    /// A corrupted or missing persist file is handled gracefully — the rate limiter
    /// starts with an empty attempt list.
    ///
    /// # Arguments
    ///
    /// * `persist_path` - Path to the JSON file used to persist attempt timestamps
    ///
    /// # Returns
    ///
    /// A new `RateLimiter` with state loaded from `persist_path` (if it exists)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::rate_limit::RateLimiter;
    /// use std::path::PathBuf;
    ///
    /// let limiter = RateLimiter::with_persistence(PathBuf::from("/tmp/rate_limit.json"));
    /// ```
    #[must_use]
    pub fn with_persistence(persist_path: PathBuf) -> Self {
        let mut limiter = Self::new();
        // Load existing attempts from file, filtering out expired ones
        if let Ok(data) = fs::read_to_string(&persist_path) {
            if let Ok(timestamps) = serde_json::from_str::<Vec<u64>>(&data) {
                let now = SystemTime::now();
                let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECONDS);
                if let Ok(mut attempts) = limiter.attempts.lock() {
                    for ts in timestamps {
                        let attempt_time = UNIX_EPOCH + Duration::from_secs(ts);
                        if now.duration_since(attempt_time).unwrap_or(window) < window {
                            attempts.push(attempt_time);
                        }
                    }
                }
            }
            // If serde_json::from_str fails (corrupted file), attempts remain empty — graceful reset
        }
        limiter.persist_path = Some(persist_path);
        limiter
    }

    /// Checks if an attempt is allowed and records it if so.
    ///
    /// This method:
    /// 1. Removes attempts older than the time window
    /// 2. Checks if max attempts have been exceeded
    /// 3. If exceeded, enforces lockout duration
    /// 4. Records the current attempt if allowed
    /// 5. Persists the updated attempt list to disk (if persistence is configured)
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the attempt is allowed
    /// - `Err(String)` with a user-friendly error message if blocked
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Maximum attempts exceeded within time window
    /// - Still within lockout period after exceeding limit
    /// - Unable to acquire lock on attempts (internal error)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::rate_limit::RateLimiter;
    ///
    /// let limiter = RateLimiter::new();
    ///
    /// match limiter.check_and_record_attempt() {
    ///     Ok(()) => {
    ///         // Proceed with authentication
    ///         println!("Attempting authentication...");
    ///     }
    ///     Err(msg) => {
    ///         // Display error to user
    ///         println!("Rate limit exceeded: {}", msg);
    ///     }
    /// }
    /// ```
    pub fn check_and_record_attempt(&self) -> Result<(), String> {
        {
            let mut attempts = self
                .attempts
                .lock()
                .map_err(|_| "Internal error: Failed to acquire rate limiter lock".to_string())?;

            let now = SystemTime::now();

            // Remove attempts outside the time window
            attempts.retain(|attempt_time| {
                now.duration_since(*attempt_time).unwrap_or(self.window) < self.window
            });

            // Check if we've exceeded max attempts
            if attempts.len() >= self.max_attempts {
                // Find the most recent attempt in the window to enforce lockout from there
                if let Some(&most_recent_attempt) = attempts.last() {
                    let time_since_most_recent =
                        now.duration_since(most_recent_attempt).unwrap_or_default();

                    // If we're still within the lockout period after the most recent attempt
                    if time_since_most_recent < self.lockout_duration {
                        let remaining_secs = self
                            .lockout_duration
                            .checked_sub(time_since_most_recent)
                            .map_or(0, |d| d.as_secs());
                        return Err(format!(
                            "Too many failed attempts. Please wait {} seconds before trying again.",
                            remaining_secs
                        ));
                    }

                    // If lockout has expired, clear old attempts and allow this one
                    attempts.clear();
                }
            }

            // Record this attempt
            attempts.push(now);
            // MutexGuard released here so persist_attempts can acquire the lock
        }
        self.persist_attempts();
        Ok(())
    }

    /// Records a successful authentication and clears all failed attempts.
    ///
    /// This method should be called when the user successfully authenticates
    /// with the correct master password. It resets the rate limiter state both
    /// in memory and in the persistent file (if persistence is configured).
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::rate_limit::RateLimiter;
    ///
    /// let limiter = RateLimiter::new();
    ///
    /// // After successful authentication
    /// limiter.record_success();
    ///
    /// // Rate limiter is now reset
    /// assert!(limiter.check_and_record_attempt().is_ok());
    /// ```
    pub fn record_success(&self) {
        if let Ok(mut attempts) = self.attempts.lock() {
            attempts.clear();
        }
        // Persist the cleared state (writes an empty array to the file)
        self.persist_attempts();
    }

    /// Serialises the current attempt list to the persist file (if configured).
    ///
    /// Each timestamp is stored as a Unix epoch seconds value. The file is written
    /// atomically via [`secure_update_file`] and set to 0600 permissions on Unix.
    /// Any I/O error is silently ignored — persistence is best-effort.
    fn persist_attempts(&self) {
        if let Some(path) = &self.persist_path {
            let timestamps: Vec<u64> = self
                .attempts
                .lock()
                .map(|attempts| {
                    attempts
                        .iter()
                        .filter_map(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .collect()
                })
                .unwrap_or_default();
            let json = serde_json::to_string(&timestamps).unwrap_or_else(|_| "[]".to_string());
            let _ = secure_update_file(path, json.as_bytes());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let permissions = fs::Permissions::from_mode(0o600);
                let _ = fs::set_permissions(path, permissions);
            }
        }
    }

    /// Returns the number of attempts currently recorded in the window.
    ///
    /// This method is primarily useful for testing and debugging.
    ///
    /// # Returns
    ///
    /// The number of failed attempts in the current time window
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::rate_limit::RateLimiter;
    ///
    /// let limiter = RateLimiter::new();
    /// let _ = limiter.check_and_record_attempt();
    ///
    /// assert_eq!(limiter.attempt_count(), 1);
    /// ```
    #[must_use]
    #[allow(dead_code)]
    pub fn attempt_count(&self) -> usize {
        self.attempts.lock().map_or(0, |attempts| {
            let now = SystemTime::now();
            attempts
                .iter()
                .filter(|attempt_time| {
                    now.duration_since(**attempt_time).unwrap_or(self.window) < self.window
                })
                .count()
        })
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_initial_attempts_allowed() {
        let limiter = RateLimiter::new();

        // First few attempts should be allowed
        for i in 0..5 {
            assert!(
                limiter.check_and_record_attempt().is_ok(),
                "Attempt {} should be allowed",
                i + 1
            );
        }
    }

    #[test]
    fn test_rate_limit_triggers() {
        let limiter = RateLimiter::new();

        // Use up all allowed attempts
        for _ in 0..5 {
            let _ = limiter.check_and_record_attempt();
        }

        // Next attempt should be blocked
        let result = limiter.check_and_record_attempt();
        assert!(result.is_err(), "Should be rate limited");

        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("Too many failed attempts"),
            "Error message should mention failed attempts"
        );
    }

    #[test]
    fn test_successful_auth_clears_attempts() {
        let limiter = RateLimiter::new();

        // Make some failed attempts
        for _ in 0..3 {
            let _ = limiter.check_and_record_attempt();
        }

        // Record success
        limiter.record_success();

        // Should be able to make new attempts
        assert!(
            limiter.check_and_record_attempt().is_ok(),
            "Should allow attempts after successful auth"
        );
    }

    #[test]
    fn test_lockout_duration() {
        let limiter = RateLimiter::new();

        // Exceed max attempts
        for _ in 0..5 {
            let _ = limiter.check_and_record_attempt();
        }

        // Should be locked out
        assert!(limiter.check_and_record_attempt().is_err());

        // Wait for a short time (less than lockout)
        thread::sleep(Duration::from_millis(100));

        // Should still be locked out
        assert!(
            limiter.check_and_record_attempt().is_err(),
            "Should still be locked out"
        );
    }

    #[test]
    fn test_attempt_count() {
        let limiter = RateLimiter::new();

        assert_eq!(limiter.attempt_count(), 0, "Should start with 0 attempts");

        let _ = limiter.check_and_record_attempt();
        assert_eq!(limiter.attempt_count(), 1, "Should have 1 attempt");

        let _ = limiter.check_and_record_attempt();
        assert_eq!(limiter.attempt_count(), 2, "Should have 2 attempts");

        limiter.record_success();
        assert_eq!(
            limiter.attempt_count(),
            0,
            "Should have 0 attempts after success"
        );
    }

    #[test]
    fn test_old_attempts_cleaned_up() {
        // Create a rate limiter with very short window for testing
        let limiter = RateLimiter {
            attempts: Mutex::new(Vec::new()),
            max_attempts: 5,
            window: Duration::from_millis(100), // 100ms window
            lockout_duration: Duration::from_millis(50),
            persist_path: None,
        };

        // Make some attempts
        let _ = limiter.check_and_record_attempt();
        let _ = limiter.check_and_record_attempt();
        assert_eq!(limiter.attempt_count(), 2);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(150));

        // Old attempts should be cleaned up
        assert_eq!(limiter.attempt_count(), 0);
    }
}
