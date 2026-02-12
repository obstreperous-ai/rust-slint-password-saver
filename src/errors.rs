//! Security-focused error types for password manager operations.
//!
//! This module provides sanitized error types that prevent information leakage
//! while still providing useful feedback to users. Detailed error information
//! is available for debugging but not exposed in user-facing messages.
//!
//! # Security Considerations
//!
//! - User messages are generic to prevent information leakage
//! - Debug messages contain detailed information for developers
//! - Cryptographic failures don't reveal specific details
//! - Storage errors don't expose filesystem internals

use std::fmt;

/// Security-focused error types for password manager operations.
///
/// These errors provide user-friendly messages that don't reveal sensitive
/// implementation details while maintaining debug-level details for developers.
///
/// # Example
///
/// ```
/// use rust_slint_password_saver::errors::SecurityError;
///
/// let error = SecurityError::AuthenticationFailed;
/// // User sees: "Incorrect master password. Please try again."
/// assert_eq!(error.user_message(), "Incorrect master password. Please try again.");
///
/// // Developers see full details in logs
/// println!("Debug: {}", error.debug_message());
/// ```
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum SecurityError {
    /// Authentication failed (wrong master password or corrupted data)
    AuthenticationFailed,

    /// Invalid input provided by user
    InvalidInput(String),

    /// Storage operation failed (file I/O error)
    StorageError,

    /// Cryptographic operation failed
    CryptographicError,

    /// Database integrity check failed (with detailed issues)
    IntegrityError(String),

    /// Permission denied for file operation
    PermissionDenied,

    /// Too many authentication attempts
    RateLimitExceeded,
}

impl SecurityError {
    /// Returns a user-friendly message that doesn't leak internal details.
    ///
    /// These messages are safe to display to end users and won't reveal
    /// sensitive information about the system or cryptographic operations.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::errors::SecurityError;
    ///
    /// let error = SecurityError::AuthenticationFailed;
    /// assert_eq!(
    ///     error.user_message(),
    ///     "Incorrect master password. Please try again."
    /// );
    /// ```
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::AuthenticationFailed => "Incorrect master password. Please try again.".into(),
            Self::InvalidInput(field) => {
                format!("Invalid {}", field)
            }
            Self::StorageError => {
                "Unable to access password storage. Check file permissions.".into()
            }
            Self::CryptographicError => "Encryption error occurred. Data may be corrupted.".into(),
            Self::IntegrityError(details) => {
                format!("Database integrity check failed: {}", details)
            }
            Self::PermissionDenied => "Permission denied. Check file permissions.".into(),
            Self::RateLimitExceeded => "Too many attempts. Please try again later.".into(),
        }
    }

    /// Returns a detailed message for logging and debugging.
    ///
    /// These messages contain full error details and should only be written
    /// to logs, not displayed to end users.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::errors::SecurityError;
    ///
    /// let error = SecurityError::AuthenticationFailed;
    /// // Log detailed information
    /// eprintln!("Error details: {}", error.debug_message());
    /// ```
    #[must_use]
    pub fn debug_message(&self) -> String {
        format!("{:?}", self)
    }
}

impl fmt::Display for SecurityError {
    /// Formats the error using the user-friendly message.
    ///
    /// When errors are displayed (e.g., via `to_string()`), they show
    /// the sanitized user message, not internal details.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.user_message())
    }
}

impl std::error::Error for SecurityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_failed_message() {
        let error = SecurityError::AuthenticationFailed;
        assert_eq!(
            error.user_message(),
            "Incorrect master password. Please try again."
        );
        // Debug message should contain the variant name
        assert!(error.debug_message().contains("AuthenticationFailed"));
    }

    #[test]
    fn test_invalid_input_message() {
        let error = SecurityError::InvalidInput("password".to_string());
        assert_eq!(error.user_message(), "Invalid password");
        assert!(error.debug_message().contains("InvalidInput"));
    }

    #[test]
    fn test_storage_error_message() {
        let error = SecurityError::StorageError;
        assert_eq!(
            error.user_message(),
            "Unable to access password storage. Check file permissions."
        );
    }

    #[test]
    fn test_cryptographic_error_message() {
        let error = SecurityError::CryptographicError;
        assert_eq!(
            error.user_message(),
            "Encryption error occurred. Data may be corrupted."
        );
    }

    #[test]
    fn test_integrity_error_message() {
        let error = SecurityError::IntegrityError(
            "Missing salt field, File appears truncated (only 50 bytes)".to_string(),
        );
        assert_eq!(
            error.user_message(),
            "Database integrity check failed: Missing salt field, File appears truncated (only 50 bytes)"
        );
        assert!(error.debug_message().contains("IntegrityError"));
    }

    #[test]
    fn test_display_trait() {
        let error = SecurityError::AuthenticationFailed;
        let displayed = format!("{}", error);
        // Display should use user_message
        assert_eq!(displayed, "Incorrect master password. Please try again.");
    }

    #[test]
    fn test_error_trait() {
        let error = SecurityError::AuthenticationFailed;
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &error;
    }
}
