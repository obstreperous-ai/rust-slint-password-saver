//! Input validation module for password saver.
//!
//! This module provides comprehensive input validation functions to ensure
//! data integrity and prevent security issues from invalid inputs.
//!
//! # Validation Rules
//!
//! - **Length limits**: Enforced maximum lengths for all input fields
//! - **Minimum master password length**: At least 12 characters for security
//! - **Control characters**: Rejected to prevent UI injection and display issues
//! - **Empty strings**: Title and password fields cannot be empty
//!
//! # Example
//!
//! ```
//! use rust_slint_password_saver::validation::validate_title;
//!
//! // Valid title
//! assert!(validate_title("GitHub Account").is_ok());
//!
//! // Invalid - contains control character
//! assert!(validate_title("GitHub\nAccount").is_err());
//!
//! // Invalid - too long
//! let long_title = "a".repeat(300);
//! assert!(validate_title(&long_title).is_err());
//! ```

/// Maximum length for password entry titles (200 characters)
pub const MAX_TITLE_LENGTH: usize = 200;

/// Maximum length for usernames (500 characters)
pub const MAX_USERNAME_LENGTH: usize = 500;

/// Maximum length for passwords (1000 characters)
pub const MAX_PASSWORD_LENGTH: usize = 1000;

/// Maximum length for master passwords (500 characters)
pub const MAX_MASTER_PASSWORD_LENGTH: usize = 500;

/// Minimum length for master passwords (12 characters for security)
pub const MIN_MASTER_PASSWORD_LENGTH: usize = 12;

/// Validates a password entry title.
///
/// # Validation Rules
///
/// - Must not be empty
/// - Maximum length: 200 characters
/// - Must not contain control characters (e.g., newlines, tabs)
///
/// # Arguments
///
/// * `title` - The title string to validate
///
/// # Returns
///
/// - `Ok(())` if validation passes
/// - `Err(String)` with a user-friendly error message if validation fails
///
/// # Examples
///
/// ```
/// use rust_slint_password_saver::validation::validate_title;
///
/// // Valid title
/// assert!(validate_title("GitHub Account").is_ok());
///
/// // Empty title
/// assert!(validate_title("").is_err());
///
/// // Title with control character
/// assert!(validate_title("Title\nWith Newline").is_err());
/// ```
pub fn validate_title(title: &str) -> Result<(), String> {
    if title.is_empty() {
        return Err("Title cannot be empty".into());
    }
    if title.len() > MAX_TITLE_LENGTH {
        return Err(format!(
            "Title too long (max {} characters)",
            MAX_TITLE_LENGTH
        ));
    }
    if title.chars().any(char::is_control) {
        return Err("Title contains invalid characters".into());
    }
    Ok(())
}

/// Validates a username.
///
/// # Validation Rules
///
/// - Can be empty (username is optional)
/// - Maximum length: 500 characters
/// - Must not contain control characters
///
/// # Arguments
///
/// * `username` - The username string to validate
///
/// # Returns
///
/// - `Ok(())` if validation passes
/// - `Err(String)` with a user-friendly error message if validation fails
///
/// # Examples
///
/// ```
/// use rust_slint_password_saver::validation::validate_username;
///
/// // Valid username
/// assert!(validate_username("user@example.com").is_ok());
///
/// // Empty username is allowed
/// assert!(validate_username("").is_ok());
///
/// // Username with control character
/// assert!(validate_username("user\x00name").is_err());
/// ```
pub fn validate_username(username: &str) -> Result<(), String> {
    // Username is optional, so empty is OK
    if username.len() > MAX_USERNAME_LENGTH {
        return Err(format!(
            "Username too long (max {} characters)",
            MAX_USERNAME_LENGTH
        ));
    }
    if username.chars().any(char::is_control) {
        return Err("Username contains invalid characters".into());
    }
    Ok(())
}

/// Validates a password.
///
/// # Validation Rules
///
/// - Must not be empty
/// - Maximum length: 1000 characters
/// - Must not contain control characters (tab character is allowed for compatibility)
///
/// # Arguments
///
/// * `password` - The password string to validate
///
/// # Returns
///
/// - `Ok(())` if validation passes
/// - `Err(String)` with a user-friendly error message if validation fails
///
/// # Examples
///
/// ```
/// use rust_slint_password_saver::validation::validate_password;
///
/// // Valid password
/// assert!(validate_password("MySecureP@ssw0rd!").is_ok());
///
/// // Empty password
/// assert!(validate_password("").is_err());
///
/// // Password with newline control character
/// assert!(validate_password("pass\nword").is_err());
///
/// // Tab character is allowed
/// assert!(validate_password("pass\tword").is_ok());
/// ```
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(format!(
            "Password too long (max {} characters)",
            MAX_PASSWORD_LENGTH
        ));
    }
    // Note: Tab character is allowed as it may be used in some passwords,
    // but other control characters (newlines, null bytes, etc.) are rejected
    if password.chars().any(|c| c.is_control() && c != '\t') {
        return Err("Password contains invalid characters".into());
    }
    Ok(())
}

/// Validates a master password.
///
/// # Validation Rules
///
/// - Must not be empty
/// - Minimum length: 12 characters (for security)
/// - Maximum length: 500 characters
/// - Must not contain control characters
///
/// # Arguments
///
/// * `master_password` - The master password string to validate
///
/// # Returns
///
/// - `Ok(())` if validation passes
/// - `Err(String)` with a user-friendly error message if validation fails
///
/// # Examples
///
/// ```
/// use rust_slint_password_saver::validation::validate_master_password;
///
/// // Valid master password
/// assert!(validate_master_password("MySecureM@sterP@ss123").is_ok());
///
/// // Too short
/// assert!(validate_master_password("short").is_err());
///
/// // Contains control character
/// assert!(validate_master_password("MyPassword\x00With Null").is_err());
/// ```
pub fn validate_master_password(master_password: &str) -> Result<(), String> {
    if master_password.is_empty() {
        return Err("Master password cannot be empty".into());
    }
    if master_password.len() < MIN_MASTER_PASSWORD_LENGTH {
        return Err(format!(
            "Master password too short (min {} characters)",
            MIN_MASTER_PASSWORD_LENGTH
        ));
    }
    if master_password.len() > MAX_MASTER_PASSWORD_LENGTH {
        return Err(format!(
            "Master password too long (max {} characters)",
            MAX_MASTER_PASSWORD_LENGTH
        ));
    }
    // Master password should not contain control characters
    if master_password.chars().any(char::is_control) {
        return Err("Master password contains invalid characters".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Title validation tests
    #[test]
    fn test_validate_title_valid() {
        assert!(validate_title("Valid Title").is_ok());
        assert!(validate_title("A").is_ok());
        assert!(validate_title("Title with special chars!@#$%").is_ok());
    }

    #[test]
    fn test_validate_title_empty() {
        assert!(validate_title("").is_err());
        assert!(validate_title("").unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_title_too_long() {
        let long_title = "a".repeat(MAX_TITLE_LENGTH + 1);
        let result = validate_title(&long_title);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_validate_title_max_length() {
        let exact_max = "a".repeat(MAX_TITLE_LENGTH);
        assert!(validate_title(&exact_max).is_ok());
    }

    #[test]
    fn test_validate_title_control_chars() {
        assert!(validate_title("Title\nWith Newline").is_err());
        assert!(validate_title("Title\tWith Tab").is_err());
        assert!(validate_title("Title\x00With Null").is_err());
        let result = validate_title("Title\nWith Newline");
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    // Username validation tests
    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("user@example.com").is_ok());
        assert!(validate_username("").is_ok()); // Empty is valid
        assert!(validate_username("user123").is_ok());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long_username = "a".repeat(MAX_USERNAME_LENGTH + 1);
        let result = validate_username(&long_username);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_validate_username_max_length() {
        let exact_max = "a".repeat(MAX_USERNAME_LENGTH);
        assert!(validate_username(&exact_max).is_ok());
    }

    #[test]
    fn test_validate_username_control_chars() {
        assert!(validate_username("user\nname").is_err());
        assert!(validate_username("user\x00name").is_err());
    }

    // Password validation tests
    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("ValidP@ssw0rd").is_ok());
        assert!(validate_password("a").is_ok()); // Single char is valid
        assert!(validate_password("Pass with spaces").is_ok());
    }

    #[test]
    fn test_validate_password_empty() {
        assert!(validate_password("").is_err());
        assert!(validate_password("")
            .unwrap_err()
            .contains("cannot be empty"));
    }

    #[test]
    fn test_validate_password_too_long() {
        let long_password = "a".repeat(MAX_PASSWORD_LENGTH + 1);
        let result = validate_password(&long_password);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_validate_password_max_length() {
        let exact_max = "a".repeat(MAX_PASSWORD_LENGTH);
        assert!(validate_password(&exact_max).is_ok());
    }

    #[test]
    fn test_validate_password_control_chars() {
        // Tab is allowed in passwords
        assert!(validate_password("pass\tword").is_ok());
        // Other control characters are not
        assert!(validate_password("pass\nword").is_err());
        assert!(validate_password("pass\x00word").is_err());
    }

    // Master password validation tests
    #[test]
    fn test_validate_master_password_valid() {
        assert!(validate_master_password("ValidM@sterP@ss123").is_ok());
        assert!(validate_master_password("a".repeat(MIN_MASTER_PASSWORD_LENGTH).as_str()).is_ok());
    }

    #[test]
    fn test_validate_master_password_empty() {
        assert!(validate_master_password("").is_err());
        assert!(validate_master_password("")
            .unwrap_err()
            .contains("cannot be empty"));
    }

    #[test]
    fn test_validate_master_password_too_short() {
        let short_password = "a".repeat(MIN_MASTER_PASSWORD_LENGTH - 1);
        let result = validate_master_password(&short_password);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_validate_master_password_min_length() {
        let exact_min = "a".repeat(MIN_MASTER_PASSWORD_LENGTH);
        assert!(validate_master_password(&exact_min).is_ok());
    }

    #[test]
    fn test_validate_master_password_too_long() {
        let long_password = "a".repeat(MAX_MASTER_PASSWORD_LENGTH + 1);
        let result = validate_master_password(&long_password);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_validate_master_password_max_length() {
        let exact_max = "a".repeat(MAX_MASTER_PASSWORD_LENGTH);
        assert!(validate_master_password(&exact_max).is_ok());
    }

    #[test]
    fn test_validate_master_password_control_chars() {
        assert!(validate_master_password(&format!(
            "MyPassword\nWith{}Newline",
            "a".repeat(MIN_MASTER_PASSWORD_LENGTH)
        ))
        .is_err());
        assert!(validate_master_password(&format!(
            "MyPassword\x00With{}Null",
            "a".repeat(MIN_MASTER_PASSWORD_LENGTH)
        ))
        .is_err());
    }
}
