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
//! # Security Note
//!
//! Documentation examples in this module contain hardcoded passwords for
//! demonstration purposes only. These are NOT real passwords and should
//! never be used in production code.
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

/// Generic string field validation helper.
///
/// # Arguments
///
/// * `input` - The string to validate
/// * `field_name` - Human-readable name used in error messages
/// * `min_length` - Minimum required length; `0` means empty input is allowed
/// * `max_length` - Maximum allowed length
/// * `char_validator` - Optional per-character predicate; returns `true` if the
///   character is acceptable
fn validate_string_field(
    input: &str,
    field_name: &str,
    min_length: usize,
    max_length: usize,
    char_validator: Option<fn(char) -> bool>,
) -> Result<(), String> {
    if input.is_empty() {
        if min_length > 0 {
            return Err(format!("{} cannot be empty", field_name));
        }
        return Ok(());
    }

    if input.len() < min_length {
        return Err(format!(
            "{} too short (min {} characters)",
            field_name, min_length
        ));
    }

    if input.len() > max_length {
        return Err(format!(
            "{} too long (max {} characters)",
            field_name, max_length
        ));
    }

    if let Some(validator) = char_validator {
        if input.chars().any(|c| !validator(c)) {
            return Err(format!("{} contains invalid characters", field_name));
        }
    }

    Ok(())
}

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
    validate_string_field(
        title,
        "Title",
        1,
        MAX_TITLE_LENGTH,
        Some(|c| !c.is_control()),
    )
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
    // Username is optional, so empty is OK (min_length = 0)
    validate_string_field(
        username,
        "Username",
        0,
        MAX_USERNAME_LENGTH,
        Some(|c| !c.is_control()),
    )
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
/// // codeql[rust/hardcoded-credentials] - Example password for documentation only
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
    // Note: Tab character is allowed as it may be used in some passwords,
    // but other control characters (newlines, null bytes, etc.) are rejected
    validate_string_field(
        password,
        "Password",
        1,
        MAX_PASSWORD_LENGTH,
        Some(|c| !c.is_control() || c == '\t'),
    )
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
/// // codeql[rust/hardcoded-credentials] - Example password for documentation only
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
    // Master password should not contain control characters
    validate_string_field(
        master_password,
        "Master password",
        MIN_MASTER_PASSWORD_LENGTH,
        MAX_MASTER_PASSWORD_LENGTH,
        Some(|c| !c.is_control()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function tests
    #[test]
    fn test_validate_string_field_empty_required() {
        let result = validate_string_field("", "Field", 1, 100, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_string_field_empty_optional() {
        assert!(validate_string_field("", "Field", 0, 100, None).is_ok());
    }

    #[test]
    fn test_validate_string_field_too_short() {
        let result = validate_string_field("ab", "Field", 5, 100, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_validate_string_field_too_long() {
        let result = validate_string_field(&"a".repeat(11), "Field", 1, 10, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_validate_string_field_invalid_char() {
        let result =
            validate_string_field("bad\nvalue", "Field", 1, 100, Some(|c| !c.is_control()));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    #[test]
    fn test_validate_string_field_valid() {
        assert!(validate_string_field("hello", "Field", 1, 100, Some(|c| !c.is_control())).is_ok());
    }

    #[test]
    fn test_validate_string_field_no_char_validator() {
        // Without a char validator, control characters are accepted
        assert!(validate_string_field("hello\n", "Field", 1, 100, None).is_ok());
    }

    #[test]
    fn test_validate_string_field_exact_min_and_max() {
        assert!(validate_string_field("abc", "Field", 3, 3, None).is_ok());
        assert!(validate_string_field("ab", "Field", 3, 3, None).is_err());
        assert!(validate_string_field("abcd", "Field", 3, 3, None).is_err());
    }

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
