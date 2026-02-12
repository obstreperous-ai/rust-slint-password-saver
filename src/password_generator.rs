//! # Password Generator Module
//!
//! Provides cryptographically secure password generation functionality with
//! customizable character sets and constraints.
//!
//! ## Features
//!
//! - Cryptographically secure random number generation using `rand::thread_rng()`
//! - Customizable password length (8-128 characters)
//! - Configurable character sets (uppercase, lowercase, digits, special)
//! - Optional exclusion of ambiguous characters (0,O,I,l,1)
//! - Entropy calculation for generated passwords
//! - Validation to ensure all selected character types are present
//!
//! ## Example
//!
//! ```
//! use rust_slint_password_saver::password_generator::{generate_password, PasswordGeneratorConfig};
//!
//! // Generate with default configuration (16 chars, all types, exclude ambiguous)
//! let config = PasswordGeneratorConfig::default();
//! let password = generate_password(&config).expect("Failed to generate password");
//! assert_eq!(password.len(), 16);
//!
//! // Generate with custom configuration
//! let config = PasswordGeneratorConfig {
//!     length: 20,
//!     use_uppercase: true,
//!     use_lowercase: true,
//!     use_digits: true,
//!     use_special: false,
//!     exclude_ambiguous: true,
//! };
//! let password = generate_password(&config).expect("Failed to generate password");
//! ```

use rand::{thread_rng, Rng};

/// Configuration for password generation.
///
/// Specifies the length and character types to include in generated passwords.
#[derive(Debug, Clone)]
pub struct PasswordGeneratorConfig {
    /// Length of the password (must be 8-128 characters)
    pub length: usize,
    /// Include uppercase letters (A-Z)
    pub use_uppercase: bool,
    /// Include lowercase letters (a-z)
    pub use_lowercase: bool,
    /// Include digits (0-9)
    pub use_digits: bool,
    /// Include special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)
    pub use_special: bool,
    /// Exclude ambiguous characters (O,0,I,l,1)
    pub exclude_ambiguous: bool,
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_digits: true,
            use_special: true,
            exclude_ambiguous: true,
        }
    }
}

/// Generate a cryptographically secure random password.
///
/// Creates a password based on the provided configuration, ensuring:
/// - Length is within bounds (8-128 characters)
/// - At least one character type is selected
/// - Password contains at least one character from each selected type
///
/// # Arguments
///
/// * `config` - Configuration specifying password requirements
///
/// # Returns
///
/// * `Ok(String)` - Generated password
/// * `Err(String)` - Error message if configuration is invalid
///
/// # Examples
///
/// ```
/// use rust_slint_password_saver::password_generator::{generate_password, PasswordGeneratorConfig};
///
/// let config = PasswordGeneratorConfig::default();
/// let password = generate_password(&config).expect("Failed to generate password");
/// assert_eq!(password.len(), 16);
/// ```
///
/// # Security
///
/// This function uses `rand::thread_rng()` which provides cryptographically
/// secure random number generation suitable for password generation.
pub fn generate_password(config: &PasswordGeneratorConfig) -> Result<String, String> {
    // Validate length constraints
    if config.length < 8 {
        return Err("Password length must be at least 8 characters".to_string());
    }

    if config.length > 128 {
        return Err("Password length must not exceed 128 characters".to_string());
    }

    // Build character set based on configuration
    let mut charset = String::new();

    if config.use_lowercase {
        if config.exclude_ambiguous {
            charset.push_str("abcdefghjkmnpqrstuvwxyz"); // Exclude i, l, o
        } else {
            charset.push_str("abcdefghijklmnopqrstuvwxyz");
        }
    }

    if config.use_uppercase {
        if config.exclude_ambiguous {
            charset.push_str("ABCDEFGHJKLMNPQRSTUVWXYZ"); // Exclude I, O
        } else {
            charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
    }

    if config.use_digits {
        if config.exclude_ambiguous {
            charset.push_str("23456789"); // Exclude 0, 1
        } else {
            charset.push_str("0123456789");
        }
    }

    if config.use_special {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
    }

    if charset.is_empty() {
        return Err("At least one character type must be selected".to_string());
    }

    let charset: Vec<char> = charset.chars().collect();
    let mut rng = thread_rng();

    // Generate password using cryptographically secure RNG
    let password: String = (0..config.length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx]
        })
        .collect();

    // Ensure password contains at least one character from each selected type
    // If not, regenerate (recursive call)
    if !validate_generated_password(&password, config) {
        return generate_password(config);
    }

    Ok(password)
}

/// Validate that a generated password contains required character types.
///
/// Checks that the password contains at least one character from each
/// character type that was selected in the configuration.
///
/// # Arguments
///
/// * `password` - The password to validate
/// * `config` - Configuration specifying which character types should be present
///
/// # Returns
///
/// `true` if password meets all requirements, `false` otherwise
fn validate_generated_password(password: &str, config: &PasswordGeneratorConfig) -> bool {
    if config.use_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return false;
    }
    if config.use_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return false;
    }
    if config.use_digits && !password.chars().any(|c| c.is_numeric()) {
        return false;
    }
    if config.use_special && !password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
    {
        return false;
    }
    true
}

/// Calculate entropy bits for a password.
///
/// Entropy is calculated as: length × log₂(charset_size)
/// Higher entropy indicates stronger passwords that are harder to crack.
///
/// # Arguments
///
/// * `password` - The password (used for length)
/// * `charset_size` - Size of the character set used to generate the password
///
/// # Returns
///
/// Entropy in bits
///
/// # Examples
///
/// ```
/// use rust_slint_password_saver::password_generator::calculate_entropy;
///
/// // 16 character password with 94 possible characters (full ASCII printable)
/// let entropy = calculate_entropy("0123456789abcdef", 94);
/// assert!((entropy - 104.88).abs() < 0.1);
/// ```
pub fn calculate_entropy(password: &str, charset_size: usize) -> f64 {
    let length = password.len() as f64;
    let charset_size = charset_size as f64;
    length * charset_size.log2()
}

/// Calculate the character set size for a given configuration.
///
/// Returns the number of possible characters that can be used in password
/// generation based on the configuration.
///
/// # Arguments
///
/// * `config` - Password generator configuration
///
/// # Returns
///
/// Number of characters in the charset
pub fn calculate_charset_size(config: &PasswordGeneratorConfig) -> usize {
    let mut size = 0;

    if config.use_lowercase {
        size += if config.exclude_ambiguous { 23 } else { 26 };
    }

    if config.use_uppercase {
        size += if config.exclude_ambiguous { 24 } else { 26 };
    }

    if config.use_digits {
        size += if config.exclude_ambiguous { 8 } else { 10 };
    }

    if config.use_special {
        size += 28; // "!@#$%^&*()_+-=[]{}|;:,.<>?"
    }

    size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PasswordGeneratorConfig::default();
        assert_eq!(config.length, 16);
        assert!(config.use_uppercase);
        assert!(config.use_lowercase);
        assert!(config.use_digits);
        assert!(config.use_special);
        assert!(config.exclude_ambiguous);
    }

    #[test]
    fn test_validate_generated_password() {
        let config = PasswordGeneratorConfig {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_digits: true,
            use_special: true,
            exclude_ambiguous: false,
        };

        // Valid password with all types
        assert!(validate_generated_password("Abc123!@#def", &config));

        // Missing uppercase
        assert!(!validate_generated_password("abc123!@#def", &config));

        // Missing lowercase
        assert!(!validate_generated_password("ABC123!@#DEF", &config));

        // Missing digits
        assert!(!validate_generated_password("Abcdef!@#XYZ", &config));

        // Missing special
        assert!(!validate_generated_password("Abc123defXYZ", &config));
    }

    #[test]
    fn test_calculate_charset_size() {
        // All types, exclude ambiguous
        let config = PasswordGeneratorConfig {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_digits: true,
            use_special: true,
            exclude_ambiguous: true,
        };
        assert_eq!(calculate_charset_size(&config), 23 + 24 + 8 + 28);

        // All types, include ambiguous
        let config = PasswordGeneratorConfig {
            exclude_ambiguous: false,
            ..config
        };
        assert_eq!(calculate_charset_size(&config), 26 + 26 + 10 + 28);

        // Lowercase only
        let config = PasswordGeneratorConfig {
            length: 16,
            use_uppercase: false,
            use_lowercase: true,
            use_digits: false,
            use_special: false,
            exclude_ambiguous: false,
        };
        assert_eq!(calculate_charset_size(&config), 26);
    }

    #[test]
    fn test_entropy_calculation() {
        // Test with known values
        let entropy = calculate_entropy("12345678", 10); // 8 digits
        assert!((entropy - 26.58).abs() < 0.1);

        let entropy = calculate_entropy("abcdefghijklmnop", 26); // 16 lowercase
        assert!((entropy - 75.20).abs() < 0.1);
    }
}
