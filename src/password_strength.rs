//! # Password Strength Validation Module
//!
//! This module provides password strength validation to ensure users create
//! strong master passwords for the password manager.
//!
//! ## Security Rationale
//!
//! Even with strong encryption (Argon2 + AES-256-GCM), weak passwords can be
//! brute-forced. This module enforces minimum security requirements for master
//! passwords to protect against dictionary attacks and common password patterns.
//!
//! ## Requirements
//!
//! Default password requirements:
//! - Minimum 12 characters (NIST recommends at least 8, we use 12 for extra security)
//! - At least one uppercase letter
//! - At least one lowercase letter
//! - At least one digit
//! - At least one special character
//! - Must achieve "Strong" or better rating from zxcvbn library
//!
//! ## Example
//!
//! ```
//! // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
//! use rust_slint_password_saver::password_strength::{validate_password_strength, PasswordRequirements};
//!
//! let requirements = PasswordRequirements::default();
//! let result = validate_password_strength("MySecureP@ssw0rd123", &requirements);
//!
//! match result {
//!     Ok(strength) => println!("Password strength: {:?}", strength),
//!     Err(e) => eprintln!("Password validation failed: {}", e),
//! }
//! ```

use std::fmt::Write;
use zxcvbn::{zxcvbn, Score};

/// Password strength levels based on composition and entropy
///
/// These levels are derived from the zxcvbn library's scoring system
/// and our custom requirement checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PasswordStrength {
    /// Very weak password - easily guessable
    VeryWeak = 0,
    /// Weak password - vulnerable to attacks
    Weak = 1,
    /// Medium strength - acceptable for low-value accounts
    Medium = 2,
    /// Strong password - recommended minimum for password managers
    Strong = 3,
    /// Very strong password - excellent security
    VeryStrong = 4,
}

/// Password requirements configuration
///
/// Defines the minimum requirements that a password must meet.
/// The default configuration provides strong security suitable for
/// a password manager's master password.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordRequirements {
    /// Minimum password length (default: 12 characters)
    pub min_length: usize,
    /// Require at least one uppercase letter (A-Z)
    pub require_uppercase: bool,
    /// Require at least one lowercase letter (a-z)
    pub require_lowercase: bool,
    /// Require at least one digit (0-9)
    pub require_digit: bool,
    /// Require at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
    pub require_special: bool,
}

impl Default for PasswordRequirements {
    /// Creates default password requirements for a password manager
    ///
    /// These requirements provide strong protection against common attacks:
    /// - 12+ characters makes brute-force attacks computationally expensive
    /// - Character diversity requirements prevent simple patterns
    /// - Combined with zxcvbn scoring, prevents dictionary words and common passwords
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
        }
    }
}

/// Validates password strength against requirements and entropy analysis
///
/// This function performs two-stage validation:
/// 1. **Requirement checks**: Ensures password meets basic composition requirements
/// 2. **Entropy analysis**: Uses zxcvbn library to detect common patterns, dictionary words
///
/// # Arguments
///
/// * `password` - The password to validate
/// * `requirements` - The requirements configuration to check against
///
/// # Returns
///
/// * `Ok(PasswordStrength)` - Password meets requirements, returns strength level
/// * `Err(String)` - Password fails validation, returns descriptive error message
///
/// # Examples
///
/// ```
/// // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
/// use rust_slint_password_saver::password_strength::{validate_password_strength, PasswordRequirements, PasswordStrength};
///
/// // Strong password passes validation
/// let result = validate_password_strength("MySecureP@ssw0rd123", &PasswordRequirements::default());
/// assert!(result.is_ok());
/// assert!(result.unwrap() >= PasswordStrength::Strong);
///
/// // Weak password fails validation
/// let result = validate_password_strength("password123", &PasswordRequirements::default());
/// assert!(result.is_err());
/// ```
///
/// # Security Notes
///
/// - This function does not log or store passwords
/// - All validation happens in memory
/// - Strings are not explicitly cleared from memory (consider using zeroize for production)
pub fn validate_password_strength(
    password: &str,
    requirements: &PasswordRequirements,
) -> Result<PasswordStrength, String> {
    // Check minimum length
    if password.len() < requirements.min_length {
        return Err(format!(
            "Password must be at least {} characters long (currently {} characters)",
            requirements.min_length,
            password.len()
        ));
    }

    // Check for uppercase letter
    if requirements.require_uppercase && !password.chars().any(char::is_uppercase) {
        return Err("Password must contain at least one uppercase letter (A-Z)".to_string());
    }

    // Check for lowercase letter
    if requirements.require_lowercase && !password.chars().any(char::is_lowercase) {
        return Err("Password must contain at least one lowercase letter (a-z)".to_string());
    }

    // Check for digit
    if requirements.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit (0-9)".to_string());
    }

    // Check for special character
    if requirements.require_special {
        let has_special = password
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace());
        if !has_special {
            return Err(
                "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
                    .to_string(),
            );
        }
    }

    // Use zxcvbn for entropy and pattern analysis
    // Empty user_inputs means no personalized dictionary (more strict)
    let entropy = zxcvbn(password, &[]);

    // Map zxcvbn Score to our PasswordStrength enum
    // Score values: Zero = 0, One = 1, Two = 2, Three = 3, Four = 4
    // Scores 0-2 are weak/guessable, 3-4 are strong/unguessable
    #[allow(clippy::match_same_arms)]
    let strength = match entropy.score() {
        Score::Zero => PasswordStrength::VeryWeak,
        Score::One => PasswordStrength::Weak,
        Score::Two => PasswordStrength::Medium,
        Score::Three => PasswordStrength::Strong,
        Score::Four => PasswordStrength::VeryStrong,
        _ => PasswordStrength::VeryWeak, // Defensive: in case new score values are added
    };

    // Provide feedback for weak passwords
    if strength < PasswordStrength::Strong {
        let mut feedback = format!("Password is too weak (strength: {:?}). ", strength);

        // Add specific suggestions from zxcvbn
        if let Some(fb) = entropy.feedback() {
            if let Some(warning) = fb.warning() {
                let _ = write!(feedback, "Warning: {}. ", warning);
            }

            let suggestions = fb.suggestions();
            if !suggestions.is_empty() {
                feedback.push_str("Suggestions: ");
                for (i, suggestion) in suggestions.iter().enumerate() {
                    if i > 0 {
                        feedback.push_str("; ");
                    }
                    let _ = write!(feedback, "{}", suggestion);
                }
            }
        }

        return Err(feedback);
    }

    Ok(strength)
}

/// Assesses password strength without enforcing requirements
///
/// Unlike `validate_password_strength`, this function provides strength assessment
/// without requiring the password to meet any specific requirements. This is useful
/// for providing real-time feedback as the user types.
///
/// # Arguments
///
/// * `password` - The password to assess
///
/// # Returns
///
/// Returns a tuple of (`PasswordStrength`, `String`) where the String is a human-readable
/// description of the strength level.
///
/// # Examples
///
/// ```
/// // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
/// use rust_slint_password_saver::password_strength::assess_password_strength;
///
/// let (strength, description) = assess_password_strength("short");
/// // strength will be VeryWeak or Weak
/// // description will be "Weak" or similar
/// ```
#[must_use]
pub fn assess_password_strength(password: &str) -> (PasswordStrength, String) {
    // Empty password is very weak
    if password.is_empty() {
        return (PasswordStrength::VeryWeak, "Too Short".to_string());
    }

    // Use zxcvbn for entropy and pattern analysis
    let entropy = zxcvbn(password, &[]);

    // Map zxcvbn Score to our PasswordStrength enum
    // Note: Score enum is non-exhaustive, so wildcard pattern is required
    #[allow(clippy::match_same_arms)] // Zero and wildcard both intentionally map to VeryWeak
    let strength = match entropy.score() {
        Score::Zero => PasswordStrength::VeryWeak,
        Score::One => PasswordStrength::Weak,
        Score::Two => PasswordStrength::Medium,
        Score::Three => PasswordStrength::Strong,
        Score::Four => PasswordStrength::VeryStrong,
        _ => PasswordStrength::VeryWeak, // Future-proof for new score variants
    };

    // Create descriptive text based on strength
    let description = match strength {
        PasswordStrength::VeryWeak => "Weak",
        PasswordStrength::Weak => "Fair",
        PasswordStrength::Medium => "Good",
        PasswordStrength::Strong => "Strong",
        PasswordStrength::VeryStrong => "Excellent",
    };

    (strength, description.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_requirements() {
        let req = PasswordRequirements::default();
        assert_eq!(req.min_length, 12);
        assert!(req.require_uppercase);
        assert!(req.require_lowercase);
        assert!(req.require_digit);
        assert!(req.require_special);
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_password_too_short() {
        let requirements = PasswordRequirements::default();
        let result = validate_password_strength("Short1!", &requirements);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 12 characters"));
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_password_missing_uppercase() {
        let requirements = PasswordRequirements::default();
        let result = validate_password_strength("longpassword123!", &requirements);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("uppercase letter"));
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_password_missing_lowercase() {
        let requirements = PasswordRequirements::default();
        let result = validate_password_strength("LONGPASSWORD123!", &requirements);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("lowercase letter"));
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_password_missing_digit() {
        let requirements = PasswordRequirements::default();
        let result = validate_password_strength("LongPassword!@#", &requirements);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("digit"));
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_password_missing_special() {
        let requirements = PasswordRequirements::default();
        let result = validate_password_strength("LongPassword123", &requirements);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("special character"));
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_strong_password_accepted() {
        let requirements = PasswordRequirements::default();
        // This should be a strong password
        let result = validate_password_strength("MyS3cur3P@ssw0rd!", &requirements);
        assert!(result.is_ok());
        let strength = result.unwrap();
        assert!(strength >= PasswordStrength::Strong);
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_very_strong_password() {
        let requirements = PasswordRequirements::default();
        // Long, random-like password
        let result = validate_password_strength("xK9#mP2$vL8@nQ5!wR7&", &requirements);
        assert!(result.is_ok());
        let strength = result.unwrap();
        // Should be at least strong, possibly very strong
        assert!(strength >= PasswordStrength::Strong);
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_common_password_rejected() {
        let requirements = PasswordRequirements::default();
        // Even if it meets basic requirements, common patterns should be weak
        let result = validate_password_strength("Password123!", &requirements);
        // This might fail due to being too common/predictable
        // The exact behavior depends on zxcvbn's dictionary
        if let Ok(strength) = result {
            // If it passes basic checks, it should still be flagged as weak by zxcvbn
            assert!(
                strength < PasswordStrength::Strong,
                "Common password should be rated as weak"
            );
        }
    }

    #[test]
    fn test_password_strength_ordering() {
        assert!(PasswordStrength::VeryWeak < PasswordStrength::Weak);
        assert!(PasswordStrength::Weak < PasswordStrength::Medium);
        assert!(PasswordStrength::Medium < PasswordStrength::Strong);
        assert!(PasswordStrength::Strong < PasswordStrength::VeryStrong);
    }

    #[test]
    fn test_empty_password() {
        let requirements = PasswordRequirements::default();
        let result = validate_password_strength("", &requirements);
        assert!(result.is_err());
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_custom_requirements() {
        let requirements = PasswordRequirements {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
        };
        // Should pass with relaxed requirements
        let result = validate_password_strength("mylongpassword1234", &requirements);
        // May still be weak due to entropy, but should pass basic checks
        assert!(result.is_ok() || result.unwrap_err().contains("too weak"));
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_unicode_characters() {
        let requirements = PasswordRequirements::default();
        // Unicode characters count as special characters
        let result = validate_password_strength("MyP@ssw0rd™Ωπ", &requirements);
        assert!(result.is_ok() || result.unwrap_err().contains("too weak"));
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_very_long_password() {
        let requirements = PasswordRequirements::default();
        let long_password = "MyS3cur3P@ssw0rd!".repeat(5); // 85 characters
        let result = validate_password_strength(&long_password, &requirements);
        assert!(result.is_ok());
        // Very long passwords should be very strong
        assert!(result.unwrap() >= PasswordStrength::Strong);
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_assess_empty_password() {
        let (strength, description) = assess_password_strength("");
        assert_eq!(strength, PasswordStrength::VeryWeak);
        assert_eq!(description, "Too Short");
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_assess_weak_password() {
        let (strength, _description) = assess_password_strength("password");
        assert!(strength <= PasswordStrength::Weak);
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_assess_strong_password() {
        let (strength, _description) = assess_password_strength("MyS3cur3P@ssw0rd!");
        assert!(strength >= PasswordStrength::Strong);
    }

    #[test]
    // codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
    fn test_assess_returns_description() {
        let (_strength, description) = assess_password_strength("test");
        assert!(!description.is_empty());
        // Should be one of the expected descriptions
        assert!(
            description == "Weak"
                || description == "Fair"
                || description == "Good"
                || description == "Strong"
                || description == "Excellent"
                || description == "Too Short"
        );
    }
}
