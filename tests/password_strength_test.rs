//! Edge case tests for password strength validation boundary conditions.
//!
//! These tests verify exact boundary conditions for password validation logic,
//! including length boundaries, character set boundaries, entropy boundaries,
//! and pathological cases.
//!
//! # Security Note
//! This file contains hardcoded passwords for testing purposes only.
//! These are NOT real passwords and are used solely for validation testing.

use rust_slint_password_saver::password_strength::{
    assess_password_strength, validate_password_strength, PasswordRequirements, PasswordStrength,
};

// =============================================================================
// Length Boundary Tests
// =============================================================================

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_length_one_below_minimum() {
    // 11 characters (one below the minimum of 12) - must be rejected with a helpful message
    let password = "Abcdefg123!";
    assert_eq!(
        password.len(),
        11,
        "Password should be exactly 11 characters"
    );
    let result = validate_password_strength(password, &PasswordRequirements::default());
    assert!(result.is_err(), "11-char password should fail validation");
    assert!(
        result.unwrap_err().contains("12 characters"),
        "Error message should mention the 12-character minimum"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_length_exact_minimum() {
    // Exactly 12 characters (minimum length) using a high-entropy password so that
    // the zxcvbn entropy check is also satisfied
    let password = "xK9#mP2$vL8@";
    assert_eq!(
        password.len(),
        12,
        "Password should be exactly 12 characters"
    );
    let result = validate_password_strength(password, &PasswordRequirements::default());
    assert!(
        result.is_ok(),
        "12-char high-entropy password should pass all checks: {result:?}"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_length_one_above_minimum() {
    // 13 characters (one above the minimum of 12)
    let password = "xK9#mP2$vL8@n";
    assert_eq!(
        password.len(),
        13,
        "Password should be exactly 13 characters"
    );
    let result = validate_password_strength(password, &PasswordRequirements::default());
    assert!(
        result.is_ok(),
        "13-char high-entropy password should pass all checks: {result:?}"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_length_127_chars() {
    // 127 characters (one below a common 128-char boundary)
    // The strong base is repeated so the password retains all character types
    let base = "xK9#mP2$vL8@"; // 12 chars per cycle
    let password = format!("{}{}", base.repeat(10), &base[..7]); // 120 + 7 = 127 chars
    assert_eq!(
        password.len(),
        127,
        "Password should be exactly 127 characters"
    );
    let result = validate_password_strength(&password, &PasswordRequirements::default());
    assert!(result.is_ok(), "127-char password should be valid");
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_length_128_chars() {
    // Exactly 128 characters
    let base = "xK9#mP2$vL8@"; // 12 chars per cycle
    let password = format!("{}{}", base.repeat(10), &base[..8]); // 120 + 8 = 128 chars
    assert_eq!(
        password.len(),
        128,
        "Password should be exactly 128 characters"
    );
    let result = validate_password_strength(&password, &PasswordRequirements::default());
    assert!(result.is_ok(), "128-char password should be valid");
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_length_129_chars() {
    // 129 characters - no maximum length is enforced, so this should also be valid
    let base = "xK9#mP2$vL8@"; // 12 chars per cycle
    let password = format!("{}{}", base.repeat(10), &base[..9]); // 120 + 9 = 129 chars
    assert_eq!(
        password.len(),
        129,
        "Password should be exactly 129 characters"
    );
    let result = validate_password_strength(&password, &PasswordRequirements::default());
    assert!(
        result.is_ok(),
        "129-char password should be valid (no maximum length is enforced)"
    );
}

// =============================================================================
// Character Set Boundary Tests
// =============================================================================

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_missing_uppercase_fails_character_check() {
    // All lowercase with digits and special chars, but no uppercase
    let requirements = PasswordRequirements::default();
    let result = validate_password_strength("longpassword123!", &requirements);
    assert!(result.is_err(), "Password without uppercase should fail");
    assert!(
        result.unwrap_err().contains("uppercase"),
        "Error should mention missing uppercase letter"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_missing_lowercase_fails_character_check() {
    // All uppercase with digits and special chars, but no lowercase
    let requirements = PasswordRequirements::default();
    let result = validate_password_strength("LONGPASSWORD123!", &requirements);
    assert!(result.is_err(), "Password without lowercase should fail");
    assert!(
        result.unwrap_err().contains("lowercase"),
        "Error should mention missing lowercase letter"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_missing_digit_fails_character_check() {
    // Uppercase, lowercase, and special chars, but no digit
    let requirements = PasswordRequirements::default();
    let result = validate_password_strength("LongPassword!@#$", &requirements);
    assert!(result.is_err(), "Password without digit should fail");
    assert!(
        result.unwrap_err().contains("digit"),
        "Error should mention missing digit"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_missing_special_fails_character_check() {
    // Uppercase, lowercase, and digits, but no special character
    let requirements = PasswordRequirements::default();
    let result = validate_password_strength("LongPassword1234", &requirements);
    assert!(
        result.is_err(),
        "Password without special character should fail"
    );
    assert!(
        result.unwrap_err().contains("special"),
        "Error should mention missing special character"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_exactly_one_of_each_required_character_type() {
    // Password with exactly one uppercase, one lowercase, one digit, and one special
    // character; remaining characters are high-entropy filler to satisfy zxcvbn
    let password = "Az1!xK9#mP2$"; // 12 chars: A(upper), z(lower), 1(digit), !(special)
    assert_eq!(password.len(), 12);
    let result = validate_password_strength(password, &PasswordRequirements::default());
    assert!(
        result.is_ok(),
        "Password with exactly one of each required type should be valid: {result:?}"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_all_uppercase_except_one_lowercase_one_digit_one_special() {
    // Meets all character-type requirements despite being mostly uppercase
    let requirements = PasswordRequirements::default();
    let result = validate_password_strength("XXXXXXXXXXX1aZ!", &requirements);
    // Should not fail the character-type checks; may or may not pass entropy check
    if let Err(ref e) = result {
        assert!(
            !e.contains("uppercase")
                && !e.contains("lowercase")
                && !e.contains("digit")
                && !e.contains("special"),
            "Should not fail any character-type check; failed with: {e}"
        );
    }
}

// =============================================================================
// Pathological Cases
// =============================================================================

#[test]
fn test_all_same_character_is_assessed_as_weak() {
    // Twelve identical characters - very low entropy despite meeting minimum length
    let password = "A".repeat(12);
    let (strength, _description) = assess_password_strength(&password);
    assert!(
        strength <= PasswordStrength::Weak,
        "All-same-character password should be rated Weak or VeryWeak, got {strength:?}"
    );
}

#[test]
fn test_all_same_character_fails_validation() {
    // All-same-character password fails because it is missing lowercase, digit,
    // special character requirements and has very weak entropy
    let password = "A".repeat(12);
    let result = validate_password_strength(&password, &PasswordRequirements::default());
    assert!(
        result.is_err(),
        "All-same-character password should fail validation"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_alternating_two_chars_is_not_strong() {
    // A simple alternating pattern has low entropy despite using two different characters
    let password = "aAbBaAbBaAbB"; // 12 chars, simple alternating pattern
    assert_eq!(password.len(), 12);
    let (strength, _description) = assess_password_strength(password);
    assert!(
        strength <= PasswordStrength::Medium,
        "Simple alternating-character pattern should not be rated Strong or better, got {strength:?}"
    );
}

#[test]
fn test_single_char_type_at_long_length_fails_validation() {
    // 128 uppercase-only characters: fails because it is missing lowercase, digit,
    // and special character requirements
    let password = "A".repeat(128);
    let result = validate_password_strength(&password, &PasswordRequirements::default());
    assert!(
        result.is_err(),
        "All-uppercase 128-char password should fail validation due to missing character types"
    );
    let error = result.unwrap_err();
    assert!(
        error.contains("lowercase") || error.contains("digit") || error.contains("special"),
        "Error should identify the missing character type"
    );
}

// =============================================================================
// Entropy Boundary Tests
// =============================================================================

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_maximum_entropy_password_is_very_strong() {
    // Very long password with all character types should achieve maximum strength
    let base = "xK9#mP2$vL8@nQ5!wR7&"; // 20 chars, all character types, high entropy
    let password = base.repeat(6); // 120 characters
    let result = validate_password_strength(&password, &PasswordRequirements::default());
    assert!(
        result.is_ok(),
        "High-entropy 120-char password should be valid"
    );
    assert_eq!(
        result.unwrap(),
        PasswordStrength::VeryStrong,
        "Maximum-entropy password should be rated VeryStrong"
    );
}

#[test]
// codeql[rust/hardcoded-credentials] - Test fixture with intentional hardcoded passwords
fn test_common_pattern_fails_or_is_not_strong() {
    // "Password123!" meets all composition requirements but is a very common pattern.
    // zxcvbn should rate it as weak; validation either rejects it or rates it below Strong.
    let result = validate_password_strength("Password123!", &PasswordRequirements::default());
    // If the password passes composition checks, zxcvbn must rate it below Strong.
    // If it fails entirely (the expected outcome), that is also acceptable.
    if let Ok(strength) = result {
        assert!(
            strength < PasswordStrength::Strong,
            "Common pattern 'Password123!' should not be rated Strong or better"
        );
    }
}
