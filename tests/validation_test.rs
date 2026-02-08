//! Integration tests for input validation
//!
//! These tests verify that the validation module correctly rejects invalid inputs
//! and accepts valid inputs across different scenarios.

use rust_slint_password_saver::validation::*;

#[test]
fn test_validation_rejects_extremely_long_inputs() {
    // Create inputs that exceed maximum lengths
    let too_long_title = "a".repeat(MAX_TITLE_LENGTH + 100);
    let too_long_username = "u".repeat(MAX_USERNAME_LENGTH + 100);
    let too_long_password = "p".repeat(MAX_PASSWORD_LENGTH + 100);
    let too_long_master = "m".repeat(MAX_MASTER_PASSWORD_LENGTH + 100);

    // All should be rejected
    assert!(validate_title(&too_long_title).is_err());
    assert!(validate_username(&too_long_username).is_err());
    assert!(validate_password(&too_long_password).is_err());
    assert!(validate_master_password(&too_long_master).is_err());
}

#[test]
fn test_validation_accepts_maximum_length_inputs() {
    // Create inputs at exactly maximum lengths
    let max_title = "a".repeat(MAX_TITLE_LENGTH);
    let max_username = "u".repeat(MAX_USERNAME_LENGTH);
    let max_password = "p".repeat(MAX_PASSWORD_LENGTH);
    let max_master = "m".repeat(MAX_MASTER_PASSWORD_LENGTH);

    // All should be accepted
    assert!(validate_title(&max_title).is_ok());
    assert!(validate_username(&max_username).is_ok());
    assert!(validate_password(&max_password).is_ok());
    assert!(validate_master_password(&max_master).is_ok());
}

#[test]
fn test_validation_rejects_control_characters() {
    // Test various control characters
    let control_chars = [
        "\n",   // newline
        "\r",   // carriage return
        "\x00", // null byte
        "\x01", // start of heading
        "\x1b", // escape
        "\x7f", // delete
    ];

    for control in control_chars {
        let title = format!("Title{}Here", control);
        let username = format!("user{}name", control);
        let password = format!("pass{}word", control);
        let master = format!("master{}password123", control);

        assert!(
            validate_title(&title).is_err(),
            "Should reject title with control char: {:?}",
            control
        );
        assert!(
            validate_username(&username).is_err(),
            "Should reject username with control char: {:?}",
            control
        );
        // Note: password allows tab but not other control chars
        if control != "\t" {
            assert!(
                validate_password(&password).is_err(),
                "Should reject password with control char: {:?}",
                control
            );
        }
        assert!(
            validate_master_password(&master).is_err(),
            "Should reject master password with control char: {:?}",
            control
        );
    }
}

#[test]
fn test_validation_master_password_minimum_length() {
    // Test master passwords below minimum length
    for len in 1..MIN_MASTER_PASSWORD_LENGTH {
        let short_password = "a".repeat(len);
        assert!(
            validate_master_password(&short_password).is_err(),
            "Should reject master password of length {}",
            len
        );
    }

    // Test exactly at minimum length - should be accepted
    let min_password = "a".repeat(MIN_MASTER_PASSWORD_LENGTH);
    assert!(validate_master_password(&min_password).is_ok());
}

#[test]
fn test_validation_accepts_valid_real_world_inputs() {
    // Test realistic valid inputs
    struct TestCase {
        title: &'static str,
        username: &'static str,
        password: &'static str,
        master_password: &'static str,
    }

    let test_cases = [
        TestCase {
            title: "GitHub Account",
            username: "user@example.com",
            password: "MySecureP@ssw0rd!",
            master_password: "MyMasterPassword123!",
        },
        TestCase {
            title: "Bank Account - Wells Fargo",
            username: "john.doe",
            password: "V3ry$ecur3P@ss",
            master_password: "AnotherSecureMasterPass123",
        },
        TestCase {
            title: "WiFi Password",
            username: "", // Username is optional
            password: "wifi-password-2024",
            master_password: "MasterPassword2024!@#",
        },
        TestCase {
            title: "Email (work)",
            username: "user+tag@company.com",
            password: "C0mpl3x!P@ssw0rd#",
            master_password: "SuperSecureMaster2024",
        },
    ];

    for (i, test) in test_cases.iter().enumerate() {
        assert!(
            validate_title(test.title).is_ok(),
            "Test case {} title should be valid",
            i
        );
        assert!(
            validate_username(test.username).is_ok(),
            "Test case {} username should be valid",
            i
        );
        assert!(
            validate_password(test.password).is_ok(),
            "Test case {} password should be valid",
            i
        );
        assert!(
            validate_master_password(test.master_password).is_ok(),
            "Test case {} master password should be valid",
            i
        );
    }
}

#[test]
fn test_validation_rejects_empty_required_fields() {
    // Title must not be empty
    assert!(validate_title("").is_err());

    // Password must not be empty
    assert!(validate_password("").is_err());

    // Master password must not be empty
    assert!(validate_master_password("").is_err());

    // Username CAN be empty (it's optional)
    assert!(validate_username("").is_ok());
}

#[test]
fn test_validation_error_messages_are_user_friendly() {
    // Test that error messages are clear and helpful
    let empty_title_error = validate_title("").unwrap_err();
    assert!(empty_title_error.contains("empty"));

    let long_title_error = validate_title(&"a".repeat(300)).unwrap_err();
    assert!(long_title_error.contains("too long"));
    assert!(long_title_error.contains("200")); // Should mention the limit

    let control_char_error = validate_title("Title\nWithNewline").unwrap_err();
    assert!(control_char_error.contains("invalid"));

    let short_master_error = validate_master_password("short").unwrap_err();
    assert!(short_master_error.contains("too short"));
    assert!(short_master_error.contains("12")); // Should mention the minimum
}

#[test]
fn test_validation_accepts_special_characters_in_passwords() {
    // Passwords should accept special characters
    let special_chars = [
        "Pass!@#$%^&*()",
        "Pass{}<>?",
        "Pass[]|\\",
        "Pass-_=+",
        "Pass~`",
    ];

    for password in special_chars {
        assert!(
            validate_password(password).is_ok(),
            "Should accept password with special chars: {}",
            password
        );
    }
}

#[test]
fn test_validation_accepts_unicode_in_inputs() {
    // Unicode characters should be accepted (except control chars)
    assert!(validate_title("Café Account ☕").is_ok());
    assert!(validate_username("用户@example.com").is_ok());
    assert!(validate_password("Пароль123!").is_ok());
    assert!(validate_master_password("MasterПароль123").is_ok());
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_validation_constants_are_reasonable() {
    // Verify that the constants are set to reasonable values
    assert_eq!(MAX_TITLE_LENGTH, 200);
    assert_eq!(MAX_USERNAME_LENGTH, 500);
    assert_eq!(MAX_PASSWORD_LENGTH, 1000);
    assert_eq!(MAX_MASTER_PASSWORD_LENGTH, 500);
    assert_eq!(MIN_MASTER_PASSWORD_LENGTH, 12);

    // Verify relationships between constants make sense
    assert!(MIN_MASTER_PASSWORD_LENGTH < MAX_MASTER_PASSWORD_LENGTH);
    assert!(MAX_TITLE_LENGTH < MAX_USERNAME_LENGTH);
    assert!(MAX_USERNAME_LENGTH < MAX_PASSWORD_LENGTH);
}
