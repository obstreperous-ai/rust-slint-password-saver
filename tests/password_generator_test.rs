//! Integration tests for password generator module
//!
//! These tests verify the password generator produces secure passwords
//! with the expected characteristics based on configuration.

use rust_slint_password_saver::password_generator::{
    calculate_entropy, generate_password, CharsetFlags, PasswordGeneratorConfig,
};

#[test]
fn test_default_config() {
    let config = PasswordGeneratorConfig::default();
    assert_eq!(config.length, 16);
    assert!(config.charset.contains(CharsetFlags::UPPERCASE));
    assert!(config.charset.contains(CharsetFlags::LOWERCASE));
    assert!(config.charset.contains(CharsetFlags::DIGITS));
    assert!(config.charset.contains(CharsetFlags::SPECIAL));
    assert!(config.exclude_ambiguous);
}

#[test]
fn test_generate_password_default() {
    let config = PasswordGeneratorConfig::default();
    let password = generate_password(&config).expect("Failed to generate password");

    assert_eq!(password.len(), 16);
    assert!(password.chars().any(char::is_uppercase));
    assert!(password.chars().any(char::is_lowercase));
    assert!(password.chars().any(char::is_numeric));
    assert!(password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)));
}

#[test]
fn test_generate_password_minimum_length() {
    let config = PasswordGeneratorConfig {
        length: 8,
        ..Default::default()
    };
    let password = generate_password(&config).expect("Failed to generate password");
    assert_eq!(password.len(), 8);
}

#[test]
fn test_generate_password_maximum_length() {
    let config = PasswordGeneratorConfig {
        length: 128,
        ..Default::default()
    };
    let password = generate_password(&config).expect("Failed to generate password");
    assert_eq!(password.len(), 128);
}

#[test]
fn test_generate_password_too_short() {
    let config = PasswordGeneratorConfig {
        length: 7,
        ..Default::default()
    };
    let result = generate_password(&config);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Password length must be at least 8 characters"
    );
}

#[test]
fn test_generate_password_too_long() {
    let config = PasswordGeneratorConfig {
        length: 129,
        ..Default::default()
    };
    let result = generate_password(&config);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Password length must not exceed 128 characters"
    );
}

#[test]
fn test_generate_password_lowercase_only() {
    let config = PasswordGeneratorConfig {
        length: 12,
        charset: CharsetFlags::LOWERCASE,
        exclude_ambiguous: false,
    };
    let password = generate_password(&config).expect("Failed to generate password");

    assert_eq!(password.len(), 12);
    assert!(password.chars().all(char::is_lowercase));
}

#[test]
fn test_generate_password_uppercase_only() {
    let config = PasswordGeneratorConfig {
        length: 12,
        charset: CharsetFlags::UPPERCASE,
        exclude_ambiguous: false,
    };
    let password = generate_password(&config).expect("Failed to generate password");

    assert_eq!(password.len(), 12);
    assert!(password.chars().all(char::is_uppercase));
}

#[test]
fn test_generate_password_digits_only() {
    let config = PasswordGeneratorConfig {
        length: 12,
        charset: CharsetFlags::DIGITS,
        exclude_ambiguous: false,
    };
    let password = generate_password(&config).expect("Failed to generate password");

    assert_eq!(password.len(), 12);
    assert!(password.chars().all(char::is_numeric));
}

#[test]
fn test_generate_password_special_only() {
    let config = PasswordGeneratorConfig {
        length: 12,
        charset: CharsetFlags::SPECIAL,
        exclude_ambiguous: false,
    };
    let password = generate_password(&config).expect("Failed to generate password");

    assert_eq!(password.len(), 12);
    assert!(password
        .chars()
        .all(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)));
}

#[test]
fn test_generate_password_no_character_types() {
    let config = PasswordGeneratorConfig {
        length: 12,
        charset: CharsetFlags::empty(),
        exclude_ambiguous: false,
    };
    let result = generate_password(&config);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "At least one character type must be selected"
    );
}

#[test]
fn test_exclude_ambiguous_characters() {
    let config = PasswordGeneratorConfig {
        length: 20,
        charset: CharsetFlags::UPPERCASE | CharsetFlags::LOWERCASE | CharsetFlags::DIGITS,
        exclude_ambiguous: true,
    };

    // Generate multiple passwords to increase confidence
    for _ in 0..10 {
        let password = generate_password(&config).expect("Failed to generate password");

        // Should not contain ambiguous characters
        assert!(!password.contains('O'));
        assert!(!password.contains('I'));
        assert!(!password.contains('i'));
        assert!(!password.contains('l'));
        assert!(!password.contains('o'));
        assert!(!password.contains('0'));
        assert!(!password.contains('1'));
    }
}

#[test]
fn test_include_ambiguous_characters() {
    let config = PasswordGeneratorConfig {
        length: 100, // Large length to ensure we hit ambiguous chars
        charset: CharsetFlags::UPPERCASE | CharsetFlags::LOWERCASE | CharsetFlags::DIGITS,
        exclude_ambiguous: false,
    };

    // Generate multiple passwords to check ambiguous chars can appear
    let mut found_ambiguous = false;
    for _ in 0..10 {
        let password = generate_password(&config).expect("Failed to generate password");

        // At least one should contain ambiguous characters
        if password.contains('O')
            || password.contains('I')
            || password.contains('i')
            || password.contains('l')
            || password.contains('o')
            || password.contains('0')
            || password.contains('1')
        {
            found_ambiguous = true;
            break;
        }
    }
    assert!(
        found_ambiguous,
        "Expected to find ambiguous characters when not excluded"
    );
}

#[test]
fn test_password_contains_all_selected_types() {
    let config = PasswordGeneratorConfig {
        length: 16,
        charset: CharsetFlags::all(),
        exclude_ambiguous: false,
    };

    // Test multiple times to ensure validation works
    for _ in 0..5 {
        let password = generate_password(&config).expect("Failed to generate password");

        assert!(
            password.chars().any(char::is_uppercase),
            "Password missing uppercase: {}",
            password
        );
        assert!(
            password.chars().any(char::is_lowercase),
            "Password missing lowercase: {}",
            password
        );
        assert!(
            password.chars().any(char::is_numeric),
            "Password missing digits: {}",
            password
        );
        assert!(
            password
                .chars()
                .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)),
            "Password missing special: {}",
            password
        );
    }
}

#[test]
fn test_calculate_entropy() {
    // Entropy = length * log2(charset_size)
    // For 16 characters with charset of 94: 16 * log2(94) ≈ 16 * 6.555 ≈ 104.88
    let entropy = calculate_entropy("0123456789abcdef", 94);
    assert!((entropy - 104.88).abs() < 0.1);

    // For 8 characters with charset of 26 (lowercase only)
    let entropy = calculate_entropy("abcdefgh", 26);
    assert!((entropy - 37.60).abs() < 0.1);
}

#[test]
fn test_password_randomness() {
    let config = PasswordGeneratorConfig::default();

    // Generate multiple passwords and ensure they're different
    let mut passwords = Vec::new();
    for _ in 0..10 {
        let password = generate_password(&config).expect("Failed to generate password");
        passwords.push(password);
    }

    // All passwords should be unique
    let unique_count = passwords
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(unique_count, 10, "Generated passwords should all be unique");
}

#[test]
fn test_custom_length() {
    for length in [10, 15, 20, 25, 32, 50, 64] {
        let config = PasswordGeneratorConfig {
            length,
            ..Default::default()
        };
        let password = generate_password(&config).expect("Failed to generate password");
        assert_eq!(password.len(), length);
    }
}

#[test]
fn test_mixed_character_sets() {
    // Test uppercase + lowercase
    let config = PasswordGeneratorConfig {
        length: 16,
        charset: CharsetFlags::UPPERCASE | CharsetFlags::LOWERCASE,
        exclude_ambiguous: false,
    };
    let password = generate_password(&config).expect("Failed to generate password");
    assert!(password.chars().any(char::is_uppercase));
    assert!(password.chars().any(char::is_lowercase));
    assert!(password.chars().all(char::is_alphabetic));

    // Test digits + special
    let config = PasswordGeneratorConfig {
        length: 16,
        charset: CharsetFlags::DIGITS | CharsetFlags::SPECIAL,
        exclude_ambiguous: false,
    };
    let password = generate_password(&config).expect("Failed to generate password");
    assert!(password.chars().any(char::is_numeric));
    assert!(password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)));
}
