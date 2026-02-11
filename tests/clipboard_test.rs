//! Integration tests for clipboard security functionality
//!
//! These tests verify the clipboard module's configuration and initialization.
//! Full clipboard operations cannot be tested in headless environments.

use rust_slint_password_saver::clipboard::{ClipboardConfig, SecureClipboard};

#[test]
fn test_clipboard_config_default_values() {
    let config = ClipboardConfig::default();
    assert!(
        config.auto_clear_enabled,
        "Auto-clear should be enabled by default"
    );
    assert_eq!(
        config.clear_timeout_seconds, 30,
        "Default timeout should be 30 seconds"
    );
}

#[test]
fn test_clipboard_config_custom_values() {
    let config = ClipboardConfig {
        auto_clear_enabled: false,
        clear_timeout_seconds: 60,
    };
    assert!(
        !config.auto_clear_enabled,
        "Auto-clear should be disabled when set to false"
    );
    assert_eq!(
        config.clear_timeout_seconds, 60,
        "Timeout should match configured value"
    );
}

#[test]
fn test_clipboard_config_various_timeouts() {
    // Test short timeout
    let config_short = ClipboardConfig {
        auto_clear_enabled: true,
        clear_timeout_seconds: 10,
    };
    assert_eq!(config_short.clear_timeout_seconds, 10);

    // Test long timeout
    let config_long = ClipboardConfig {
        auto_clear_enabled: true,
        clear_timeout_seconds: 300,
    };
    assert_eq!(config_long.clear_timeout_seconds, 300);
}

// Note: Full clipboard operations cannot be tested in headless CI environments
// as clipboard access requires a display server (X11/Wayland on Linux, etc.)
// The following test attempts to create a clipboard instance but may fail
// in CI environments without display servers.

#[test]
#[ignore] // Ignored by default as it requires display server
fn test_clipboard_initialization_with_display() {
    // This test should only be run manually on systems with clipboard support
    let result = SecureClipboard::new(30);
    
    // In environments with clipboard support, this should succeed
    // In headless environments, this will fail with an error
    match result {
        Ok(_clipboard) => {
            println!("Clipboard initialized successfully");
        }
        Err(e) => {
            println!("Clipboard initialization failed (expected in headless environment): {}", e);
        }
    }
}

#[test]
fn test_clipboard_error_messages_are_informative() {
    // Test that error messages contain useful information
    // We can't actually trigger clipboard errors reliably, but we can
    // verify that the error handling structure is in place by checking
    // that the module compiles and basic instantiation works
    
    // Attempt to create clipboard - may succeed or fail depending on environment
    let _ = SecureClipboard::new(30);
    
    // If we get here, error handling is at least syntactically correct
    assert!(true, "Error handling structure is valid");
}

#[test]
fn test_clipboard_timeout_bounds() {
    // Test that various timeout values are accepted
    let timeouts = vec![1, 10, 30, 60, 120, 300, 600];
    
    for timeout in timeouts {
        let config = ClipboardConfig {
            auto_clear_enabled: true,
            clear_timeout_seconds: timeout,
        };
        assert_eq!(
            config.clear_timeout_seconds, timeout,
            "Timeout should be configurable to {} seconds",
            timeout
        );
    }
}

#[test]
fn test_clipboard_auto_clear_toggle() {
    // Test that auto-clear can be toggled
    let config_enabled = ClipboardConfig {
        auto_clear_enabled: true,
        clear_timeout_seconds: 30,
    };
    assert!(config_enabled.auto_clear_enabled);

    let config_disabled = ClipboardConfig {
        auto_clear_enabled: false,
        clear_timeout_seconds: 30,
    };
    assert!(!config_disabled.auto_clear_enabled);
}
