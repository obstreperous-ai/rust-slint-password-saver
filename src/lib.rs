//! # Rust Slint Password Saver Library
//!
//! A secure password manager library providing encrypted storage of password entries
//! using Argon2 for key derivation and AES-256-GCM for encryption.
//!
//! ## Features
//!
//! - **Military-grade encryption**: Uses Argon2 + AES-256-GCM
//! - **Zero-knowledge architecture**: Master password never stored
//! - **Cross-platform support**: Works on macOS, Linux, and other Unix-like systems
//! - **Rate limiting**: Protection against brute-force attacks
//! - **Password strength validation**: Enforces strong master passwords
//! - **Security audit logging**: Comprehensive logging of security events with integrity protection
//!
//! ## Example
//!
//! ```no_run
//! use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
//! use rust_slint_password_saver::password_strength::{validate_password_strength, PasswordRequirements};
//! use std::path::PathBuf;
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! // Validate master password strength
//! let master_password = "MyS3cur3P@ssw0rd!";
//! match validate_password_strength(master_password, &PasswordRequirements::default()) {
//!     Ok(strength) => println!("Password strength: {:?}", strength),
//!     Err(e) => panic!("Weak password: {}", e),
//! }
//!
//! // Create a password storage instance
//! let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
//!
//! // Create a password entry
//! let entry = PasswordEntry {
//!     title: "GitHub".to_string(),
//!     username: "user@example.com".to_string(),
//!     password: "secure_password".to_string(),
//!     created_at: SystemTime::now()
//!         .duration_since(UNIX_EPOCH)
//!         .unwrap()
//!         .as_secs(),
//! };
//!
//! // Save entries with master password
//! let entries = vec![entry];
//! storage.save_entries(&entries, master_password).unwrap();
//!
//! // Load entries back
//! let loaded = storage.load_entries(master_password).unwrap();
//! ```

pub mod audit_log;
pub mod clipboard;
pub mod errors;
pub mod password_strength;
pub mod rate_limit;
pub mod secure_delete;
pub mod session;
pub mod storage;
pub mod validation;

#[cfg(windows)]
pub mod windows_permissions;
