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
//!
//! ## Example
//!
//! ```no_run
//! use rust_slint_password_saver::storage::{PasswordEntry, PasswordStorage};
//! use std::path::PathBuf;
//! use std::time::{SystemTime, UNIX_EPOCH};
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
//! storage.save_entries(&entries, "master_password").unwrap();
//!
//! // Load entries back
//! let loaded = storage.load_entries("master_password").unwrap();
//! ```

pub mod rate_limit;
pub mod storage;
