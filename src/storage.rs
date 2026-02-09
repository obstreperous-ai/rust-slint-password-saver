//! Encrypted password storage module.
//!
//! This module provides functionality for securely storing and retrieving password entries
//! using industry-standard encryption algorithms:
//!
//! - **Argon2id**: Password hashing and key derivation with strengthened parameters
//!   - Memory: 32 MiB (balances strong security with reasonable performance)
//!   - Iterations: 2 (provides good security while maintaining usability)
//!   - Parallelism: 4 threads (balances security with performance)
//! - **AES-256-GCM**: Authenticated encryption with associated data (AEAD)
//!
//! # Security Properties
//!
//! - **Confidentiality**: All data encrypted with AES-256-GCM
//! - **Authenticity**: GCM mode provides tamper detection
//! - **Integrity**: Any modification causes decryption to fail
//! - **Zero-Knowledge**: Master password never stored
//! - **Unique Encryption**: New salt and nonce per save operation
//! - **Strong Key Derivation**: Enhanced Argon2 parameters optimized for password managers
//! - **Audit Trail**: All operations logged for forensic analysis

use crate::audit_log::{get_audit_log_path, AuditEventType, AuditLogger};
use crate::errors::SecurityError;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use log::warn;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Represents a single password entry in the password manager.
///
/// # Fields
///
/// * `title` - The name/title of the password entry (e.g., "Gmail", "GitHub")
/// * `username` - The username or email associated with this entry
/// * `password` - The actual password to store (securely cleared on drop)
/// * `created_at` - Unix timestamp (seconds since epoch) when entry was created
///
/// # Security
///
/// This struct implements `ZeroizeOnDrop` to ensure that sensitive data (passwords)
/// is securely cleared from memory when the struct is dropped. The `title` and
/// `username` fields are skipped from zeroization as they are less sensitive.
///
/// # Example
///
/// ```
/// use rust_slint_password_saver::storage::PasswordEntry;
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// let entry = PasswordEntry {
///     title: "GitHub".to_string(),
///     username: "user@example.com".to_string(),
///     password: "my_secure_password".to_string(),
///     created_at: SystemTime::now()
///         .duration_since(UNIX_EPOCH)
///         .unwrap()
///         .as_secs(),
/// };
/// // password field will be securely cleared when entry is dropped
/// ```
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    #[zeroize(skip)]
    pub title: String,
    #[zeroize(skip)]
    pub username: String,
    pub password: String,
    #[zeroize(skip)]
    pub created_at: u64,
}

/// Manages encrypted storage of password entries using AES-256-GCM encryption.
///
/// This structure provides methods to securely save and load password entries
/// to/from disk with encryption. All data is encrypted using a key derived from
/// a master password via Argon2.
///
/// # Security
///
/// - Uses Argon2 for password hashing (memory-hard, GPU-resistant)
/// - Uses AES-256-GCM for authenticated encryption
/// - Generates new salt and nonce for each save operation
/// - Master password is never stored on disk
///
/// # Example
///
/// ```no_run
/// use rust_slint_password_saver::storage::{PasswordStorage, PasswordEntry};
/// use std::path::PathBuf;
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
/// let entry = PasswordEntry {
///     title: "Example".to_string(),
///     username: "user".to_string(),
///     password: "pass".to_string(),
///     created_at: SystemTime::now()
///         .duration_since(UNIX_EPOCH)
///         .unwrap()
///         .as_secs(),
/// };
///
/// // Save entries
/// storage.save_entries(&vec![entry], "master_password").unwrap();
///
/// // Load entries back
/// let loaded = storage.load_entries("master_password").unwrap();
/// ```
#[allow(dead_code)]
pub struct PasswordStorage {
    storage_path: PathBuf,
}

#[allow(dead_code)]
impl PasswordStorage {
    /// Creates a new password storage instance.
    ///
    /// # Arguments
    ///
    /// * `storage_path` - Path where encrypted password data will be stored
    ///
    /// # Returns
    ///
    /// A new `PasswordStorage` instance
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::storage::PasswordStorage;
    /// use std::path::PathBuf;
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    /// ```
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path }
    }

    /// Derives an encryption key from a master password using Argon2.
    ///
    /// This function uses the Argon2id password hashing algorithm (winner of the
    /// Password Hashing Competition) to derive a cryptographic key from a password.
    /// Argon2 is specifically designed to be memory-hard and resistant to GPU/ASIC
    /// cracking attacks.
    ///
    /// # Security Parameters
    ///
    /// This implementation uses strengthened parameters optimized for password managers:
    /// - **Algorithm**: Argon2id (hybrid mode - combines data-dependent and data-independent passes)
    /// - **Memory**: 32 MiB (32768 KiB) - balances strong security with reasonable performance
    /// - **Iterations**: 2 - provides good security while maintaining usability
    /// - **Parallelism**: 4 threads - balances security with reasonable derivation time
    /// - **Output**: 32 bytes (256 bits) - matches AES-256 key size
    ///
    /// These parameters provide a good balance between security and usability, with typical
    /// key derivation time of 100ms-2000ms depending on hardware (measured ~869ms on GitHub Actions CI).
    ///
    /// # Arguments
    ///
    /// * `master_password` - The master password to derive the key from
    /// * `salt` - Random salt bytes for key derivation (should be unique per storage)
    ///
    /// # Returns
    ///
    /// A 32-byte encryption key on success, or a `SecurityError` on failure
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::CryptographicError` if:
    /// - Argon2 parameter creation fails
    /// - Salt encoding fails
    /// - Password hashing fails
    /// - Generated hash is too short (< 32 bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::storage::PasswordStorage;
    ///
    /// let salt = b"random_salt_1234";
    /// let key = PasswordStorage::derive_key("my_password", salt).unwrap();
    /// assert_eq!(key.len(), 32);
    /// ```
    pub fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32], SecurityError> {
        // Configure Argon2id with stronger parameters optimized for password managers
        // Memory: 32 MiB, Iterations: 2, Parallelism: 4, Output: 32 bytes
        let params = Params::new(
            32768,    // 32 MiB memory cost (in KiB) - balances security with performance
            2,        // 2 iterations - provides good security while maintaining usability
            4,        // 4 parallel threads - balances security with performance
            Some(32), // 32 byte output length - matches AES-256 key size
        )
        .map_err(|_| SecurityError::CryptographicError)?;

        let argon2 = Argon2::new(
            Algorithm::Argon2id, // Argon2id (hybrid mode) - recommended for password hashing
            Version::V0x13,      // Version 1.3 (latest) - includes security improvements
            params,
        );

        let salt_string =
            SaltString::encode_b64(salt).map_err(|_| SecurityError::CryptographicError)?;

        let password_hash = argon2
            .hash_password(master_password.as_bytes(), &salt_string)
            .map_err(|_| SecurityError::CryptographicError)?;

        // Extract the hash bytes and use first 32 bytes as key
        let hash = password_hash
            .hash
            .ok_or(SecurityError::CryptographicError)?;
        let hash_bytes = hash.as_bytes();

        // Verify hash is at least 32 bytes
        if hash_bytes.len() < 32 {
            return Err(SecurityError::CryptographicError);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);

        Ok(key)
    }

    /// Encrypts data using AES-256-GCM authenticated encryption.
    ///
    /// AES-256-GCM provides both confidentiality and authenticity, ensuring that
    /// encrypted data cannot be decrypted or tampered with by attackers.
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt
    /// * `key` - 32-byte encryption key (should be derived from master password)
    /// * `nonce` - 12-byte nonce (must be unique for each encryption with same key)
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext on success, or a `SecurityError` on failure
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::CryptographicError` if encryption fails
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::storage::PasswordStorage;
    ///
    /// let key = [0u8; 32];
    /// let nonce = [0u8; 12];
    /// let data = b"secret data";
    ///
    /// let encrypted = PasswordStorage::encrypt_data(data, &key, &nonce).unwrap();
    /// assert!(!encrypted.is_empty());
    /// ```
    pub fn encrypt_data(
        data: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, SecurityError> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        cipher
            .encrypt(nonce, data)
            .map_err(|_| SecurityError::CryptographicError)
    }

    /// Decrypts data using AES-256-GCM authenticated encryption.
    ///
    /// This function verifies both the authenticity and integrity of the encrypted
    /// data before decrypting it. If the data has been tampered with, decryption
    /// will fail.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - The ciphertext to decrypt
    /// * `key` - 32-byte encryption key (must match the key used for encryption)
    /// * `nonce` - 12-byte nonce (must match the nonce used for encryption)
    ///
    /// # Returns
    ///
    /// The decrypted plaintext on success, or a `SecurityError` on failure
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::AuthenticationFailed` if:
    /// - The key is incorrect
    /// - The nonce is incorrect
    /// - The encrypted data has been tampered with
    /// - The encrypted data is corrupted
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::storage::PasswordStorage;
    ///
    /// let key = [0u8; 32];
    /// let nonce = [0u8; 12];
    /// let data = b"secret data";
    ///
    /// let encrypted = PasswordStorage::encrypt_data(data, &key, &nonce).unwrap();
    /// let decrypted = PasswordStorage::decrypt_data(&encrypted, &key, &nonce).unwrap();
    /// assert_eq!(data, decrypted.as_slice());
    /// ```
    pub fn decrypt_data(
        encrypted_data: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, SecurityError> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|_| SecurityError::AuthenticationFailed)
    }

    /// Saves password entries to disk with encryption.
    ///
    /// This method performs the following operations:
    /// 1. Serializes entries to JSON
    /// 2. Generates a random salt and nonce
    /// 3. Derives an encryption key from the master password
    /// 4. Encrypts the data using AES-256-GCM
    /// 5. Writes the encrypted data to disk
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of password entries to save
    /// * `master_password` - Master password for encryption
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `SecurityError` on failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - JSON serialization fails (`SecurityError::CryptographicError`)
    /// - Key derivation fails (`SecurityError::CryptographicError`)
    /// - Encryption fails (`SecurityError::CryptographicError`)
    /// - File write fails (`SecurityError::StorageError`)
    ///
    /// # Security
    ///
    /// - Generates a new random salt for each save operation
    /// - Generates a new random nonce for each save operation
    /// - This ensures different ciphertexts even for identical plaintexts
    /// - Protects against rainbow table attacks on the password hash
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::storage::{PasswordStorage, PasswordEntry};
    /// use std::path::PathBuf;
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    /// let entry = PasswordEntry {
    ///     title: "GitHub".to_string(),
    ///     username: "user".to_string(),
    ///     password: "pass".to_string(),
    ///     created_at: SystemTime::now()
    ///         .duration_since(UNIX_EPOCH)
    ///         .unwrap()
    ///         .as_secs(),
    /// };
    ///
    /// storage.save_entries(&vec![entry], "master_password").unwrap();
    /// ```
    pub fn save_entries(
        &self,
        entries: &[PasswordEntry],
        master_password: &str,
    ) -> Result<(), SecurityError> {
        // Initialize audit logger
        let audit_logger = AuditLogger::new(get_audit_log_path());

        // Log file access attempt
        let file_access_entry = AuditLogger::create_entry(
            AuditEventType::FileAccess,
            true,
            Some(format!("Writing to {}", self.storage_path.display())),
        );
        if let Err(e) = audit_logger.log_event(&file_access_entry) {
            warn!("Failed to log file access: {}", e);
        }

        // Serialize entries to JSON
        let json_data =
            serde_json::to_string(entries).map_err(|_| SecurityError::CryptographicError)?;

        // Generate cryptographically random salt for key derivation
        // Each save operation gets a new salt to prevent rainbow table attacks
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes();

        // Generate cryptographically random nonce for AES-GCM
        // Must be unique for each encryption with the same key
        let mut nonce_bytes = [0u8; 12];
        use aes_gcm::aead::rand_core::RngCore;
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive encryption key from master password using Argon2
        let key = Self::derive_key(master_password, salt_bytes)?;

        // Encrypt the data using AES-256-GCM (provides both confidentiality and authenticity)
        let encrypted_data = Self::encrypt_data(json_data.as_bytes(), &key, &nonce_bytes)?;

        // Create storage structure with salt, nonce, and encrypted data
        let storage_data = StorageData {
            salt: salt_bytes.to_vec(),
            nonce: nonce_bytes.to_vec(),
            encrypted_data,
        };

        // Serialize storage data to JSON and write to disk
        let storage_json =
            serde_json::to_string(&storage_data).map_err(|_| SecurityError::CryptographicError)?;

        fs::write(&self.storage_path, storage_json).map_err(|_| SecurityError::StorageError)?;

        // Log successful password save
        let save_entry = AuditLogger::create_entry(
            AuditEventType::PasswordsSaved,
            true,
            Some(format!("Saved {} password entries", entries.len())),
        );
        if let Err(e) = audit_logger.log_event(&save_entry) {
            warn!("Failed to log password save: {}", e);
        }

        Ok(())
    }

    /// Loads and decrypts password entries from disk.
    ///
    /// This method performs the following operations:
    /// 1. Reads the encrypted storage file
    /// 2. Deserializes the storage data (salt, nonce, encrypted data)
    /// 3. Derives the decryption key from the master password
    /// 4. Decrypts the data using AES-256-GCM
    /// 5. Deserializes the password entries from JSON
    ///
    /// # Arguments
    ///
    /// * `master_password` - Master password for decryption (must match password used for encryption)
    ///
    /// # Returns
    ///
    /// A vector of password entries on success, or a `SecurityError` on failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage file cannot be read (`SecurityError::StorageError`)
    /// - JSON deserialization fails (`SecurityError::CryptographicError`)
    /// - Master password is incorrect (`SecurityError::AuthenticationFailed`)
    /// - Encrypted data has been tampered with (`SecurityError::AuthenticationFailed`)
    /// - Nonce size is invalid (`SecurityError::CryptographicError`)
    /// - Decrypted data is not valid UTF-8 (`SecurityError::CryptographicError`)
    ///
    /// # Security
    ///
    /// - Incorrect master password will result in decryption failure
    /// - Tampered data will be detected by the GCM authentication tag
    /// - No partial decryption occurs on error
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::storage::PasswordStorage;
    /// use std::path::PathBuf;
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    ///
    /// // Load entries (will fail if master password is wrong)
    /// match storage.load_entries("master_password") {
    ///     Ok(entries) => println!("Loaded {} passwords", entries.len()),
    ///     Err(e) => eprintln!("Failed to load: {}", e),
    /// }
    /// ```
    pub fn load_entries(&self, master_password: &str) -> Result<Vec<PasswordEntry>, SecurityError> {
        // Initialize audit logger
        let audit_logger = AuditLogger::new(get_audit_log_path());

        // Log file access attempt
        let file_access_entry = AuditLogger::create_entry(
            AuditEventType::FileAccess,
            true,
            Some(format!("Reading from {}", self.storage_path.display())),
        );
        if let Err(e) = audit_logger.log_event(&file_access_entry) {
            warn!("Failed to log file access: {}", e);
        }

        // Read encrypted storage file from disk
        let storage_json =
            fs::read_to_string(&self.storage_path).map_err(|_| SecurityError::StorageError)?;

        // Deserialize storage data (salt, nonce, encrypted data)
        let storage_data: StorageData =
            serde_json::from_str(&storage_json).map_err(|_| SecurityError::CryptographicError)?;

        // Derive decryption key using the same salt that was used for encryption
        let key = Self::derive_key(master_password, &storage_data.salt)?;

        // Extract nonce (must be exactly 12 bytes for AES-GCM)
        let nonce: [u8; 12] = storage_data
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| SecurityError::CryptographicError)?;

        // Log master password check
        let password_check_entry = AuditLogger::create_entry(
            AuditEventType::MasterPasswordCheck,
            true,
            Some("Attempting decryption".to_string()),
        );
        if let Err(e) = audit_logger.log_event(&password_check_entry) {
            warn!("Failed to log password check: {}", e);
        }

        // Decrypt data (will fail if password is wrong or data has been tampered with)
        let decrypted_data = Self::decrypt_data(&storage_data.encrypted_data, &key, &nonce)
            .inspect_err(|_| {
                // Log failed decryption attempt
                let failed_entry = AuditLogger::create_entry(
                    AuditEventType::MasterPasswordCheck,
                    false,
                    Some("Decryption failed - possibly wrong master password".to_string()),
                );
                if let Err(e) = audit_logger.log_event(&failed_entry) {
                    warn!("Failed to log failed decryption: {}", e);
                }
            })?;

        // Convert decrypted bytes to UTF-8 string
        let json_str =
            String::from_utf8(decrypted_data).map_err(|_| SecurityError::CryptographicError)?;

        // Deserialize password entries from JSON
        let entries: Vec<PasswordEntry> =
            serde_json::from_str(&json_str).map_err(|_| SecurityError::CryptographicError)?;

        // Log successful password load
        let load_entry = AuditLogger::create_entry(
            AuditEventType::PasswordsLoaded,
            true,
            Some(format!("Loaded {} password entries", entries.len())),
        );
        if let Err(e) = audit_logger.log_event(&load_entry) {
            warn!("Failed to log password load: {}", e);
        }

        Ok(entries)
    }

    /// Checks if the storage file exists on disk.
    ///
    /// # Returns
    ///
    /// `true` if the storage file exists, `false` otherwise
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::storage::PasswordStorage;
    /// use std::path::PathBuf;
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    ///
    /// if storage.exists() {
    ///     println!("Storage file found");
    /// } else {
    ///     println!("No storage file yet");
    /// }
    /// ```
    #[must_use]
    pub fn exists(&self) -> bool {
        self.storage_path.exists()
    }

    /// Changes the master password by re-encrypting all stored entries.
    ///
    /// This method performs the following operations:
    /// 1. Verifies the old password by attempting to load entries
    /// 2. Validates the new password strength
    /// 3. Ensures the new password is different from the old one
    /// 4. Re-encrypts all entries with the new password
    ///
    /// # Arguments
    ///
    /// * `old_password` - Current master password (must be correct)
    /// * `new_password` - New master password to use (must meet strength requirements)
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `SecurityError` if:
    /// - Old password is incorrect
    /// - New password doesn't meet strength requirements
    /// - New password is same as old password
    /// - Storage file doesn't exist
    /// - Re-encryption fails
    ///
    /// # Security
    ///
    /// - Verifies old password before making any changes
    /// - Generates new salt and nonce for re-encryption
    /// - All data is re-encrypted with new key derivation
    /// - No data is lost if operation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::storage::PasswordStorage;
    /// use std::path::PathBuf;
    ///
    /// let storage = PasswordStorage::new(PathBuf::from("passwords.enc"));
    ///
    /// match storage.change_master_password("OldPassword123", "NewPassword456") {
    ///     Ok(()) => println!("Password changed successfully"),
    ///     Err(e) => eprintln!("Failed to change password: {}", e),
    /// }
    /// ```
    pub fn change_master_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), SecurityError> {
        // Verify storage file exists
        if !self.exists() {
            return Err(SecurityError::StorageError);
        }

        // Step 1: Load entries with old password (verifies old password is correct)
        let entries = self.load_entries(old_password)?;

        // Step 2: Validate new password strength
        validate_password_strength(new_password)?;

        // Step 3: Ensure new password is different from old password
        if old_password == new_password {
            return Err(SecurityError::InvalidInput(
                "password: new password must be different from old password".into(),
            ));
        }

        // Step 4: Save entries with new password (re-encrypts with new key)
        self.save_entries(&entries, new_password)?;

        Ok(())
    }
}

/// Internal structure for storing encrypted data on disk.
///
/// This structure contains all the information needed to decrypt password entries:
///
/// # Fields
///
/// * `salt` - Random salt bytes used for Argon2 key derivation
/// * `nonce` - Random nonce bytes used for AES-256-GCM encryption
/// * `encrypted_data` - The actual encrypted password entries
///
/// # Security Note
///
/// The salt and nonce are stored in plaintext alongside the encrypted data.
/// This is safe because:
/// - Salt is public information used to prevent rainbow table attacks
/// - Nonce is public information that ensures unique ciphertexts
/// - Security depends entirely on the secrecy of the master password
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct StorageData {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    encrypted_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_encryption_decryption() {
        let data = b"Hello, World!";
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        let encrypted = PasswordStorage::encrypt_data(data, &key, &nonce).unwrap();
        let decrypted = PasswordStorage::decrypt_data(&encrypted, &key, &nonce).unwrap();

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let password = "test_password";
        // Use random salt for testing to avoid security scan warnings
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes();

        let key1 = PasswordStorage::derive_key(password, salt_bytes).unwrap();
        let key2 = PasswordStorage::derive_key(password, salt_bytes).unwrap();

        // Same password and salt should produce the same key
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_key_derivation_time() {
        // Test that key derivation with strengthened parameters takes a reasonable time
        // Expected: 100ms - 2000ms (acceptable range balancing security vs usability)
        // Measured on CI: ~869ms
        let password = "test_password_for_timing";
        // Use random salt for testing to avoid security scan warnings
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes();

        let start = Instant::now();
        let _key = PasswordStorage::derive_key(password, salt_bytes).unwrap();
        let duration = start.elapsed();

        println!(
            "Key derivation time with strengthened parameters: {:?}",
            duration
        );

        // Verify key derivation takes at least 100ms (security requirement)
        assert!(
            duration.as_millis() >= 100,
            "Key derivation too fast: {:?}ms - strengthened parameters not working",
            duration.as_millis()
        );

        // Verify key derivation takes less than 2 seconds (usability requirement)
        assert!(
            duration.as_secs() < 2,
            "Key derivation too slow: {:?}s - poor user experience",
            duration.as_secs()
        );
    }

    #[test]
    fn test_password_entry_serialization() {
        let entry = PasswordEntry {
            title: "Test".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: PasswordEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.title, deserialized.title);
        assert_eq!(entry.username, deserialized.username);
        assert_eq!(entry.password, deserialized.password);
    }

    #[test]
    fn test_validate_password_strength_valid() {
        assert!(validate_password_strength("SecurePass123").is_ok());
        assert!(validate_password_strength("MyPassword1").is_ok());
        assert!(validate_password_strength("Abc12345").is_ok());
    }

    #[test]
    fn test_validate_password_strength_too_short() {
        let result = validate_password_strength("Pass1");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.user_message().contains("at least 8 characters"));
    }

    #[test]
    fn test_validate_password_strength_no_uppercase() {
        let result = validate_password_strength("password123");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.user_message().contains("uppercase letter"));
    }

    #[test]
    fn test_validate_password_strength_no_lowercase() {
        let result = validate_password_strength("PASSWORD123");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.user_message().contains("lowercase letter"));
    }

    #[test]
    fn test_validate_password_strength_no_number() {
        let result = validate_password_strength("PasswordOnly");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.user_message().contains("number"));
    }
}
