use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Represents a single password entry
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub created_at: u64,
}

/// Manages encrypted storage of password entries
#[allow(dead_code)]
pub struct PasswordStorage {
    storage_path: PathBuf,
}

#[allow(dead_code)]
impl PasswordStorage {
    /// Create a new password storage instance
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path }
    }

    /// Derive an encryption key from a master password using Argon2
    pub fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
        let argon2 = Argon2::default();
        let salt_string =
            SaltString::encode_b64(salt).map_err(|e| format!("Failed to encode salt: {}", e))?;

        let password_hash = argon2
            .hash_password(master_password.as_bytes(), &salt_string)
            .map_err(|e| format!("Failed to hash password: {}", e))?;

        // Extract the hash bytes and use first 32 bytes as key
        let hash = password_hash.hash.ok_or("No hash generated")?;
        let hash_bytes = hash.as_bytes();

        // Verify hash is at least 32 bytes
        if hash_bytes.len() < 32 {
            return Err(format!(
                "Hash too short: expected at least 32 bytes, got {}",
                hash_bytes.len()
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);

        Ok(key)
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt_data(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        cipher
            .encrypt(nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt_data(
        encrypted_data: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))
    }

    /// Save encrypted password entries to disk
    pub fn save_entries(
        &self,
        entries: &[PasswordEntry],
        master_password: &str,
    ) -> Result<(), String> {
        // Serialize entries to JSON
        let json_data = serde_json::to_string(entries)
            .map_err(|e| format!("Failed to serialize entries: {}", e))?;

        // Generate cryptographically random salt and nonce
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes();
        let mut nonce_bytes = [0u8; 12];
        use aes_gcm::aead::rand_core::RngCore;
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive encryption key from master password
        let key = Self::derive_key(master_password, salt_bytes)?;

        // Encrypt the data
        let encrypted_data = Self::encrypt_data(json_data.as_bytes(), &key, &nonce_bytes)?;

        // Create storage structure with salt, nonce, and encrypted data
        let storage_data = StorageData {
            salt: salt_bytes.to_vec(),
            nonce: nonce_bytes.to_vec(),
            encrypted_data,
        };

        // Serialize and write to disk
        let storage_json = serde_json::to_string(&storage_data)
            .map_err(|e| format!("Failed to serialize storage data: {}", e))?;

        fs::write(&self.storage_path, storage_json)
            .map_err(|e| format!("Failed to write to disk: {}", e))?;

        Ok(())
    }

    /// Load and decrypt password entries from disk
    pub fn load_entries(&self, master_password: &str) -> Result<Vec<PasswordEntry>, String> {
        // Read storage file
        let storage_json = fs::read_to_string(&self.storage_path)
            .map_err(|e| format!("Failed to read storage file: {}", e))?;

        // Deserialize storage data
        let storage_data: StorageData = serde_json::from_str(&storage_json)
            .map_err(|e| format!("Failed to deserialize storage data: {}", e))?;

        // Derive decryption key
        let key = Self::derive_key(master_password, &storage_data.salt)?;

        // Decrypt data
        let nonce: [u8; 12] = storage_data
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid nonce size")?;
        let decrypted_data = Self::decrypt_data(&storage_data.encrypted_data, &key, &nonce)?;

        // Deserialize entries
        let json_str = String::from_utf8(decrypted_data)
            .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))?;

        let entries: Vec<PasswordEntry> = serde_json::from_str(&json_str)
            .map_err(|e| format!("Failed to deserialize entries: {}", e))?;

        Ok(entries)
    }

    /// Check if storage file exists
    #[must_use]
    pub fn exists(&self) -> bool {
        self.storage_path.exists()
    }
}

/// Internal structure for storing encrypted data on disk
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
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let salt = [0u8; 16];

        let key1 = PasswordStorage::derive_key(password, &salt).unwrap();
        let key2 = PasswordStorage::derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2);
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
}
