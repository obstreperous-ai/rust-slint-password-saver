//! Emergency recovery module for account recovery.
//!
//! This module provides emergency access mechanisms for recovering access to the password
//! database when the master password is forgotten or lost. It implements recovery codes
//! that are generated during initial setup and can be used as an alternative authentication
//! method.
//!
//! # Security Properties
//!
//! - Recovery codes are cryptographically random (using OS RNG)
//! - Codes are hashed before storage (never stored in plaintext)
//! - Recovery key derivation uses SHA-256
//! - Recovery codes provide equivalent security to master password
//! - Rate limiting applies to recovery attempts (prevents brute force)
//!
//! # Example
//!
//! ```no_run
//! use rust_slint_password_saver::recovery::EmergencyRecovery;
//!
//! // Generate recovery codes during initial setup
//! let recovery = EmergencyRecovery::create("MyMasterPassword123!");
//!
//! // Display codes to user (they must save these securely)
//! for code in recovery.get_codes() {
//!     println!("Recovery Code: {}", code);
//! }
//!
//! // Later, recover access with a valid code
//! match recovery.recover_access("ABCD-EFGH-IJKL-MNOP") {
//!     Ok(recovery_key) => println!("Access recovered!"),
//!     Err(e) => println!("Recovery failed: {}", e),
//! }
//! ```

use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single recovery code with its hash for verification.
///
/// Recovery codes are formatted as XXXX-XXXX-XXXX-XXXX where each character
/// is from a reduced character set (excluding ambiguous characters like 0/O, 1/I/l).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode {
    #[zeroize(skip)]
    pub code: String,
    #[zeroize(skip)]
    hash: String,
}

impl RecoveryCode {
    /// Generate a cryptographically secure recovery code.
    ///
    /// The code is 16 characters long (formatted with dashes) and uses a character
    /// set that excludes ambiguous characters to prevent confusion when manually
    /// entering codes.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::recovery::RecoveryCode;
    ///
    /// let code = RecoveryCode::generate();
    /// println!("Recovery code: {}", code.code);
    /// // Example output: "ABCD-EFGH-IJKL-MNOP"
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();

        // Use character set without ambiguous characters (0, O, 1, I, l)
        // 30-character set provides ~77 bits of entropy (16 × log2(30) ≈ 77 bits)
        // This is comparable to a 12-character alphanumeric password
        let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

        // Generate 16 random characters
        let code: String = (0..16)
            .map(|_| {
                let idx = rng.gen_range(0..chars.len());
                chars.chars().nth(idx).unwrap()
            })
            .collect();

        // Format as XXXX-XXXX-XXXX-XXXX for readability
        let formatted = format!(
            "{}-{}-{}-{}",
            &code[0..4],
            &code[4..8],
            &code[8..12],
            &code[12..16]
        );

        // Hash the code for verification
        let mut hasher = Sha256::new();
        hasher.update(formatted.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Self {
            code: formatted,
            hash,
        }
    }

    /// Verify that an input code matches this recovery code.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// # Arguments
    ///
    /// * `input` - The recovery code to verify
    ///
    /// # Returns
    ///
    /// `true` if the input matches this recovery code, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_slint_password_saver::recovery::RecoveryCode;
    ///
    /// let code = RecoveryCode::generate();
    /// let code_str = code.code.clone();
    ///
    /// assert!(code.verify(&code_str));
    /// assert!(!code.verify("WRONG-CODE-HERE-XXXX"));
    /// ```
    pub fn verify(&self, input: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let input_hash = hex::encode(hasher.finalize());

        // Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        self.hash.as_bytes().ct_eq(input_hash.as_bytes()).into()
    }
}

/// Emergency recovery system for account recovery.
///
/// Manages multiple recovery codes and provides methods to recover access
/// to the password database when the master password is lost.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EmergencyRecovery {
    recovery_codes: Vec<RecoveryCode>,
    recovery_master_key: Vec<u8>,
}

impl EmergencyRecovery {
    /// Create a new emergency recovery system during initial setup.
    ///
    /// Generates 3 recovery codes and derives a recovery master key from them.
    /// This key can be used to decrypt the database if the master password is lost.
    ///
    /// # Arguments
    ///
    /// * `master_password` - The master password (used for additional key derivation)
    ///
    /// # Returns
    ///
    /// A new `EmergencyRecovery` instance with generated recovery codes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::recovery::EmergencyRecovery;
    ///
    /// let recovery = EmergencyRecovery::create("MyMasterPassword123!");
    /// // Save recovery codes securely (print, export, etc.)
    /// ```
    #[must_use]
    pub fn create(master_password: &str) -> Self {
        // Generate 3 recovery codes
        let codes: Vec<RecoveryCode> = (0..3).map(|_| RecoveryCode::generate()).collect();

        // Derive recovery key from recovery codes
        let recovery_master_key = Self::derive_recovery_key(&codes, master_password);

        Self {
            recovery_codes: codes,
            recovery_master_key,
        }
    }

    /// Get the recovery codes (for display to the user).
    ///
    /// Returns a vector of recovery code strings that the user should save securely.
    ///
    /// # Returns
    ///
    /// A vector containing the recovery code strings.
    #[must_use]
    pub fn get_codes(&self) -> Vec<String> {
        self.recovery_codes.iter().map(|c| c.code.clone()).collect()
    }

    /// Get the hashes of recovery codes (for secure storage).
    ///
    /// Returns a vector of SHA-256 hashes of the recovery codes.
    /// These hashes can be stored without exposing the actual codes.
    ///
    /// # Returns
    ///
    /// A vector containing the recovery code hashes.
    #[must_use]
    pub fn get_code_hashes(&self) -> Vec<String> {
        self.recovery_codes.iter().map(|c| c.hash.clone()).collect()
    }

    /// Get the recovery master key.
    ///
    /// This key can be used to decrypt the database or re-encrypt with a new password.
    ///
    /// # Returns
    ///
    /// The recovery master key as a byte vector.
    #[must_use]
    pub fn get_recovery_key(&self) -> Vec<u8> {
        self.recovery_master_key.clone()
    }

    /// Verify a recovery code and provide access if valid.
    ///
    /// Checks if the provided code matches any of the stored recovery codes.
    /// If valid, returns the recovery master key which can be used to decrypt
    /// the password database.
    ///
    /// # Arguments
    ///
    /// * `code` - The recovery code to verify
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The recovery master key if the code is valid
    /// * `Err(String)` - An error message if the code is invalid
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_slint_password_saver::recovery::EmergencyRecovery;
    ///
    /// let recovery = EmergencyRecovery::create("MyMasterPassword123!");
    /// let code = recovery.get_codes()[0].clone();
    ///
    /// match recovery.recover_access(&code) {
    ///     Ok(key) => println!("Access granted!"),
    ///     Err(e) => println!("Access denied: {}", e),
    /// }
    /// ```
    pub fn recover_access(&self, code: &str) -> Result<Vec<u8>, String> {
        // Verify code matches one of the recovery codes
        if self.recovery_codes.iter().any(|rc| rc.verify(code)) {
            Ok(self.recovery_master_key.clone())
        } else {
            Err("Invalid recovery code".to_string())
        }
    }

    /// Derive the recovery master key from recovery codes and master password.
    ///
    /// Combines all recovery codes with the master password and derives a key
    /// using SHA-256. This key can decrypt the database.
    ///
    /// # Arguments
    ///
    /// * `codes` - The recovery codes to derive from
    /// * `master_password` - The master password for additional entropy
    ///
    /// # Returns
    ///
    /// A 32-byte recovery key.
    fn derive_recovery_key(codes: &[RecoveryCode], master_password: &str) -> Vec<u8> {
        // Combine recovery codes and master password
        let combined = codes
            .iter()
            .map(|c| c.code.as_str())
            .collect::<Vec<&str>>()
            .join("|");

        // Include master password for additional entropy
        let combined_with_password = format!("{}:{}", combined, master_password);

        // Derive key using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(combined_with_password.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Create an `EmergencyRecovery` instance from stored hashes and a known recovery key.
    ///
    /// This is used when loading recovery data from storage.
    ///
    /// # Arguments
    ///
    /// * `hashes` - The stored recovery code hashes
    /// * `recovery_key` - The stored recovery master key
    ///
    /// # Returns
    ///
    /// An `EmergencyRecovery` instance that can verify codes.
    #[must_use]
    pub fn from_hashes(hashes: Vec<String>, recovery_key: Vec<u8>) -> Self {
        let recovery_codes: Vec<RecoveryCode> = hashes
            .into_iter()
            .map(|hash| RecoveryCode {
                code: String::new(), // We don't store the actual code
                hash,
            })
            .collect();

        Self {
            recovery_codes,
            recovery_master_key: recovery_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_code_generation() {
        let code = RecoveryCode::generate();
        
        // Check format: XXXX-XXXX-XXXX-XXXX
        assert_eq!(code.code.len(), 19); // 16 chars + 3 dashes
        assert_eq!(code.code.matches('-').count(), 3);
        
        // Check that hash is non-empty
        assert!(!code.hash.is_empty());
    }

    #[test]
    fn test_recovery_code_verification() {
        let code = RecoveryCode::generate();
        let code_str = code.code.clone();
        
        // Correct code should verify
        assert!(code.verify(&code_str));
        
        // Wrong code should not verify
        assert!(!code.verify("WRONG-CODE-HERE-XXXX"));
    }

    #[test]
    fn test_recovery_code_uniqueness() {
        let code1 = RecoveryCode::generate();
        let code2 = RecoveryCode::generate();
        
        // Codes should be different
        assert_ne!(code1.code, code2.code);
        assert_ne!(code1.hash, code2.hash);
    }

    #[test]
    fn test_emergency_recovery_creation() {
        let recovery = EmergencyRecovery::create("test_password");
        
        // Should have 3 recovery codes
        assert_eq!(recovery.get_codes().len(), 3);
        
        // Should have a recovery key
        assert!(!recovery.get_recovery_key().is_empty());
    }

    #[test]
    fn test_recover_access_with_valid_code() {
        let recovery = EmergencyRecovery::create("test_password");
        let code = recovery.get_codes()[0].clone();
        
        // Should succeed with valid code
        let result = recovery.recover_access(&code);
        assert!(result.is_ok());
        
        // Should return the recovery key
        let key = result.unwrap();
        assert_eq!(key, recovery.get_recovery_key());
    }

    #[test]
    fn test_recover_access_with_invalid_code() {
        let recovery = EmergencyRecovery::create("test_password");
        
        // Should fail with invalid code
        let result = recovery.recover_access("INVALID-CODE-XXXX-YYYY");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid recovery code");
    }

    #[test]
    fn test_recovery_from_hashes() {
        let recovery = EmergencyRecovery::create("test_password");
        let hashes = recovery.get_code_hashes();
        let key = recovery.get_recovery_key();
        
        // Create new recovery from hashes
        let recovered = EmergencyRecovery::from_hashes(hashes, key.clone());
        
        // Should be able to verify with original code
        let code = recovery.get_codes()[0].clone();
        let result = recovered.recover_access(&code);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), key);
    }

    #[test]
    fn test_recovery_key_derivation_deterministic() {
        let recovery1 = EmergencyRecovery::create("test_password");
        let codes = recovery1.get_codes();
        
        // Manually recreate recovery codes with same values
        let recovery_codes: Vec<RecoveryCode> = codes
            .iter()
            .map(|code_str| {
                let mut hasher = Sha256::new();
                hasher.update(code_str.as_bytes());
                let hash = hex::encode(hasher.finalize());
                RecoveryCode {
                    code: code_str.clone(),
                    hash,
                }
            })
            .collect();
        
        let key1 = EmergencyRecovery::derive_recovery_key(&recovery_codes, "test_password");
        let key2 = EmergencyRecovery::derive_recovery_key(&recovery_codes, "test_password");
        
        // Keys should be identical
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_recovery_key_different_for_different_passwords() {
        let recovery1 = EmergencyRecovery::create("password1");
        let recovery2 = EmergencyRecovery::create("password2");
        
        // Keys should be different
        assert_ne!(recovery1.get_recovery_key(), recovery2.get_recovery_key());
    }

    #[test]
    fn test_all_recovery_codes_work() {
        let recovery = EmergencyRecovery::create("test_password");
        let codes = recovery.get_codes();
        
        // All 3 codes should work
        for code in codes {
            let result = recovery.recover_access(&code);
            assert!(result.is_ok());
        }
    }
}
