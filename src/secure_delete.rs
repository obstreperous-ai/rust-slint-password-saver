//! Secure file deletion with multi-pass overwriting.
//!
//! This module provides functionality for securely deleting files by overwriting
//! data multiple times before deletion. This is a defense-in-depth measure for
//! systems without full disk encryption.
//!
//! # Security Considerations
//!
//! - **SSDs with wear-leveling**: Modern SSDs may not actually overwrite the same
//!   physical blocks due to wear-leveling algorithms. Secure deletion is less
//!   effective on SSDs.
//! - **Filesystem encryption**: Full disk encryption (`LUKS`, `FileVault`, `BitLocker`)
//!   provides better protection than secure deletion.
//! - **Defense-in-depth**: This provides an additional layer of security for HDDs
//!   and some SSD configurations, even though data is encrypted.
//!
//! # Implementation
//!
//! The secure deletion uses a 3-pass overwrite pattern:
//! 1. Overwrite with random data
//! 2. Overwrite with zeros
//! 3. Overwrite with random data again
//! 4. Delete the file
//!
//! # Example
//!
//! ```no_run
//! use rust_slint_password_saver::secure_delete::secure_delete_file;
//! use std::path::Path;
//!
//! let path = Path::new("sensitive_file.txt");
//! secure_delete_file(path).expect("Failed to securely delete file");
//! ```

use crate::errors::SecurityError;
use rand::Rng;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Securely overwrites a file multiple times before deletion.
///
/// This implements a 3-pass overwrite pattern:
/// 1. Overwrite with random data
/// 2. Overwrite with zeros
/// 3. Overwrite with random data again
/// 4. Delete file
///
/// # Arguments
///
/// * `path` - Path to file to securely delete
///
/// # Returns
///
/// `Ok(())` on success, or a `SecurityError` on failure
///
/// # Errors
///
/// Returns an error if:
/// - File metadata cannot be read (`SecurityError::StorageError`)
/// - File cannot be opened for writing (`SecurityError::StorageError`)
/// - Write operations fail (`SecurityError::StorageError`)
/// - File deletion fails (`SecurityError::StorageError`)
///
/// # Security Notes
///
/// - Modern SSDs with wear-leveling may not actually overwrite the same physical blocks
/// - Encrypting the filesystem (`LUKS`, `FileVault`, `BitLocker`) provides better protection
/// - This provides defense-in-depth for HDDs and some SSD configurations
/// - Even encrypted data should be securely deleted for maximum security
///
/// # Example
///
/// ```no_run
/// use rust_slint_password_saver::secure_delete::secure_delete_file;
/// use std::path::Path;
///
/// let path = Path::new("old_passwords.enc");
/// secure_delete_file(path).expect("Failed to securely delete file");
/// ```
pub fn secure_delete_file(path: &Path) -> Result<(), SecurityError> {
    // Get file size
    let metadata = fs::metadata(path)
        .map_err(|e| SecurityError::InvalidInput(format!("Failed to get file metadata: {}", e)))?;
    #[allow(clippy::cast_possible_truncation)]
    let file_size = metadata.len() as usize;

    // Open file for writing
    let mut file = OpenOptions::new().write(true).open(path).map_err(|e| {
        SecurityError::InvalidInput(format!("Failed to open file for secure deletion: {}", e))
    })?;

    // Pass 1: Overwrite with random data
    overwrite_with_random(&mut file, file_size)?;

    // Pass 2: Overwrite with zeros
    overwrite_with_zeros(&mut file, file_size)?;

    // Pass 3: Overwrite with random data again
    overwrite_with_random(&mut file, file_size)?;

    // Close file and delete
    drop(file);
    fs::remove_file(path)
        .map_err(|e| SecurityError::InvalidInput(format!("Failed to delete file: {}", e)))?;

    Ok(())
}

/// Overwrites a file with random data.
///
/// # Arguments
///
/// * `file` - File handle to overwrite
/// * `size` - Number of bytes to write
///
/// # Errors
///
/// Returns `SecurityError::StorageError` if write operations fail
fn overwrite_with_random(file: &mut File, size: usize) -> Result<(), SecurityError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SecurityError::StorageError)?;

    let mut rng = rand::thread_rng();
    let random_data: Vec<u8> = (0..size).map(|_| rng.gen::<u8>()).collect();

    file.write_all(&random_data)
        .map_err(|_| SecurityError::StorageError)?;
    file.sync_all().map_err(|_| SecurityError::StorageError)?;

    Ok(())
}

/// Overwrites a file with zeros.
///
/// # Arguments
///
/// * `file` - File handle to overwrite
/// * `size` - Number of bytes to write
///
/// # Errors
///
/// Returns `SecurityError::StorageError` if write operations fail
fn overwrite_with_zeros(file: &mut File, size: usize) -> Result<(), SecurityError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SecurityError::StorageError)?;

    let zero_data = vec![0u8; size];

    file.write_all(&zero_data)
        .map_err(|_| SecurityError::StorageError)?;
    file.sync_all().map_err(|_| SecurityError::StorageError)?;

    Ok(())
}

/// Creates a backup copy before secure deletion for atomic updates.
///
/// This function performs atomic file updates by:
/// 1. Renaming existing file to backup (if it exists)
/// 2. Writing new data to the original path
/// 3. Securely deleting the backup file
///
/// If writing the new data fails, the backup remains and can be manually restored.
///
/// # Arguments
///
/// * `path` - Path to the file to update
/// * `new_data` - New data to write to the file
///
/// # Returns
///
/// `Ok(())` on success, or a `SecurityError` on failure
///
/// # Errors
///
/// Returns an error if:
/// - File rename fails (`SecurityError::StorageError`)
/// - Write operation fails (`SecurityError::StorageError`)
/// - Secure deletion of backup fails (propagates from `secure_delete_file`)
///
/// # Example
///
/// ```no_run
/// use rust_slint_password_saver::secure_delete::secure_update_file;
/// use std::path::Path;
///
/// let path = Path::new("passwords.enc");
/// let new_data = b"encrypted data";
/// secure_update_file(path, new_data).expect("Failed to update file");
/// ```
pub fn secure_update_file(path: &Path, new_data: &[u8]) -> Result<(), SecurityError> {
    let backup_path = path.with_extension("enc.backup");

    // If file exists, rename to backup
    if path.exists() {
        fs::rename(path, &backup_path).map_err(|_| SecurityError::StorageError)?;
    }

    // Write new data
    fs::write(path, new_data).map_err(|_| SecurityError::StorageError)?;

    // If backup exists, securely delete it
    if backup_path.exists() {
        secure_delete_file(&backup_path)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_secure_delete_file_success() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_secure_delete.txt");

        // Create a test file with some content
        fs::write(&test_file, b"sensitive data").expect("Failed to create test file");
        assert!(test_file.exists());

        // Securely delete the file
        secure_delete_file(&test_file).expect("Secure deletion failed");

        // Verify file no longer exists
        assert!(!test_file.exists());
    }

    #[test]
    fn test_secure_delete_file_nonexistent() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("nonexistent_file.txt");

        // Try to delete a file that doesn't exist
        let result = secure_delete_file(&test_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_update_file_new_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_secure_update_new.txt");

        // Ensure file doesn't exist
        let _ = fs::remove_file(&test_file);

        // Update with new data (should create the file)
        let new_data = b"new encrypted data";
        secure_update_file(&test_file, new_data).expect("Secure update failed");

        // Verify file exists with correct content
        assert!(test_file.exists());
        let content = fs::read(&test_file).expect("Failed to read file");
        assert_eq!(content, new_data);

        // Cleanup
        let _ = fs::remove_file(&test_file);
    }

    #[test]
    fn test_secure_update_file_existing_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_secure_update_existing.txt");
        let backup_path = test_file.with_extension("enc.backup");

        // Create an existing file
        let old_data = b"old sensitive data";
        fs::write(&test_file, old_data).expect("Failed to create test file");

        // Update with new data
        let new_data = b"new encrypted data";
        secure_update_file(&test_file, new_data).expect("Secure update failed");

        // Verify file exists with new content
        assert!(test_file.exists());
        let content = fs::read(&test_file).expect("Failed to read file");
        assert_eq!(content, new_data);

        // Verify backup was deleted
        assert!(!backup_path.exists());

        // Cleanup
        let _ = fs::remove_file(&test_file);
    }

    #[test]
    fn test_overwrite_with_random() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_overwrite_random.txt");

        // Create a test file
        fs::write(&test_file, b"original data").expect("Failed to create test file");

        let mut file = OpenOptions::new()
            .write(true)
            .open(&test_file)
            .expect("Failed to open file");

        // Overwrite with random data
        overwrite_with_random(&mut file, 13).expect("Overwrite failed");
        drop(file);

        // Verify file content changed
        let content = fs::read(&test_file).expect("Failed to read file");
        assert_eq!(content.len(), 13);
        assert_ne!(content, b"original data");

        // Cleanup
        let _ = fs::remove_file(&test_file);
    }

    #[test]
    fn test_overwrite_with_zeros() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_overwrite_zeros.txt");

        // Create a test file
        fs::write(&test_file, b"original data").expect("Failed to create test file");

        let mut file = OpenOptions::new()
            .write(true)
            .open(&test_file)
            .expect("Failed to open file");

        // Overwrite with zeros
        overwrite_with_zeros(&mut file, 13).expect("Overwrite failed");
        drop(file);

        // Verify file content is all zeros
        let content = fs::read(&test_file).expect("Failed to read file");
        assert_eq!(content.len(), 13);
        assert_eq!(content, vec![0u8; 13]);

        // Cleanup
        let _ = fs::remove_file(&test_file);
    }
}
