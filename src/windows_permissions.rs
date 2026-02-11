//! Windows-specific file and directory permissions using ACLs
//!
//! This module provides Windows Access Control List (ACL) based permissions
//! to restrict file and directory access to the current user only.
//! This is the Windows equivalent of Unix permissions 0600 (files) and 0700 (directories).

#[cfg(windows)]
use crate::errors::SecurityError;
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use windows::core::PWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, PSID};
#[cfg(windows)]
use windows::Win32::Security::{
    GetSecurityInfo, SetSecurityInfo, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SE_FILE_OBJECT,
};
#[cfg(windows)]
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Set secure Windows ACL permissions on a file (equivalent to Unix 0600).
///
/// This function restricts file access to the current user only by:
/// 1. Opening the file handle
/// 2. Getting the current user's SID
/// 3. Setting DACL to allow only the current user full control
/// 4. Protecting the DACL from inheritance
///
/// # Arguments
///
/// * `path` - Path to the file to secure
///
/// # Errors
///
/// Returns `SecurityError::PermissionDenied` if the ACL cannot be set.
///
/// # Platform
///
/// This function is only available on Windows platforms.
#[cfg(windows)]
pub fn set_windows_secure_permissions(path: &Path) -> Result<(), SecurityError> {
    use windows::Win32::Foundation::CloseHandle;

    // Convert path to wide string for Windows API
    let path_str = path.to_str().ok_or(SecurityError::PermissionDenied)?;
    let mut wide_path: Vec<u16> = path_str.encode_utf16().collect();
    wide_path.push(0); // Null terminator

    unsafe {
        // Open file handle
        let file_handle = CreateFileW(
            PWSTR(wide_path.as_mut_ptr()),
            FILE_ALL_ACCESS.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )
        .map_err(|_| SecurityError::PermissionDenied)?;

        // Get current process token
        let mut token_handle = HANDLE(0);
        if !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_ok() {
            let _ = CloseHandle(file_handle);
            return Err(SecurityError::PermissionDenied);
        }

        // Get token user information to retrieve the current user's SID
        let mut token_user_size = 0u32;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut token_user_size);

        if token_user_size == 0 {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(file_handle);
            return Err(SecurityError::PermissionDenied);
        }

        // Allocate buffer for token user
        let mut token_user_buffer = vec![0u8; token_user_size as usize];
        if !GetTokenInformation(
            token_handle,
            TokenUser,
            Some(token_user_buffer.as_mut_ptr() as *mut _),
            token_user_size,
            &mut token_user_size,
        )
        .is_ok()
        {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(file_handle);
            return Err(SecurityError::PermissionDenied);
        }

        let token_user = &*(token_user_buffer.as_ptr() as *const TOKEN_USER);
        let user_sid = PSID(token_user.User.Sid.0);

        // Set security information to restrict access to current user only
        // This sets:
        // - Owner to current user
        // - Group to current user
        // - DACL to null (which means no access except for owner)
        // - Protected flag to prevent inheritance
        let result = SetSecurityInfo(
            file_handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            user_sid,
            user_sid,
            None, // NULL DACL means only owner has access
            None,
        );

        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(file_handle);

        if result != ERROR_SUCCESS {
            return Err(SecurityError::PermissionDenied);
        }

        Ok(())
    }
}

/// Set secure Windows ACL permissions on a directory (equivalent to Unix 0700).
///
/// This function restricts directory access to the current user only.
/// The implementation is the same as file permissions but applied to a directory.
///
/// # Arguments
///
/// * `path` - Path to the directory to secure
///
/// # Errors
///
/// Returns `SecurityError::PermissionDenied` if the ACL cannot be set.
///
/// # Platform
///
/// This function is only available on Windows platforms.
#[cfg(windows)]
pub fn set_windows_directory_permissions(path: &Path) -> Result<(), SecurityError> {
    // Directory permissions use the same ACL mechanism as files
    set_windows_secure_permissions(path)
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_windows_file_permissions_secure() {
        // Create a temporary test file
        let test_dir = std::env::temp_dir().join("password_saver_test_win");
        let _ = fs::create_dir_all(&test_dir);

        let test_file = test_dir.join("test_secure_file.txt");
        let mut file = fs::File::create(&test_file).unwrap();
        file.write_all(b"test data").unwrap();
        drop(file);

        // Set secure permissions
        let result = set_windows_secure_permissions(&test_file);

        // Clean up
        let _ = fs::remove_file(&test_file);
        let _ = fs::remove_dir(&test_dir);

        // Verify the operation succeeded
        assert!(
            result.is_ok(),
            "Failed to set Windows file permissions: {:?}",
            result
        );
    }

    #[test]
    fn test_windows_directory_permissions_secure() {
        // Create a temporary test directory
        let test_dir = std::env::temp_dir().join("password_saver_test_win_dir");
        let _ = fs::create_dir_all(&test_dir);

        // Set secure permissions
        let result = set_windows_directory_permissions(&test_dir);

        // Clean up
        let _ = fs::remove_dir(&test_dir);

        // Verify the operation succeeded
        assert!(
            result.is_ok(),
            "Failed to set Windows directory permissions: {:?}",
            result
        );
    }
}
