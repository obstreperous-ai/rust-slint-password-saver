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
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{HANDLE, HLOCAL, PSID};
#[cfg(windows)]
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, SET_ACCESS, SE_FILE_OBJECT,
    TRUSTEE_IS_SID, TRUSTEE_W,
};

// ACE inheritance flags — these constants are not re-exported by the `windows` v0.52 crate
// under `windows::Win32::Security::Authorization`, so they are defined locally using the
// documented Win32 values from the Microsoft WinNT.h header.
#[cfg(windows)]
const NO_INHERITANCE: u32 = 0x0;
// OBJECT_INHERIT_ACE (0x1) | CONTAINER_INHERIT_ACE (0x2)
#[cfg(windows)]
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3;
#[cfg(windows)]
use windows::Win32::Security::{
    ACE_FLAGS, GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Set secure Windows ACL permissions on a file (equivalent to Unix 0600).
///
/// This function restricts file access to the current user only by:
/// 1. Opening the file handle with appropriate permissions
/// 2. Getting the current user's SID
/// 3. Creating an explicit DACL with ACE that grants only the current user access
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
///
/// # Security
///
/// This creates an explicit DACL with Access Control Entries (ACEs) that grant
/// the current user full control and denies all other access. This is more secure
/// than using a NULL DACL which would grant everyone access.
#[cfg(windows)]
pub fn set_windows_secure_permissions(path: &Path) -> Result<(), SecurityError> {
    use windows::Win32::Foundation::{CloseHandle, LocalFree};
    use windows::Win32::Security::ACL;

    // Convert path to wide string for Windows API
    let path_str = path.to_str().ok_or(SecurityError::PermissionDenied)?;
    let mut wide_path: Vec<u16> = path_str.encode_utf16().collect();
    wide_path.push(0); // Null terminator

    unsafe {
        // Open file handle with permissions needed to modify DACL
        // Using READ_CONTROL and WRITE_DAC instead of FILE_ALL_ACCESS (principle of least privilege)
        let file_handle = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            READ_CONTROL.0 | WRITE_DAC.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            Default::default(),
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

        // Create an explicit access entry for the current user
        // This grants the user full control (read, write, delete, etc.)
        // Using SET_ACCESS mode to replace all existing permissions and ensure
        // ONLY the current user has access (equivalent to Unix 0600).
        // This is intentional for maximum security - we want to remove any
        // inherited or default permissions that might grant access to other users.
        let mut ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: (FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0),
            grfAccessMode: SET_ACCESS,
            grfInheritance: ACE_FLAGS(NO_INHERITANCE),
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: Default::default(),
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: Default::default(),
                ptstrName: PWSTR(user_sid.0 as *mut u16),
            },
        };

        // Create a new ACL with the explicit access entry
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let result = SetEntriesInAclW(
            Some(&[ea]),
            None, // No existing ACL - create a new one
            &mut new_acl,
        );

        if result.is_err() {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(file_handle);
            return Err(SecurityError::PermissionDenied);
        }

        // Set the new DACL on the file with protection from inheritance
        let set_result = SetSecurityInfo(
            file_handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            user_sid,
            PSID::default(),
            Some(new_acl),
            None,
        );

        // Clean up resources
        if !new_acl.is_null() {
            let _ = LocalFree(HLOCAL(new_acl.cast()));
        }
        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(file_handle);

        if set_result.is_err() {
            return Err(SecurityError::PermissionDenied);
        }

        Ok(())
    }
}

/// Set secure Windows ACL permissions on a directory (equivalent to Unix 0700).
///
/// This function restricts directory access to the current user only by:
/// 1. Opening the directory handle with `FILE_FLAG_BACKUP_SEMANTICS` (required for directories)
/// 2. Getting the current user's SID
/// 3. Creating an explicit DACL with ACE that grants only the current user access
/// 4. Protecting the DACL from inheritance
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
///
/// # Security
///
/// Opening a directory with `CreateFileW` requires `FILE_FLAG_BACKUP_SEMANTICS` in
/// `dwFlagsAndAttributes`. Without it, `CreateFileW` returns `INVALID_HANDLE_VALUE`
/// and the ACL is never applied.
#[cfg(windows)]
pub fn set_windows_directory_permissions(path: &Path) -> Result<(), SecurityError> {
    use windows::Win32::Foundation::{CloseHandle, LocalFree};
    use windows::Win32::Security::ACL;

    // Convert path to wide string for Windows API
    let path_str = path.to_str().ok_or(SecurityError::PermissionDenied)?;
    let mut wide_path: Vec<u16> = path_str.encode_utf16().collect();
    wide_path.push(0); // Null terminator

    unsafe {
        // Open directory handle with permissions needed to modify DACL.
        // FILE_FLAG_BACKUP_SEMANTICS is required to open a directory handle with CreateFileW.
        let dir_handle = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            READ_CONTROL.0 | WRITE_DAC.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            HANDLE(0),
        )
        .map_err(|_| SecurityError::PermissionDenied)?;

        // Get current process token
        let mut token_handle = HANDLE(0);
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            let _ = CloseHandle(dir_handle);
            return Err(SecurityError::PermissionDenied);
        }

        // Get token user information to retrieve the current user's SID
        let mut token_user_size = 0u32;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut token_user_size);

        if token_user_size == 0 {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(dir_handle);
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
            let _ = CloseHandle(dir_handle);
            return Err(SecurityError::PermissionDenied);
        }

        let token_user = &*(token_user_buffer.as_ptr() as *const TOKEN_USER);
        let user_sid = PSID(token_user.User.Sid.0);

        // Create an explicit access entry for the current user.
        // Grants the user read and write access with sub-container and object inheritance
        // so the ACL propagates to nested files and directories (Windows-specific behaviour;
        // this differs from Unix 0700 which does not propagate permissions to nested items).
        // Using SET_ACCESS mode to replace all existing permissions.
        let mut ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: (FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0),
            grfAccessMode: SET_ACCESS,
            grfInheritance: ACE_FLAGS(SUB_CONTAINERS_AND_OBJECTS_INHERIT),
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: Default::default(),
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: Default::default(),
                ptstrName: PWSTR(user_sid.0 as *mut u16),
            },
        };

        // Create a new ACL with the explicit access entry
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        let result = SetEntriesInAclW(
            Some(&[ea]),
            None, // No existing ACL - create a new one
            &mut new_acl,
        );

        if result.is_err() {
            let _ = CloseHandle(token_handle);
            let _ = CloseHandle(dir_handle);
            return Err(SecurityError::PermissionDenied);
        }

        // Set the new DACL on the directory with protection from inheritance
        let set_result = SetSecurityInfo(
            dir_handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            user_sid,
            PSID::default(),
            Some(new_acl),
            None,
        );

        // Clean up resources
        if !new_acl.is_null() {
            let _ = LocalFree(HLOCAL(new_acl.cast()));
        }
        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(dir_handle);

        if set_result.is_err() {
            return Err(SecurityError::PermissionDenied);
        }

        Ok(())
    }
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
