//! # Update Checker Module
//!
//! Provides privacy-preserving version checking and update notification functionality.
//! Checks GitHub releases API for newer versions without sending any user data or telemetry.
//!
//! ## Features
//!
//! - Privacy-preserving: No user data or telemetry sent
//! - Semantic version comparison
//! - Security update detection
//! - Configurable check intervals
//! - Graceful offline handling
//!
//! ## Example
//!
//! ```no_run
//! use rust_slint_password_saver::update_checker::UpdateChecker;
//!
//! let checker = UpdateChecker::new();
//! match checker.check_for_updates() {
//!     Ok(Some(info)) => {
//!         println!("Update available: {}", info.latest_version);
//!         if info.security_update {
//!             println!("⚠️ This is a security update!");
//!         }
//!     }
//!     Ok(None) => println!("No updates available"),
//!     Err(e) => eprintln!("Update check failed: {}", e),
//! }
//! ```

use log::warn;
use serde::{Deserialize, Serialize};

/// Information about an available version update
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionInfo {
    pub latest_version: String,
    pub release_date: String,
    pub security_update: bool,
    pub download_url: String,
    pub changelog_url: String,
}

/// GitHub release API response structure
#[derive(Deserialize, Debug)]
struct GitHubRelease {
    tag_name: String,
    published_at: String,
    html_url: String,
    body: String,
}

/// Update checker configuration
///
/// This configuration struct is part of the public API for future enhancements.
/// It allows users to configure update checking behavior once persistent settings
/// are implemented. Currently not used in the UI but available for future use.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UpdateCheckConfig {
    pub enabled: bool,
    pub check_interval_days: u64,
    pub notify_security_only: bool,
}

impl Default for UpdateCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_days: 7, // Check weekly
            notify_security_only: false,
        }
    }
}

/// Privacy-preserving update checker
///
/// Checks for available updates by querying GitHub releases API.
/// No user data or telemetry is sent - only a standard HTTP GET request.
pub struct UpdateChecker {
    current_version: String,
    check_url: String,
}

impl UpdateChecker {
    /// Create a new update checker
    ///
    /// Uses the current package version from Cargo.toml and the GitHub releases API URL.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            check_url:
                "https://api.github.com/repos/obstreperous-ai/rust-slint-password-saver/releases/latest"
                    .to_string(),
        }
    }

    /// Check for updates (privacy-preserving - no telemetry)
    ///
    /// Makes a blocking HTTP request to GitHub API to check for newer versions.
    /// Returns `Ok(Some(VersionInfo))` if an update is available,
    /// `Ok(None)` if running latest version,
    /// or `Err(String)` if the check fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Network request fails
    /// - API response cannot be parsed
    /// - Version comparison fails
    ///
    /// # Privacy
    ///
    /// This function makes a standard HTTP GET request to GitHub's public API.
    /// No user data, telemetry, or identifying information is sent.
    pub fn check_for_updates(&self) -> Result<Option<VersionInfo>, String> {
        // Make blocking HTTP request to GitHub API
        let client = reqwest::blocking::Client::builder()
            .user_agent(format!(
                "rust-slint-password-saver/{}",
                self.current_version
            ))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let response = client
            .get(&self.check_url)
            .send()
            .map_err(|e| format!("Failed to fetch release info: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("GitHub API returned status: {}", response.status()));
        }

        let release: GitHubRelease = response
            .json()
            .map_err(|e| format!("Failed to parse release info: {}", e))?;

        // Compare versions
        if Self::is_newer_version(&release.tag_name, &self.current_version) {
            let security_update = Self::is_security_release(&release);

            Ok(Some(VersionInfo {
                latest_version: release.tag_name.clone(),
                release_date: release.published_at,
                security_update,
                download_url: release.html_url.clone(),
                changelog_url: release.html_url,
            }))
        } else {
            Ok(None)
        }
    }

    /// Parse version string and compare
    ///
    /// Compares two semantic version strings to determine if the latest is newer.
    /// Strips 'v' prefix if present (e.g., "v1.2.3" -> "1.2.3").
    ///
    /// # Arguments
    ///
    /// * `latest` - Version string from the latest release
    /// * `current` - Current version string
    ///
    /// # Returns
    ///
    /// `true` if latest is newer than current, `false` otherwise.
    /// Returns `false` if version parsing fails.
    fn is_newer_version(latest: &str, current: &str) -> bool {
        // Strip 'v' prefix if present
        let latest_clean = latest.trim_start_matches('v');
        let current_clean = current.trim_start_matches('v');

        if let (Ok(latest_ver), Ok(current_ver)) = (
            semver::Version::parse(latest_clean),
            semver::Version::parse(current_clean),
        ) {
            latest_ver > current_ver
        } else {
            warn!(
                "Failed to parse versions: latest='{}', current='{}'",
                latest, current
            );
            false
        }
    }

    /// Check if release contains security fixes
    ///
    /// Analyzes the release body/notes for security-related keywords.
    ///
    /// # Arguments
    ///
    /// * `release` - GitHub release information
    ///
    /// # Returns
    ///
    /// `true` if the release contains security fixes, `false` otherwise.
    fn is_security_release(release: &GitHubRelease) -> bool {
        let body_lower = release.body.to_lowercase();
        body_lower.contains("security")
            || body_lower.contains("vulnerability")
            || body_lower.contains("cve")
    }
}

impl Default for UpdateChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_version_basic() {
        assert!(UpdateChecker::is_newer_version("1.1.0", "1.0.0"));
        assert!(UpdateChecker::is_newer_version("2.0.0", "1.9.9"));
        assert!(UpdateChecker::is_newer_version("1.0.1", "1.0.0"));
        assert!(!UpdateChecker::is_newer_version("1.0.0", "1.0.0"));
        assert!(!UpdateChecker::is_newer_version("1.0.0", "1.1.0"));
    }

    #[test]
    fn test_is_newer_version_with_v_prefix() {
        assert!(UpdateChecker::is_newer_version("v1.1.0", "v1.0.0"));
        assert!(UpdateChecker::is_newer_version("v2.0.0", "1.0.0"));
        assert!(UpdateChecker::is_newer_version("1.1.0", "v1.0.0"));
    }

    #[test]
    fn test_is_newer_version_invalid() {
        // Invalid versions should return false
        assert!(!UpdateChecker::is_newer_version("invalid", "1.0.0"));
        assert!(!UpdateChecker::is_newer_version("1.0.0", "invalid"));
    }

    #[test]
    fn test_update_checker_creation() {
        let checker = UpdateChecker::new();
        assert_eq!(checker.current_version, env!("CARGO_PKG_VERSION"));
        assert!(checker.check_url.contains("github.com"));
    }

    #[test]
    fn test_update_check_config_default() {
        let config = UpdateCheckConfig::default();
        assert!(config.enabled);
        assert_eq!(config.check_interval_days, 7);
        assert!(!config.notify_security_only);
    }

    // Note: We don't test actual API calls in unit tests to avoid network dependencies
    // Integration tests can be added separately if needed
}
