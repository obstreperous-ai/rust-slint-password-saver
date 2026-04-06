//! Integration test suite for complete user workflows.
//!
//! This crate groups integration tests into four focused modules:
//! - [`full_lifecycle_test`]: end-to-end password management lifecycle.
//! - [`backup_recovery_test`]: backup creation and restore scenarios.
//! - [`security_scenarios_test`]: rate limiting, session management, recovery
//!   codes, and audit logging interactions.
//! - [`recovery_workflow_test`]: full password-less end-to-end recovery workflow.

#[path = "integration/backup_recovery_test.rs"]
mod backup_recovery_test;

#[path = "integration/full_lifecycle_test.rs"]
mod full_lifecycle_test;

#[path = "integration/security_scenarios_test.rs"]
mod security_scenarios_test;

#[path = "integration/recovery_workflow_test.rs"]
mod recovery_workflow_test;
