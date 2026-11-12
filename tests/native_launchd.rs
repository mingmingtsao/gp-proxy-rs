#![cfg(target_os = "macos")]
//! Explicit native launchd opt-in. Ordinary tests never run these cases.
//! Only private temporary plists are used, not login-directory discovery.
#[path = "support/native_harness.rs"]
mod harness;

#[tokio::test]
#[ignore = "real current-user gui launchd; reviewed GP_TEST_NATIVE_* opt-in and frozen artifacts required"]
async fn native_launchd_private_namespace_lifecycle_with_explicit_authentication() {
    harness::run(harness::Case::Normal).await;
}

#[tokio::test]
#[ignore = "one SIGKILL to the exact owned launchd service; reviewed GP_TEST_NATIVE_* opt-in required"]
async fn native_launchd_crash_restarts_without_replaying_credentials() {
    harness::run(harness::Case::DaemonCrash).await;
}

#[tokio::test]
#[ignore = "kills only its owned management CLI child; real current-user gui launchd and reviewed GP_TEST_NATIVE_* opt-in required"]
async fn native_launchd_interrupted_manager_recovers_durable_cleanup() {
    harness::run(harness::Case::ManagerInterrupted).await;
}
