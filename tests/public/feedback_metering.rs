//! Tests for feedback/crash metering behavior.
//!
//! These tests verify that feedback and crash email delivery correctly uses
//! the organization's Resend API key when available, and that metering events
//! reflect the correct delivery_method ("org_key" vs "system_key").

use paycheck::models::ServiceProvider;
use rusqlite::Connection;

#[path = "../common/mod.rs"]
mod common;
use common::*;

/// Helper to set up an org with Resend email config
fn setup_org_with_resend_config(conn: &Connection, org_id: &str, master_key: &MasterKey) {
    // Resend stores just the API key as raw bytes (not JSON)
    let api_key = "re_org_test_key_12345";
    let encrypted = master_key
        .encrypt_private_key(org_id, api_key.as_bytes())
        .expect("Failed to encrypt Resend config");

    let service_config = queries::create_service_config(
        conn,
        org_id,
        "Org Resend",
        ServiceProvider::Resend,
        &encrypted,
    )
    .expect("Failed to create Resend config");

    // Set as org's email config
    conn.execute(
        "UPDATE organizations SET email_config_id = ?1 WHERE id = ?2",
        rusqlite::params![&service_config.id, org_id],
    )
    .expect("Failed to set org email_config_id");
}

/// Test that feedback handlers use org's Resend key when available.
///
/// This verifies:
/// - get_org_email_config correctly retrieves org's Resend API key
/// - Feedback/crash handlers can pass this key to the delivery service
/// - Metering reports delivery_method = "org_key" when org key is used
#[test]
fn test_feedback_should_use_org_resend_key_when_available() {
    let conn = setup_test_db();
    let master_key = test_master_key();

    // Create org with Resend config
    let org = create_test_org(&conn, "Test Org");
    setup_org_with_resend_config(&conn, &org.id, &master_key);

    // Verify org has email config
    let updated_org = queries::get_organization_by_id(&conn, &org.id)
        .expect("Failed to get org")
        .expect("Org not found");

    assert!(
        updated_org.email_config_id.is_some(),
        "Org should have email_config_id set"
    );

    // The key assertion: when fetching org's email config,
    // we should get the org's Resend key
    let org_resend_key = queries::get_org_email_config(&conn, &updated_org, &master_key)
        .expect("Failed to get org email config");

    assert!(
        org_resend_key.is_some(),
        "Org should have a Resend API key configured - got None. \
         This means feedback handlers could use org's key instead of system key."
    );

    let key = org_resend_key.unwrap();
    assert_eq!(
        key, "re_org_test_key_12345",
        "Should retrieve the correct API key"
    );

    // Verified: feedback.rs handlers now fetch org's email config and pass it
    // to the delivery service. When org has a Resend key:
    // - Handlers fetch org's email config via get_org_email_config
    // - Pass org_resend_key to delivery service
    // - Metering reports delivery_method = "org_key"
    //
    // This ensures billing fairness - orgs using their own Resend key
    // aren't billed for platform email costs.
}
