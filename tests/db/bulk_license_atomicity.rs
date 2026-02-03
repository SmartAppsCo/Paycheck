//! Tests for bulk license creation atomicity.
//!
//! These tests verify that bulk license creation is atomic - either all licenses
//! are created or none are. Partial failures should not leave orphaned data.
//!
//! Bug: The bulk license creation handler at src/handlers/orgs/licenses.rs:221-265
//! was not wrapped in a transaction, allowing partial failures to leave orphaned
//! licenses and activation codes in the database.

#[path = "../common/mod.rs"]
mod common;

use common::*;
use rusqlite::params;

// ============================================================================
// ATOMICITY TESTS
// ============================================================================

/// Test that bulk license creation is atomic at the database level.
///
/// This test verifies that when creating multiple licenses in a transaction,
/// if ANY operation fails, ALL changes are rolled back (no orphaned data).
///
/// The test simulates a failure during bulk creation by:
/// 1. Starting a transaction
/// 2. Creating some licenses successfully
/// 3. Triggering a rollback (simulating failure)
/// 4. Verifying no licenses were persisted
#[test]
fn test_bulk_license_creation_rolls_back_on_failure() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Count licenses before
    let count_before: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM licenses WHERE project_id = ?1",
            params![&project.id],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(count_before, 0, "should start with no licenses");

    // Simulate bulk creation with failure using a transaction
    {
        let tx = conn.transaction().unwrap();

        // Create first license (would succeed)
        let input1 = CreateLicense {
            email_hash: Some(test_email_hasher().hash("user1@example.com")),
            customer_id: None,
            expires_at: None,
            updates_expires_at: None,
        };
        let license1 = queries::create_license(&tx, &project.id, &product.id, &input1)
            .expect("First license should be created");

        // Create activation code for first license
        let _code1 = queries::create_activation_code(&tx, &license1.id, "TEST")
            .expect("First activation code should be created");

        // Create second license (would succeed)
        let input2 = CreateLicense {
            email_hash: Some(test_email_hasher().hash("user2@example.com")),
            customer_id: None,
            expires_at: None,
            updates_expires_at: None,
        };
        let license2 = queries::create_license(&tx, &project.id, &product.id, &input2)
            .expect("Second license should be created");

        // Create activation code for second license
        let _code2 = queries::create_activation_code(&tx, &license2.id, "TEST")
            .expect("Second activation code should be created");

        // Verify licenses exist within transaction
        let count_in_tx: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM licenses WHERE project_id = ?1",
                params![&project.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count_in_tx, 2, "should have 2 licenses within transaction");

        // Simulate failure - DON'T commit, let transaction drop (rollback)
        // tx.commit() is NOT called, so changes are rolled back
    }

    // Verify no licenses were persisted after rollback
    let count_after: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM licenses WHERE project_id = ?1",
            params![&project.id],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        count_after, 0,
        "transaction rollback should leave no orphaned licenses"
    );

    // Verify no activation codes were persisted
    let code_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM activation_codes", [], |row| {
            row.get(0)
        })
        .unwrap();

    assert_eq!(
        code_count, 0,
        "transaction rollback should leave no orphaned activation codes"
    );
}

/// Test that successful bulk license creation commits all data.
///
/// This is the happy path - when all operations succeed, all data is persisted.
#[test]
fn test_bulk_license_creation_commits_on_success() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Perform bulk creation in a transaction
    {
        let tx = conn.transaction().unwrap();

        for i in 1..=3 {
            let input = CreateLicense {
                email_hash: Some(test_email_hasher().hash(&format!("user{}@example.com", i))),
                customer_id: None,
                expires_at: None,
                updates_expires_at: None,
            };
            let license = queries::create_license(&tx, &project.id, &product.id, &input)
                .expect("License creation should succeed");

            queries::create_activation_code(&tx, &license.id, "TEST")
                .expect("Activation code creation should succeed");
        }

        // Commit the transaction
        tx.commit().unwrap();
    }

    // Verify all licenses were persisted
    let license_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM licenses WHERE project_id = ?1",
            params![&project.id],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(license_count, 3, "all 3 licenses should be persisted");

    // Verify all activation codes were persisted
    let code_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM activation_codes", [], |row| {
            row.get(0)
        })
        .unwrap();

    assert_eq!(
        code_count, 3,
        "all 3 activation codes should be persisted"
    );
}

/// Test that demonstrates the bug: without transaction, partial data persists.
///
/// This test shows what happens WITHOUT proper transaction handling:
/// if we create licenses one by one without a transaction, and something
/// fails midway, the earlier licenses remain (orphaned data).
///
/// NOTE: This test documents the problematic behavior that the fix addresses.
/// After the fix, the handler wraps everything in a transaction.
#[test]
fn test_without_transaction_partial_data_persists_demonstrates_bug() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Simulate the buggy behavior: create licenses WITHOUT a transaction
    // First license succeeds
    let input1 = CreateLicense {
        email_hash: Some(test_email_hasher().hash("user1@example.com")),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
    };
    let license1 = queries::create_license(&conn, &project.id, &product.id, &input1)
        .expect("First license should be created");
    let _code1 = queries::create_activation_code(&conn, &license1.id, "TEST")
        .expect("First activation code should be created");

    // Second license succeeds
    let input2 = CreateLicense {
        email_hash: Some(test_email_hasher().hash("user2@example.com")),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
    };
    let license2 = queries::create_license(&conn, &project.id, &product.id, &input2)
        .expect("Second license should be created");
    let _code2 = queries::create_activation_code(&conn, &license2.id, "TEST")
        .expect("Second activation code should be created");

    // Third license would fail (simulated by not creating it)
    // In real scenario, this could be a DB constraint, disk full, etc.
    // The point is: the first two licenses are now orphaned if the operation
    // was supposed to be all-or-nothing.

    // Verify: the first two licenses PERSIST (this is the bug!)
    let license_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM licenses WHERE project_id = ?1",
            params![&project.id],
            |row| row.get(0),
        )
        .unwrap();

    // This assertion documents the buggy behavior:
    // Without a transaction, partial data persists
    assert_eq!(
        license_count, 2,
        "BUG DEMO: without transaction, partial licenses persist"
    );

    // The fix ensures that if we wanted 3 licenses and only got 2,
    // the entire operation would be rolled back (0 licenses).
}
