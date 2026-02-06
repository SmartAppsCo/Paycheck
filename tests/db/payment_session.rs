//! Payment session and webhook event deduplication tests
//!
//! Tests the compare-and-swap operations that prevent duplicate license creation
//! from concurrent webhooks, and webhook replay attack prevention.

#[path = "../common/mod.rs"]
mod common;

use common::*;
use rusqlite::Connection;

// ============ Payment Session CRUD Tests ============

#[test]
fn test_create_and_get_payment_session() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreatePaymentSession {
        product_id: product.id.clone(),
        customer_id: Some("cust_123".to_string()),
    };

    let session = queries::create_payment_session(&conn, &input)
        .expect("create_payment_session should succeed");

    assert_eq!(session.product_id, product.id);
    assert_eq!(session.customer_id, Some("cust_123".to_string()));
    assert!(!session.completed);
    assert!(session.license_id.is_none());
    assert!(session.id.starts_with("pc_ps_"), "session ID should have pc_ps_ prefix");

    // Retrieve and verify all fields match
    let retrieved = queries::get_payment_session(&conn, &session.id)
        .expect("query failed")
        .expect("session should exist");

    assert_eq!(retrieved.id, session.id);
    assert_eq!(retrieved.product_id, session.product_id);
    assert_eq!(retrieved.customer_id, session.customer_id);
    assert_eq!(retrieved.created_at, session.created_at);
    assert_eq!(retrieved.completed, session.completed);
    assert_eq!(retrieved.license_id, session.license_id);
}

#[test]
fn test_get_payment_session_nonexistent() {
    let conn = setup_test_db();

    let result = queries::get_payment_session(&conn, "ps_nonexistent")
        .expect("query should not error");
    assert!(result.is_none(), "nonexistent session should return None");
}

// ============ Payment Session CAS (Compare-and-Swap) Tests ============

#[test]
fn test_try_claim_payment_session_succeeds_once() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreatePaymentSession {
        product_id: product.id.clone(),
        customer_id: None,
    };
    let session = queries::create_payment_session(&conn, &input)
        .expect("create should succeed");

    // First claim should succeed
    let first_claim = queries::try_claim_payment_session(&conn, &session.id)
        .expect("try_claim should not error");
    assert!(first_claim, "first claim should return true");

    // Verify session is now marked completed
    let retrieved = queries::get_payment_session(&conn, &session.id)
        .expect("query failed")
        .expect("session should exist");
    assert!(retrieved.completed, "session should be completed after claim");

    // Second claim of the same session should fail
    let second_claim = queries::try_claim_payment_session(&conn, &session.id)
        .expect("try_claim should not error");
    assert!(!second_claim, "second claim should return false (already completed)");

    // Third claim should also fail -- idempotent rejection
    let third_claim = queries::try_claim_payment_session(&conn, &session.id)
        .expect("try_claim should not error");
    assert!(!third_claim, "third claim should also return false");
}

#[test]
fn test_try_claim_payment_session_nonexistent() {
    let conn = setup_test_db();

    // Claiming a session that doesn't exist should return false (0 rows affected)
    let result = queries::try_claim_payment_session(&conn, "ps_nonexistent")
        .expect("try_claim should not error");
    assert!(!result, "claiming nonexistent session should return false");
}

#[test]
fn test_try_claim_payment_session_concurrent() {
    // Verify CAS prevents double-claiming under concurrent access.
    // Multiple threads try to claim the same session -- exactly 1 should win.

    use std::sync::{Arc, Barrier};

    let num_threads = 5;
    let db_path = format!(
        "/tmp/claude/test_claim_concurrent_{}.db",
        uuid::Uuid::new_v4()
    );

    let conn = Connection::open(&db_path).expect("Failed to create test db");
    init_db(&conn).expect("Failed to init schema");

    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    let input = CreatePaymentSession {
        product_id: product.id.clone(),
        customer_id: None,
    };
    let session = queries::create_payment_session(&conn, &input)
        .expect("create should succeed");
    let session_id = session.id.clone();

    drop(conn);

    let barrier = Arc::new(Barrier::new(num_threads));
    let db_path_arc = Arc::new(db_path.clone());

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let db_path = Arc::clone(&db_path_arc);
            let session_id = session_id.clone();

            std::thread::spawn(move || {
                let thread_conn =
                    Connection::open(db_path.as_str()).expect("thread failed to open db");
                thread_conn
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .expect("failed to set busy timeout");

                barrier.wait();

                queries::try_claim_payment_session(&thread_conn, &session_id)
                    .expect("try_claim should not error")
            })
        })
        .collect();

    let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let claim_count = results.iter().filter(|&&r| r).count();

    assert_eq!(
        claim_count, 1,
        "exactly 1 of {} concurrent claims should succeed, got {}",
        num_threads, claim_count
    );

    // Verify DB state
    let verify_conn = Connection::open(&db_path).expect("failed to open db for verification");
    let session = queries::get_payment_session(&verify_conn, &session_id)
        .expect("query failed")
        .expect("session should exist");
    assert!(session.completed, "session should be completed");

    std::fs::remove_file(&db_path).ok();
}

// ============ Payment Session License Linking Tests ============

#[test]
fn test_set_payment_session_license() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));

    let input = CreatePaymentSession {
        product_id: product.id.clone(),
        customer_id: None,
    };
    let session = queries::create_payment_session(&conn, &input)
        .expect("create should succeed");

    // Claim the session first (as a webhook would)
    let claimed = queries::try_claim_payment_session(&conn, &session.id)
        .expect("claim should not error");
    assert!(claimed);

    // Link the license to the session
    queries::set_payment_session_license(&conn, &session.id, &license.id)
        .expect("set_payment_session_license should succeed");

    // Verify the link
    let retrieved = queries::get_payment_session(&conn, &session.id)
        .expect("query failed")
        .expect("session should exist");
    assert_eq!(
        retrieved.license_id,
        Some(license.id.clone()),
        "license_id should be set on session"
    );
    assert!(retrieved.completed, "session should still be completed");
}

// ============ Payment Session Purge Tests ============

#[test]
fn test_purge_old_payment_sessions() {
    let conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");

    // Create 3 sessions
    let mk_session = |cid: &str| {
        let input = CreatePaymentSession {
            product_id: product.id.clone(),
            customer_id: Some(cid.to_string()),
        };
        queries::create_payment_session(&conn, &input).expect("create should succeed")
    };

    let old_completed = mk_session("completed-old");
    let old_incomplete = mk_session("incomplete-old");
    let recent_incomplete = mk_session("incomplete-recent");

    // Claim the old_completed session so it's completed=1
    queries::try_claim_payment_session(&conn, &old_completed.id)
        .expect("claim should succeed");

    // Set created_at to 2 hours ago for the two "old" sessions
    let two_hours_ago = now() - (2 * 3600);
    conn.execute(
        "UPDATE payment_sessions SET created_at = ?1 WHERE id = ?2",
        rusqlite::params![two_hours_ago, &old_completed.id],
    )
    .expect("failed to set timestamp");
    conn.execute(
        "UPDATE payment_sessions SET created_at = ?1 WHERE id = ?2",
        rusqlite::params![two_hours_ago, &old_incomplete.id],
    )
    .expect("failed to set timestamp");

    // recent_incomplete keeps its current timestamp (just created)

    // Purge with 1-hour retention (= 1/24 of a day)
    // Since purge_old_payment_sessions takes days, 1 hour = set cutoff appropriately.
    // The function calculates: cutoff = now() - (retention_days * 86400)
    // For 1 hour: we need retention_days such that retention_days * 86400 < 2 * 3600
    // That means retention_days < 2/24 ≈ 0.083
    // But it takes i64, so we can't use fractions. Instead, we set created_at further back.
    // Let's set the old sessions to 2 days ago and purge with 1 day retention.
    let two_days_ago = now() - (2 * 86400);
    conn.execute(
        "UPDATE payment_sessions SET created_at = ?1 WHERE id = ?2",
        rusqlite::params![two_days_ago, &old_completed.id],
    )
    .expect("failed to set timestamp");
    conn.execute(
        "UPDATE payment_sessions SET created_at = ?1 WHERE id = ?2",
        rusqlite::params![two_days_ago, &old_incomplete.id],
    )
    .expect("failed to set timestamp");

    let purged = queries::purge_old_payment_sessions(&conn, 1)
        .expect("purge should succeed");

    // Only the old INCOMPLETE session should be purged.
    // The old completed session survives (completed sessions are kept).
    // The recent incomplete session survives (too new).
    assert_eq!(purged, 1, "only 1 old incomplete session should be purged");

    // Verify which sessions remain
    let completed_still_exists = queries::get_payment_session(&conn, &old_completed.id)
        .expect("query failed");
    assert!(
        completed_still_exists.is_some(),
        "old completed session should survive purge"
    );

    let incomplete_old_gone = queries::get_payment_session(&conn, &old_incomplete.id)
        .expect("query failed");
    assert!(
        incomplete_old_gone.is_none(),
        "old incomplete session should be purged"
    );

    let recent_still_exists = queries::get_payment_session(&conn, &recent_incomplete.id)
        .expect("query failed");
    assert!(
        recent_still_exists.is_some(),
        "recent incomplete session should survive purge"
    );
}

#[test]
fn test_purge_payment_sessions_returns_zero_when_nothing_to_purge() {
    let conn = setup_test_db();

    let purged = queries::purge_old_payment_sessions(&conn, 1)
        .expect("purge should succeed");
    assert_eq!(purged, 0, "nothing to purge on empty table");
}

// ============ Webhook Event Deduplication Tests ============

#[test]
fn test_try_record_webhook_event_new() {
    let conn = setup_test_db();

    let result = queries::try_record_webhook_event(&conn, "stripe", "evt_123")
        .expect("try_record should not error");
    assert!(result, "first recording of an event should return true");
}

#[test]
fn test_try_record_webhook_event_duplicate() {
    let conn = setup_test_db();

    let first = queries::try_record_webhook_event(&conn, "stripe", "evt_123")
        .expect("try_record should not error");
    assert!(first, "first recording should return true");

    let second = queries::try_record_webhook_event(&conn, "stripe", "evt_123")
        .expect("try_record should not error");
    assert!(!second, "duplicate recording should return false");

    // Third attempt should also be rejected
    let third = queries::try_record_webhook_event(&conn, "stripe", "evt_123")
        .expect("try_record should not error");
    assert!(!third, "third recording should also return false");
}

#[test]
fn test_try_record_webhook_event_same_id_different_provider() {
    let conn = setup_test_db();

    let stripe = queries::try_record_webhook_event(&conn, "stripe", "evt_123")
        .expect("try_record should not error");
    assert!(stripe, "stripe event should succeed");

    // Same event_id but different provider should be treated as a separate event
    let lemon = queries::try_record_webhook_event(&conn, "lemonsqueezy", "evt_123")
        .expect("try_record should not error");
    assert!(
        lemon,
        "same event_id with different provider should succeed (composite PK)"
    );
}

#[test]
fn test_try_record_webhook_event_different_id_same_provider() {
    let conn = setup_test_db();

    let first = queries::try_record_webhook_event(&conn, "stripe", "evt_001")
        .expect("try_record should not error");
    assert!(first);

    let second = queries::try_record_webhook_event(&conn, "stripe", "evt_002")
        .expect("try_record should not error");
    assert!(second, "different event_ids from same provider should both succeed");
}

// ============ Webhook Event Purge Tests ============

#[test]
fn test_purge_old_webhook_events() {
    let conn = setup_test_db();

    // Record 3 events
    queries::try_record_webhook_event(&conn, "stripe", "evt_old_1")
        .expect("record should succeed");
    queries::try_record_webhook_event(&conn, "stripe", "evt_old_2")
        .expect("record should succeed");
    queries::try_record_webhook_event(&conn, "lemonsqueezy", "evt_recent")
        .expect("record should succeed");

    // Set 2 of them to 2 days ago
    let two_days_ago = now() - (2 * 86400);
    conn.execute(
        "UPDATE webhook_events SET created_at = ?1 WHERE event_id IN ('evt_old_1', 'evt_old_2')",
        rusqlite::params![two_days_ago],
    )
    .expect("failed to set timestamps");

    // Purge with 1-day retention
    let purged = queries::purge_old_webhook_events(&conn, 1)
        .expect("purge should succeed");
    assert_eq!(purged, 2, "2 old events should be purged");

    // The recent event should still be dedup-blocked
    let retry_recent = queries::try_record_webhook_event(&conn, "lemonsqueezy", "evt_recent")
        .expect("try_record should not error");
    assert!(!retry_recent, "recent event should still exist and block duplicates");

    // The purged events can now be re-recorded (dedup window expired)
    let re_record = queries::try_record_webhook_event(&conn, "stripe", "evt_old_1")
        .expect("try_record should not error");
    assert!(
        re_record,
        "purged event should be re-recordable (dedup window has passed)"
    );
}

#[test]
fn test_purge_webhook_events_returns_zero_when_nothing_to_purge() {
    let conn = setup_test_db();

    let purged = queries::purge_old_webhook_events(&conn, 1)
        .expect("purge should succeed");
    assert_eq!(purged, 0, "nothing to purge on empty table");
}
