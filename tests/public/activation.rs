//! Tests for the POST /activation/request-code endpoint:
//! Request activation codes to be sent to the purchase email.

use axum::{body::Body, http::Request};
use serde_json::json;
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::*;

// ============================================================================
// Expired License Handling
// ============================================================================

/// Verify expired licenses do NOT receive activation codes.
///
/// Without this protection, users with expired licenses would:
/// 1. Request activation code → succeeds (code created and emailed)
/// 2. Try to redeem → fails with generic "cannot be redeemed" error
/// 3. Be confused why a valid-looking code doesn't work
///
/// The `get_licenses_by_email_hash` query filters expired licenses:
/// ```sql
/// AND (expires_at IS NULL OR expires_at > unixepoch())
/// ```
///
/// This test verifies that:
/// 1. An expired license exists in the database
/// 2. Requesting an activation code returns 200 OK (email enumeration protection)
/// 3. No activation code is actually created for the expired license
#[tokio::test]
async fn test_expired_license_should_not_receive_activation_code() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let email = "expired@example.com";
    let license_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        // Create an EXPIRED license
        let input = CreateLicense {
            email_hash: Some(test_email_hasher().hash(email)),
            customer_id: Some("test-customer".to_string()),
            expires_at: Some(past_timestamp(ONE_DAY)), // Expired yesterday
            updates_expires_at: Some(past_timestamp(ONE_DAY)),
        };
        let license = queries::create_license(&conn, &project.id, &product.id, &input)
            .expect("Failed to create expired license");

        public_key = project.public_key.clone();
        license_id = license.id.clone();
    }

    let app = public_app(state.clone());

    // Request activation code for expired license
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/activation/request-code")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "email": email,
                        "public_key": public_key
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Response is always 200 (to prevent email enumeration)
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Check if an activation code was created (it shouldn't be for expired licenses)
    let conn = state.db.get().unwrap();

    // Check directly using license_id since get_licenses_by_email_hash filters expired
    let code_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM activation_codes WHERE license_id = ? AND used = 0",
            [&license_id],
            |row| row.get(0),
        )
        .unwrap();

    // Expired licenses should NOT receive activation codes
    assert_eq!(
        code_count, 0,
        "Expired licenses should NOT receive activation codes. Found {} codes",
        code_count
    );
}

/// Verify the full confusing user journey: expired license gets code, redeem fails.
///
/// This test documents the current buggy behavior and will fail after the fix
/// because the activation code won't be created in the first place.
#[tokio::test]
async fn test_expired_license_activation_code_cannot_be_redeemed() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let code: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        // Create an EXPIRED license
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(past_timestamp(ONE_DAY)), // Expired yesterday
        );

        // Directly create activation code (simulating what the handler does for expired licenses)
        let activation_code =
            queries::create_activation_code(&mut conn, &license.id, &project.license_key_prefix)
                .unwrap();

        public_key = project.public_key.clone();
        code = activation_code.code.clone();
    }

    let app = public_app(state);

    // Try to redeem - should fail because license is expired
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/redeem")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "code": code,
                        "device_id": "test-device",
                        "device_type": "uuid"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Redemption fails for expired license (this part is correct)
    assert_eq!(
        response.status(),
        axum::http::StatusCode::FORBIDDEN,
        "redeeming code for expired license should return FORBIDDEN"
    );
}

// ============================================================================
// Valid Activation Code Request Tests
// ============================================================================

#[tokio::test]
async fn test_valid_license_can_request_activation_code() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let email = "valid@example.com";

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        // Create a valid (non-expired) license
        let input = CreateLicense {
            email_hash: Some(test_email_hasher().hash(email)),
            customer_id: Some("test-customer".to_string()),
            expires_at: Some(future_timestamp(ONE_YEAR)),
            updates_expires_at: Some(future_timestamp(ONE_YEAR)),
        };
        queries::create_license(&conn, &project.id, &product.id, &input)
            .expect("Failed to create license");

        public_key = project.public_key.clone();
    }

    let app = public_app(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/activation/request-code")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "email": email,
                        "public_key": public_key
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify activation code was created
    let conn = state.db.get().unwrap();
    let email_hash = test_email_hasher().hash(email);
    let project = queries::get_project_by_public_key(&conn, &public_key)
        .unwrap()
        .unwrap();
    let licenses = queries::get_licenses_by_email_hash(&conn, &project.id, &email_hash).unwrap();
    let license = &licenses[0];

    let code_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM activation_codes WHERE license_id = ? AND used = 0",
            [&license.id],
            |row| row.get(0),
        )
        .unwrap();

    assert!(
        code_count > 0,
        "Valid license should receive activation code"
    );
}

#[tokio::test]
async fn test_revoked_license_should_not_receive_activation_code() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let email = "revoked@example.com";

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        // Create a license and then revoke it
        let input = CreateLicense {
            email_hash: Some(test_email_hasher().hash(email)),
            customer_id: Some("test-customer".to_string()),
            expires_at: Some(future_timestamp(ONE_YEAR)),
            updates_expires_at: Some(future_timestamp(ONE_YEAR)),
        };
        let license = queries::create_license(&conn, &project.id, &product.id, &input)
            .expect("Failed to create license");

        // Revoke the license
        queries::revoke_license(&mut conn, &license.id).unwrap();

        public_key = project.public_key.clone();
    }

    let app = public_app(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/activation/request-code")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "email": email,
                        "public_key": public_key
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify NO activation code was created for revoked license
    let conn = state.db.get().unwrap();
    let email_hash = test_email_hasher().hash(email);
    let project = queries::get_project_by_public_key(&conn, &public_key)
        .unwrap()
        .unwrap();
    let licenses = queries::get_licenses_by_email_hash(&conn, &project.id, &email_hash).unwrap();

    // The query should filter out revoked licenses, so we shouldn't find any
    // OR if we do find the license, there should be no codes
    if !licenses.is_empty() {
        let license = &licenses[0];
        let code_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM activation_codes WHERE license_id = ? AND used = 0",
                [&license.id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(
            code_count, 0,
            "Revoked license should NOT receive activation codes"
        );
    }
}

#[tokio::test]
async fn test_perpetual_license_can_request_activation_code() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;
    let email = "perpetual@example.com";

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        // Create a perpetual license (no expiration)
        let input = CreateLicense {
            email_hash: Some(test_email_hasher().hash(email)),
            customer_id: Some("test-customer".to_string()),
            expires_at: None, // Perpetual!
            updates_expires_at: Some(future_timestamp(ONE_YEAR)),
        };
        queries::create_license(&conn, &project.id, &product.id, &input)
            .expect("Failed to create perpetual license");

        public_key = project.public_key.clone();
    }

    let app = public_app(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/activation/request-code")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "email": email,
                        "public_key": public_key
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify activation code was created for perpetual license
    let conn = state.db.get().unwrap();
    let email_hash = test_email_hasher().hash(email);
    let project = queries::get_project_by_public_key(&conn, &public_key)
        .unwrap()
        .unwrap();
    let licenses = queries::get_licenses_by_email_hash(&conn, &project.id, &email_hash).unwrap();
    let license = &licenses[0];

    let code_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM activation_codes WHERE license_id = ? AND used = 0",
            [&license.id],
            |row| row.get(0),
        )
        .unwrap();

    assert!(
        code_count > 0,
        "Perpetual license should receive activation code"
    );
}

#[tokio::test]
async fn test_nonexistent_email_returns_same_response() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let public_key: String;

    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    // Request with email that has no license
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/activation/request-code")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "email": "nonexistent@example.com",
                        "public_key": public_key
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 200 with same message (email enumeration protection)
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("If a license exists"),
        "Response should contain generic message"
    );
}
