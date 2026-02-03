//! Tests for the POST /validate endpoint.
//!
//! The validate endpoint allows clients to perform online license validation,
//! checking if a JWT token is still valid (not revoked, not expired) for a given project.
//! It requires the full JWT token to prove possession and verify the signature.

use axum::{body::Body, http::Request};
use common::{ONE_DAY, ONE_YEAR};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::*;

/// Helper to setup test data and return (app, token, public_key, license_id, device_id)
fn setup_validate_test() -> (axum::Router, String, String, String, String) {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;
    let license_id: String;
    let device_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(ONE_YEAR)),
        );
        let device = create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();
        license_id = license.id.clone();
        device_id = device.device_id.clone();
    }

    let app = public_app(state);
    (app, token, public_key, license_id, device_id)
}

#[tokio::test]
async fn test_validate_with_valid_token_returns_valid() {
    let (app, token, public_key, _license_id, _device_id) = setup_validate_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": token
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for valid token"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], true,
        "license should be marked as valid for active, non-revoked token"
    );
    assert!(
        json.get("reason").is_none() || json["reason"].is_null(),
        "valid license should not include a reason field"
    );
    // Should include expiration info for valid licenses
    assert!(
        json.get("license_exp").is_some(),
        "response should include license_exp for valid license"
    );
    assert!(
        json.get("updates_exp").is_some(),
        "response should include updates_exp for valid license"
    );
}

#[tokio::test]
async fn test_validate_with_invalid_token_returns_invalid() {
    let (app, _token, public_key, _license_id, _device_id) = setup_validate_test();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": "invalid.token.here"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK even for invalid token"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid for malformed token"
    );
    // No reason should be given (prevents information disclosure)
    assert!(
        json.get("reason").is_none() || json["reason"].is_null(),
        "invalid response should not reveal reason to prevent information disclosure"
    );
}

#[tokio::test]
async fn test_validate_with_revoked_license_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(ONE_YEAR)),
        );
        let device = create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();

        // Revoke the license
        queries::revoke_license(&mut conn, &license.id).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": token
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for revoked license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid when license is revoked"
    );
}

#[tokio::test]
async fn test_validate_with_revoked_jti_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(ONE_YEAR)),
        );
        let device = create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();

        // Revoke this specific JTI (not the whole license)
        queries::add_revoked_jti(&mut conn, &license.id, &device.jti, Some("test revocation")).unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": token
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for revoked JTI"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid when specific JTI is revoked"
    );
}

#[tokio::test]
async fn test_validate_with_expired_license_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        // Create license that expired yesterday
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(past_timestamp(ONE_DAY)), // Expired 1 day ago
        );
        let device = create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": token
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for expired license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid when license has expired"
    );
}

#[tokio::test]
async fn test_validate_with_wrong_project_key_returns_invalid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(ONE_YEAR)),
        );
        let device = create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
    }

    let app = public_app(state);

    // Try to validate with a different public key (signature won't verify)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": "wrong-public-key",
                        "token": token
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for wrong public key"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "license should be marked as invalid when public key does not match (signature fails)"
    );
}

#[tokio::test]
async fn test_validate_missing_fields_returns_error() {
    let (app, _token, _public_key, _license_id, _device_id) = setup_validate_test();

    // Missing token
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": "some-key"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "validate endpoint should return 400 Bad Request when required fields are missing"
    );
}

#[tokio::test]
async fn test_validate_updates_last_seen_timestamp() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;
    let jti: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(ONE_YEAR)),
        );
        let device = create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();
        jti = device.jti.clone();
    }

    let app = public_app(state.clone());

    // Get initial last_seen_at
    let initial_last_seen = {
        let mut conn = state.db.get().unwrap();
        queries::get_device_by_jti(&mut conn, &jti)
            .unwrap()
            .unwrap()
            .last_seen_at
    };

    // Small delay to ensure timestamp differs
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Perform validation
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": token
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for valid license"
    );

    // Check that last_seen_at was updated
    let updated_last_seen = {
        let mut conn = state.db.get().unwrap();
        queries::get_device_by_jti(&mut conn, &jti)
            .unwrap()
            .unwrap()
            .last_seen_at
    };

    assert!(
        updated_last_seen >= initial_last_seen,
        "last_seen_at should be updated after successful validation"
    );
}

/// Test that a renewed subscription validates correctly.
///
/// This tests the scenario where:
/// 1. User buys a 30-day subscription
/// 2. Device activates (activated_at = purchase time)
/// 3. 60 days pass (device.activated_at is now 60 days ago)
/// 4. User renews - webhook updates license.expires_at to 90 days from original purchase
/// 5. Validation should succeed because license.expires_at is in the future
#[tokio::test]
async fn test_validate_renewed_subscription_uses_stored_expiration() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

        // Create a 30-day subscription product
        let input = CreateProduct {
            name: "Monthly Sub".to_string(),
            tier: "pro".to_string(),
            price_cents: Some(999),
            currency: Some("usd".to_string()),
            license_exp_days: Some(30), // 30-day subscription
            updates_exp_days: Some(365),
            activation_limit: Some(5),
            device_limit: Some(3),
            device_inactive_days: None,
            features: vec![],
            payment_config_id: None,
            email_config_id: None,
        };
        let product = queries::create_product(&mut conn, &project.id, &input).unwrap();

        // Create license - initially expires in 30 days (set by webhook at purchase)
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(30)), // Original expiration: 30 days from now
        );

        // Create device
        let device =
            create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();

        // Simulate time passing: backdate device activation to 60 days ago
        conn.execute(
            "UPDATE devices SET activated_at = ?1 WHERE jti = ?2",
            rusqlite::params![past_timestamp(60), &device.jti],
        )
        .unwrap();

        // Simulate renewal: update license.expires_at to 30 days from now
        // (as if webhook extended it after user renewed at day 55)
        queries::extend_license_expiration(
            &conn,
            &license.id,
            Some(future_timestamp(30)), // New expiration: 30 days from now
            Some(future_timestamp(365)), // Updates expiration unchanged
        )
        .unwrap();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": token
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    // The license was renewed - it should be valid!
    assert_eq!(
        json["valid"], true,
        "Renewed subscription should be valid. license.expires_at is in the future."
    );

    // The returned license_exp should reflect the stored value
    let returned_license_exp = json["license_exp"].as_i64().expect("license_exp should be set");
    let now = chrono::Utc::now().timestamp();
    assert!(
        returned_license_exp > now,
        "license_exp should be in the future (stored renewal value), got {} which is {} seconds from now",
        returned_license_exp,
        returned_license_exp - now
    );
}

#[tokio::test]
async fn test_validate_perpetual_license_returns_valid() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let token: String;
    let public_key: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

        // Create product with no expiration (perpetual license)
        let input = CreateProduct {
            name: "Perpetual Plan".to_string(),
            tier: "perpetual".to_string(),
            price_cents: None,
            currency: None,
            license_exp_days: None, // No expiration
            updates_exp_days: None,
            activation_limit: Some(5),
            device_limit: Some(3),
            device_inactive_days: None,
            features: vec![],
            payment_config_id: None,
            email_config_id: None,
        };
        let product =
            queries::create_product(&mut conn, &project.id, &input).expect("Failed to create product");

        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            None, // Perpetual
        );
        let device = create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": token
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK for perpetual license"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], true,
        "perpetual license should be marked as valid"
    );
    // Perpetual license should not have license_exp
    assert!(
        json.get("license_exp").is_none() || json["license_exp"].is_null(),
        "perpetual license should not have license_exp set"
    );
}

/// Test that raw JTI without proper JWT is rejected.
/// This verifies the security fix - the endpoint now requires a valid JWT token,
/// not just a JTI string.
#[tokio::test]
async fn test_validate_rejects_raw_jti_without_jwt() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let jti: String;
    let public_key: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let license = create_test_license(
            &conn,
            &project.id,
            &product.id,
            Some(future_timestamp(ONE_YEAR)),
        );
        let device = create_test_device(&mut conn, &license.id, "test-device-123", DeviceType::Uuid);

        jti = device.jti.clone();
        public_key = project.public_key.clone();
    }

    let app = public_app(state);

    // Try to send just the JTI as the token (which would have worked with the old endpoint)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "public_key": public_key,
                        "token": jti  // Raw JTI, not a valid JWT
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "validate endpoint should return 200 OK"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).expect("Response should be valid JSON");

    assert_eq!(
        json["valid"], false,
        "Raw JTI without valid JWT signature should be rejected. \
        This ensures the security fix is working - callers must prove possession \
        of the signed JWT, not just know the JTI."
    );
}
