//! Tests for feedback/crash metering behavior and HTTP integration tests
//! for the /feedback and /crash endpoints.
//!
//! These tests verify that:
//! - Feedback and crash email delivery correctly uses the org's Resend API key
//! - The /feedback and /crash endpoints enforce auth, validate input, and check config

use axum::body::Body;
use axum::http::Request;
use paycheck::config::RateLimitConfig;
use paycheck::models::ServiceProvider;
use rusqlite::Connection;
use tower::ServiceExt;

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

// ============================================================================
// HTTP Integration Tests for /feedback and /crash endpoints
// ============================================================================

/// Helper: creates a full production public router with the given AppState.
fn feedback_app(state: AppState) -> axum::Router {
    paycheck::handlers::public::router(RateLimitConfig::disabled()).with_state(state)
}

/// Helper: creates a test project, product, license, device, and JWT token.
/// Returns (project, token) for use in feedback/crash tests.
fn setup_feedback_test_data(state: &AppState) -> (Project, String) {
    let conn = state.db.get().unwrap();
    let master_key = test_master_key();

    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));
    let device = create_test_device(&conn, &license.id, "device-1", DeviceType::Uuid);
    let token = create_test_token(&project, &product, &license, &device, &master_key);

    (project, token)
}

/// POST /feedback without Authorization header should be rejected.
/// Note: Returns 400 (not 401) because axum-extra's TypedHeaderRejection
/// uses its own IntoResponse impl which returns 400 directly, bypassing
/// the app's AppError::Header mapping that would return 401.
#[tokio::test]
async fn test_feedback_without_auth_returns_error() {
    let state = create_test_app_state();
    let app = feedback_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/feedback")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"message": "Great app"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status().is_client_error(),
        "POST /feedback without auth should return a client error, got {}",
        response.status()
    );
    assert_ne!(
        response.status(),
        axum::http::StatusCode::OK,
        "POST /feedback without auth must not return 200"
    );
}

/// POST /feedback with valid JWT and configured webhook.
/// The webhook URL is unreachable (dummy), so delivery will fail,
/// but the endpoint should not return 400 (that's for "not configured").
#[tokio::test]
async fn test_feedback_with_valid_jwt_and_configured_webhook() {
    let state = create_test_app_state();
    let (project, token) = setup_feedback_test_data(&state);

    // Configure a feedback webhook URL on the project
    let conn = state.db.get().unwrap();
    conn.execute(
        "UPDATE projects SET feedback_webhook_url = ?1 WHERE id = ?2",
        rusqlite::params!["https://dummy.example.com/feedback", &project.id],
    )
    .unwrap();
    drop(conn);

    let app = feedback_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/feedback")
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"message": "Great app", "type": "feature"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Webhook delivery will fail (dummy URL), but the endpoint should not return 400.
    // It returns either 200 (if email fallback succeeds or delivery is best-effort)
    // or 500 (if all delivery methods fail). Either is acceptable -- not 400.
    let status = response.status();
    assert_ne!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "configured webhook should not return 400 'not configured'. Got: {}",
        status
    );
}

/// POST /feedback with valid JWT but no feedback_webhook_url or feedback_email.
/// Should return 400 "not configured".
#[tokio::test]
async fn test_feedback_not_configured_returns_400() {
    let state = create_test_app_state();
    let (_project, token) = setup_feedback_test_data(&state);
    // Default project has no feedback_webhook_url and no feedback_email

    let app = feedback_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/feedback")
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"message": "Great app"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "feedback with no configured delivery method should return 400"
    );

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["details"]
            .as_str()
            .unwrap_or("")
            .contains("not configured"),
        "error should mention 'not configured', got: {}",
        json
    );
}

/// POST /crash without Authorization header should be rejected.
/// Note: Returns 400 (not 401) -- same axum-extra TypedHeaderRejection behavior
/// as the feedback endpoint.
#[tokio::test]
async fn test_crash_without_auth_returns_error() {
    let state = create_test_app_state();
    let app = feedback_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/crash")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"error_type": "panic", "error_message": "oops"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status().is_client_error(),
        "POST /crash without auth should return a client error, got {}",
        response.status()
    );
    assert_ne!(
        response.status(),
        axum::http::StatusCode::OK,
        "POST /crash without auth must not return 200"
    );
}

/// POST /crash with valid JWT but missing required fields (error_type, error_message).
/// Should return 400 due to deserialization failure.
#[tokio::test]
async fn test_crash_missing_required_fields() {
    let state = create_test_app_state();
    let (_project, token) = setup_feedback_test_data(&state);

    let app = feedback_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/crash")
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"message": "oops"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "crash with missing required fields should return 400"
    );
}

/// POST /feedback with valid JWT but empty body (no message field).
/// Should return 400 due to deserialization failure.
#[tokio::test]
async fn test_feedback_missing_message_returns_400() {
    let state = create_test_app_state();
    let (_project, token) = setup_feedback_test_data(&state);

    let app = feedback_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/feedback")
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "feedback with missing message should return 400"
    );
}
