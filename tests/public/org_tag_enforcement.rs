//! Tests for organization tag enforcement on public API endpoints.
//!
//! These tests verify that organizations can be disabled via tags, blocking
//! access to public API endpoints when configured via environment variables.
//!
//! Two levels of disabling:
//! - `disable_checkout_tag`: Blocks POST /buy only
//! - `disable_public_api_tag`: Blocks /buy, /validate, /activation/request-code, /refresh

use axum::{body::Body, http::Request};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::*;

/// Create an AppState with custom tag enforcement configuration
fn create_app_state_with_tags(
    disable_checkout_tag: Option<String>,
    disable_public_api_tag: Option<String>,
) -> AppState {
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();
    {
        let conn = pool.get().unwrap();
        init_db(&conn).unwrap();
    }

    let audit_manager = SqliteConnectionManager::memory();
    let audit_pool = Pool::builder().max_size(4).build(audit_manager).unwrap();
    {
        let conn = audit_pool.get().unwrap();
        init_audit_db(&conn).unwrap();
    }

    AppState {
        db: pool,
        audit: audit_pool,
        base_url: "http://localhost:3000".to_string(),
        audit_log_enabled: false,
        master_key,
        email_hasher,
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: Arc::new(ActivationRateLimiter::default()),
        email_service: Arc::new(paycheck::email::EmailService::new(
            None,
            "test@example.com".to_string(),
        )),
        delivery_service: Arc::new(paycheck::feedback::DeliveryService::new(
            None,
            "test@example.com".to_string(),
        )),
        http_client: reqwest::Client::new(),
        metering_webhook_url: None,
        disable_checkout_tag,
        disable_public_api_tag,
    }
}

/// Helper to add tags to an org
fn add_tags_to_org(conn: &rusqlite::Connection, org_id: &str, tags: &[&str]) {
    let update = UpdateTags {
        add: tags.iter().map(|s| s.to_string()).collect(),
        remove: vec![],
    };
    queries::update_organization_tags(conn, org_id, &update).unwrap();
}

// ============ /buy endpoint tests ============

#[tokio::test]
async fn test_buy_blocked_when_org_has_checkout_disabled_tag() {
    let state = create_app_state_with_tags(Some("disabled_checkout".to_string()), None);
    let master_key = test_master_key();

    let product_id: String;
    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        product_id = product.id.clone();

        // Add the disabled_checkout tag to org
        add_tags_to_org(&conn, &org.id, &["disabled_checkout"]);
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "product_id": product_id
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "/buy should return 503 when org has checkout disabled tag"
    );
}

#[tokio::test]
async fn test_buy_blocked_when_org_has_public_api_disabled_tag() {
    let state = create_app_state_with_tags(None, Some("disabled_public_api".to_string()));
    let master_key = test_master_key();

    let product_id: String;
    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        product_id = product.id.clone();

        // Add the disabled_public_api tag to org
        add_tags_to_org(&conn, &org.id, &["disabled_public_api"]);
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "product_id": product_id
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "/buy should return 503 when org has public API disabled tag"
    );
}

#[tokio::test]
async fn test_buy_not_blocked_when_no_tags_configured() {
    // No tag configuration - should not block
    let state = create_app_state_with_tags(None, None);
    let master_key = test_master_key();

    let product_id: String;
    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        product_id = product.id.clone();

        // Add tags to org - but no env vars are set so they shouldn't matter
        add_tags_to_org(&conn, &org.id, &["disabled_checkout", "disabled_public_api"]);
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "product_id": product_id
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should NOT be 503 - tags are not configured in env vars
    // Will fail on "no payment provider" but that's expected
    assert_ne!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "/buy should NOT return 503 when no tag enforcement is configured"
    );
    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "/buy should fail on payment provider config, not tag enforcement"
    );
}

#[tokio::test]
async fn test_buy_not_blocked_when_org_does_not_have_tag() {
    let state = create_app_state_with_tags(
        Some("disabled_checkout".to_string()),
        Some("disabled_public_api".to_string()),
    );
    let master_key = test_master_key();

    let product_id: String;
    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
        product_id = product.id.clone();
        // Org has NO tags - should not be blocked
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/buy")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "product_id": product_id
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should NOT be 503 - org doesn't have the tag
    assert_ne!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "/buy should NOT return 503 when org does not have the tag"
    );
    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "/buy should fail on payment provider config, not tag enforcement"
    );
}

// ============ /validate endpoint tests ============

#[tokio::test]
async fn test_validate_blocked_when_org_has_public_api_disabled_tag() {
    let state = create_app_state_with_tags(None, Some("disabled_public_api".to_string()));
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
        let device = create_test_device(&mut conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();

        // Add the disabled_public_api tag to org
        add_tags_to_org(&conn, &org.id, &["disabled_public_api"]);
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
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "/validate should return 503 when org has public API disabled tag"
    );
}

#[tokio::test]
async fn test_validate_not_blocked_when_no_tags_configured() {
    let state = create_app_state_with_tags(None, None);
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
        let device = create_test_device(&mut conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();

        // Add tags to org - but no env vars are set so they shouldn't matter
        add_tags_to_org(&conn, &org.id, &["disabled_public_api"]);
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
        "/validate should return 200 when no tag enforcement is configured"
    );
}

#[tokio::test]
async fn test_validate_not_blocked_by_checkout_disabled_tag() {
    // checkout_disabled should NOT block /validate
    let state = create_app_state_with_tags(
        Some("disabled_checkout".to_string()),
        None, // No public API tag
    );
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
        let device = create_test_device(&mut conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);
        public_key = project.public_key.clone();

        // Add checkout disabled tag
        add_tags_to_org(&conn, &org.id, &["disabled_checkout"]);
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

    // checkout_disabled should NOT block /validate
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "/validate should NOT be blocked by checkout_disabled tag"
    );
}

// ============ /activation/request-code endpoint tests ============

#[tokio::test]
async fn test_activation_request_code_blocked_when_org_has_public_api_disabled_tag() {
    let state = create_app_state_with_tags(None, Some("disabled_public_api".to_string()));
    let master_key = test_master_key();

    let public_key: String;
    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        public_key = project.public_key.clone();

        // Add the disabled_public_api tag to org
        add_tags_to_org(&conn, &org.id, &["disabled_public_api"]);
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/activation/request-code")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "email": "test@example.com",
                        "public_key": public_key
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "/activation/request-code should return 503 when org has public API disabled tag"
    );
}

#[tokio::test]
async fn test_activation_request_code_not_blocked_when_no_tags_configured() {
    let state = create_app_state_with_tags(None, None);
    let master_key = test_master_key();

    let public_key: String;
    {
        let conn = state.db.get().unwrap();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        public_key = project.public_key.clone();

        // Add tags to org - but no env vars are set so they shouldn't matter
        add_tags_to_org(&conn, &org.id, &["disabled_public_api"]);
    }

    let app = public_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/activation/request-code")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "email": "test@example.com",
                        "public_key": public_key
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be OK (returns generic message regardless of license existence)
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "/activation/request-code should return 200 when no tag enforcement is configured"
    );
}

// ============ /refresh endpoint tests ============

#[tokio::test]
async fn test_refresh_blocked_when_org_has_public_api_disabled_tag() {
    let state = create_app_state_with_tags(None, Some("disabled_public_api".to_string()));
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
        let device = create_test_device(&mut conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);

        // Add the disabled_public_api tag to org
        add_tags_to_org(&conn, &org.id, &["disabled_public_api"]);
    }

    // Need to add refresh endpoint to the router
    use axum::routing::post;
    use paycheck::handlers::public::refresh_token;

    let app = axum::Router::new()
        .route("/refresh", post(refresh_token))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "/refresh should return 503 when org has public API disabled tag"
    );
}

#[tokio::test]
async fn test_refresh_not_blocked_when_no_tags_configured() {
    let state = create_app_state_with_tags(None, None);
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
        let device = create_test_device(&mut conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);

        // Add tags to org - but no env vars are set so they shouldn't matter
        add_tags_to_org(&conn, &org.id, &["disabled_public_api"]);
    }

    use axum::routing::post;
    use paycheck::handlers::public::refresh_token;

    let app = axum::Router::new()
        .route("/refresh", post(refresh_token))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "/refresh should return 200 when no tag enforcement is configured"
    );
}

#[tokio::test]
async fn test_refresh_not_blocked_by_checkout_disabled_tag() {
    // checkout_disabled should NOT block /refresh
    let state = create_app_state_with_tags(
        Some("disabled_checkout".to_string()),
        None, // No public API tag
    );
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
        let device = create_test_device(&mut conn, &license.id, "test-device", DeviceType::Uuid);

        token = create_test_token(&project, &product, &license, &device, &master_key);

        // Add checkout disabled tag
        add_tags_to_org(&conn, &org.id, &["disabled_checkout"]);
    }

    use axum::routing::post;
    use paycheck::handlers::public::refresh_token;

    let app = axum::Router::new()
        .route("/refresh", post(refresh_token))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/refresh")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // checkout_disabled should NOT block /refresh
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "/refresh should NOT be blocked by checkout_disabled tag"
    );
}
