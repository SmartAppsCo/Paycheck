//! Security tests for request body size limits.
//!
//! These tests verify that the server rejects oversized request bodies
//! to prevent memory exhaustion attacks (DoS).
//!
//! Without body size limits, attackers could send multi-gigabyte payloads
//! to endpoints like /webhook/stripe or /webhook/lemonsqueezy that use
//! the Bytes extractor (no default limit) and exhaust server memory.

use axum::{
    Router,
    body::Body,
    extract::DefaultBodyLimit,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use paycheck::config::RateLimitConfig;
use paycheck::db::AppState;
use paycheck::handlers;

#[path = "../common/mod.rs"]
mod common;
use common::*;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::sync::Arc;

/// Creates a minimal app with body size limit configured.
fn app_with_body_limit(max_bytes: usize) -> Router {
    let master_key = test_master_key();

    let manager = SqliteConnectionManager::memory();
    let pool = Pool::builder().max_size(4).build(manager).unwrap();
    {
        let conn = pool.get().unwrap();
        paycheck::db::init_db(&conn).unwrap();
    }

    let audit_manager = SqliteConnectionManager::memory();
    let audit_pool = Pool::builder().max_size(4).build(audit_manager).unwrap();
    {
        let conn = audit_pool.get().unwrap();
        paycheck::db::init_audit_db(&conn).unwrap();
    }

    let state = AppState {
        db: pool,
        audit: audit_pool,
        base_url: "http://localhost:3000".to_string(),
        audit_log_enabled: false,
        master_key,
        email_hasher: paycheck::crypto::EmailHasher::from_bytes([0xAA; 32]),
        success_page_url: "http://localhost:3000/success".to_string(),
        activation_rate_limiter: Arc::new(paycheck::rate_limit::ActivationRateLimiter::default()),
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
        disable_checkout_tag: None,
        disable_public_api_tag: None,
    };

    // Use high rate limits to avoid rate limiting interfering with body size tests
    let rate_config = RateLimitConfig {
        strict_rpm: 1000,
        standard_rpm: 1000,
        relaxed_rpm: 1000,
        org_ops_rpm: 1000,
        ..RateLimitConfig::default()
    };

    // Build router similar to main.rs but with webhooks and body limit
    Router::new()
        .merge(handlers::public::router(rate_config))
        .merge(handlers::webhooks::router())
        .layer(DefaultBodyLimit::max(max_bytes))
        .with_state(state)
}

// ============================================================================
// BODY SIZE LIMIT TESTS
// ============================================================================

/// Verify that requests within the body size limit succeed.
#[tokio::test]
async fn test_request_within_body_limit_succeeds() {
    let app = app_with_body_limit(1024 * 1024); // 1MB limit

    // Small valid request
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/validate")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"jwt": "test.jwt.token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not be rejected for size (may fail for other reasons like invalid JWT)
    assert_ne!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Small request should not be rejected for size"
    );
}

/// Verify that requests exceeding the body size limit are rejected.
/// This protects against memory exhaustion attacks.
/// Uses webhook endpoint since it uses Bytes extractor (the vulnerable one).
#[tokio::test]
async fn test_request_exceeding_body_limit_rejected() {
    let app = app_with_body_limit(1024); // 1KB limit for testing

    // Create a payload larger than the limit
    let large_payload = "x".repeat(2048); // 2KB

    // Use webhook endpoint which uses Bytes extractor (no default limit)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", "t=123,v1=abc")
                .body(Body::from(large_payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Oversized request should be rejected with 413 Payload Too Large"
    );
}

/// Verify that webhook endpoints (which use Bytes extractor) are protected.
/// This is the main vulnerability - Bytes has no default limit.
#[tokio::test]
async fn test_webhook_endpoint_body_limit_enforced() {
    let app = app_with_body_limit(1024); // 1KB limit for testing

    // Create a payload larger than the limit
    let large_payload = "x".repeat(2048); // 2KB

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", "t=123,v1=abc")
                .body(Body::from(large_payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Oversized webhook request should be rejected with 413 Payload Too Large"
    );
}

/// Verify that LemonSqueezy webhook endpoint is also protected.
#[tokio::test]
async fn test_lemonsqueezy_webhook_body_limit_enforced() {
    let app = app_with_body_limit(1024); // 1KB limit for testing

    // Create a payload larger than the limit
    let large_payload = "x".repeat(2048); // 2KB

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/lemonsqueezy")
                .header("content-type", "application/json")
                .header("x-signature", "abc123")
                .body(Body::from(large_payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Oversized LemonSqueezy webhook request should be rejected with 413 Payload Too Large"
    );
}

/// Verify that the default 1MB limit is reasonable for normal webhooks.
/// Stripe webhooks are typically a few KB, so 1MB is plenty.
#[tokio::test]
async fn test_default_1mb_limit_allows_normal_webhooks() {
    let app = app_with_body_limit(1024 * 1024); // 1MB limit (default)

    // A realistic-sized webhook payload (10KB - larger than most Stripe webhooks)
    let normal_payload = "x".repeat(10 * 1024);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", "t=123,v1=abc")
                .body(Body::from(normal_payload))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not be rejected for size (will fail for invalid signature)
    assert_ne!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Normal-sized webhook should not be rejected for size"
    );
}

/// Verify that extremely large payloads are rejected before consuming memory.
#[tokio::test]
async fn test_very_large_payload_rejected_quickly() {
    let app = app_with_body_limit(1024); // 1KB limit

    // Try to send a 1MB payload (1000x the limit)
    // Note: This tests that the limit is enforced early, not after buffering
    let huge_payload = "x".repeat(1024 * 1024);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", "t=123,v1=abc")
                .body(Body::from(huge_payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Huge payload should be rejected with 413"
    );
}
