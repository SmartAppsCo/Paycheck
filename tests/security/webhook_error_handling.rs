//! Security tests for webhook error handling.
//!
//! These tests verify that webhook endpoints handle configuration errors gracefully
//! without leaking internal state or causing retry storms from payment providers.

#[path = "../common/mod.rs"]
mod common;

use axum::{Router, body::Body, http::Request, routing::post};
use axum::body::to_bytes;
use axum::http::StatusCode;
use common::*;
use paycheck::handlers::webhooks::{handle_lemonsqueezy_webhook, handle_stripe_webhook};
use rusqlite::params;
use serde_json::json;
use tower::ServiceExt;

fn webhook_app(state: paycheck::db::AppState) -> Router {
    Router::new()
        .route("/webhook/stripe", post(handle_stripe_webhook))
        .route("/webhook/lemonsqueezy", post(handle_lemonsqueezy_webhook))
        .with_state(state)
}

/// Helper to set CORRUPTED Stripe config for an organization.
/// This simulates a scenario where encrypted data is corrupted (e.g., master key changed
/// but data wasn't re-encrypted, or database corruption).
fn setup_corrupted_stripe_config(conn: &rusqlite::Connection, org_id: &str) {
    // Create bytes that look like encrypted data (start with ENC1 magic) but will fail
    // AES-GCM decryption because the ciphertext is garbage
    let mut corrupted_bytes = Vec::new();
    corrupted_bytes.extend_from_slice(b"ENC1"); // Magic bytes
    corrupted_bytes.extend_from_slice(&[0u8; 12]); // Fake nonce (12 bytes)
    corrupted_bytes.extend_from_slice(b"corrupted_ciphertext_garbage_data"); // Invalid ciphertext

    // Insert a corrupted service config directly
    let config_id = format!("cfg_corrupted_stripe_{}", &org_id[..8]);
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO service_configs (id, org_id, name, category, provider, config_encrypted, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![&config_id, org_id, "Corrupted Stripe", "payment", "stripe", &corrupted_bytes, now, now],
    ).expect("Failed to insert corrupted config");

    // Set this as the org's payment config
    conn.execute(
        "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
        params![&config_id, org_id],
    ).expect("Failed to set org payment_config_id");
}

fn compute_stripe_signature(payload: &[u8], secret: &str, timestamp: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(signed_payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn current_timestamp() -> String {
    chrono::Utc::now().timestamp().to_string()
}

// ============ VULNERABILITY TEST ============

/// SECURITY TEST: Webhook with corrupted config should NOT return 500.
///
/// This test verifies a security issue where an organization with corrupted
/// payment provider configuration causes the webhook to return HTTP 500.
///
/// Why this is a problem:
/// 1. Payment providers (Stripe, LemonSqueezy) retry on 5xx errors indefinitely
/// 2. This creates a "retry storm" that wastes resources
/// 3. It leaks internal state (attacker can probe which orgs have broken configs)
/// 4. It distinguishes "config exists but is broken" from "no config" (info leak)
///
/// Expected behavior: Return 200 OK (or 401) so provider doesn't retry.
/// Current behavior (vulnerability): Returns 500 INTERNAL_SERVER_ERROR.
#[tokio::test]
async fn test_stripe_webhook_corrupted_config_should_not_return_500() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");

        // Set up CORRUPTED Stripe config - this is the key difference
        setup_corrupted_stripe_config(&mut conn, &org.id);

        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&mut conn, &product.id, None);

        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    // Create a valid-format webhook payload
    let payload = json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "payment_status": "paid",
                "customer": "cus_test",
                "subscription": "sub_test_123",
                "customer_details": {
                    "email": "test@example.com"
                },
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // Create a valid-looking signature (won't verify, but that's OK - we won't get that far)
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "any_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", signature_header)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();

    // THE VULNERABILITY: This currently returns 500, but should return 200 or 401
    // If this test PASSES (status != 500), the vulnerability has been fixed
    // If this test FAILS (status == 500), the vulnerability exists
    assert_ne!(
        status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "SECURITY VULNERABILITY: Webhook with corrupted config returns 500, \
         which causes payment providers to retry indefinitely and leaks internal state. \
         Should return 200 OK or 401 UNAUTHORIZED instead."
    );
}

/// Verify that a properly configured webhook works (control test).
/// This ensures our test setup is correct.
#[tokio::test]
async fn test_stripe_webhook_valid_config_works() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");

        // Set up VALID Stripe config
        setup_stripe_config(&mut conn, &org.id, &master_key);

        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&mut conn, &product.id, None);

        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    let payload = json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_123",
                "payment_status": "paid",
                "customer": "cus_test",
                "subscription": "sub_test_123",
                "customer_details": {
                    "email": "test@example.com"
                },
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // Use the correct webhook secret from setup_stripe_config
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", signature_header)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "Valid webhook with correct config should return 200 OK"
    );
}

// ============ LemonSqueezy Tests ============

/// Helper to set CORRUPTED LemonSqueezy config for an organization.
fn setup_corrupted_lemonsqueezy_config(conn: &rusqlite::Connection, org_id: &str) {
    let mut corrupted_bytes = Vec::new();
    corrupted_bytes.extend_from_slice(b"ENC1"); // Magic bytes
    corrupted_bytes.extend_from_slice(&[0u8; 12]); // Fake nonce (12 bytes)
    corrupted_bytes.extend_from_slice(b"corrupted_ciphertext_garbage_data"); // Invalid ciphertext

    // Insert a corrupted service config directly
    let config_id = format!("cfg_corrupted_ls_{}", &org_id[..8]);
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO service_configs (id, org_id, name, category, provider, config_encrypted, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![&config_id, org_id, "Corrupted LemonSqueezy", "payment", "lemonsqueezy", &corrupted_bytes, now, now],
    ).expect("Failed to insert corrupted config");

    // Set this as the org's payment config
    conn.execute(
        "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
        params![&config_id, org_id],
    ).expect("Failed to set org payment_config_id");
}

fn compute_lemonsqueezy_signature(payload: &[u8], secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// SECURITY TEST: LemonSqueezy webhook with corrupted config should NOT return 500.
#[tokio::test]
async fn test_lemonsqueezy_webhook_corrupted_config_should_not_return_500() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");

        // Set up CORRUPTED LemonSqueezy config
        setup_corrupted_lemonsqueezy_config(&mut conn, &org.id);

        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&mut conn, &product.id, None);

        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    // Create a valid-format LemonSqueezy webhook payload
    let payload = json!({
        "meta": {
            "event_name": "order_created",
            "custom_data": {
                "paycheck_session_id": session_id,
                "project_id": project_id
            }
        },
        "data": {
            "id": "12345",
            "attributes": {
                "first_order_item": {
                    "product_id": 123
                },
                "user_email": "test@example.com",
                "customer_id": 456,
                "status": "paid"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // Create a signature (won't verify, but we won't get that far)
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "any_secret");

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/lemonsqueezy")
                .header("content-type", "application/json")
                .header("x-signature", signature)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();

    assert_ne!(
        status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "SECURITY VULNERABILITY: LemonSqueezy webhook with corrupted config returns 500, \
         which causes payment providers to retry indefinitely and leaks internal state. \
         Should return 200 OK or 401 UNAUTHORIZED instead."
    );
}

// ============ Stripe Signature Verification Integration Tests ============

/// Helper: create a fully-configured Stripe webhook test environment.
/// Returns (state, session_id, project_id) ready for webhook calls.
fn setup_stripe_webhook_env() -> (paycheck::db::AppState, String, String) {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id;
    let project_id;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Webhook Org");
        setup_stripe_config(&mut conn, &org.id, &master_key);
        let project = create_test_project(&mut conn, &org.id, "Webhook Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&mut conn, &product.id, None);
        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    (state, session_id, project_id)
}

fn stripe_checkout_payload(session_id: &str, project_id: &str, cs_id: &str) -> Vec<u8> {
    let payload = json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": cs_id,
                "payment_status": "paid",
                "customer": "cus_test",
                "subscription": "sub_test_123",
                "customer_details": {
                    "email": "test@example.com"
                },
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    serde_json::to_vec(&payload).unwrap()
}

const STRIPE_WEBHOOK_SECRET: &str = "whsec_test123secret456";

#[tokio::test]
async fn test_stripe_invalid_signature_rejected() {
    let (state, session_id, project_id) = setup_stripe_webhook_env();
    let payload_bytes = stripe_checkout_payload(&session_id, &project_id, "cs_invalid_sig");

    // Sign with WRONG webhook secret
    let timestamp = current_timestamp();
    let bad_signature = compute_stripe_signature(&payload_bytes, "whsec_WRONG_secret", &timestamp);
    let sig_header = format!("t={},v1={}", timestamp, bad_signature);

    let app = webhook_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", sig_header)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not be 200 (which would mean the webhook was processed)
    // and should not be 500 (which would cause retries)
    let status = response.status();
    assert_ne!(
        status,
        StatusCode::OK,
        "webhook with wrong signature should NOT return 200 (would process forged event)"
    );
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "webhook with wrong signature should NOT return 500 (causes retry storms)"
    );
}

#[tokio::test]
async fn test_stripe_tampered_payload_rejected() {
    let (state, session_id, project_id) = setup_stripe_webhook_env();
    let payload_bytes = stripe_checkout_payload(&session_id, &project_id, "cs_tampered");

    // Sign the original payload correctly
    let timestamp = current_timestamp();
    let valid_signature =
        compute_stripe_signature(&payload_bytes, STRIPE_WEBHOOK_SECRET, &timestamp);
    let sig_header = format!("t={},v1={}", timestamp, valid_signature);

    // Tamper with the payload AFTER signing
    let mut tampered = payload_bytes.clone();
    if tampered.len() > 20 {
        tampered[20] ^= 0xFF;
    }

    let app = webhook_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", sig_header)
                .body(Body::from(tampered))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert_ne!(
        status,
        StatusCode::OK,
        "tampered payload should NOT be accepted (signature mismatch)"
    );
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "tampered payload should NOT return 500"
    );
}

#[tokio::test]
async fn test_stripe_replay_prevention() {
    let (state, session_id, project_id) = setup_stripe_webhook_env();
    let cs_id = "cs_replay_test_001";
    let payload_bytes = stripe_checkout_payload(&session_id, &project_id, cs_id);

    let timestamp = current_timestamp();
    let signature =
        compute_stripe_signature(&payload_bytes, STRIPE_WEBHOOK_SECRET, &timestamp);
    let sig_header = format!("t={},v1={}", timestamp, signature);

    // Send the first webhook -- should create a license
    let app = webhook_app(state.clone());
    let response1 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", &sig_header)
                .body(Body::from(payload_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response1.status(),
        StatusCode::OK,
        "first checkout webhook should succeed"
    );

    // Count licenses after first webhook
    let conn = state.db.get().unwrap();
    let count_after_first: i64 = conn
        .query_row("SELECT COUNT(*) FROM licenses", [], |row| row.get(0))
        .unwrap();

    drop(conn);

    // Send the exact same webhook again (replay)
    let app2 = webhook_app(state.clone());
    let response2 = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", &sig_header)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status2 = response2.status();
    assert_ne!(
        status2,
        StatusCode::INTERNAL_SERVER_ERROR,
        "replayed webhook should not cause 500"
    );

    // Verify: no duplicate licenses created
    let conn = state.db.get().unwrap();
    let count_after_second: i64 = conn
        .query_row("SELECT COUNT(*) FROM licenses", [], |row| row.get(0))
        .unwrap();

    assert_eq!(
        count_after_first, count_after_second,
        "replay should NOT create a duplicate license (CAS on payment session prevents it)"
    );
}

#[tokio::test]
async fn test_stripe_old_timestamp_rejected() {
    let (state, session_id, project_id) = setup_stripe_webhook_env();
    let payload_bytes = stripe_checkout_payload(&session_id, &project_id, "cs_old_ts");

    // Use a timestamp from 10 minutes ago (Stripe tolerance is 5 minutes)
    let old_timestamp = (chrono::Utc::now().timestamp() - 600).to_string();
    let signature =
        compute_stripe_signature(&payload_bytes, STRIPE_WEBHOOK_SECRET, &old_timestamp);
    let sig_header = format!("t={},v1={}", old_timestamp, signature);

    let app = webhook_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", sig_header)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert_ne!(
        status,
        StatusCode::OK,
        "webhook with 10-minute old timestamp should be rejected (tolerance is 5 min)"
    );
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "old timestamp should not cause 500"
    );
}

#[tokio::test]
async fn test_stripe_missing_signature_header() {
    let (state, session_id, project_id) = setup_stripe_webhook_env();
    let payload_bytes = stripe_checkout_payload(&session_id, &project_id, "cs_no_sig");

    let app = webhook_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                // NO stripe-signature header
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "missing signature header should not cause 500"
    );
    assert_ne!(
        status,
        StatusCode::OK,
        "missing signature header should not process the webhook"
    );
}

#[tokio::test]
async fn test_stripe_malformed_json_payload() {
    let (state, _session_id, _project_id) = setup_stripe_webhook_env();
    let payload_bytes = b"this is not json at all {{{{";

    // Sign the malformed payload correctly
    let timestamp = current_timestamp();
    let signature =
        compute_stripe_signature(payload_bytes, STRIPE_WEBHOOK_SECRET, &timestamp);
    let sig_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", sig_header)
                .body(Body::from(payload_bytes.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "malformed JSON should not cause 500"
    );
}

// ============ LemonSqueezy Signature Verification Integration Tests ============

/// Helper: create a fully-configured LemonSqueezy webhook test environment.
fn setup_ls_webhook_env() -> (paycheck::db::AppState, String, String) {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id;
    let project_id;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "LS Webhook Org");
        setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
        let project = create_test_project(&mut conn, &org.id, "LS Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&mut conn, &product.id, None);
        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    (state, session_id, project_id)
}

fn ls_checkout_payload(session_id: &str, project_id: &str) -> Vec<u8> {
    let payload = json!({
        "meta": {
            "event_name": "order_created",
            "custom_data": {
                "paycheck_session_id": session_id,
                "project_id": project_id
            }
        },
        "data": {
            "id": "12345",
            "attributes": {
                "first_order_item": {
                    "product_id": 123
                },
                "user_email": "test@example.com",
                "customer_id": 456,
                "status": "paid"
            }
        }
    });
    serde_json::to_vec(&payload).unwrap()
}

#[tokio::test]
async fn test_ls_invalid_signature_rejected() {
    let (state, session_id, project_id) = setup_ls_webhook_env();
    let payload_bytes = ls_checkout_payload(&session_id, &project_id);

    // Sign with WRONG webhook secret
    let bad_signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_whsec_WRONG");

    let app = webhook_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/lemonsqueezy")
                .header("content-type", "application/json")
                .header("x-signature", bad_signature)
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert_ne!(
        status,
        StatusCode::OK,
        "LS webhook with wrong signature should NOT return 200"
    );
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "LS webhook with wrong signature should NOT return 500"
    );
}

#[tokio::test]
async fn test_ls_missing_signature_rejected() {
    let (state, session_id, project_id) = setup_ls_webhook_env();
    let payload_bytes = ls_checkout_payload(&session_id, &project_id);

    let app = webhook_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/lemonsqueezy")
                .header("content-type", "application/json")
                // NO x-signature header
                .body(Body::from(payload_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "missing LS signature should not cause 500"
    );
    assert_ne!(
        status,
        StatusCode::OK,
        "missing LS signature should not process the webhook"
    );
}

// ============ Response Body Leakage Tests ============

/// Verify that error responses don't leak sensitive internal details.
#[tokio::test]
async fn test_webhook_response_body_no_leakage() {
    let (state, session_id, project_id) = setup_stripe_webhook_env();
    let payload_bytes = stripe_checkout_payload(&session_id, &project_id, "cs_leak_test");

    // Create several error scenarios and check response bodies
    let error_scenarios: Vec<(&str, Option<String>)> = vec![
        // Wrong signature
        (
            "wrong_sig",
            {
                let ts = current_timestamp();
                let sig = compute_stripe_signature(&payload_bytes, "whsec_WRONG", &ts);
                Some(format!("t={},v1={}", ts, sig))
            },
        ),
        // Missing header
        ("missing_header", None),
    ];

    let sensitive_patterns = [
        "whsec_test123secret456",  // webhook secret
        "sk_test_abc123xyz789",    // stripe secret key
        "master_key",
        "INTERNAL_ERROR",
        "stack trace",
        "panicked",
        "thread",
        "rusqlite",
        "at src/",
    ];

    for (scenario_name, sig_header) in error_scenarios {
        let app = webhook_app(state.clone());

        let mut builder = Request::builder()
            .method("POST")
            .uri("/webhook/stripe")
            .header("content-type", "application/json");

        if let Some(ref sig) = sig_header {
            builder = builder.header("stripe-signature", sig.as_str());
        }

        let response = app
            .oneshot(
                builder
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes).to_lowercase();

        for pattern in &sensitive_patterns {
            assert!(
                !body_str.contains(&pattern.to_lowercase()),
                "scenario '{}': response body should not contain '{}', got: {}",
                scenario_name,
                pattern,
                body_str
            );
        }
    }
}
