//! Integration tests for service config CRUD handlers.
//!
//! Service configs store encrypted payment provider credentials (Stripe, LemonSqueezy, Resend).
//! These tests verify the full CRUD lifecycle, response formats, secret masking,
//! and encryption at rest.

use axum::{Router, body::Body, http::Request};
use serde_json::Value;
use tower::ServiceExt;

#[path = "../common/mod.rs"]
mod common;
use common::*;

use paycheck::db::AppState;
use paycheck::handlers;
use paycheck::models::OrgMemberRole;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// ============================================================================
// Test App Setup
// ============================================================================

fn org_app() -> (Router, AppState) {
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
        activation_rate_limiter: std::sync::Arc::new(
            paycheck::rate_limit::ActivationRateLimiter::default(),
        ),
        email_service: std::sync::Arc::new(paycheck::email::EmailService::new(
            None,
            "test@example.com".to_string(),
        )),
        delivery_service: std::sync::Arc::new(paycheck::feedback::DeliveryService::new(
            None,
            "test@example.com".to_string(),
        )),
        http_client: reqwest::Client::new(),
        metering_webhook_url: None,
        disable_checkout_tag: None,
        disable_public_api_tag: None,
    };

    let app = handlers::orgs::router(state.clone(), paycheck::config::RateLimitConfig::disabled())
        .with_state(state.clone());

    (app, state)
}

// ============================================================================
// CREATE TESTS
// ============================================================================

#[tokio::test]
async fn test_create_stripe_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let (_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/service-configs", org.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{
                        "name": "Production Stripe",
                        "provider": "stripe",
                        "stripe_config": {
                            "secret_key": "sk_test_abc123def456ghi789",
                            "publishable_key": "pk_test_abc123def456ghi789",
                            "webhook_secret": "whsec_test_secret_value_here"
                        }
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Verify structural fields
    assert!(json["id"].as_str().is_some(), "response should include id");
    assert_eq!(json["org_id"], org.id);
    assert_eq!(json["name"], "Production Stripe");
    assert_eq!(json["provider"], "stripe");
    assert_eq!(json["category"], "payment");
    assert!(json["created_at"].as_i64().is_some());
    assert!(json["updated_at"].as_i64().is_some());

    // Verify secrets are MASKED in response
    let stripe = &json["stripe_config"];
    assert!(stripe.is_object(), "stripe_config should be present");

    let secret_key = stripe["secret_key"].as_str().unwrap();
    assert!(
        secret_key.contains("..."),
        "secret_key should be masked, got: {}",
        secret_key
    );
    assert!(
        !secret_key.contains("abc123"),
        "secret_key should NOT contain plaintext"
    );

    // publishable_key is NOT masked (it's public)
    assert_eq!(
        stripe["publishable_key"], "pk_test_abc123def456ghi789",
        "publishable_key should NOT be masked"
    );

    let webhook_secret = stripe["webhook_secret"].as_str().unwrap();
    assert!(
        webhook_secret.contains("..."),
        "webhook_secret should be masked, got: {}",
        webhook_secret
    );

    // ls_config and resend_api_key should not be present
    assert!(json["ls_config"].is_null(), "ls_config should not be present for stripe");
    assert!(
        json["resend_api_key"].is_null(),
        "resend_api_key should not be present for stripe"
    );
}

#[tokio::test]
async fn test_create_lemonsqueezy_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let (_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/service-configs", org.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{
                        "name": "Production LemonSqueezy",
                        "provider": "lemonsqueezy",
                        "ls_config": {
                            "api_key": "ls_key_test_abc123def456",
                            "store_id": "store_123",
                            "webhook_secret": "ls_whsec_secret_value_here"
                        }
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["name"], "Production LemonSqueezy");
    assert_eq!(json["provider"], "lemonsqueezy");
    assert_eq!(json["category"], "payment");

    let ls = &json["ls_config"];
    assert!(ls.is_object(), "ls_config should be present");

    let api_key_masked = ls["api_key"].as_str().unwrap();
    assert!(
        api_key_masked.contains("..."),
        "api_key should be masked, got: {}",
        api_key_masked
    );

    // store_id is NOT masked (not sensitive)
    assert_eq!(ls["store_id"], "store_123", "store_id should NOT be masked");

    let webhook_secret = ls["webhook_secret"].as_str().unwrap();
    assert!(
        webhook_secret.contains("..."),
        "webhook_secret should be masked, got: {}",
        webhook_secret
    );
}

#[tokio::test]
async fn test_create_resend_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let (_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/service-configs", org.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{
                        "name": "Production Resend",
                        "provider": "resend",
                        "resend_api_key": "re_6789abcdefghij0123"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["name"], "Production Resend");
    assert_eq!(json["provider"], "resend");
    assert_eq!(json["category"], "email");

    let masked = json["resend_api_key"].as_str().unwrap();
    assert!(
        masked.contains("..."),
        "resend_api_key should be masked, got: {}",
        masked
    );
    assert!(
        !masked.contains("abcdefghij"),
        "masked key should NOT contain plaintext middle"
    );
}

// ============================================================================
// LIST TESTS
// ============================================================================

#[tokio::test]
async fn test_list_service_configs() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let (_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

    // Create two configs directly in DB
    let stripe_encrypted = master_key
        .encrypt_private_key(
            &org.id,
            br#"{"secret_key":"sk_test_list_key_12345678","publishable_key":"pk_test_list","webhook_secret":"whsec_list_secret_12345"}"#,
        )
        .unwrap();
    queries::create_service_config(
        &conn,
        &org.id,
        "Stripe Config",
        paycheck::models::ServiceProvider::Stripe,
        &stripe_encrypted,
    )
    .unwrap();

    let ls_encrypted = master_key
        .encrypt_private_key(
            &org.id,
            br#"{"api_key":"ls_key_list_test_12345678","store_id":"store_456","webhook_secret":"ls_whsec_list_secret_1234"}"#,
        )
        .unwrap();
    queries::create_service_config(
        &conn,
        &org.id,
        "LS Config",
        paycheck::models::ServiceProvider::LemonSqueezy,
        &ls_encrypted,
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/service-configs", org.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let configs = json.as_array().expect("response should be an array");
    assert_eq!(configs.len(), 2, "should return both configs");

    // Verify all secrets are masked in the list
    for config in configs {
        if config["provider"] == "stripe" {
            let sk = config["stripe_config"]["secret_key"].as_str().unwrap();
            assert!(sk.contains("..."), "stripe secret_key should be masked in list");
        } else if config["provider"] == "lemonsqueezy" {
            let ak = config["ls_config"]["api_key"].as_str().unwrap();
            assert!(ak.contains("..."), "ls api_key should be masked in list");
        }
    }
}

// ============================================================================
// GET TESTS
// ============================================================================

#[tokio::test]
async fn test_get_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let (_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

    // Create a config directly in DB
    let encrypted = master_key
        .encrypt_private_key(
            &org.id,
            br#"{"secret_key":"sk_test_get_key_123456789","publishable_key":"pk_test_get","webhook_secret":"whsec_get_secret_123456"}"#,
        )
        .unwrap();
    let config = queries::create_service_config(
        &conn,
        &org.id,
        "Get Test Config",
        paycheck::models::ServiceProvider::Stripe,
        &encrypted,
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/service-configs/{}", org.id, config.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["id"], config.id);
    assert_eq!(json["name"], "Get Test Config");
    assert_eq!(json["provider"], "stripe");

    let sk = json["stripe_config"]["secret_key"].as_str().unwrap();
    assert!(sk.contains("..."), "secret_key should be masked");
}

// ============================================================================
// UPDATE TESTS
// ============================================================================

#[tokio::test]
async fn test_update_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let (_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

    // Create initial config
    let encrypted = master_key
        .encrypt_private_key(
            &org.id,
            br#"{"secret_key":"sk_test_old_key_123456789","publishable_key":"pk_test_old","webhook_secret":"whsec_old_secret_123456"}"#,
        )
        .unwrap();
    let config = queries::create_service_config(
        &conn,
        &org.id,
        "Original Name",
        paycheck::models::ServiceProvider::Stripe,
        &encrypted,
    )
    .unwrap();

    // Update name and credentials
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/orgs/{}/service-configs/{}", org.id, config.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{
                        "name": "Updated Name",
                        "stripe_config": {
                            "secret_key": "sk_test_new_key_987654321",
                            "publishable_key": "pk_test_new",
                            "webhook_secret": "whsec_new_secret_654321"
                        }
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["id"], config.id, "ID should not change");
    assert_eq!(json["name"], "Updated Name", "name should be updated");

    // The masked output should reflect the new key (new publishable key is visible)
    assert_eq!(
        json["stripe_config"]["publishable_key"], "pk_test_new",
        "publishable_key should reflect the new value"
    );

    // Secret key should still be masked but show new prefix/suffix
    let sk = json["stripe_config"]["secret_key"].as_str().unwrap();
    assert!(sk.contains("..."), "secret_key should be masked");
    assert!(
        sk.ends_with("4321"),
        "masked secret_key should show last 4 chars of new key, got: {}",
        sk
    );
}

// ============================================================================
// DELETE TESTS
// ============================================================================

#[tokio::test]
async fn test_delete_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let (_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

    // Create a config
    let encrypted = master_key
        .encrypt_private_key(
            &org.id,
            br#"{"secret_key":"sk_test_del_key_123456789","publishable_key":"pk_test_del","webhook_secret":"whsec_del_secret_123456"}"#,
        )
        .unwrap();
    let config = queries::create_service_config(
        &conn,
        &org.id,
        "To Be Deleted",
        paycheck::models::ServiceProvider::Stripe,
        &encrypted,
    )
    .unwrap();

    // DELETE the config
    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/orgs/{}/service-configs/{}", org.id, config.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(delete_response.status(), 200);

    let body = axum::body::to_bytes(delete_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);

    // GET should now return 404
    let get_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/service-configs/{}", org.id, config.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        get_response.status(),
        404,
        "GET after DELETE should return 404"
    );
}

// ============================================================================
// MEMBER ROLE READ ACCESS
// ============================================================================

#[tokio::test]
async fn test_member_role_can_list_service_configs() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");

    // Create owner (required for org)
    let (_owner, _owner_member, _owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

    // Create a config as admin (via DB since we want to test member read)
    let encrypted = master_key
        .encrypt_private_key(
            &org.id,
            br#"{"secret_key":"sk_test_member_key_12345","publishable_key":"pk_test_member","webhook_secret":"whsec_member_secret_123"}"#,
        )
        .unwrap();
    queries::create_service_config(
        &conn,
        &org.id,
        "Admin Created Config",
        paycheck::models::ServiceProvider::Stripe,
        &encrypted,
    )
    .unwrap();

    // Create a member (NOT admin)
    let (_member_user, _member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

    // Member should be able to LIST service configs
    // (list_service_configs does not call require_admin)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/service-configs", org.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        200,
        "Member role should be able to list service configs (read access)"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let configs = json.as_array().expect("response should be an array");
    assert_eq!(configs.len(), 1, "member should see the config");

    // Verify secrets are STILL masked for member role
    let sk = configs[0]["stripe_config"]["secret_key"].as_str().unwrap();
    assert!(
        sk.contains("..."),
        "secrets should be masked even for member role, got: {}",
        sk
    );
}

// ============================================================================
// ENCRYPTED AT REST
// ============================================================================

#[tokio::test]
async fn test_service_config_encrypted_at_rest() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");
    let (_user, _member, api_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);

    let plaintext_secret = "sk_test_supersecret_key_do_not_store_plaintext";

    // Create a Stripe service config via HTTP
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/service-configs", org.id))
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{
                        "name": "Encryption Test",
                        "provider": "stripe",
                        "stripe_config": {{
                            "secret_key": "{}",
                            "publishable_key": "pk_test_pub",
                            "webhook_secret": "whsec_test_webhook_secret_123"
                        }}
                    }}"#,
                    plaintext_secret
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let config_id = json["id"].as_str().unwrap();

    // Read the raw DB row to verify encryption at rest
    let raw_encrypted: Vec<u8> = conn
        .query_row(
            "SELECT config_encrypted FROM service_configs WHERE id = ?1",
            rusqlite::params![config_id],
            |row| row.get(0),
        )
        .expect("should find the service config row");

    // Assert the raw bytes start with ENC1 magic bytes
    assert!(
        raw_encrypted.starts_with(b"ENC1"),
        "encrypted data should start with ENC1 magic bytes, got first 4 bytes: {:?}",
        &raw_encrypted[..4.min(raw_encrypted.len())]
    );

    // Assert the raw bytes do NOT contain the plaintext secret key
    let raw_as_string = String::from_utf8_lossy(&raw_encrypted);
    assert!(
        !raw_as_string.contains(plaintext_secret),
        "raw DB bytes should NOT contain the plaintext secret key"
    );
    assert!(
        !raw_as_string.contains("supersecret"),
        "raw DB bytes should NOT contain any part of the plaintext secret"
    );
}
