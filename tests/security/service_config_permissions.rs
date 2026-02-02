//! Service config permission tests.
//!
//! Service configs contain sensitive payment credentials (Stripe API keys,
//! LemonSqueezy secrets, webhook secrets). Only admins should be able to
//! create, update, or delete these configs.

#[path = "../common/mod.rs"]
mod common;
use common::*;

use axum::{Router, body::Body, http::Request};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tower::ServiceExt;

use axum::http::StatusCode;
use paycheck::config::RateLimitConfig;
use paycheck::db::{AppState, queries};
use paycheck::handlers;
use paycheck::models::OrgMemberRole;

/// Creates a test app with the org router.
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
        jwks_cache: std::sync::Arc::new(paycheck::jwt::JwksCache::new()),
        trusted_issuers: vec![],
        http_client: reqwest::Client::new(),
        metering_webhook_url: None,
    };

    let app = handlers::orgs::router(state.clone(), RateLimitConfig::disabled())
        .with_state(state.clone());

    (app, state)
}

// ============================================================================
// MEMBER ROLE CANNOT MODIFY SERVICE CONFIGS
// ============================================================================

/// Member role should NOT be able to create service configs.
/// Service configs contain sensitive payment credentials.
#[tokio::test]
async fn member_cannot_create_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");

    // Create an owner (required for org)
    let (_owner_user, _owner_member, _owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

    // Create a member (NOT admin)
    let (_member_user, _member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

    // Try to create a service config as member
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/service-configs", org.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{
                    "name": "My Stripe Config",
                    "provider": "stripe",
                    "stripe_config": {
                        "secret_key": "sk_test_xxx",
                        "publishable_key": "pk_test_xxx",
                        "webhook_secret": "whsec_xxx"
                    }
                }"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Member role should NOT be able to create service configs"
    );
}

/// Member role should NOT be able to update service configs.
#[tokio::test]
async fn member_cannot_update_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");

    // Create owner and a service config
    let (_owner_user, _owner_member, _owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

    // Create a service config
    let encrypted = state
        .master_key
        .encrypt_private_key(&org.id, br#"{"secret_key":"sk_test_xxx","publishable_key":"pk_test_xxx","webhook_secret":"whsec_xxx"}"#)
        .unwrap();
    let config = queries::create_service_config(
        &conn,
        &org.id,
        "Existing Config",
        paycheck::models::ServiceProvider::Stripe,
        &encrypted,
    )
    .unwrap();

    // Create a member (NOT admin)
    let (_member_user, _member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

    // Try to update the service config as member
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/orgs/{}/service-configs/{}", org.id, config.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name": "Hacked Config"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Member role should NOT be able to update service configs"
    );
}

/// Member role should NOT be able to delete service configs.
#[tokio::test]
async fn member_cannot_delete_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");

    // Create owner and a service config
    let (_owner_user, _owner_member, _owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

    // Create a service config
    let encrypted = state
        .master_key
        .encrypt_private_key(&org.id, br#"{"secret_key":"sk_test_xxx","publishable_key":"pk_test_xxx","webhook_secret":"whsec_xxx"}"#)
        .unwrap();
    let config = queries::create_service_config(
        &conn,
        &org.id,
        "Existing Config",
        paycheck::models::ServiceProvider::Stripe,
        &encrypted,
    )
    .unwrap();

    // Create a member (NOT admin)
    let (_member_user, _member, member_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);

    // Try to delete the service config as member
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/orgs/{}/service-configs/{}", org.id, config.id))
                .header("Authorization", format!("Bearer {}", member_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Member role should NOT be able to delete service configs"
    );
}

// ============================================================================
// ADMIN ROLE CAN MODIFY SERVICE CONFIGS
// ============================================================================

/// Admin role SHOULD be able to create service configs.
#[tokio::test]
async fn admin_can_create_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");

    // Create an admin
    let (_admin_user, _admin_member, admin_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Admin);

    // Create a service config as admin
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/service-configs", org.id))
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{
                    "name": "Admin Stripe Config",
                    "provider": "stripe",
                    "stripe_config": {
                        "secret_key": "sk_test_xxx",
                        "publishable_key": "pk_test_xxx",
                        "webhook_secret": "whsec_xxx"
                    }
                }"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Admin role SHOULD be able to create service configs"
    );
}

/// Admin role SHOULD be able to update service configs.
#[tokio::test]
async fn admin_can_update_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");

    // Create an admin
    let (_admin_user, _admin_member, admin_key) =
        create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Admin);

    // Create a service config
    let encrypted = state
        .master_key
        .encrypt_private_key(&org.id, br#"{"secret_key":"sk_test_xxx","publishable_key":"pk_test_xxx","webhook_secret":"whsec_xxx"}"#)
        .unwrap();
    let config = queries::create_service_config(
        &conn,
        &org.id,
        "Existing Config",
        paycheck::models::ServiceProvider::Stripe,
        &encrypted,
    )
    .unwrap();

    // Update the service config as admin
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/orgs/{}/service-configs/{}", org.id, config.id))
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name": "Updated Config"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Admin role SHOULD be able to update service configs"
    );
}

/// Owner role SHOULD be able to modify service configs.
#[tokio::test]
async fn owner_can_delete_service_config() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");

    // Create owner
    let (_owner_user, _owner_member, owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

    // Create a service config
    let encrypted = state
        .master_key
        .encrypt_private_key(&org.id, br#"{"secret_key":"sk_test_xxx","publishable_key":"pk_test_xxx","webhook_secret":"whsec_xxx"}"#)
        .unwrap();
    let config = queries::create_service_config(
        &conn,
        &org.id,
        "Existing Config",
        paycheck::models::ServiceProvider::Stripe,
        &encrypted,
    )
    .unwrap();

    // Delete the service config as owner
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/orgs/{}/service-configs/{}", org.id, config.id))
                .header("Authorization", format!("Bearer {}", owner_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Owner role SHOULD be able to delete service configs"
    );
}
