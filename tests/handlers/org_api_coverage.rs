//! Additional integration tests for org API handlers to improve coverage.
//!
//! These tests cover endpoints that were identified as having gaps in test coverage,
//! with each test tied to a real-world use case.

use axum::{body::Body, http::Request, Router};
use serde_json::{json, Value};
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
        jwks_cache: std::sync::Arc::new(paycheck::jwt::JwksCache::new()),
        trusted_issuers: vec![],
        http_client: reqwest::Client::new(),
        metering_webhook_url: None,
    };

    let app = handlers::orgs::router(state.clone(), paycheck::config::RateLimitConfig::disabled())
        .with_state(state.clone());

    (app, state)
}

// ============================================================================
// LICENSE FILTER TESTS
// ============================================================================
//
// Use case: Support staff need to look up customer licenses when handling
// refund requests, disputes, or account issues. They may have:
// - A Stripe order ID from a refund request
// - A customer ID from the support ticket
// These filters allow quick lookup without knowing the license ID.

mod license_filter_tests {
    use super::*;

    /// Test filtering licenses by payment_provider_order_id.
    ///
    /// Use case: A customer requests a refund through Stripe. Support staff
    /// receives the Stripe order ID and needs to find the associated license
    /// to process the refund or check license status.
    #[tokio::test]
    async fn test_list_licenses_filter_by_payment_provider_order_id() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;
        let target_order_id = "pi_stripe_order_12345";

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "support@test.com", OrgMemberRole::Admin);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

            // Create license 1 and link it to a transaction with the target order ID
            let license1 = queries::create_license(
                &conn,
                &project.id,
                &product.id,
                &paycheck::models::CreateLicense {
                    email_hash: Some("hash1".to_string()),
                    customer_id: Some("cust1".to_string()),
                    expires_at: Some(future_timestamp(ONE_YEAR)),
                    updates_expires_at: Some(future_timestamp(ONE_YEAR)),
                },
            )
            .unwrap();

            // Create a transaction linking to license1 with the target order ID
            queries::create_transaction(
                &conn,
                &paycheck::models::CreateTransaction {
                    org_id: org.id.clone(),
                    project_id: project.id.clone(),
                    product_id: Some(product.id.clone()),
                    license_id: Some(license1.id.clone()),
                    transaction_type: paycheck::models::TransactionType::Purchase,
                    subtotal_cents: 4999,
                    discount_cents: 0,
                    net_cents: 4999,
                    tax_cents: 0,
                    total_cents: 4999,
                    currency: "usd".to_string(),
                    payment_provider: "stripe".to_string(),
                    provider_order_id: target_order_id.to_string(),
                    provider_customer_id: None,
                    provider_subscription_id: None,
                    discount_code: None,
                    tax_inclusive: None,
                    customer_country: Some("US".to_string()),
                    parent_transaction_id: None,
                    is_subscription: false,
                    source: "payment".to_string(),
                    metadata: None,
                    test_mode: false,
                },
            )
            .unwrap();

            // Create another license with a different order ID
            let license2 = queries::create_license(
                &conn,
                &project.id,
                &product.id,
                &paycheck::models::CreateLicense {
                    email_hash: Some("hash2".to_string()),
                    customer_id: Some("cust2".to_string()),
                    expires_at: Some(future_timestamp(ONE_YEAR)),
                    updates_expires_at: Some(future_timestamp(ONE_YEAR)),
                },
            )
            .unwrap();

            queries::create_transaction(
                &conn,
                &paycheck::models::CreateTransaction {
                    org_id: org.id.clone(),
                    project_id: project.id.clone(),
                    product_id: Some(product.id.clone()),
                    license_id: Some(license2.id.clone()),
                    transaction_type: paycheck::models::TransactionType::Purchase,
                    subtotal_cents: 4999,
                    discount_cents: 0,
                    net_cents: 4999,
                    tax_cents: 0,
                    total_cents: 4999,
                    currency: "usd".to_string(),
                    payment_provider: "stripe".to_string(),
                    provider_order_id: "pi_other_order".to_string(),
                    provider_customer_id: None,
                    provider_subscription_id: None,
                    discount_code: None,
                    tax_inclusive: None,
                    customer_country: Some("US".to_string()),
                    parent_transaction_id: None,
                    is_subscription: false,
                    source: "payment".to_string(),
                    metadata: None,
                    test_mode: false,
                },
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Query with payment_provider_order_id filter
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses?payment_provider_order_id={}",
                        org_id, project_id, target_order_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Filter by payment_provider_order_id should return 200"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["total"], 1,
            "Should find exactly one license with the target order ID"
        );
    }

    /// Test filtering licenses by customer_id.
    ///
    /// Use case: A customer contacts support saying they bought multiple products
    /// but can't activate one. Support looks up all licenses for that customer
    /// to see their full purchase history and troubleshoot activation issues.
    #[tokio::test]
    async fn test_list_licenses_filter_by_customer_id() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;
        let target_customer_id = "cust_vip_customer_789";

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "support@test.com", OrgMemberRole::Admin);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product1 = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let product2 = create_test_product(&conn, &project.id, "Enterprise Plan", "enterprise");

            // Create two licenses for the target customer (bought multiple products)
            queries::create_license(
                &conn,
                &project.id,
                &product1.id,
                &paycheck::models::CreateLicense {
                    email_hash: Some("vip_hash".to_string()),
                    customer_id: Some(target_customer_id.to_string()),
                    expires_at: Some(future_timestamp(ONE_YEAR)),
                    updates_expires_at: Some(future_timestamp(ONE_YEAR)),
                },
            )
            .unwrap();

            queries::create_license(
                &conn,
                &project.id,
                &product2.id,
                &paycheck::models::CreateLicense {
                    email_hash: Some("vip_hash".to_string()),
                    customer_id: Some(target_customer_id.to_string()),
                    expires_at: Some(future_timestamp(ONE_YEAR)),
                    updates_expires_at: Some(future_timestamp(ONE_YEAR)),
                },
            )
            .unwrap();

            // Create a license for a different customer
            queries::create_license(
                &conn,
                &project.id,
                &product1.id,
                &paycheck::models::CreateLicense {
                    email_hash: Some("other_hash".to_string()),
                    customer_id: Some("cust_other".to_string()),
                    expires_at: Some(future_timestamp(ONE_YEAR)),
                    updates_expires_at: Some(future_timestamp(ONE_YEAR)),
                },
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Query with customer_id filter
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses?customer_id={}",
                        org_id, project_id, target_customer_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Filter by customer_id should return 200"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["total"], 2,
            "Should find both licenses for the VIP customer"
        );

        // Verify all returned licenses belong to the target customer
        for item in json["items"].as_array().unwrap() {
            assert_eq!(
                item["customer_id"], target_customer_id,
                "All returned licenses should belong to the filtered customer"
            );
        }
    }
}

// ============================================================================
// RESTORE ENDPOINT TESTS
// ============================================================================
//
// Use case: Admins occasionally make mistakes - deleting the wrong project,
// accidentally revoking a valid license during cleanup, etc. The restore
// endpoints allow recovery without database-level intervention.

mod restore_tests {
    use super::*;

    /// Test restoring a soft-deleted project.
    ///
    /// Use case: Admin accidentally deletes a production project while trying
    /// to clean up test projects. They need to restore it along with all its
    /// products and licenses before customers notice.
    #[tokio::test]
    async fn test_restore_project_restores_hierarchy() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Production App", &master_key);
            let _product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

            // Soft-delete the project (simulating accidental deletion)
            queries::soft_delete_project(&mut conn, &project.id).unwrap();

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Verify project is deleted
        {
            let conn = state.db.get().unwrap();
            let project = queries::get_project_by_id(&conn, &project_id).unwrap();
            assert!(
                project.is_none(),
                "Project should not be visible after soft delete"
            );
        }

        // Restore the project
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/restore",
                        org_id, project_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"force": false}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Restore should return 200 OK");

        // Verify project is restored
        {
            let conn = state.db.get().unwrap();
            let project = queries::get_project_by_id(&conn, &project_id).unwrap();
            assert!(project.is_some(), "Project should be visible after restore");
            assert!(
                project.unwrap().deleted_at.is_none(),
                "Project deleted_at should be cleared"
            );
        }
    }

    /// Test restoring a soft-deleted license.
    ///
    /// Use case: Customer disputes a chargeback and wins. The license was
    /// revoked during the dispute, but now needs to be restored to honor
    /// the customer's legitimate purchase.
    #[tokio::test]
    async fn test_restore_license_after_dispute_resolution() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let license_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");
            let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(ONE_YEAR)));

            // Soft-delete the license (simulating revocation during dispute)
            queries::soft_delete_license(&conn, &license.id).unwrap();

            org_id = org.id;
            project_id = project.id;
            license_id = license.id;
            api_key = key;
        }

        // Restore the license (requires JSON body)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/licenses/{}/restore",
                        org_id, project_id, license_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"force": false}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Restore license should return 200 OK");

        // Verify license is restored
        {
            let conn = state.db.get().unwrap();
            let license = queries::get_license_by_id(&conn, &license_id).unwrap();
            assert!(license.is_some(), "License should be visible after restore");
            assert!(
                license.unwrap().deleted_at.is_none(),
                "License deleted_at should be cleared"
            );
        }
    }

    /// Test restoring a soft-deleted product.
    ///
    /// Use case: Marketing decides to discontinue a product tier, but later
    /// reverses the decision. The product and its configuration need to be
    /// restored so new customers can purchase it again.
    #[tokio::test]
    async fn test_restore_product_makes_it_purchasable_again() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let product_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "admin@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Discontinued Tier", "legacy");

            // Soft-delete the product
            queries::soft_delete_product(&mut conn, &product.id).unwrap();

            org_id = org.id;
            project_id = project.id;
            product_id = product.id;
            api_key = key;
        }

        // Restore the product (requires JSON body)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/projects/{}/products/{}/restore",
                        org_id, project_id, product_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"force": false}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Restore product should return 200 OK");

        // Verify product is restored and visible
        {
            let conn = state.db.get().unwrap();
            let product = queries::get_product_by_id(&conn, &product_id).unwrap();
            assert!(product.is_some(), "Product should be visible after restore");
        }
    }
}

// ============================================================================
// API KEY MANAGEMENT TESTS
// ============================================================================
//
// Use case: Developers need programmatic access for CI/CD pipelines,
// automated tooling, or custom integrations. They also need to revoke
// keys when they're compromised or no longer needed.

mod api_key_tests {
    use super::*;

    /// Test creating an API key for an org member.
    ///
    /// Use case: A developer joins the team and needs an API key to set up
    /// their local development environment and CI/CD pipeline.
    #[tokio::test]
    async fn test_create_api_key_for_org_member() {
        let (app, state) = org_app();

        let org_id: String;
        let member_user_id: String;
        let owner_api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_owner_user, _owner_member, owner_key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            // Create a member who needs an API key (no key yet)
            let member_user = create_test_user(&conn, "dev@test.com", "Developer");
            let _member = queries::create_org_member(
                &conn,
                &org.id,
                &paycheck::models::CreateOrgMember {
                    user_id: member_user.id.clone(),
                    role: OrgMemberRole::Member,
                },
            )
            .unwrap();

            org_id = org.id;
            member_user_id = member_user.id;
            owner_api_key = owner_key;
        }

        // Owner creates an API key for the member
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/orgs/{}/members/{}/api-keys",
                        org_id, member_user_id
                    ))
                    .header("Authorization", format!("Bearer {}", owner_api_key))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "CI/CD Pipeline Key"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Creating API key should return 200 OK"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["key"].as_str().unwrap().starts_with("pc_"),
            "API key should start with 'pc_' prefix"
        );
        assert_eq!(
            json["name"], "CI/CD Pipeline Key",
            "API key should have the specified name"
        );
    }

    /// Test listing API keys for an org member.
    ///
    /// Use case: Security audit requires listing all API keys for a user
    /// to verify they have appropriate access and identify unused keys.
    #[tokio::test]
    async fn test_list_api_keys_for_org_member() {
        let (app, state) = org_app();

        let org_id: String;
        let member_user_id: String;
        let owner_api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_owner_user, _owner_member, owner_key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            // Create a member with multiple API keys
            let (member_user, _member, _member_key) =
                create_test_org_member(&mut conn, &org.id, "dev@test.com", OrgMemberRole::Member);

            // Create additional API keys for the member
            queries::create_api_key(&mut conn, &member_user.id, "Key 2", None, true, None).unwrap();
            queries::create_api_key(&mut conn, &member_user.id, "Key 3", None, true, None).unwrap();

            org_id = org.id;
            member_user_id = member_user.id;
            owner_api_key = owner_key;
        }

        // Owner lists the member's API keys
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/members/{}/api-keys",
                        org_id, member_user_id
                    ))
                    .header("Authorization", format!("Bearer {}", owner_api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200, "Listing API keys should return 200");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        // Response is paginated with items array
        let keys = json["items"].as_array().unwrap();
        assert_eq!(keys.len(), 3, "Member should have 3 API keys");

        // Verify keys don't expose the full secret
        for key in keys {
            assert!(
                key.get("key").is_none(),
                "Full API key should not be returned in list"
            );
            assert!(
                key.get("prefix").is_some(),
                "Key prefix should be included for identification"
            );
        }
    }

    /// Test revoking an API key.
    ///
    /// Use case: A developer's laptop is stolen. Their API key needs to be
    /// immediately revoked to prevent unauthorized access to the system.
    #[tokio::test]
    async fn test_revoke_api_key_after_compromise() {
        let (app, state) = org_app();

        let org_id: String;
        let member_user_id: String;
        let compromised_key_id: String;
        let owner_api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_owner_user, _owner_member, owner_key) =
                create_test_org_member(&mut conn, &org.id, "owner@test.com", OrgMemberRole::Owner);

            let (member_user, _member, _member_key) =
                create_test_org_member(&mut conn, &org.id, "dev@test.com", OrgMemberRole::Member);

            // Create the key that will be "compromised"
            let (compromised_key, _) =
                queries::create_api_key(&mut conn, &member_user.id, "Laptop Key", None, true, None)
                    .unwrap();

            org_id = org.id;
            member_user_id = member_user.id;
            compromised_key_id = compromised_key.id;
            owner_api_key = owner_key;
        }

        // Owner revokes the compromised key
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/orgs/{}/members/{}/api-keys/{}",
                        org_id, member_user_id, compromised_key_id
                    ))
                    .header("Authorization", format!("Bearer {}", owner_api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Revoking API key should return 200 OK"
        );

        // Verify the key is revoked
        {
            let conn = state.db.get().unwrap();
            let key = queries::get_api_key_by_id(&conn, &compromised_key_id).unwrap();
            assert!(
                key.unwrap().revoked_at.is_some(),
                "Key should have revoked_at timestamp set"
            );
        }
    }
}

// ============================================================================
// TRANSACTION ENDPOINT TESTS
// ============================================================================
//
// Use case: Business analytics dashboards need to query revenue data,
// filter by date ranges, and see aggregate statistics for financial reporting.

mod transaction_tests {
    use super::*;

    /// Helper to create a test transaction with common defaults
    fn make_transaction(
        org_id: &str,
        project_id: &str,
        product_id: &str,
        order_id: &str,
        total_cents: i64,
        test_mode: bool,
    ) -> paycheck::models::CreateTransaction {
        paycheck::models::CreateTransaction {
            org_id: org_id.to_string(),
            project_id: project_id.to_string(),
            product_id: Some(product_id.to_string()),
            license_id: None,
            transaction_type: paycheck::models::TransactionType::Purchase,
            subtotal_cents: total_cents,
            discount_cents: 0,
            net_cents: total_cents,
            tax_cents: 0,
            total_cents,
            currency: "usd".to_string(),
            payment_provider: "stripe".to_string(),
            provider_order_id: order_id.to_string(),
            provider_customer_id: None,
            provider_subscription_id: None,
            discount_code: None,
            tax_inclusive: None,
            customer_country: Some("US".to_string()),
            parent_transaction_id: None,
            is_subscription: false,
            source: "payment".to_string(),
            metadata: None,
            test_mode,
        }
    }

    /// Test listing transactions for a project.
    ///
    /// Use case: Finance team needs to reconcile monthly revenue for a
    /// specific product/project with their accounting records.
    #[tokio::test]
    async fn test_list_project_transactions() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "finance@test.com", OrgMemberRole::Admin);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

            // Create some test transactions
            queries::create_transaction(
                &conn,
                &make_transaction(&org.id, &project.id, &product.id, "order_123", 4999, false),
            )
            .unwrap();

            queries::create_transaction(
                &conn,
                &make_transaction(&org.id, &project.id, &product.id, "order_456", 4999, false),
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Query project transactions
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/transactions",
                        org_id, project_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Listing transactions should return 200"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["total"], 2, "Should have 2 transactions");
    }

    /// Test getting transaction statistics.
    ///
    /// Use case: Executive dashboard shows aggregate revenue metrics -
    /// total revenue, number of transactions, average order value, etc.
    #[tokio::test]
    async fn test_get_project_transaction_stats() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "ceo@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

            // Create transactions for stats
            for i in 0..5 {
                queries::create_transaction(
                    &conn,
                    &make_transaction(&org.id, &project.id, &product.id, &format!("order_{}", i), 4999, false),
                )
                .unwrap();
            }

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Query transaction stats
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/transactions/stats",
                        org_id, project_id
                    ))
                    .header("Authorization", format!("Bearer {}", api_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Transaction stats should return 200"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["purchase_count"], 5,
            "Should count all 5 purchase transactions"
        );

        // Stats are now grouped by currency
        let by_currency = json["by_currency"].as_array().expect("by_currency should be array");
        assert_eq!(by_currency.len(), 1, "Should have exactly one currency (usd)");

        let usd_stats = &by_currency[0];
        assert_eq!(usd_stats["currency"], "usd", "Currency should be usd");
        // net_revenue_cents = gross - refunds, for 5 purchases at 4999 cents each = 24995
        assert_eq!(
            usd_stats["net_revenue_cents"], 24995,
            "Net revenue should be 5 * $49.99 = $249.95 (in cents)"
        );
    }

    /// Test that transaction stats correctly group by currency.
    ///
    /// This prevents the bug where USD and EUR amounts were summed together,
    /// producing meaningless totals like "15000 cents" for $100 + €50.
    #[tokio::test]
    async fn test_transaction_stats_group_by_currency() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "cfo@test.com", OrgMemberRole::Owner);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

            // Create USD transactions
            queries::create_transaction(
                &conn,
                &CreateTransaction {
                    license_id: None,
                    project_id: project.id.clone(),
                    product_id: Some(product.id.clone()),
                    org_id: org.id.clone(),
                    payment_provider: "stripe".to_string(),
                    provider_customer_id: None,
                    provider_subscription_id: None,
                    provider_order_id: "pi_usd_1".to_string(),
                    currency: "usd".to_string(),
                    subtotal_cents: 10000,
                    discount_cents: 0,
                    net_cents: 10000,
                    tax_cents: 0,
                    total_cents: 10000,
                    discount_code: None,
                    tax_inclusive: None,
                    customer_country: Some("US".to_string()),
                    transaction_type: TransactionType::Purchase,
                    parent_transaction_id: None,
                    is_subscription: false,
                    source: "payment".to_string(),
                    metadata: None,
                    test_mode: false,
                },
            )
            .unwrap();

            // Create EUR transactions
            queries::create_transaction(
                &conn,
                &CreateTransaction {
                    license_id: None,
                    project_id: project.id.clone(),
                    product_id: Some(product.id.clone()),
                    org_id: org.id.clone(),
                    payment_provider: "stripe".to_string(),
                    provider_customer_id: None,
                    provider_subscription_id: None,
                    provider_order_id: "pi_eur_1".to_string(),
                    currency: "eur".to_string(),
                    subtotal_cents: 5000,
                    discount_cents: 0,
                    net_cents: 5000,
                    tax_cents: 0,
                    total_cents: 5000,
                    discount_code: None,
                    tax_inclusive: None,
                    customer_country: Some("DE".to_string()),
                    transaction_type: TransactionType::Purchase,
                    parent_transaction_id: None,
                    is_subscription: false,
                    source: "payment".to_string(),
                    metadata: None,
                    test_mode: false,
                },
            )
            .unwrap();

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Query transaction stats
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/transactions/stats",
                        org_id, project_id
                    ))
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

        // Total counts span all currencies
        assert_eq!(json["purchase_count"], 2, "Should count both purchases");

        // Revenue is grouped by currency - NOT summed together
        let by_currency = json["by_currency"].as_array().expect("by_currency should be array");
        assert_eq!(by_currency.len(), 2, "Should have two currencies (usd, eur)");

        // Find each currency's stats (order is by gross_revenue DESC)
        let usd_stats = by_currency.iter().find(|s| s["currency"] == "usd").expect("should have usd");
        let eur_stats = by_currency.iter().find(|s| s["currency"] == "eur").expect("should have eur");

        assert_eq!(usd_stats["net_revenue_cents"], 10000, "USD should be $100.00");
        assert_eq!(eur_stats["net_revenue_cents"], 5000, "EUR should be €50.00");

        // The old bug would have returned a single sum of 15000 "cents" which is meaningless
        // Now we correctly separate them by currency
    }

    /// Test filtering transactions by test_mode.
    ///
    /// Use case: Finance team needs to exclude test transactions from
    /// revenue reports, but QA needs to see only test transactions to
    /// verify payment flow testing.
    #[tokio::test]
    async fn test_filter_transactions_by_test_mode() {
        let (app, state) = org_app();
        let master_key = test_master_key();

        let org_id: String;
        let project_id: String;
        let api_key: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&conn, "Test Org");
            let (_user, _member, key) =
                create_test_org_member(&mut conn, &org.id, "qa@test.com", OrgMemberRole::Admin);
            let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&conn, &project.id, "Pro Plan", "pro");

            // Create live transaction
            queries::create_transaction(
                &conn,
                &make_transaction(&org.id, &project.id, &product.id, "live_order", 4999, false),
            )
            .unwrap();

            // Create test transactions
            for i in 0..3 {
                queries::create_transaction(
                    &conn,
                    &make_transaction(&org.id, &project.id, &product.id, &format!("test_order_{}", i), 100, true),
                )
                .unwrap();
            }

            org_id = org.id;
            project_id = project.id;
            api_key = key;
        }

        // Query only test transactions
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/orgs/{}/projects/{}/transactions?test_mode=true",
                        org_id, project_id
                    ))
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

        assert_eq!(
            json["total"], 3,
            "Should find only the 3 test transactions"
        );

        // Verify all are test mode
        for item in json["items"].as_array().unwrap() {
            assert_eq!(
                item["test_mode"], true,
                "All returned transactions should be test mode"
            );
        }
    }
}
