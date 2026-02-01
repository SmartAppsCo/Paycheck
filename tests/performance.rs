//! Performance tests for large datasets.
//!
//! These tests verify system behavior with large amounts of data.
//! They are marked with `#[ignore]` and must be run manually:
//!
//! ```bash
//! # Run all performance tests
//! cargo test --test performance -- --ignored --test-threads=1
//!
//! # Run a specific test
//! cargo test --test performance test_license_list_large_dataset -- --ignored
//! ```
//!
//! Issue 12 from security audit tier 3.

#[path = "common/mod.rs"]
mod common;
use common::*;

use paycheck::models::AuditLogQuery;
use std::time::Instant;

// ============================================================================
// LARGE DATASET PAGINATION TESTS
// ============================================================================

/// Test license list pagination with many licenses.
/// Verifies that pagination works correctly and queries complete in reasonable time.
#[tokio::test]
#[ignore]
async fn test_license_list_large_dataset() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    // Setup: Create org, project, product
    let org = create_test_org(&mut conn, "Performance Test Org");
    let project = create_test_project(&mut conn, &org.id, "Perf Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Create 1000 licenses (batch insert)
    println!("Creating 1000 licenses...");
    let start = Instant::now();

    for i in 0..1000 {
        let input = CreateLicense {
            email_hash: Some(email_hasher.hash(&format!("user{}@example.com", i))),
            customer_id: Some(format!("customer-{}", i)),
            expires_at: Some(future_timestamp(ONE_YEAR)),
            updates_expires_at: Some(future_timestamp(ONE_YEAR)),
            payment_provider: None,
            payment_provider_customer_id: None,
            payment_provider_subscription_id: None,
            payment_provider_order_id: None,
        };
        queries::create_license(&mut conn, &project.id, &product.id, &input)
            .expect("Failed to create license");
    }

    let insert_duration = start.elapsed();
    println!("Created 1000 licenses in {:?}", insert_duration);

    // Test pagination queries
    println!("\nTesting pagination queries...");

    // Query first page
    let start = Instant::now();
    let (page1, total) = queries::list_licenses_for_project_paginated(&mut conn, &project.id, 50, 0)
        .expect("Failed to list licenses page 1");
    let query1_duration = start.elapsed();
    assert_eq!(page1.len(), 50, "First page should have 50 licenses");
    assert_eq!(total, 1000, "Total should be 1000");
    println!("Page 1 (offset=0, limit=50): {:?}", query1_duration);
    assert!(
        query1_duration.as_millis() < 500,
        "Query should complete in <500ms, took {:?}",
        query1_duration
    );

    // Query middle page
    let start = Instant::now();
    let (page_middle, _) =
        queries::list_licenses_for_project_paginated(&mut conn, &project.id, 50, 500)
            .expect("Failed to list licenses middle page");
    let query_middle_duration = start.elapsed();
    assert_eq!(page_middle.len(), 50, "Middle page should have 50 licenses");
    println!(
        "Page 11 (offset=500, limit=50): {:?}",
        query_middle_duration
    );
    assert!(
        query_middle_duration.as_millis() < 500,
        "Query should complete in <500ms, took {:?}",
        query_middle_duration
    );

    // Query last page
    let start = Instant::now();
    let (page_last, _) = queries::list_licenses_for_project_paginated(&mut conn, &project.id, 50, 950)
        .expect("Failed to list licenses last page");
    let query_last_duration = start.elapsed();
    assert_eq!(page_last.len(), 50, "Last page should have 50 licenses");
    println!("Page 20 (offset=950, limit=50): {:?}", query_last_duration);
    assert!(
        query_last_duration.as_millis() < 500,
        "Query should complete in <500ms, took {:?}",
        query_last_duration
    );

    // Query with email filter
    let start = Instant::now();
    let email_hash = email_hasher.hash("user500@example.com");
    let (filtered, filter_total) = queries::get_all_licenses_by_email_hash_for_admin_paginated(
        &conn,
        &project.id,
        &email_hash,
        50,
        0,
    )
    .expect("Failed to list licenses with email filter");
    let filter_duration = start.elapsed();
    assert_eq!(filtered.len(), 1, "Should find exactly 1 license by email");
    assert_eq!(filter_total, 1, "Total should be 1 for specific email");
    println!("Email filter query: {:?}", filter_duration);
    assert!(
        filter_duration.as_millis() < 100,
        "Filtered query should be fast (<100ms), took {:?}",
        filter_duration
    );

    println!("\nAll pagination tests passed!");
}

/// Test audit log query performance with high volume.
/// Verifies that audit log queries scale reasonably.
#[tokio::test]
#[ignore]
async fn test_audit_log_large_volume() {
    use rusqlite::params;

    let mut conn = setup_test_db();
    let audit_conn = setup_test_audit_db();
    let master_key = test_master_key();

    // Setup
    let org = create_test_org(&mut conn, "Audit Test Org");
    let (user, _, _) =
        create_test_org_member(&mut conn, &org.id, "auditor@test.com", OrgMemberRole::Admin);
    let project = create_test_project(&mut conn, &org.id, "Audit Project", &master_key);

    // Generate 10,000 audit log entries using direct SQL for speed
    println!("Creating 10,000 audit log entries...");
    let start = Instant::now();

    let now = chrono::Utc::now().timestamp();
    for i in 0..10_000 {
        let action = match i % 5 {
            0 => "license.created",
            1 => "license.activated",
            2 => "device.created",
            3 => "license.validated",
            _ => "device.deactivated",
        };
        let id = uuid::Uuid::new_v4().to_string();
        let details = format!("{{\"index\": {}}}", i);

        audit_conn
            .execute(
                "INSERT INTO audit_logs (id, timestamp, actor_type, user_id, action, resource_type, resource_id, details, org_id, project_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![&id, now, "user", &user.id, action, "license", &id, &details, &org.id, &project.id],
            )
            .expect("Failed to create audit log");
    }

    let insert_duration = start.elapsed();
    println!("Created 10,000 audit logs in {:?}", insert_duration);

    // Test queries
    println!("\nTesting audit log queries...");

    // Helper to create query with common defaults
    fn make_query(
        org_id: Option<String>,
        project_id: Option<String>,
        action: Option<String>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> AuditLogQuery {
        AuditLogQuery {
            actor_type: None,
            user_id: None,
            action,
            resource_type: None,
            resource_id: None,
            org_id,
            project_id,
            from_timestamp: None,
            to_timestamp: None,
            auth_type: None,
            auth_credential: None,
            limit,
            offset,
        }
    }

    // Query without filters
    let start = Instant::now();
    let query = make_query(Some(org.id.clone()), None, None, Some(100), Some(0));
    let (logs, total) =
        queries::query_audit_logs(&audit_conn, &query).expect("Failed to list audit logs");
    let query_duration = start.elapsed();
    assert_eq!(logs.len(), 100, "Should return 100 logs");
    assert_eq!(total, 10_000, "Total should be 10,000");
    println!("Unfiltered query (limit=100): {:?}", query_duration);
    assert!(
        query_duration.as_millis() < 1000,
        "Query should complete in <1s, took {:?}",
        query_duration
    );

    // Query with project filter
    let start = Instant::now();
    let query = make_query(
        Some(org.id.clone()),
        Some(project.id.clone()),
        None,
        Some(100),
        Some(0),
    );
    let (filtered_logs, _) = queries::query_audit_logs(&audit_conn, &query)
        .expect("Failed to list audit logs with project filter");
    let filter_duration = start.elapsed();
    assert_eq!(filtered_logs.len(), 100, "Should return 100 logs");
    println!("Project filter query: {:?}", filter_duration);
    assert!(
        filter_duration.as_millis() < 1000,
        "Filtered query should complete in <1s, took {:?}",
        filter_duration
    );

    // Query with action filter
    let start = Instant::now();
    let query = make_query(
        Some(org.id.clone()),
        None,
        Some("license.created".to_string()),
        Some(100),
        Some(0),
    );
    let (action_logs, _) = queries::query_audit_logs(&audit_conn, &query)
        .expect("Failed to list audit logs with action filter");
    let action_filter_duration = start.elapsed();
    assert_eq!(action_logs.len(), 100, "Should return 100 logs");
    println!("Action filter query: {:?}", action_filter_duration);
    assert!(
        action_filter_duration.as_millis() < 1000,
        "Action filter query should complete in <1s, took {:?}",
        action_filter_duration
    );

    // Query deep pagination (offset 9000)
    let start = Instant::now();
    let query = make_query(Some(org.id.clone()), None, None, Some(100), Some(9000));
    let (deep_page, _) = queries::query_audit_logs(&audit_conn, &query)
        .expect("Failed to list audit logs deep page");
    let deep_duration = start.elapsed();
    assert!(
        deep_page.len() <= 100,
        "Should return at most 100 logs from deep page"
    );
    println!("Deep pagination (offset=9000): {:?}", deep_duration);
    assert!(
        deep_duration.as_millis() < 2000,
        "Deep pagination should complete in <2s, took {:?}",
        deep_duration
    );

    println!("\nAll audit log tests passed!");
}

/// Test license with many devices.
/// Verifies operations scale with device count.
#[tokio::test]
#[ignore]
async fn test_license_many_devices() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Setup
    let org = create_test_org(&mut conn, "Device Test Org");
    let project = create_test_project(&mut conn, &org.id, "Device Project", &master_key);

    // Create product with unlimited devices
    let input = CreateProduct {
        name: "Unlimited".to_string(),
        tier: "enterprise".to_string(),
        price_cents: Some(9999),
        currency: Some("usd".to_string()),
        license_exp_days: Some(365),
        updates_exp_days: Some(365),
        activation_limit: Some(1000), // High activation limit
        device_limit: None,           // None = unlimited
        device_inactive_days: None,
        features: vec!["unlimited_devices".to_string()],
        payment_config_id: None,
        email_config_id: None,
    };
    let product =
        queries::create_product(&mut conn, &project.id, &input).expect("Failed to create product");

    // Create license
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(ONE_YEAR)),
    );

    // Activate 500 devices
    println!("Creating 500 devices...");
    let start = Instant::now();

    for i in 0..500 {
        let jti = uuid::Uuid::new_v4().to_string();
        queries::create_device(
            &conn,
            &license.id,
            &format!("device-{}", i),
            DeviceType::Machine,
            &jti,
            Some(&format!("Device {}", i)),
        )
        .expect("Failed to create device");
    }

    let insert_duration = start.elapsed();
    println!("Created 500 devices in {:?}", insert_duration);

    // Test operations
    println!("\nTesting operations with many devices...");

    // Get license with device count
    let start = Instant::now();
    let license_info =
        queries::get_license_by_id(&mut conn, &license.id).expect("Failed to get license");
    let get_duration = start.elapsed();
    assert!(license_info.is_some(), "License should exist");
    println!("Get license: {:?}", get_duration);
    assert!(
        get_duration.as_millis() < 100,
        "Get license should be fast (<100ms), took {:?}",
        get_duration
    );

    // List devices for license
    let start = Instant::now();
    let devices =
        queries::list_devices_for_license(&mut conn, &license.id).expect("Failed to list devices");
    let list_duration = start.elapsed();
    assert_eq!(devices.len(), 500, "Should have 500 devices");
    println!("List 500 devices: {:?}", list_duration);
    assert!(
        list_duration.as_millis() < 500,
        "List devices should complete in <500ms, took {:?}",
        list_duration
    );

    // Deactivate a device
    let start = Instant::now();
    let device_to_deactivate = &devices[250];
    queries::delete_device(&mut conn, &device_to_deactivate.id).expect("Failed to deactivate device");
    let deactivate_duration = start.elapsed();
    println!("Deactivate device: {:?}", deactivate_duration);
    assert!(
        deactivate_duration.as_millis() < 50,
        "Deactivate should be fast (<50ms), took {:?}",
        deactivate_duration
    );

    // Verify device count after deactivation
    let start = Instant::now();
    let active_devices = queries::list_devices_for_license(&mut conn, &license.id)
        .expect("Failed to list devices after deactivation");
    let recount_duration = start.elapsed();
    assert_eq!(active_devices.len(), 499, "Should have 499 active devices");
    println!("Recount after deactivation: {:?}", recount_duration);

    println!("\nAll device tests passed!");
}

/// Test user with many API keys.
/// Verifies API key operations scale correctly.
#[tokio::test]
#[ignore]
async fn test_user_many_api_keys() {
    let mut conn = setup_test_db();

    // Create user
    let user = create_test_user(&mut conn, "apikey-test@example.com", "API Key Test User");

    // Create 100 API keys (mix of active and revoked)
    println!("Creating 100 API keys...");
    let start = Instant::now();

    let mut active_keys = Vec::new();
    for i in 0..100 {
        let (key_record, raw_key) = queries::create_api_key(
        &mut conn,
            &user.id,
            &format!("Key {}", i),
            Some(365), // 1 year expiry
            true,
            None,
        )
        .expect("Failed to create API key");

        // Revoke every other key
        if i % 2 == 1 {
            queries::revoke_api_key(&mut conn, &key_record.id).expect("Failed to revoke API key");
        } else {
            active_keys.push(raw_key);
        }
    }

    let insert_duration = start.elapsed();
    println!("Created 100 API keys in {:?}", insert_duration);

    // Test operations
    println!("\nTesting API key operations...");

    // List API keys for user
    let start = Instant::now();
    let keys = queries::list_api_keys(&mut conn, &user.id, false).expect("Failed to list API keys");
    let list_duration = start.elapsed();
    assert_eq!(keys.len(), 50, "Should have 50 active keys (50 revoked)");
    println!("List API keys: {:?}", list_duration);
    assert!(
        list_duration.as_millis() < 200,
        "List should complete in <200ms, took {:?}",
        list_duration
    );

    // Authenticate with one of the keys
    let test_key = &active_keys[25];
    let start = Instant::now();
    let auth_result = queries::get_user_by_api_key(&mut conn, test_key);
    let auth_duration = start.elapsed();
    assert!(auth_result.is_ok(), "Authentication should succeed");
    let (auth_user, auth_key) = auth_result.unwrap().expect("Should find user by API key");
    assert_eq!(
        auth_user.id, user.id,
        "Should authenticate as the correct user"
    );
    println!("Authenticate API key: {:?}", auth_duration);
    assert!(
        auth_duration.as_millis() < 50,
        "Auth should be fast (<50ms), took {:?}",
        auth_duration
    );

    // Verify last_used_at was updated
    let start = Instant::now();
    let keys_after = queries::list_api_keys(&mut conn, &user.id, false).expect("Failed to list keys");
    let key_record = keys_after.iter().find(|k| k.id == auth_key.id);
    assert!(
        key_record.unwrap().last_used_at.is_some(),
        "last_used_at should be set after authentication"
    );
    let verify_duration = start.elapsed();
    println!("Verify last_used_at: {:?}", verify_duration);

    println!("\nAll API key tests passed!");
}

/// Test organization with many projects.
/// Verifies project listing scales correctly.
#[tokio::test]
#[ignore]
async fn test_org_many_projects() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Create org
    let org = create_test_org(&mut conn, "Many Projects Org");

    // Create 100 projects
    println!("Creating 100 projects...");
    let start = Instant::now();

    for i in 0..100 {
        let input = CreateProject {
            name: format!("Project {}", i),
            license_key_prefix: format!("P{:03}", i),
            redirect_url: None,
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
        };
        let (private_key, public_key) = jwt::generate_keypair();
        queries::create_project(
            &conn,
            &org.id,
            &input,
            &private_key,
            &public_key,
            &master_key,
        )
        .expect("Failed to create project");
    }

    let insert_duration = start.elapsed();
    println!("Created 100 projects in {:?}", insert_duration);

    // Test listing
    println!("\nTesting project listing...");

    let start = Instant::now();
    let projects = queries::list_projects_for_org(&mut conn, &org.id).expect("Failed to list projects");
    let list_duration = start.elapsed();
    assert_eq!(projects.len(), 100, "Should have 100 projects");
    println!("List 100 projects: {:?}", list_duration);
    assert!(
        list_duration.as_millis() < 200,
        "List should complete in <200ms, took {:?}",
        list_duration
    );

    println!("\nAll project tests passed!");
}
