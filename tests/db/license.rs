//! Database license operation tests

#[path = "../common/mod.rs"]
mod common;

use common::*;

// ============ License Creation Tests ============

#[test]
fn test_create_license() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(ONE_YEAR)),
    );

    assert!(!license.id.is_empty(), "license should have a generated ID");
    assert!(
        license.email_hash.is_some(),
        "license should have an email hash set"
    );
    assert_eq!(
        license.product_id, product.id,
        "license product_id should match the created product"
    );
    assert_eq!(
        license.project_id, project.id,
        "license project_id should match the created project"
    );
    assert_eq!(
        license.activation_count, 0,
        "new license should have zero activations"
    );
    assert!(!license.revoked, "new license should not be revoked");
}

#[test]
fn test_create_license_without_identifier_fails() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Try to create a license with no identifier
    let input = CreateLicense {
        email_hash: None,
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
    };

    let result = queries::create_license(&mut conn, &project.id, &product.id, &input);

    assert!(
        result.is_err(),
        "creating license without any identifier should fail"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("at least one identifier"),
        "error message should mention 'at least one identifier', got: {}",
        err
    );
}

#[test]
fn test_create_license_with_customer_id() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    let input = CreateLicense {
        email_hash: Some(test_email_hasher().hash("customer@example.com")),
        customer_id: Some("cust_12345".to_string()),
        expires_at: None,
        updates_expires_at: None,
    };

    let license = queries::create_license(&mut conn, &project.id, &product.id, &input)
        .expect("Failed to create license");

    assert_eq!(
        license.customer_id,
        Some("cust_12345".to_string()),
        "license should store the customer ID"
    );
}

#[test]
fn test_create_transaction_with_license() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Create license first
    let license_input = CreateLicense {
        email_hash: Some(test_email_hasher().hash("customer@example.com")),
        customer_id: None,
        expires_at: Some(future_timestamp(ONE_MONTH)),
        updates_expires_at: Some(future_timestamp(ONE_YEAR)),
    };
    let license = queries::create_license(&mut conn, &project.id, &product.id, &license_input)
        .expect("Failed to create license");

    // Create transaction linked to license
    let tx_input = CreateTransaction {
        license_id: Some(license.id.clone()),
        project_id: project.id.clone(),
        product_id: Some(product.id.clone()),
        org_id: org.id.clone(),
        payment_provider: "stripe".to_string(),
        provider_customer_id: Some("cus_xxx".to_string()),
        provider_subscription_id: Some("sub_yyy".to_string()),
        provider_order_id: "cs_test_xxx".to_string(),
        currency: "usd".to_string(),
        subtotal_cents: 1999,
        discount_cents: 0,
        net_cents: 1999,
        tax_cents: 200,
        total_cents: 2199,
        discount_code: None,
        tax_inclusive: Some(false),
        customer_country: Some("US".to_string()),
        transaction_type: TransactionType::Purchase,
        parent_transaction_id: None,
        is_subscription: true,
        source: "payment".to_string(),
        metadata: None,
        test_mode: false,
    };
    let tx = queries::create_transaction(&mut conn, &tx_input)
        .expect("Failed to create transaction");

    assert_eq!(tx.payment_provider, "stripe");
    assert_eq!(tx.provider_subscription_id, Some("sub_yyy".to_string()));
    assert_eq!(tx.license_id, Some(license.id.clone()));
    assert_eq!(tx.subtotal_cents, 1999);
    assert_eq!(tx.total_cents, 2199);

    // Verify we can look up transaction by provider order
    let found = queries::get_transaction_by_provider_order(&mut conn, "stripe", "cs_test_xxx")
        .expect("Failed to query transaction")
        .expect("Transaction should exist");
    assert_eq!(found.id, tx.id);

    // Verify we can get transactions by license
    let txs = queries::get_transactions_by_license(&mut conn, &license.id)
        .expect("Failed to get transactions by license");
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].id, tx.id);
}

// ============ License Lookup Tests ============

#[test]
fn test_get_license_by_id() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let created = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(ONE_YEAR)),
    );

    let fetched = queries::get_license_by_id(&mut conn, &created.id)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(
        fetched.id, created.id,
        "fetched license ID should match created license ID"
    );
    assert_eq!(
        fetched.product_id, created.product_id,
        "fetched license product_id should match created license"
    );
}

#[test]
fn test_get_license_by_email_hash() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    let email = "unique@example.com";
    let email_hash = test_email_hasher().hash(email);

    let input = CreateLicense {
        email_hash: Some(email_hash.clone()),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
    };

    let created = queries::create_license(&mut conn, &project.id, &product.id, &input)
        .expect("Failed to create license");

    let fetched = queries::get_license_by_email_hash(&mut conn, &project.id, &email_hash)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(
        fetched.id, created.id,
        "license looked up by email hash should match created license"
    );
}

#[test]
fn test_get_license_by_subscription() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Create license
    let license_input = CreateLicense {
        email_hash: Some(test_email_hasher().hash("subscriber@example.com")),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
    };
    let created = queries::create_license(&mut conn, &project.id, &product.id, &license_input)
        .expect("Failed to create license");

    // Create transaction with subscription info
    let tx_input = CreateTransaction {
        license_id: Some(created.id.clone()),
        project_id: project.id.clone(),
        product_id: Some(product.id.clone()),
        org_id: org.id.clone(),
        payment_provider: "stripe".to_string(),
        provider_customer_id: Some("cus_xxx".to_string()),
        provider_subscription_id: Some("sub_unique_id".to_string()),
        provider_order_id: "order_123".to_string(),
        currency: "usd".to_string(),
        subtotal_cents: 999,
        discount_cents: 0,
        net_cents: 999,
        tax_cents: 0,
        total_cents: 999,
        discount_code: None,
        tax_inclusive: None,
        customer_country: None,
        transaction_type: TransactionType::Purchase,
        parent_transaction_id: None,
        is_subscription: true,
        source: "payment".to_string(),
        metadata: None,
        test_mode: false,
    };
    queries::create_transaction(&mut conn, &tx_input).expect("Failed to create transaction");

    let fetched = queries::get_license_by_subscription(&mut conn, "stripe", "sub_unique_id")
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(
        fetched.id, created.id,
        "license looked up by subscription ID should match created license"
    );
}

#[test]
fn test_get_license_by_subscription_wrong_provider() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Create license
    let license_input = CreateLicense {
        email_hash: Some(test_email_hasher().hash("subscriber@example.com")),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
    };
    let license = queries::create_license(&mut conn, &project.id, &product.id, &license_input)
        .expect("Failed to create license");

    // Create transaction with Stripe subscription
    let tx_input = CreateTransaction {
        license_id: Some(license.id.clone()),
        project_id: project.id.clone(),
        product_id: Some(product.id.clone()),
        org_id: org.id.clone(),
        payment_provider: "stripe".to_string(),
        provider_customer_id: None,
        provider_subscription_id: Some("sub_id".to_string()),
        provider_order_id: "order_456".to_string(),
        currency: "usd".to_string(),
        subtotal_cents: 999,
        discount_cents: 0,
        net_cents: 999,
        tax_cents: 0,
        total_cents: 999,
        discount_code: None,
        tax_inclusive: None,
        customer_country: None,
        transaction_type: TransactionType::Purchase,
        parent_transaction_id: None,
        is_subscription: true,
        source: "payment".to_string(),
        metadata: None,
        test_mode: false,
    };
    queries::create_transaction(&mut conn, &tx_input).expect("Failed to create transaction");

    // Same subscription ID but different provider should return None
    let result = queries::get_license_by_subscription(&mut conn, "lemonsqueezy", "sub_id")
        .expect("Query failed");

    assert!(
        result.is_none(),
        "subscription lookup with wrong provider should return None"
    );
}

#[test]
fn test_list_licenses_for_project() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product1 = create_test_product(&mut conn, &project.id, "Free", "free");
    let product2 = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Create licenses for both products
    create_test_license(&mut conn, &project.id, &product1.id, None);
    create_test_license(&mut conn, &project.id, &product1.id, None);
    create_test_license(&mut conn, &project.id, &product2.id, None);

    let licenses = queries::list_licenses_for_project(&mut conn, &project.id).expect("Query failed");

    assert_eq!(
        licenses.len(),
        3,
        "should list all 3 licenses for the project"
    );
    // Verify the product name is included
    assert!(
        licenses.iter().any(|l| l.product_name == "Free"),
        "license list should include Free tier license"
    );
    assert!(
        licenses.iter().any(|l| l.product_name == "Pro"),
        "license list should include Pro tier license"
    );
}

// ============ License Operations Tests ============

#[test]
fn test_increment_activation_count() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    assert_eq!(
        license.activation_count, 0,
        "new license should start with zero activations"
    );

    queries::increment_activation_count(&mut conn, &license.id).expect("Increment failed");
    queries::increment_activation_count(&mut conn, &license.id).expect("Increment failed");
    queries::increment_activation_count(&mut conn, &license.id).expect("Increment failed");

    let updated = queries::get_license_by_id(&mut conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(
        updated.activation_count, 3,
        "activation count should be 3 after 3 increments"
    );
}

#[test]
fn test_revoke_license() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    assert!(!license.revoked, "new license should not be revoked");

    queries::revoke_license(&mut conn, &license.id).expect("Revoke failed");

    let revoked = queries::get_license_by_id(&mut conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert!(
        revoked.revoked,
        "license should be revoked after calling revoke_license"
    );
}

#[test]
fn test_add_revoked_jti_marks_jti_as_revoked() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    // Initially no JTIs are revoked
    assert!(
        !queries::is_jti_revoked(&mut conn, "jti_1").unwrap(),
        "jti_1 should not be revoked initially"
    );
    assert!(
        !queries::is_jti_revoked(&mut conn, "jti_2").unwrap(),
        "jti_2 should not be revoked initially"
    );

    queries::add_revoked_jti(&mut conn, &license.id, "jti_1", Some("test revocation"))
        .expect("Add JTI failed");
    queries::add_revoked_jti(&mut conn, &license.id, "jti_2", None).expect("Add JTI failed");

    // Now both should be revoked
    assert!(
        queries::is_jti_revoked(&mut conn, "jti_1").unwrap(),
        "jti_1 should be revoked after adding"
    );
    assert!(
        queries::is_jti_revoked(&mut conn, "jti_2").unwrap(),
        "jti_2 should be revoked after adding"
    );

    // Adding same JTI again should be idempotent (INSERT OR IGNORE)
    queries::add_revoked_jti(&mut conn, &license.id, "jti_1", None)
        .expect("Add duplicate JTI should not fail");
}

#[test]
fn test_extend_license_expiration() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    let old_exp = future_timestamp(ONE_MONTH);
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(old_exp));

    let new_exp = future_timestamp(ONE_YEAR);
    queries::extend_license_expiration(&mut conn, &license.id, Some(new_exp), Some(new_exp))
        .expect("Extend failed");

    let updated = queries::get_license_by_id(&mut conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(
        updated.expires_at,
        Some(new_exp),
        "license expires_at should be extended to new date"
    );
    assert_eq!(
        updated.updates_expires_at,
        Some(new_exp),
        "license updates_expires_at should be extended to new date"
    );
}

// ============ License Update Tests ============

/// Tests that update_license correctly handles partial updates.
///
/// Bug: The old implementation overwrote all fields unconditionally - passing None
/// would set columns to NULL, wiping data. This test ensures that:
/// - None = don't change the field (skip)
/// - Some(None) = explicitly set to NULL
/// - Some(Some(value)) = set to value
#[test]
fn test_update_license_partial_update_preserves_other_fields() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Create license with all fields populated
    let original_email_hash = test_email_hasher().hash("original@example.com");
    let original_customer_id = "cust_original".to_string();
    let original_expires_at = future_timestamp(ONE_YEAR);
    let original_updates_expires_at = future_timestamp(ONE_MONTH);

    let input = CreateLicense {
        email_hash: Some(original_email_hash.clone()),
        customer_id: Some(original_customer_id.clone()),
        expires_at: Some(original_expires_at),
        updates_expires_at: Some(original_updates_expires_at),
    };
    let license =
        queries::create_license(&mut conn, &project.id, &product.id, &input).expect("Create failed");

    // Update ONLY the email_hash, leaving other fields unchanged
    let new_email_hash = test_email_hasher().hash("new@example.com");
    let update = UpdateLicense {
        email_hash: Some(new_email_hash.clone()),
        customer_id: None,         // Don't change
        expires_at: None,          // Don't change
        updates_expires_at: None,  // Don't change
    };
    let result = queries::update_license(&conn, &license.id, &update).expect("Update failed");
    assert!(result, "update should return true when license exists");

    // Verify: email_hash changed, all other fields preserved
    let updated = queries::get_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert_eq!(
        updated.email_hash,
        Some(new_email_hash),
        "email_hash should be updated to new value"
    );
    assert_eq!(
        updated.customer_id,
        Some(original_customer_id),
        "customer_id should be PRESERVED when update passes None"
    );
    assert_eq!(
        updated.expires_at,
        Some(original_expires_at),
        "expires_at should be PRESERVED when update passes None"
    );
    assert_eq!(
        updated.updates_expires_at,
        Some(original_updates_expires_at),
        "updates_expires_at should be PRESERVED when update passes None"
    );
}

/// Tests that update_license can explicitly set fields to NULL using Some(None).
#[test]
fn test_update_license_explicit_null_sets_field_to_null() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    // Create license with expiration dates set
    let input = CreateLicense {
        email_hash: Some(test_email_hasher().hash("user@example.com")),
        customer_id: Some("cust_123".to_string()),
        expires_at: Some(future_timestamp(ONE_YEAR)),
        updates_expires_at: Some(future_timestamp(ONE_MONTH)),
    };
    let license =
        queries::create_license(&mut conn, &project.id, &product.id, &input).expect("Create failed");

    // Explicitly set expires_at to NULL (convert to perpetual license)
    // while preserving other fields
    let update = UpdateLicense {
        email_hash: None,                    // Don't change
        customer_id: None,                   // Don't change
        expires_at: Some(None),              // Explicitly set to NULL (perpetual)
        updates_expires_at: None,            // Don't change
    };
    queries::update_license(&conn, &license.id, &update).expect("Update failed");

    let updated = queries::get_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("License not found");

    assert!(
        updated.expires_at.is_none(),
        "expires_at should be NULL after explicit Some(None)"
    );
    assert!(
        updated.updates_expires_at.is_some(),
        "updates_expires_at should be PRESERVED (not wiped)"
    );
    assert!(
        updated.customer_id.is_some(),
        "customer_id should be PRESERVED (not wiped)"
    );
}

/// Tests that update_license returns false for non-existent licenses.
#[test]
fn test_update_license_nonexistent_returns_false() {
    let conn = setup_test_db();

    let update = UpdateLicense {
        email_hash: Some("new_hash".to_string()),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
    };
    let result =
        queries::update_license(&conn, "nonexistent_license_id", &update).expect("Query failed");

    assert!(
        !result,
        "update_license should return false for non-existent license"
    );
}

/// Tests that update_license ignores soft-deleted licenses.
#[test]
fn test_update_license_ignores_soft_deleted() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(
        &mut conn,
        &project.id,
        &product.id,
        Some(future_timestamp(ONE_YEAR)),
    );

    let original_email_hash = license.email_hash.clone();

    // Soft delete the license
    queries::soft_delete_license(&mut conn, &license.id).expect("Soft delete failed");

    // Try to update the soft-deleted license
    let update = UpdateLicense {
        email_hash: Some("new_hash".to_string()),
        customer_id: None,
        expires_at: None,
        updates_expires_at: None,
    };
    let result = queries::update_license(&conn, &license.id, &update).expect("Query failed");

    assert!(
        !result,
        "update_license should return false for soft-deleted license"
    );

    // Verify the deleted license was not modified
    let deleted_license = queries::get_deleted_license_by_id(&conn, &license.id)
        .expect("Query failed")
        .expect("Deleted license should exist");
    assert_eq!(
        deleted_license.email_hash, original_email_hash,
        "soft-deleted license should not have been modified"
    );
}

// ============ Activation Code Tests ============

#[test]
fn test_create_activation_code() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let code = queries::create_activation_code(&mut conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    assert!(
        !code.code.is_empty(),
        "activation code should have a generated code"
    );
    assert!(
        code.code.starts_with("TEST-"),
        "activation code should start with PREFIX-"
    ); // PREFIX-XXXX-XXXX format
    assert_eq!(
        code.license_id, license.id,
        "activation code should be linked to the license"
    );
    assert!(
        !code.used,
        "new activation code should not be marked as used"
    );
    assert!(
        code.expires_at > now(),
        "activation code should expire in the future"
    ); // Expires in the future
}

#[test]
fn test_activation_code_format() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let code = queries::create_activation_code(&mut conn, &license.id, "MYAPP")
        .expect("Failed to create activation code");

    // Format should be PREFIX-XXXX-XXXX (40 bits entropy)
    assert!(
        code.code.starts_with("MYAPP-"),
        "code should start with the specified prefix"
    );
    let parts: Vec<&str> = code.code.split('-').collect();
    assert_eq!(
        parts.len(),
        3,
        "code should have 3 parts separated by dashes"
    );
    assert_eq!(parts[0], "MYAPP", "first part should be the prefix");
    for (i, part) in parts[1..].iter().enumerate() {
        assert_eq!(part.len(), 4, "part {} should be 4 characters", i + 1);
    }
}

#[test]
fn test_get_activation_code_by_code() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let created = queries::create_activation_code(&mut conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    let fetched = queries::get_activation_code_by_code(&mut conn, &created.code)
        .expect("Query failed")
        .expect("Code not found");

    assert_eq!(
        fetched.license_id, created.license_id,
        "fetched activation code license_id should match created code"
    );
    assert_eq!(
        fetched.license_id, license.id,
        "fetched activation code should be linked to the correct license"
    );
}

#[test]
fn test_mark_activation_code_used() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let code = queries::create_activation_code(&mut conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    assert!(
        !code.used,
        "new activation code should not be marked as used"
    );

    queries::mark_activation_code_used(&mut conn, &code.code).expect("Mark used failed");

    let updated = queries::get_activation_code_by_code(&mut conn, &code.code)
        .expect("Query failed")
        .expect("Code not found");

    assert!(
        updated.used,
        "activation code should be marked as used after calling mark_activation_code_used"
    );
}

// ============ Activation Code Atomic Claim Tests ============

#[test]
fn test_try_claim_activation_code_success() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let code = queries::create_activation_code(&mut conn, &license.id, "TEST")
        .expect("Failed to create activation code");
    assert!(!code.used, "new code should not be used");

    // Claim the code
    let claimed = queries::try_claim_activation_code(&conn, &code.code)
        .expect("try_claim should not error")
        .expect("claim should return Some for valid unused code");

    assert!(claimed.used, "claimed code should have used=true");
    assert_eq!(
        claimed.license_id, license.id,
        "claimed code should be linked to the correct license"
    );
    assert_eq!(
        claimed.expires_at, code.expires_at,
        "expiry should not change after claiming"
    );

    // Verify via separate query that the code is marked used in DB
    let fetched = queries::get_activation_code_by_code(&conn, &code.code)
        .expect("query failed")
        .expect("code should still exist");
    assert!(fetched.used, "code should be marked used in DB after claim");
}

#[test]
fn test_try_claim_activation_code_already_used() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let code = queries::create_activation_code(&mut conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    // First claim succeeds
    let first = queries::try_claim_activation_code(&conn, &code.code)
        .expect("try_claim should not error");
    assert!(first.is_some(), "first claim should succeed");

    // Second claim of the same code should fail
    let second = queries::try_claim_activation_code(&conn, &code.code)
        .expect("try_claim should not error");
    assert!(
        second.is_none(),
        "second claim of already-used code should return None"
    );

    // Third attempt also fails -- idempotent rejection
    let third = queries::try_claim_activation_code(&conn, &code.code)
        .expect("try_claim should not error");
    assert!(
        third.is_none(),
        "third claim of already-used code should also return None"
    );
}

#[test]
fn test_try_claim_activation_code_expired() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let code = queries::create_activation_code(&mut conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    // Expire the code by setting expires_at to the past
    let past = now() - 60;
    conn.execute(
        "UPDATE activation_codes SET expires_at = ?1 WHERE code_hash = ?2",
        rusqlite::params![past, paycheck::crypto::hash_secret(&code.code)],
    )
    .expect("failed to expire code");

    // Claiming an expired code should fail
    let result = queries::try_claim_activation_code(&conn, &code.code)
        .expect("try_claim should not error");
    assert!(
        result.is_none(),
        "claiming an expired code should return None"
    );

    // Verify the code still exists and is NOT marked as used (expiry prevented claim, not usage)
    let fetched = queries::get_activation_code_by_code(&conn, &code.code)
        .expect("query failed")
        .expect("code should still exist in DB");
    assert!(
        !fetched.used,
        "expired code should not be marked as used after failed claim"
    );
}

#[test]
fn test_try_claim_activation_code_nonexistent() {
    let conn = setup_test_db();

    let result = queries::try_claim_activation_code(&conn, "FAKE-XXXX-YYYY")
        .expect("try_claim should not error");
    assert!(
        result.is_none(),
        "claiming a nonexistent code should return None"
    );
}

#[test]
fn test_try_claim_activation_code_concurrent() {
    // Verify the CAS pattern prevents double-redemption under concurrent access.
    // Multiple threads try to claim the same code -- exactly 1 should win.

    use rusqlite::Connection;
    use std::sync::{Arc, Barrier};

    let num_threads = 5;
    let db_path = format!(
        "/tmp/claude/test_claim_code_concurrent_{}.db",
        uuid::Uuid::new_v4()
    );

    let conn = Connection::open(&db_path).expect("Failed to create test db");
    init_db(&conn).expect("Failed to init schema");

    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, None);

    let code = queries::create_activation_code(&conn, &license.id, "TEST")
        .expect("Failed to create activation code");
    let code_str = Arc::new(code.code.clone());

    drop(conn);

    let barrier = Arc::new(Barrier::new(num_threads));
    let db_path_arc = Arc::new(db_path.clone());

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let db_path = Arc::clone(&db_path_arc);
            let code_str = Arc::clone(&code_str);

            std::thread::spawn(move || {
                let thread_conn =
                    Connection::open(db_path.as_str()).expect("thread failed to open db");
                thread_conn
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .expect("failed to set busy timeout");

                barrier.wait();

                queries::try_claim_activation_code(&thread_conn, &code_str)
                    .expect("try_claim should not error")
                    .is_some()
            })
        })
        .collect();

    let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let claim_count = results.iter().filter(|&&r| r).count();

    assert_eq!(
        claim_count, 1,
        "exactly 1 of {} concurrent claims should succeed, got {}",
        num_threads, claim_count
    );

    // Verify DB state: code should be marked as used
    let verify_conn = Connection::open(&db_path).expect("failed to open db for verification");
    let fetched = queries::get_activation_code_by_code(&verify_conn, &code.code)
        .expect("query failed")
        .expect("code should exist");
    assert!(fetched.used, "code should be marked as used after concurrent race");

    std::fs::remove_file(&db_path).ok();
}

#[test]
fn test_cleanup_expired_activation_codes() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    // Create 3 codes
    let expired_code = queries::create_activation_code(&mut conn, &license.id, "EXP")
        .expect("create failed");
    let used_code = queries::create_activation_code(&mut conn, &license.id, "USED")
        .expect("create failed");
    let fresh_code = queries::create_activation_code(&mut conn, &license.id, "FRESH")
        .expect("create failed");

    // Expire one code
    let past = now() - 60;
    conn.execute(
        "UPDATE activation_codes SET expires_at = ?1 WHERE code_hash = ?2",
        rusqlite::params![past, paycheck::crypto::hash_secret(&expired_code.code)],
    )
    .expect("failed to expire code");

    // Mark one code as used (via try_claim)
    queries::try_claim_activation_code(&conn, &used_code.code)
        .expect("claim should succeed")
        .expect("should return Some");

    // Cleanup: should remove expired codes AND used codes
    // (implementation: DELETE WHERE expires_at < now OR used = 1)
    let deleted = queries::cleanup_expired_activation_codes(&conn)
        .expect("cleanup should succeed");
    assert_eq!(deleted, 2, "should delete 1 expired + 1 used code");

    // Fresh code should survive
    let still_exists = queries::get_activation_code_by_code(&conn, &fresh_code.code)
        .expect("query failed");
    assert!(
        still_exists.is_some(),
        "fresh unused code should survive cleanup"
    );

    // Expired code should be gone
    let expired_gone = queries::get_activation_code_by_code(&conn, &expired_code.code)
        .expect("query failed");
    assert!(
        expired_gone.is_none(),
        "expired code should be removed by cleanup"
    );

    // Used code should be gone
    let used_gone = queries::get_activation_code_by_code(&conn, &used_code.code)
        .expect("query failed");
    assert!(
        used_gone.is_none(),
        "used code should be removed by cleanup"
    );
}

#[test]
fn test_cleanup_activation_codes_empty_table() {
    let conn = setup_test_db();

    let deleted = queries::cleanup_expired_activation_codes(&conn)
        .expect("cleanup should succeed");
    assert_eq!(deleted, 0, "nothing to clean up on empty table");
}

// ============ Email Hash Tests ============

#[test]
fn test_email_hash_consistency() {
    // Same email should always produce the same hash
    let hash1 = test_email_hasher().hash("test@example.com");
    let hash2 = test_email_hasher().hash("test@example.com");
    assert_eq!(
        hash1, hash2,
        "same email should always produce the same hash"
    );
}

#[test]
fn test_email_hash_case_insensitive() {
    // Email hashing should be case-insensitive
    let hash1 = test_email_hasher().hash("Test@Example.COM");
    let hash2 = test_email_hasher().hash("test@example.com");
    assert_eq!(hash1, hash2, "email hashing should be case-insensitive");
}

#[test]
fn test_email_hash_trims_whitespace() {
    // Email hashing should trim whitespace
    let hash1 = test_email_hasher().hash("  test@example.com  ");
    let hash2 = test_email_hasher().hash("test@example.com");
    assert_eq!(
        hash1, hash2,
        "email hashing should trim leading and trailing whitespace"
    );
}

#[test]
fn test_email_hash_unicode_normalization() {
    // Email hashing should normalize Unicode to NFC form
    // This ensures that different representations of the same character hash identically
    //
    // "café" can be represented two ways:
    // - NFC (composed): é as U+00E9 (single codepoint)
    // - NFD (decomposed): e (U+0065) + combining acute accent (U+0301)
    //
    // macOS often uses NFD, while Windows uses NFC. Without normalization,
    // a user could fail to recover their license because the email hash doesn't match.

    // NFC form: é as a single character (U+00E9)
    let email_nfc = "caf\u{00E9}@example.com";
    // NFD form: e + combining acute accent (U+0065 U+0301)
    let email_nfd = "cafe\u{0301}@example.com";

    let hash_nfc = test_email_hasher().hash(email_nfc);
    let hash_nfd = test_email_hasher().hash(email_nfd);

    assert_eq!(
        hash_nfc, hash_nfd,
        "NFC and NFD representations of the same email should produce identical hashes"
    );

    // Also verify with another common case: ñ (Spanish)
    let email_nfc_es = "se\u{00F1}or@example.com"; // ñ as U+00F1
    let email_nfd_es = "sen\u{0303}or@example.com"; // n + combining tilde
    assert_eq!(
        test_email_hasher().hash(email_nfc_es),
        test_email_hasher().hash(email_nfd_es),
        "Unicode normalization should work for ñ"
    );
}

// ============ License Expiration Tests ============

#[test]
fn test_license_with_expiration() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    let exp = future_timestamp(ONE_YEAR);
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(exp));

    assert_eq!(
        license.expires_at,
        Some(exp),
        "license should have the specified expiration date"
    );
}

#[test]
fn test_license_without_expiration() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");

    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    assert!(
        license.expires_at.is_none(),
        "perpetual license should have no expiration date"
    ); // Perpetual license
}

// ============ Cascade Delete Tests ============

#[test]
fn test_delete_product_cascades_to_licenses() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    queries::delete_product(&mut conn, &product.id).expect("Delete failed");

    let result = queries::get_license_by_id(&mut conn, &license.id).expect("Query failed");
    assert!(
        result.is_none(),
        "license should be deleted when parent product is deleted"
    );
}

#[test]
fn test_delete_license_cascades_to_activation_codes() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let code = queries::create_activation_code(&mut conn, &license.id, "TEST")
        .expect("Failed to create activation code");

    // Delete the product (which cascades to licenses, which cascades to codes)
    queries::delete_product(&mut conn, &product.id).expect("Delete failed");

    let result = queries::get_activation_code_by_code(&mut conn, &code.code).expect("Query failed");
    assert!(
        result.is_none(),
        "activation code should be deleted when parent license is deleted"
    );
}
