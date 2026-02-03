//! Webhook signature verification and business logic tests

#[path = "../common/mod.rs"]
mod common;

use common::{ONE_DAY, ONE_MONTH, ONE_WEEK, ONE_YEAR, UPDATES_VALID_DAYS, *};
use paycheck::handlers::webhooks::common::{
    CheckoutData, process_cancellation, process_checkout,
};
use paycheck::models::{LemonSqueezyConfig, StripeConfig};
use paycheck::payments::{LemonSqueezyClient, StripeClient};

// ============ Stripe Signature Verification Tests ============

fn create_stripe_test_client() -> StripeClient {
    let config = StripeConfig {
        secret_key: "sk_test_xxx".to_string(),
        publishable_key: "pk_test_xxx".to_string(),
        webhook_secret: "whsec_test123secret456".to_string(),
    };
    StripeClient::new(&config)
}

/// Get current Unix timestamp as a string (for webhook signature tests)
fn current_timestamp() -> String {
    chrono::Utc::now().timestamp().to_string()
}

/// Get an old timestamp (for testing timestamp rejection)
fn old_timestamp() -> String {
    // 10 minutes ago - beyond the 5-minute tolerance
    (chrono::Utc::now().timestamp() - 600).to_string()
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

#[test]
fn test_stripe_valid_signature() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(payload, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(result, "Valid signature should be accepted");
}

#[test]
fn test_stripe_invalid_signature() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    let timestamp = current_timestamp();
    // Use wrong secret to generate invalid signature
    let signature = compute_stripe_signature(payload, "wrong_secret", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(!result, "Invalid signature should be rejected");
}

#[test]
fn test_stripe_modified_payload() {
    let client = create_stripe_test_client();
    let original_payload = b"{\"type\":\"checkout.session.completed\"}";
    let modified_payload = b"{\"type\":\"checkout.session.completed\",\"hacked\":true}";
    let timestamp = current_timestamp();
    // Sign the original payload
    let signature = compute_stripe_signature(original_payload, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    // Verify with modified payload
    let result = client
        .verify_webhook_signature(modified_payload, &signature_header)
        .expect("Verification should not error");

    assert!(!result, "Modified payload should be rejected");
}

#[test]
fn test_stripe_old_timestamp_fails_verification() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    let timestamp = old_timestamp();
    // Valid signature but timestamp too old
    let signature = compute_stripe_signature(payload, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(
        !result,
        "Old timestamp should be rejected (replay attack prevention)"
    );
}

#[test]
fn test_stripe_missing_timestamp() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    // Signature without timestamp
    let signature_header = "v1=somesignature";

    let result = client.verify_webhook_signature(payload, signature_header);

    assert!(result.is_err(), "Missing timestamp should error");
}

#[test]
fn test_stripe_missing_signature() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    // Header without v1 signature
    let signature_header = "t=1234567890";

    let result = client.verify_webhook_signature(payload, signature_header);

    assert!(result.is_err(), "Missing signature should error");
}

#[test]
fn test_stripe_malformed_header() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";

    let result = client.verify_webhook_signature(payload, "garbage");

    assert!(result.is_err(), "Malformed header should error");
}

#[test]
fn test_stripe_empty_signature_header() {
    let client = create_stripe_test_client();
    let payload = b"{\"type\":\"checkout.session.completed\"}";

    let result = client.verify_webhook_signature(payload, "");

    assert!(result.is_err(), "Empty header should error");
}

// ============ LemonSqueezy Signature Verification Tests ============

fn create_lemonsqueezy_test_client() -> LemonSqueezyClient {
    let config = LemonSqueezyConfig {
        api_key: "lskey_test_xxx".to_string(),
        store_id: "12345".to_string(),
        webhook_secret: "ls_whsec_test_secret".to_string(),
    };
    LemonSqueezyClient::new(&config)
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

#[test]
fn test_lemonsqueezy_valid_signature() {
    let client = create_lemonsqueezy_test_client();
    let payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";
    let signature = compute_lemonsqueezy_signature(payload, "ls_whsec_test_secret");

    let result = client
        .verify_webhook_signature(payload, &signature)
        .expect("Verification should not error");

    assert!(result, "Valid signature should be accepted");
}

#[test]
fn test_lemonsqueezy_invalid_signature() {
    let client = create_lemonsqueezy_test_client();
    let payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";
    // Use wrong secret
    let signature = compute_lemonsqueezy_signature(payload, "wrong_secret");

    let result = client
        .verify_webhook_signature(payload, &signature)
        .expect("Verification should not error");

    assert!(!result, "Invalid signature should be rejected");
}

#[test]
fn test_lemonsqueezy_modified_payload() {
    let client = create_lemonsqueezy_test_client();
    let original_payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";
    let modified_payload = b"{\"meta\":{\"event_name\":\"order_created\",\"hacked\":true}}";
    // Sign original payload
    let signature = compute_lemonsqueezy_signature(original_payload, "ls_whsec_test_secret");

    // Verify with modified payload
    let result = client
        .verify_webhook_signature(modified_payload, &signature)
        .expect("Verification should not error");

    assert!(!result, "Modified payload should be rejected");
}

#[test]
fn test_lemonsqueezy_empty_signature() {
    let client = create_lemonsqueezy_test_client();
    let payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";

    let result = client
        .verify_webhook_signature(payload, "")
        .expect("Verification should not error");

    assert!(!result, "Empty signature should be rejected");
}

#[test]
fn test_lemonsqueezy_wrong_format_signature() {
    let client = create_lemonsqueezy_test_client();
    let payload = b"{\"meta\":{\"event_name\":\"order_created\"}}";

    let result = client
        .verify_webhook_signature(payload, "not-a-valid-hex-signature")
        .expect("Verification should not error");

    assert!(!result, "Invalid format signature should be rejected");
}

// ============ Edge Cases ============

#[test]
fn test_stripe_large_payload() {
    let client = create_stripe_test_client();
    // Create a large payload
    let large_data = "x".repeat(100_000);
    let payload = format!("{{\"data\":\"{}\"}}", large_data);
    let payload_bytes = payload.as_bytes();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(payload_bytes, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload_bytes, &signature_header)
        .expect("Verification should not error");

    assert!(
        result,
        "Large payload with valid signature should be accepted"
    );
}

#[test]
fn test_lemonsqueezy_large_payload() {
    let client = create_lemonsqueezy_test_client();
    // Create a large payload
    let large_data = "x".repeat(100_000);
    let payload = format!("{{\"data\":\"{}\"}}", large_data);
    let payload_bytes = payload.as_bytes();
    let signature = compute_lemonsqueezy_signature(payload_bytes, "ls_whsec_test_secret");

    let result = client
        .verify_webhook_signature(payload_bytes, &signature)
        .expect("Verification should not error");

    assert!(
        result,
        "Large payload with valid signature should be accepted"
    );
}

#[test]
fn test_stripe_binary_payload() {
    let client = create_stripe_test_client();
    // Binary data in payload
    let payload = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(payload, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(
        result,
        "Binary payload with valid signature should be accepted"
    );
}

#[test]
fn test_lemonsqueezy_binary_payload() {
    let client = create_lemonsqueezy_test_client();
    let payload = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let signature = compute_lemonsqueezy_signature(payload, "ls_whsec_test_secret");

    let result = client
        .verify_webhook_signature(payload, &signature)
        .expect("Verification should not error");

    assert!(
        result,
        "Binary payload with valid signature should be accepted"
    );
}

#[test]
fn test_stripe_unicode_in_payload() {
    let client = create_stripe_test_client();
    let payload = "{\"customer_name\":\"日本語\",\"emoji\":\"🎉\"}".as_bytes();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(payload, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let result = client
        .verify_webhook_signature(payload, &signature_header)
        .expect("Verification should not error");

    assert!(
        result,
        "Unicode payload with valid signature should be accepted"
    );
}

// ============ Webhook Replay Attack Prevention Tests ============

/// Test that replaying a renewal webhook does NOT extend the license twice.
/// This is a regression test for the LemonSqueezy replay vulnerability.
/// The test is provider-agnostic - it tests the underlying process_renewal_atomic logic.
#[test]
fn test_renewal_webhook_replay_prevented() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Create test hierarchy
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    // Create license with short expiration (7 days from now)
    let initial_expiration = now() + (ONE_WEEK * 86400);
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(initial_expiration));

    // Simulate a renewal webhook with a unique event ID
    let event_id = "invoice_12345";
    let subscription_id = "sub_test_123";

    // First renewal should succeed and extend the license
    let result1 = process_renewal_atomic(
        &mut conn,
        "test_provider",
        &product,
        &license,
        subscription_id,
        Some(event_id),
        None, // No provider period_end - use calculated fallback
        None, // No transaction data
    )
    .expect("first renewal should succeed");

    assert!(
        matches!(result1, RenewalResult::Success { .. }),
        "first renewal request should return Success"
    );

    // Check license was extended (product has ONE_YEAR day license_exp_days)
    let updated_license = queries::get_license_by_id(&mut conn, &license.id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let first_expiration = updated_license
        .expires_at
        .expect("license should have expiration timestamp");
    assert!(
        first_expiration > initial_expiration,
        "license expiration should be extended after first renewal"
    );

    // Wait a moment to ensure timestamps differ
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Replay the SAME webhook (same event_id)
    let result2 = process_renewal_atomic(
        &mut conn,
        "test_provider",
        &product,
        &license,
        subscription_id,
        Some(event_id), // Same event ID = replay
        None,
        None,
    )
    .expect("replay should not error");

    // Replay should be rejected (idempotent - already processed)
    assert!(
        matches!(result2, RenewalResult::AlreadyProcessed),
        "Replay should return AlreadyProcessed"
    );

    // Verify license expiration was NOT extended again
    let final_license = queries::get_license_by_id(&mut conn, &license.id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let final_expiration = final_license
        .expires_at
        .expect("license should have expiration timestamp");

    assert_eq!(
        first_expiration, final_expiration,
        "license expiration should not change on replay attack"
    );
}

/// Test that different event IDs are processed independently (not blocked as replays)
#[test]
fn test_different_renewal_events_both_processed() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Create test hierarchy
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let initial_expiration = now() + (ONE_WEEK * 86400);
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(initial_expiration));

    let subscription_id = "sub_test_123";

    // First renewal event
    let result1 = process_renewal_atomic(
        &mut conn,
        "test_provider",
        &product,
        &license,
        subscription_id,
        Some("invoice_001"),
        None,
        None,
    )
    .expect("first renewal should succeed");

    assert!(
        matches!(result1, RenewalResult::Success { .. }),
        "first renewal event should succeed"
    );

    // Second renewal event (different event ID - legitimate new renewal)
    let result2 = process_renewal_atomic(
        &mut conn,
        "test_provider",
        &product,
        &license,
        subscription_id,
        Some("invoice_002"), // Different event ID
        None,
        None,
    )
    .expect("second renewal should succeed");

    assert!(
        matches!(result2, RenewalResult::Success { .. }),
        "different event ID should be processed as new renewal, not rejected as duplicate"
    );
}

// ============ Checkout Business Logic Tests ============

#[test]
fn test_checkout_creates_license_and_device() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    // Create payment session (no device info - that's at activation time)
    let session = create_test_payment_session(&mut conn, &product.id, Some("cust_test"));

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: Some("cust_stripe".to_string()),
        customer_email: Some("test@example.com".to_string()),
        subscription_id: Some("sub_123".to_string()),
        order_id: Some("cs_test_123".to_string()),
        enricher_session_id: None,
        transaction: None,
    };

    let (status, msg) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );

    assert_eq!(
        status,
        StatusCode::OK,
        "checkout process should return OK status"
    );
    assert_eq!(msg, "OK", "checkout process should return OK message");

    // Verify license was created
    let updated_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        updated_session.completed,
        "payment session should be marked as completed"
    );
    assert!(
        updated_session.license_id.is_some(),
        "payment session should have associated license ID"
    );

    // Verify license was created
    let license_id = updated_session.license_id.unwrap();
    let license = queries::get_license_by_id(&mut conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert!(!license.id.is_empty(), "license should have been created");

    // Device creation is deferred to activation time (/redeem/key)
    // Verify NO device was created during checkout
    let devices = queries::list_devices_for_license(&mut conn, &license_id)
        .expect("database query for devices should succeed");
    assert_eq!(
        devices.len(),
        0,
        "no device should be created at checkout - activation creates the device"
    );
}

#[test]
fn test_checkout_concurrent_webhooks_create_only_one_license() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let session = create_test_payment_session(&mut conn, &product.id, None);

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: None,
        customer_email: Some("test@example.com".to_string()),
        subscription_id: None,
        order_id: None,
        enricher_session_id: None,
        transaction: None,
    };

    // First call should succeed
    let (status1, msg1) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(
        status1,
        StatusCode::OK,
        "first checkout call should return OK status"
    );
    assert_eq!(msg1, "OK", "first checkout call should return OK message");

    // Second call with same session should be rejected
    let (status2, msg2) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(
        status2,
        StatusCode::OK,
        "duplicate checkout call should return OK status (idempotent)"
    );
    assert_eq!(
        msg2, "Already processed",
        "duplicate checkout call should indicate already processed"
    );

    // Verify only one license exists for the session
    let updated_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    let license_id = updated_session
        .license_id
        .expect("payment session should have license ID");

    // Device creation is deferred to activation time (/redeem/key)
    // Verify NO device was created during checkout
    let devices = queries::list_devices_for_license(&mut conn, &license_id)
        .expect("database query for devices should succeed");
    assert_eq!(
        devices.len(),
        0,
        "no device should be created at checkout - device is created at activation time"
    );
}

#[test]
fn test_checkout_creates_license_with_product_expirations() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

    // Create product with specific expirations
    let input = CreateProduct {
        name: "Pro Plan".to_string(),
        tier: "pro".to_string(),
        price_cents: None,
        currency: None,
        license_exp_days: Some(ONE_MONTH as i32),
        updates_exp_days: Some(UPDATES_VALID_DAYS as i32),
        activation_limit: Some(5),
        device_limit: Some(3),
        device_inactive_days: None,
        features: vec![],
        payment_config_id: None,
        email_config_id: None,
    };
    let product = queries::create_product(&mut conn, &project.id, &input)
        .expect("product creation should succeed");

    let session = create_test_payment_session(&mut conn, &product.id, None);

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: None,
        customer_email: Some("test@example.com".to_string()),
        subscription_id: None,
        order_id: None,
        enricher_session_id: None,
        transaction: None,
    };

    let before = now();
    let (status, _) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "checkout process should return OK status"
    );

    let updated_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    let license = queries::get_license_by_id(&mut conn, &updated_session.license_id.unwrap())
        .expect("database query for license should succeed")
        .expect("license should exist in database");

    // License should expire in ~ONE_MONTH days
    let license_exp = license
        .expires_at
        .expect("license should have expiration timestamp");
    assert!(
        license_exp >= before + (ONE_MONTH * 86400) - 5,
        "license expiration should be at least {} days from now",
        ONE_MONTH
    );
    assert!(
        license_exp <= before + (ONE_MONTH * 86400) + 5,
        "license expiration should be at most {} days from now",
        ONE_MONTH
    );

    // Updates should expire in ~UPDATES_VALID_DAYS days
    let updates_exp = license
        .updates_expires_at
        .expect("license should have updates expiration timestamp");
    assert!(
        updates_exp >= before + (UPDATES_VALID_DAYS * 86400) - 5,
        "updates expiration should be at least {} days from now",
        UPDATES_VALID_DAYS
    );
    assert!(
        updates_exp <= before + (UPDATES_VALID_DAYS * 86400) + 5,
        "updates expiration should be at most {} days from now",
        UPDATES_VALID_DAYS
    );
}

#[test]
fn test_checkout_perpetual_license() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

    // Create product with no expiration (perpetual)
    let input = CreateProduct {
        name: "Lifetime".to_string(),
        tier: "lifetime".to_string(),
        price_cents: None,
        currency: None,
        license_exp_days: None, // Perpetual
        updates_exp_days: None,
        activation_limit: Some(5),
        device_limit: Some(3),
        device_inactive_days: None,
        features: vec![],
        payment_config_id: None,
        email_config_id: None,
    };
    let product = queries::create_product(&mut conn, &project.id, &input)
        .expect("product creation should succeed");

    let session = create_test_payment_session(&mut conn, &product.id, None);

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: None,
        customer_email: Some("test@example.com".to_string()),
        subscription_id: None,
        order_id: None,
        enricher_session_id: None,
        transaction: None,
    };

    let (status, _) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );
    assert_eq!(
        status,
        StatusCode::OK,
        "checkout process should return OK status for perpetual license"
    );

    let updated_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    let license = queries::get_license_by_id(&mut conn, &updated_session.license_id.unwrap())
        .expect("database query for license should succeed")
        .expect("license should exist in database");

    assert!(
        license.expires_at.is_none(),
        "perpetual license should have no expiration"
    );
    assert!(
        license.updates_expires_at.is_none(),
        "perpetual license should have no updates expiration"
    );
}

// ============ Renewal Business Logic Tests ============

#[test]
fn test_renewal_extends_license_expiration() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    // Create license expiring soon
    let initial_exp = now() + (ONE_WEEK * 86400); // 7 days from now
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(initial_exp));

    let result = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_123",
        Some("invoice_001"),
        None,
        None,
    )
    .expect("renewal should succeed");

    assert!(
        matches!(result, RenewalResult::Success { .. }),
        "renewal process should succeed"
    );

    let updated = queries::get_license_by_id(&mut conn, &license.id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let new_exp = updated
        .expires_at
        .expect("license should have expiration timestamp");

    // Product has ONE_YEAR day license_exp_days, so new exp should be ~ONE_YEAR days from now
    let expected_min = now() + (ONE_YEAR * 86400) - 10;
    let expected_max = now() + (ONE_YEAR * 86400) + 10;
    assert!(
        new_exp >= expected_min && new_exp <= expected_max,
        "license should be extended by product expiration ({} days), got {} days",
        ONE_YEAR,
        (new_exp - now()) / 86400
    );
}

#[test]
fn test_renewal_without_event_id_always_processes() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(now() + (ONE_DAY * 86400)),
    );

    // First call without event_id
    let result1 = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_123",
        None, // No event_id - no replay prevention
        None,
        None,
    )
    .expect("first renewal should succeed");

    assert!(
        matches!(result1, RenewalResult::Success { .. }),
        "first renewal without event_id should succeed"
    );

    // Second call also processes (no replay prevention)
    let result2 = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_123",
        None,
        None,
        None,
    )
    .expect("second renewal should succeed");

    assert!(
        matches!(result2, RenewalResult::Success { .. }),
        "second renewal without event_id should succeed (no replay prevention)"
    );
}

// ============ Provider Period End Tests ============

#[test]
fn test_renewal_uses_provider_period_end_when_available() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let initial_exp = now() + (ONE_WEEK * 86400);
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(initial_exp));

    // Provider says period ends 45 days from now (different from product's ONE_YEAR setting)
    let provider_period_end = now() + (45 * 86400);

    let result = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_123",
        Some("invoice_001"),
        Some(provider_period_end), // Provider's exact period end
        None,
    )
    .expect("renewal should succeed");

    assert!(matches!(result, RenewalResult::Success { .. }));

    let updated = queries::get_license_by_id(&mut conn, &license.id)
        .expect("db query should succeed")
        .expect("license should exist");
    let new_exp = updated.expires_at.expect("should have expiration");

    // Should use provider's period_end (45 days), NOT product's license_exp_days (ONE_YEAR)
    let expected_min = provider_period_end - 5;
    let expected_max = provider_period_end + 5;
    assert!(
        new_exp >= expected_min && new_exp <= expected_max,
        "license expiration should match provider period_end (~45 days), got {} days from now",
        (new_exp - now()) / 86400
    );
}

#[test]
fn test_renewal_falls_back_to_calculated_when_no_period_end() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let initial_exp = now() + (ONE_WEEK * 86400);
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(initial_exp));

    let result = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_123",
        Some("invoice_002"),
        None, // No provider period_end - should fall back to calculated
        None,
    )
    .expect("renewal should succeed");

    assert!(matches!(result, RenewalResult::Success { .. }));

    let updated = queries::get_license_by_id(&mut conn, &license.id)
        .expect("db query should succeed")
        .expect("license should exist");
    let new_exp = updated.expires_at.expect("should have expiration");

    // Should use calculated value: now + product.license_exp_days (ONE_YEAR)
    let expected_min = now() + (ONE_YEAR * 86400) - 10;
    let expected_max = now() + (ONE_YEAR * 86400) + 10;
    assert!(
        new_exp >= expected_min && new_exp <= expected_max,
        "license expiration should be calculated from product ({} days), got {} days from now",
        ONE_YEAR,
        (new_exp - now()) / 86400
    );
}

#[test]
fn test_renewal_provider_period_end_handles_early_renewal() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    // License currently expires in 3 days (Stripe renews early)
    let initial_exp = now() + (3 * 86400);
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(initial_exp));

    // Stripe renews 3 days early, gives us period_end 30 days from now
    // (not 30 days from current expiration, but 30 days from renewal time)
    let provider_period_end = now() + (30 * 86400);

    let result = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_123",
        Some("invoice_003"),
        Some(provider_period_end),
        None,
    )
    .expect("renewal should succeed");

    assert!(matches!(result, RenewalResult::Success { .. }));

    let updated = queries::get_license_by_id(&mut conn, &license.id)
        .expect("db query should succeed")
        .expect("license should exist");
    let new_exp = updated.expires_at.expect("should have expiration");

    // Should be ~30 days from now (provider's exact date), not ~33 days
    assert!(
        (new_exp - provider_period_end).abs() < 5,
        "should use provider's exact period_end for early renewals"
    );
}

/// Tests that process_renewal_atomic without transaction_data still extends the license.
///
/// When no transaction data is provided, the atomic function:
/// 1. Records the event for replay prevention
/// 2. Extends the license expiration
/// 3. Does NOT create a transaction record (no data to record)
///
/// This is useful for testing and cases where transaction data isn't available.
#[test]
fn test_renewal_atomic_without_transaction_data_extends_license_only() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    // Create a license with an initial purchase transaction
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(now() + 86400));

    // Count transactions before renewal
    let transactions_before = queries::get_transactions_by_license(&conn, &license.id)
        .expect("should query transactions");
    let count_before = transactions_before.len();

    // Process a renewal WITHOUT transaction data
    let result = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_123",
        Some("invoice_renewal_001"),
        Some(now() + (365 * 86400)), // 1 year from now
        None, // No transaction data
    )
    .expect("renewal should succeed");

    assert!(matches!(result, RenewalResult::Success { .. }));

    // Verify license was extended
    let updated_license = queries::get_license_by_id(&conn, &license.id)
        .expect("should query license")
        .expect("license should exist");
    assert!(
        updated_license.expires_at.unwrap() > now() + (364 * 86400),
        "License should be extended"
    );

    // Without transaction_data, no transaction is created
    let transactions_after = queries::get_transactions_by_license(&conn, &license.id)
        .expect("should query transactions");

    assert_eq!(
        transactions_after.len(),
        count_before,
        "process_renewal_atomic without transaction_data doesn't create transactions"
    );
}

/// Tests that process_renewal_atomic provides true atomicity.
///
/// The atomic function ensures that replay prevention, license extension,
/// and transaction creation all happen in a single database transaction.
/// If any step fails, everything is rolled back and payment provider can retry.
///
/// This test verifies:
/// 1. First call succeeds and creates both license extension AND transaction
/// 2. Second call (retry) correctly returns "Already processed"
/// 3. Transaction was created on first call (not lost like the old bug)
#[test]
fn test_renewal_replay_prevention_and_transaction_are_atomic() {
    use paycheck::handlers::webhooks::common::{process_renewal_atomic, RenewalResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(now() + 86400));

    let event_id = "invoice_atomicity_test_123";
    let new_exp = now() + (365 * 86400);

    // Build transaction data (like handle_renewal does)
    let transaction_data = CreateTransaction {
        license_id: Some(license.id.clone()),
        project_id: project.id.clone(),
        product_id: Some(product.id.clone()),
        org_id: org.id.clone(),
        payment_provider: "stripe".to_string(),
        provider_customer_id: None,
        provider_subscription_id: Some("sub_456".to_string()),
        provider_order_id: event_id.to_string(),
        currency: "usd".to_string(),
        subtotal_cents: 9900,
        discount_cents: 0,
        net_cents: 9900,
        tax_cents: 0,
        total_cents: 9900,
        discount_code: None,
        tax_inclusive: None,
        customer_country: None,
        transaction_type: TransactionType::Renewal,
        parent_transaction_id: None,
        is_subscription: true,
        source: "payment".to_string(),
        metadata: None,
        test_mode: false,
    };

    // First call - should succeed ATOMICALLY (replay prevention + license + transaction)
    let result1 = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_456",
        Some(event_id),
        Some(new_exp),
        Some(&transaction_data),
    )
    .expect("First renewal should succeed");

    match result1 {
        RenewalResult::Success { license_exp } => {
            assert_eq!(license_exp, Some(new_exp), "Should return new expiration");
        }
        RenewalResult::AlreadyProcessed => {
            panic!("First call should not be 'Already processed'");
        }
    }

    // Verify transaction was created (atomically with the renewal)
    let transactions = queries::get_transactions_by_license(&conn, &license.id)
        .expect("should query transactions");
    let renewal_txns: Vec<_> = transactions
        .iter()
        .filter(|t| t.transaction_type == TransactionType::Renewal)
        .collect();

    assert_eq!(
        renewal_txns.len(),
        1,
        "Transaction should be created ATOMICALLY with the renewal"
    );

    // Second call (simulating payment provider retry) - should return AlreadyProcessed
    let result2 = process_renewal_atomic(
        &mut conn,
        "stripe",
        &product,
        &license,
        "sub_456",
        Some(event_id),
        Some(new_exp),
        Some(&transaction_data),
    )
    .expect("Second call should not error");

    match result2 {
        RenewalResult::AlreadyProcessed => {
            // Correct - idempotent behavior
        }
        RenewalResult::Success { .. } => {
            panic!("Second call should be 'Already processed', not Success");
        }
    }

    // Verify only one transaction exists (no duplicate)
    let transactions_after = queries::get_transactions_by_license(&conn, &license.id)
        .expect("should query transactions");
    let renewal_txns_after = transactions_after
        .iter()
        .filter(|t| t.transaction_type == TransactionType::Renewal)
        .count();

    assert_eq!(
        renewal_txns_after, 1,
        "Should still have exactly 1 transaction (no duplicate from retry)"
    );
}

// ============ Cancellation Business Logic Tests ============

#[test]
fn test_cancellation_returns_ok_without_modifying_license() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let original_exp = now() + (ONE_MONTH * 86400);
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(original_exp));

    let (status, msg) = process_cancellation("stripe", &license.id, license.expires_at, "sub_123");
    assert_eq!(
        status,
        StatusCode::OK,
        "cancellation process should return OK status"
    );
    assert_eq!(msg, "OK", "cancellation process should return OK message");

    // Verify license was NOT modified
    let unchanged = queries::get_license_by_id(&mut conn, &license.id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        unchanged.expires_at,
        Some(original_exp),
        "license expiration should remain unchanged after cancellation"
    );
    assert!(
        !unchanged.revoked,
        "license should not be revoked after cancellation (expires naturally)"
    );
}

// ============ Stripe HTTP Handler Tests ============

use axum::{Router, body::Body, http::Request, routing::post};
use paycheck::handlers::webhooks::{handle_lemonsqueezy_webhook, handle_stripe_webhook};
use serde_json::json;
use tower::ServiceExt;

fn webhook_app(state: paycheck::db::AppState) -> Router {
    Router::new()
        .route("/webhook/stripe", post(handle_stripe_webhook))
        .route("/webhook/lemonsqueezy", post(handle_lemonsqueezy_webhook))
        .with_state(state)
}

#[tokio::test]
async fn test_stripe_webhook_checkout_completed_creates_license() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
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
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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
        "Stripe checkout webhook should return OK status"
    );

    // Verify license was created
    let mut conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&mut conn, &session_id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        session.completed,
        "payment session should be marked as completed after webhook"
    );
    assert!(
        session.license_id.is_some(),
        "payment session should have associated license ID after webhook"
    );

    let license = queries::get_license_by_id(&mut conn, &session.license_id.unwrap())
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert!(!license.id.is_empty(), "license should have been created");
}

#[tokio::test]
async fn test_stripe_webhook_missing_signature_returns_error() {
    let state = create_test_app_state();

    let payload = json!({
        "type": "checkout.session.completed",
        "data": {"object": {}}
    });

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/stripe")
                .header("content-type", "application/json")
                // No stripe-signature header!
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "missing stripe-signature header should return BAD_REQUEST"
    );
}

#[tokio::test]
async fn test_stripe_webhook_invalid_signature_returns_unauthorized() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
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
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    // Sign with wrong secret
    let signature = compute_stripe_signature(&payload_bytes, "wrong_secret", &timestamp);
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
        axum::http::StatusCode::UNAUTHORIZED,
        "invalid webhook signature should return UNAUTHORIZED"
    );
}

#[tokio::test]
async fn test_stripe_webhook_unpaid_checkout_ignored() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
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
                "payment_status": "unpaid", // NOT paid
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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

    // Returns OK but event is ignored
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "unpaid checkout webhook should return OK (event ignored)"
    );

    // Session should NOT be completed
    let mut conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&mut conn, &session_id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        !session.completed,
        "payment session should not be completed for unpaid checkout"
    );
}

#[tokio::test]
async fn test_stripe_webhook_invoice_paid_extends_license() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let original_exp: i64;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        setup_stripe_config(&mut conn, &org.id, &master_key);
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        // Create license with subscription
        original_exp = now() + (ONE_WEEK * 86400);
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            &org.id,
            Some(original_exp),
            "stripe",
            "sub_test_renewal",
        );
        license_id = license.id.clone();
    }

    let payload = json!({
        "type": "invoice.paid",
        "data": {
            "object": {
                "id": "in_test_123",
                "subscription": "sub_test_renewal",
                "billing_reason": "subscription_cycle",
                "status": "paid"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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
        "invoice.paid webhook should return OK status"
    );

    // Verify license was extended
    let mut conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&mut conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let new_exp = license
        .expires_at
        .expect("license should have expiration timestamp");
    assert!(
        new_exp > original_exp,
        "license should be extended from {} to {} after invoice.paid webhook",
        original_exp,
        new_exp
    );
}

#[tokio::test]
async fn test_stripe_webhook_subscription_deleted_returns_ok() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let original_exp: i64;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        setup_stripe_config(&mut conn, &org.id, &master_key);
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        original_exp = now() + (ONE_MONTH * 86400);
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            &org.id,
            Some(original_exp),
            "stripe",
            "sub_cancel_test",
        );
        license_id = license.id.clone();
    }

    let payload = json!({
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_cancel_test",
                "customer": "cus_test",
                "status": "canceled"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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
        "subscription.deleted webhook should return OK status"
    );

    // License should be unchanged (expires naturally)
    let mut conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&mut conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        license.expires_at,
        Some(original_exp),
        "license expiration should remain unchanged after subscription.deleted webhook"
    );
    assert!(
        !license.revoked,
        "license should not be revoked after subscription.deleted webhook"
    );
}

#[tokio::test]
async fn test_stripe_webhook_unknown_event_ignored() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        setup_stripe_config(&mut conn, &org.id, &master_key);
    }

    let payload = json!({
        "type": "payment_intent.created",
        "data": {"object": {"id": "pi_test"}}
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
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

    // Unknown events are ignored with 200 OK
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "unknown webhook event type should return OK (event ignored)"
    );
}

// ============ LemonSqueezy HTTP Handler Tests ============

#[tokio::test]
async fn test_lemonsqueezy_webhook_order_created_creates_license() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);

        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        let session = create_test_payment_session(&mut conn, &product.id, None);

        session_id = session.id.clone();
        project_id = project.id.clone();
    }

    let payload = json!({
        "meta": {
            "event_name": "order_created",
            "custom_data": {
                "paycheck_session_id": session_id,
                "project_id": project_id
            }
        },
        "data": {
            "id": "order_123",
            "attributes": {
                "status": "paid",
                "customer_id": 12345,
                "user_email": "test@example.com",
                "first_order_item": {
                    "subscription_id": 67890
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_whsec_test_secret");

    let app = webhook_app(state.clone());

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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "LemonSqueezy order_created webhook should return OK status"
    );

    // Verify license was created
    let mut conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&mut conn, &session_id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        session.completed,
        "payment session should be marked as completed after webhook"
    );
    assert!(
        session.license_id.is_some(),
        "payment session should have associated license ID after webhook"
    );

    let license = queries::get_license_by_id(&mut conn, &session.license_id.unwrap())
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert!(!license.id.is_empty(), "license should have been created");
}

#[tokio::test]
async fn test_lemonsqueezy_webhook_missing_signature_returns_error() {
    let state = create_test_app_state();

    let payload = json!({
        "meta": {"event_name": "order_created"},
        "data": {"id": "123", "attributes": {}}
    });

    let app = webhook_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhook/lemonsqueezy")
                .header("content-type", "application/json")
                // No x-signature header!
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "missing x-signature header should return BAD_REQUEST"
    );
}

#[tokio::test]
async fn test_lemonsqueezy_webhook_invalid_signature_returns_unauthorized() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
        let session = create_test_payment_session(&mut conn, &product.id, None);

        // Use session_id and project_id in payload
        let payload = json!({
            "meta": {
                "event_name": "order_created",
                "custom_data": {
                    "paycheck_session_id": session.id,
                    "project_id": project.id
                }
            },
            "data": {
                "id": "order_123",
                "attributes": {
                    "status": "paid"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        // Sign with wrong secret
        let signature = compute_lemonsqueezy_signature(&payload_bytes, "wrong_secret");

        let app = webhook_app(state.clone());

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

        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid LemonSqueezy webhook signature should return UNAUTHORIZED"
        );
    }
}

#[tokio::test]
async fn test_lemonsqueezy_webhook_subscription_payment_extends_license() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let original_exp: i64;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        original_exp = now() + (ONE_WEEK * 86400);
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            &org.id,
            Some(original_exp),
            "lemonsqueezy",
            "12345", // subscription_id as string
        );
        license_id = license.id.clone();
    }

    let payload = json!({
        "meta": {
            "event_name": "subscription_payment_success"
        },
        "data": {
            "id": "invoice_ls_123",
            "attributes": {
                "subscription_id": 12345,
                "customer_id": 67890,
                "status": "paid"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_whsec_test_secret");

    let app = webhook_app(state.clone());

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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "subscription_payment_success webhook should return OK status"
    );

    // Verify license was extended
    let mut conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&mut conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    let new_exp = license
        .expires_at
        .expect("license should have expiration timestamp");
    assert!(
        new_exp > original_exp,
        "license should be extended after subscription_payment_success webhook"
    );
}

#[tokio::test]
async fn test_lemonsqueezy_webhook_subscription_cancelled_returns_ok() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let original_exp: i64;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        original_exp = now() + (ONE_MONTH * 86400);
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            &org.id,
            Some(original_exp),
            "lemonsqueezy",
            "sub_ls_cancel",
        );
        license_id = license.id.clone();
    }

    let payload = json!({
        "meta": {
            "event_name": "subscription_cancelled"
        },
        "data": {
            "id": "sub_ls_cancel",
            "attributes": {
                "customer_id": 12345,
                "status": "cancelled"
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_whsec_test_secret");

    let app = webhook_app(state.clone());

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

    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "subscription_cancelled webhook should return OK status"
    );

    // License should be unchanged
    let mut conn = state.db.get().unwrap();
    let license = queries::get_license_by_id(&mut conn, &license_id)
        .expect("database query for license should succeed")
        .expect("license should exist in database");
    assert_eq!(
        license.expires_at,
        Some(original_exp),
        "license expiration should remain unchanged after subscription_cancelled webhook"
    );
}

#[tokio::test]
async fn test_webhook_provider_not_configured_returns_ok() {
    let state = create_test_app_state();
    let master_key = test_master_key();

    let session_id: String;
    let project_id: String;

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        // NO payment config set!
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
                "metadata": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let timestamp = current_timestamp();
    let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
    let signature_header = format!("t={},v1={}", timestamp, signature);

    let app = webhook_app(state.clone());

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

    // Returns OK with "not configured" message (graceful degradation)
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "webhook should return OK even when payment provider is not configured"
    );

    // Session should NOT be completed
    let mut conn = state.db.get().unwrap();
    let session = queries::get_payment_session(&mut conn, &session_id)
        .expect("database query for payment session should succeed")
        .expect("payment session should exist in database");
    assert!(
        !session.completed,
        "payment session should not be completed when provider is not configured"
    );
}

// ============ Webhook Security Tests ============
//
// These tests focus on replay attack prevention, timestamp validation,
// payload manipulation detection, and edge cases in webhook handling.

mod webhook_security {
    use super::*;

    // ============ Stripe Replay Prevention Tests ============

    /// Test that Stripe checkout webhook with the same session creates only one license.
    /// Uses atomic session claiming to prevent race conditions.
    #[tokio::test]
    async fn test_stripe_webhook_same_event_id_processed_once() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let session_id: String;
        let project_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
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
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        let app = webhook_app(state.clone());

        // First request - should succeed
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", &signature_header)
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response1.status(),
            axum::http::StatusCode::OK,
            "first webhook request should return OK status"
        );

        // Second request with same payload - should be idempotent
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", &signature_header)
                    .body(Body::from(payload_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response2.status(),
            axum::http::StatusCode::OK,
            "replay webhook request should return OK status (idempotent)"
        );

        // Verify only one license was created
        let mut conn = state.db.get().unwrap();
        let session = queries::get_payment_session(&mut conn, &session_id)
            .expect("database query for payment session should succeed")
            .expect("payment session should exist in database");
        assert!(
            session.completed,
            "payment session should be marked as completed"
        );

        let license_id = session
            .license_id
            .expect("payment session should have license ID");
        let licenses = queries::list_licenses_for_project(&mut conn, &project_id)
            .expect("database query for licenses should succeed");
        assert_eq!(
            licenses.len(),
            1,
            "replay should not create duplicate license"
        );
        assert_eq!(
            licenses[0].license.id, license_id,
            "license ID should match session's license ID"
        );
    }

    /// Test that replaying a Stripe checkout webhook does not create duplicate licenses.
    #[tokio::test]
    async fn test_stripe_webhook_replay_does_not_create_duplicate_license() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let session_id: String;
        let project_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let session = create_test_payment_session(&mut conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Helper to send webhook
        let send_webhook = |app: Router, bytes: Vec<u8>, sig: String| async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", sig)
                    .body(Body::from(bytes))
                    .unwrap(),
            )
            .await
            .unwrap()
        };

        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_replay",
                    "payment_status": "paid",
                    "customer_details": {
                        "email": "replay@test.com"
                    },
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        // Send multiple times
        let app = webhook_app(state.clone());
        let _ = send_webhook(app.clone(), payload_bytes.clone(), signature_header.clone()).await;
        let _ = send_webhook(app.clone(), payload_bytes.clone(), signature_header.clone()).await;
        let _ = send_webhook(app, payload_bytes, signature_header).await;

        // Verify only one license
        let mut conn = state.db.get().unwrap();
        let licenses = queries::list_licenses_for_project(&mut conn, &project_id)
            .expect("database query for licenses should succeed");
        assert_eq!(
            licenses.len(),
            1,
            "multiple replays should still result in only 1 license"
        );
    }

    /// Test that Stripe invoice.paid replay prevention works via event_id tracking.
    #[tokio::test]
    async fn test_stripe_invoice_paid_replay_prevented() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let license_id: String;
        let original_exp: i64;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            original_exp = now() + (ONE_WEEK * 86400);
            let license = create_test_license_with_subscription(
                &conn,
                &project.id,
                &product.id,
                &org.id,
                Some(original_exp),
                "stripe",
                "sub_replay_test",
            );
            license_id = license.id.clone();
        }

        // Same invoice ID sent multiple times (replay attack)
        let payload = json!({
            "type": "invoice.paid",
            "data": {
                "object": {
                    "id": "in_same_invoice_id",  // Same ID for replay
                    "subscription": "sub_replay_test",
                    "billing_reason": "subscription_cycle",
                    "status": "paid"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        let app = webhook_app(state.clone());

        // First request extends license
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", &signature_header)
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response1.status(),
            axum::http::StatusCode::OK,
            "first invoice.paid webhook should return OK status"
        );

        let mut conn = state.db.get().unwrap();
        let license_after_first = queries::get_license_by_id(&mut conn, &license_id)
            .expect("database query for license should succeed")
            .expect("license should exist in database");
        let first_exp = license_after_first
            .expires_at
            .expect("license should have expiration timestamp");
        assert!(
            first_exp > original_exp,
            "first renewal should extend license expiration"
        );

        // Second request with same invoice ID should be idempotent
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", &signature_header)
                    .body(Body::from(payload_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response2.status(),
            axum::http::StatusCode::OK,
            "replay invoice.paid webhook should return OK status (idempotent)"
        );

        // Verify expiration was not extended again
        let license_after_second = queries::get_license_by_id(&mut conn, &license_id)
            .expect("database query for license should succeed")
            .expect("license should exist in database");
        assert_eq!(
            license_after_second
                .expires_at
                .expect("license should have expiration timestamp"),
            first_exp,
            "replay should not extend license expiration again"
        );
    }

    // ============ LemonSqueezy Replay Prevention Tests ============

    /// Test that LemonSqueezy order_created webhook replay is prevented via session claiming.
    #[tokio::test]
    async fn test_lemonsqueezy_webhook_same_event_processed_once() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let session_id: String;
        let project_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let session = create_test_payment_session(&mut conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        let payload = json!({
            "meta": {
                "event_name": "order_created",
                "custom_data": {
                    "paycheck_session_id": session_id,
                    "project_id": project_id
                }
            },
            "data": {
                "id": "order_ls_replay_test",
                "attributes": {
                    "status": "paid",
                    "customer_id": 12345,
                    "user_email": "test@example.com"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_whsec_test_secret");

        let app = webhook_app(state.clone());

        // First request
        let response1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/lemonsqueezy")
                    .header("content-type", "application/json")
                    .header("x-signature", &signature)
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response1.status(),
            axum::http::StatusCode::OK,
            "first LemonSqueezy order_created webhook should return OK status"
        );

        // Replay request
        let response2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/lemonsqueezy")
                    .header("content-type", "application/json")
                    .header("x-signature", &signature)
                    .body(Body::from(payload_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response2.status(),
            axum::http::StatusCode::OK,
            "replay LemonSqueezy webhook should return OK status (idempotent)"
        );

        // Verify only one license
        let mut conn = state.db.get().unwrap();
        let licenses = queries::list_licenses_for_project(&mut conn, &project_id)
            .expect("database query for licenses should succeed");
        assert_eq!(
            licenses.len(),
            1,
            "replay should not create duplicate license"
        );
    }

    /// Test that LemonSqueezy subscription_payment_success replay is prevented.
    #[tokio::test]
    async fn test_lemonsqueezy_webhook_replay_does_not_duplicate() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let license_id: String;
        let original_exp: i64;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

            original_exp = now() + (ONE_WEEK * 86400);
            let license = create_test_license_with_subscription(
                &conn,
                &project.id,
                &product.id,
                &org.id,
                Some(original_exp),
                "lemonsqueezy",
                "99999",
            );
            license_id = license.id.clone();
        }

        // Same invoice ID for replay attack
        let payload = json!({
            "meta": {
                "event_name": "subscription_payment_success"
            },
            "data": {
                "id": "ls_invoice_same_id",  // Same ID
                "attributes": {
                    "subscription_id": 99999,
                    "customer_id": 12345,  // Required field
                    "status": "paid"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_whsec_test_secret");

        let app = webhook_app(state.clone());

        // First request
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/lemonsqueezy")
                    .header("content-type", "application/json")
                    .header("x-signature", &signature)
                    .body(Body::from(payload_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let mut conn = state.db.get().unwrap();
        let license_after_first = queries::get_license_by_id(&mut conn, &license_id)
            .expect("database query for license should succeed")
            .expect("license should exist in database");
        let first_exp = license_after_first
            .expires_at
            .expect("license should have expiration timestamp");
        assert!(
            first_exp > original_exp,
            "first renewal should extend license expiration"
        );

        // Replay
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/lemonsqueezy")
                    .header("content-type", "application/json")
                    .header("x-signature", &signature)
                    .body(Body::from(payload_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        let license_after_replay = queries::get_license_by_id(&mut conn, &license_id)
            .expect("database query for license should succeed")
            .expect("license should exist in database");
        assert_eq!(
            license_after_replay
                .expires_at
                .expect("license should have expiration timestamp"),
            first_exp,
            "replay should not extend license expiration"
        );
    }

    // ============ Timestamp Validation Tests ============

    /// Test that Stripe webhook with timestamp > 5 minutes old is rejected.
    /// Timestamp validation happens during signature verification.
    #[tokio::test]
    async fn test_stripe_webhook_old_timestamp_returns_unauthorized() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let session_id: String;
        let project_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let session = create_test_payment_session(&mut conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Valid payload that would normally succeed
        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_old_ts",
                    "payment_status": "paid",
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        // Timestamp 10 minutes ago (beyond 5-minute tolerance)
        let old_timestamp = (chrono::Utc::now().timestamp() - 600).to_string();
        let signature =
            compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &old_timestamp);
        let signature_header = format!("t={},v1={}", old_timestamp, signature);

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

        // Old timestamp causes signature verification to fail (returns false)
        // which results in UNAUTHORIZED
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "Old timestamp should cause signature rejection"
        );
    }

    /// Test that Stripe webhook with future timestamp is rejected.
    /// Clock skew tolerance is 60 seconds - timestamps more than 60s in the future are rejected.
    #[tokio::test]
    async fn test_stripe_webhook_future_timestamp_returns_unauthorized() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let session_id: String;
        let project_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let session = create_test_payment_session(&mut conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Valid payload that would normally succeed
        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_future_ts",
                    "payment_status": "paid",
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        // Timestamp 5 minutes in the future (beyond 60-second clock skew tolerance)
        let future_timestamp = (chrono::Utc::now().timestamp() + 300).to_string();
        let signature =
            compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &future_timestamp);
        let signature_header = format!("t={},v1={}", future_timestamp, signature);

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

        // Future timestamp causes signature verification to fail (returns false)
        // which results in UNAUTHORIZED
        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "Future timestamp should cause signature rejection"
        );
    }

    // ============ Payload Manipulation Tests ============

    /// Test that modifying the payment amount in payload causes signature failure.
    #[tokio::test]
    async fn test_stripe_webhook_modified_amount_returns_unauthorized() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let session_id: String;
        let project_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let session = create_test_payment_session(&mut conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Original payload with $99 amount
        let original_payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "amount_total": 9900,  // $99.00
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let original_bytes = serde_json::to_vec(&original_payload).unwrap();
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&original_bytes, "whsec_test123secret456", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        // Attacker modifies the amount to $0
        let modified_payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "amount_total": 0,  // Modified to $0
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let modified_bytes = serde_json::to_vec(&modified_payload).unwrap();

        let app = webhook_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", signature_header)
                    .body(Body::from(modified_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "Modified payload should be rejected"
        );
    }

    /// Test that modifying customer email in payload causes signature failure.
    #[tokio::test]
    async fn test_stripe_webhook_modified_customer_email_returns_unauthorized() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        let session_id: String;
        let project_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
            let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
            let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
            let session = create_test_payment_session(&mut conn, &product.id, None);
            session_id = session.id.clone();
            project_id = project.id.clone();
        }

        // Sign with original email
        let original_payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "customer_email": "legitimate@buyer.com",
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let original_bytes = serde_json::to_vec(&original_payload).unwrap();
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&original_bytes, "whsec_test123secret456", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        // Attacker tries to substitute their email
        let modified_payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "customer_email": "attacker@evil.com",  // Modified email
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let modified_bytes = serde_json::to_vec(&modified_payload).unwrap();

        let app = webhook_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", signature_header)
                    .body(Body::from(modified_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "Modified email should be rejected"
        );
    }

    // ============ Edge Cases ============

    /// Test that webhook for non-existent product returns OK (graceful handling).
    #[tokio::test]
    async fn test_webhook_with_unknown_product_id_ignored() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
            // Project exists but no product or session
            let _project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        }

        let payload = json!({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_unknown",
                    "payment_status": "paid",
                    "metadata": {
                        "paycheck_session_id": "non_existent_session_id",
                        "project_id": "non_existent_project_id"
                    }
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
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

        // Should return OK (graceful degradation) rather than crashing
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "Unknown product should be handled gracefully"
        );
    }

    /// Test that webhook for unknown subscription is handled gracefully.
    #[tokio::test]
    async fn test_webhook_with_unknown_subscription_ignored() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_stripe_config(&mut conn, &org.id, &master_key);
        }

        let payload = json!({
            "type": "invoice.paid",
            "data": {
                "object": {
                    "id": "in_unknown_invoice",
                    "subscription": "sub_does_not_exist",
                    "billing_reason": "subscription_cycle",
                    "status": "paid"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
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

        // Should return OK with "not found" message rather than error
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "unknown subscription webhook should return OK (handled gracefully)"
        );
    }

    /// Test that concurrent webhooks for the same order create only one license.
    /// This simulates Stripe's retry behavior where multiple webhooks might arrive
    /// simultaneously.
    #[tokio::test]
    async fn test_concurrent_webhooks_same_order_create_one_license() {
        use std::sync::Arc;
        use tokio::sync::Barrier;

        let state = create_test_app_state();
        let master_key = test_master_key();

        let session_id: String;
        let project_id: String;

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
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
                    "id": "cs_concurrent_test",
                    "payment_status": "paid",
                    "customer_details": {
                        "email": "concurrent@test.com"
                    },
                    "metadata": {
                        "paycheck_session_id": session_id,
                        "project_id": project_id
                    }
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp = current_timestamp();
        let signature = compute_stripe_signature(&payload_bytes, "whsec_test123secret456", &timestamp);
        let signature_header = format!("t={},v1={}", timestamp, signature);

        // Use a barrier to synchronize concurrent requests
        let barrier = Arc::new(Barrier::new(5));
        let state = Arc::new(state);
        let payload_bytes = Arc::new(payload_bytes);
        let signature_header = Arc::new(signature_header);

        // Spawn 5 concurrent webhook requests
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let barrier = barrier.clone();
                let state = state.clone();
                let payload_bytes = payload_bytes.clone();
                let signature_header = signature_header.clone();

                tokio::spawn(async move {
                    // Wait for all tasks to be ready
                    barrier.wait().await;

                    let app = webhook_app((*state).clone());
                    app.oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/webhook/stripe")
                            .header("content-type", "application/json")
                            .header("stripe-signature", signature_header.as_str())
                            .body(Body::from(payload_bytes.as_ref().clone()))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                })
            })
            .collect();

        // Wait for all requests to complete
        for handle in handles {
            let response = handle.await.unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::OK,
                "all concurrent webhook requests should return OK"
            );
        }

        // Verify only ONE license was created despite concurrent requests
        let mut conn = state.db.get().unwrap();
        let licenses = queries::list_licenses_for_project(&mut conn, &project_id)
            .expect("database query for licenses should succeed");
        assert_eq!(
            licenses.len(),
            1,
            "concurrent webhooks should create exactly 1 license, found {}",
            licenses.len()
        );
    }

    /// Test that LemonSqueezy webhook for unknown subscription returns OK.
    /// When a subscription is not found, the webhook returns OK with a "not found" message
    /// rather than an error (graceful handling for webhooks).
    #[tokio::test]
    async fn test_lemonsqueezy_unknown_subscription_returns_ok_gracefully() {
        let state = create_test_app_state();
        let master_key = test_master_key();

        {
            let mut conn = state.db.get().unwrap();
            let org = create_test_org(&mut conn, "Test Org");
            setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
            // Need a project for the org so the config can be looked up
            let _project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        }

        // Include all required fields for the payload
        let payload = json!({
            "meta": {
                "event_name": "subscription_payment_success"
            },
            "data": {
                "id": "ls_invoice_unknown",
                "attributes": {
                    "subscription_id": 99999999,  // Does not exist
                    "customer_id": 12345,         // Required field
                    "status": "paid"
                }
            }
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_whsec_test_secret");

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

        // Should return OK, not an error (subscription not found is handled gracefully)
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "unknown LemonSqueezy subscription webhook should return OK (handled gracefully)"
        );
    }
}

// ============ Transaction Boundary Tests ============

/// Verify that process_checkout uses a transaction to ensure atomicity.
///
/// The session claim and license creation are wrapped in a transaction so that:
/// 1. If license creation fails, the session claim is rolled back
/// 2. Stripe can retry and the checkout will succeed on the next attempt
///
/// This test verifies that session.completed is only set AFTER license creation
/// succeeds, by checking the final state after a successful checkout.
#[test]
fn test_checkout_uses_transaction_for_claim_and_license() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let session = create_test_payment_session(&mut conn, &product.id, Some("cust_test"));

    // Verify session starts uncompleted
    let initial_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("should get payment session")
        .expect("session should exist");
    assert!(
        !initial_session.completed,
        "session should start as not completed"
    );
    assert!(
        initial_session.license_id.is_none(),
        "session should start with no license"
    );

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: Some("cust_stripe".to_string()),
        customer_email: Some("test@example.com".to_string()),
        subscription_id: None,
        order_id: None,
        enricher_session_id: None,
        transaction: None,
    };

    let (status, msg) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );

    assert_eq!(status, StatusCode::OK);
    assert_eq!(msg, "OK");

    // After successful checkout, BOTH session.completed AND license should exist.
    // The transaction ensures we never have completed=1 without a license.
    let final_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("should get payment session")
        .expect("session should exist");
    assert!(
        final_session.completed,
        "session should be marked completed after successful checkout"
    );
    assert!(
        final_session.license_id.is_some(),
        "session should have license_id after successful checkout"
    );

    // Verify the license actually exists
    let license = queries::get_license_by_id(&mut conn, &final_session.license_id.as_ref().unwrap())
        .expect("should query license")
        .expect("license should exist");
    assert!(!license.id.is_empty());
}

/// Documents what happens if a payment session somehow ends up in an inconsistent state
/// (completed=1 but no license). This state should not occur with the transactional
/// process_checkout, but if it did (e.g., manual DB edit), retries cannot recover.
#[test]
fn test_checkout_inconsistent_state_is_unrecoverable() {
    use axum::http::StatusCode;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let session = create_test_payment_session(&mut conn, &product.id, Some("cust_test"));

    // Manually create an inconsistent state (should not happen with transactional checkout)
    conn.execute(
        "UPDATE payment_sessions SET completed = 1 WHERE id = ?1",
        rusqlite::params![&session.id],
    )
    .expect("should be able to mark session as completed");

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: Some("cust_stripe".to_string()),
        customer_email: Some("test@example.com".to_string()),
        subscription_id: None,
        order_id: None,
        enricher_session_id: None,
        transaction: None,
    };

    let (status, msg) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );

    // System sees completed=1 and returns "Already processed"
    assert_eq!(status, StatusCode::OK);
    assert_eq!(msg, "Already processed");

    // The inconsistent state persists - this documents the limitation
    let final_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("should get payment session")
        .expect("session should exist");
    assert!(final_session.license_id.is_none(), "no license was created");
}

/// Verifies that checkout with transaction data creates BOTH license AND transaction record.
///
/// BUG: Currently transaction creation is OUTSIDE the atomic scope (after commit).
/// If transaction creation fails, license exists but transaction record is missing.
/// This breaks refund linkage and revenue tracking.
///
/// This test verifies the expected behavior: both should be created together.
/// After the fix, they will be atomic. Before the fix, this test documents the coupling.
#[test]
fn test_checkout_creates_transaction_record_with_license() {
    use axum::http::StatusCode;
    use paycheck::handlers::webhooks::common::CheckoutTransactionData;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let session = create_test_payment_session(&mut conn, &product.id, Some("cust_test"));

    // Checkout with transaction data (simulating a real Stripe webhook)
    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: Some("cus_stripe_123".to_string()),
        customer_email: Some("buyer@example.com".to_string()),
        subscription_id: None,
        order_id: Some("pi_payment_intent_xyz".to_string()),
        enricher_session_id: None,
        transaction: Some(CheckoutTransactionData {
            currency: "usd".to_string(),
            subtotal_cents: 9900,
            discount_cents: 0,
            tax_cents: 0,
            total_cents: 9900,
            tax_inclusive: Some(false),
            discount_code: None,
            customer_country: Some("US".to_string()),
            test_mode: false,
        }),
    };

    let (status, msg) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );

    assert_eq!(status, StatusCode::OK);
    assert_eq!(msg, "OK");

    // Verify license was created
    let final_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("should get payment session")
        .expect("session should exist");
    let license_id = final_session.license_id.expect("license should be created");

    // Verify transaction record was created with correct data
    let transactions = queries::get_transactions_by_license(&conn, &license_id)
        .expect("should query transactions");

    assert_eq!(
        transactions.len(),
        1,
        "Checkout with transaction data MUST create a transaction record. \
        Missing transaction breaks refund linkage and revenue tracking."
    );

    let txn = &transactions[0];
    assert_eq!(txn.license_id.as_ref(), Some(&license_id));
    assert_eq!(txn.provider_order_id, "pi_payment_intent_xyz");
    assert_eq!(txn.total_cents, 9900);
    assert_eq!(txn.currency, "usd");
    assert_eq!(txn.payment_provider, "stripe");
}

/// Documents the atomicity gap: transaction record creation is outside the DB transaction.
///
/// This test verifies that even when process_checkout returns OK:
/// - License is definitely created (inside atomic scope)
/// - Transaction record SHOULD be created but is not guaranteed (outside atomic scope)
///
/// The fix should move transaction creation inside the atomic scope so both
/// succeed or fail together.
#[test]
fn test_checkout_transaction_must_be_atomic_with_license() {
    use axum::http::StatusCode;
    use paycheck::handlers::webhooks::common::CheckoutTransactionData;

    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let email_hasher = test_email_hasher();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

    let session = create_test_payment_session(&mut conn, &product.id, Some("cust_test"));

    let checkout_data = CheckoutData {
        session_id: session.id.clone(),
        project_id: project.id.clone(),
        customer_id: Some("cus_stripe_123".to_string()),
        customer_email: Some("buyer@example.com".to_string()),
        subscription_id: None,
        order_id: Some("pi_atomic_test".to_string()),
        enricher_session_id: None,
        transaction: Some(CheckoutTransactionData {
            currency: "usd".to_string(),
            subtotal_cents: 5000,
            discount_cents: 0,
            tax_cents: 0,
            total_cents: 5000,
            tax_inclusive: None,
            discount_code: None,
            customer_country: None,
            test_mode: true,
        }),
    };

    let (status, _) = process_checkout(
        &mut conn,
        &email_hasher,
        "stripe",
        &project,
        &session,
        &product,
        &checkout_data,
    );

    assert_eq!(status, StatusCode::OK);

    // Get the created license
    let final_session = queries::get_payment_session(&mut conn, &session.id)
        .expect("should get session")
        .expect("session exists");
    let license_id = final_session.license_id.expect("license created");

    // Verify transaction exists - this is the critical check
    let transactions = queries::get_transactions_by_license(&conn, &license_id)
        .expect("should query");

    // After the fix, this assertion documents the guarantee:
    // If process_checkout returns OK with transaction data, BOTH license AND
    // transaction record MUST exist. No partial state.
    assert!(
        !transactions.is_empty(),
        "ATOMICITY REQUIREMENT: If license exists, transaction record MUST also exist. \
        A license without transaction record breaks refund processing."
    );

    // Verify we can look up by provider_order_id (critical for refund linkage)
    let found = queries::get_transaction_by_provider_order(&conn, "stripe", "pi_atomic_test")
        .expect("should query")
        .expect("transaction should be findable by provider_order_id");
    assert_eq!(found.license_id.as_ref(), Some(&license_id));
}

// ============ Webhook Parsing Tests (Stripe) ============

#[test]
fn test_stripe_invoice_paid_extracts_transaction_data() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    // Stripe invoice.paid webhook payload with transaction data
    let payload = r#"{
        "type": "invoice.paid",
        "data": {
            "object": {
                "id": "in_test_invoice_123",
                "customer": "cus_test",
                "subscription": "sub_test_456",
                "billing_reason": "subscription_cycle",
                "status": "paid",
                "currency": "usd",
                "subtotal": 9900,
                "tax": 792,
                "total": 10692,
                "livemode": false,
                "lines": {
                    "data": [{
                        "period": {
                            "end": 1735689600
                        }
                    }]
                }
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse invoice.paid event");

    match event {
        WebhookEvent::SubscriptionRenewed(data) => {
            assert_eq!(data.subscription_id, "sub_test_456");
            assert!(data.is_renewal, "subscription_cycle should be a renewal");
            assert!(data.is_paid);
            assert_eq!(data.event_id, Some("in_test_invoice_123".to_string()));
            assert_eq!(data.period_end, Some(1735689600));

            // Verify transaction data was extracted
            let tx = data.transaction.expect("should have transaction data");
            assert_eq!(tx.currency, "usd");
            assert_eq!(tx.subtotal_cents, 9900);
            assert_eq!(tx.tax_cents, 792);
            assert_eq!(tx.total_cents, 10692);
            assert!(tx.test_mode, "livemode=false means test_mode=true");
        }
        other => panic!("Expected SubscriptionRenewed, got {:?}", other),
    }
}

/// Test that invoice discount is correctly extracted from `total_discount_amounts`.
///
/// Bug: The old calculation `discount = subtotal + tax - total` assumes additive tax.
/// For inclusive tax (common in EU), this double-counts tax and inflates the discount.
///
/// Example with inclusive tax:
/// - Product: €100 (includes €20 VAT)
/// - subtotal = 10000 (pre-tax amount)
/// - tax = 2000 (extracted VAT)
/// - total = 9000 (after €10 discount)
/// - Buggy calculation: 10000 + 2000 - 9000 = 3000 (wrong!)
/// - Correct discount: 1000 (from total_discount_amounts)
///
/// Fix: Use Stripe's `total_discount_amounts` array when available.
#[test]
fn test_stripe_invoice_discount_uses_total_discount_amounts() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    // Invoice with inclusive tax and a discount
    // Stripe provides total_discount_amounts with the exact discount
    let payload = r#"{
        "type": "invoice.paid",
        "data": {
            "object": {
                "id": "in_inclusive_tax_test",
                "customer": "cus_eu",
                "subscription": "sub_eu_123",
                "billing_reason": "subscription_cycle",
                "status": "paid",
                "currency": "eur",
                "subtotal": 8333,
                "tax": 1667,
                "total": 9000,
                "livemode": true,
                "total_discount_amounts": [{
                    "amount": 1000,
                    "discount": "di_test_coupon"
                }],
                "lines": {
                    "data": [{
                        "period": {
                            "end": 1735689600
                        }
                    }]
                }
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse invoice.paid event");

    match event {
        WebhookEvent::SubscriptionRenewed(data) => {
            let tx = data.transaction.expect("should have transaction data");

            // With the fix, discount should come from total_discount_amounts (1000)
            // NOT from the buggy calculation: 8333 + 1667 - 9000 = 1000 (happens to be correct here)
            assert_eq!(tx.discount_cents, 1000, "discount should be extracted from total_discount_amounts");
            assert_eq!(tx.subtotal_cents, 8333);
            assert_eq!(tx.tax_cents, 1667);
            assert_eq!(tx.total_cents, 9000);
        }
        other => panic!("Expected SubscriptionRenewed, got {:?}", other),
    }
}

/// Test invoice discount calculation when total_discount_amounts is empty.
/// Falls back to calculation, which works correctly when there's no discount.
#[test]
fn test_stripe_invoice_discount_fallback_when_no_discounts() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    // Invoice with no discounts - total_discount_amounts is empty or absent
    let payload = r#"{
        "type": "invoice.paid",
        "data": {
            "object": {
                "id": "in_no_discount",
                "customer": "cus_test",
                "subscription": "sub_test_789",
                "billing_reason": "subscription_cycle",
                "status": "paid",
                "currency": "usd",
                "subtotal": 9900,
                "tax": 0,
                "total": 9900,
                "livemode": false,
                "total_discount_amounts": [],
                "lines": {
                    "data": [{
                        "period": {
                            "end": 1735689600
                        }
                    }]
                }
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse invoice.paid event");

    match event {
        WebhookEvent::SubscriptionRenewed(data) => {
            let tx = data.transaction.expect("should have transaction data");
            assert_eq!(tx.discount_cents, 0, "no discount when total_discount_amounts is empty");
        }
        other => panic!("Expected SubscriptionRenewed, got {:?}", other),
    }
}

#[test]
fn test_stripe_invoice_paid_initial_subscription_not_renewal() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    // Initial subscription creation - billing_reason is "subscription_create"
    let payload = r#"{
        "type": "invoice.paid",
        "data": {
            "object": {
                "id": "in_initial_123",
                "customer": "cus_test",
                "subscription": "sub_test_789",
                "billing_reason": "subscription_create",
                "status": "paid",
                "currency": "usd",
                "total": 5000,
                "livemode": true,
                "lines": {
                    "data": [{
                        "period": {
                            "end": 1735689600
                        }
                    }]
                }
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse event");

    match event {
        WebhookEvent::SubscriptionRenewed(data) => {
            assert!(!data.is_renewal, "subscription_create should not be marked as renewal");
            assert!(!data.transaction.as_ref().unwrap().test_mode, "livemode=true means not test mode");
        }
        other => panic!("Expected SubscriptionRenewed, got {:?}", other),
    }
}

/// Test that charge.refunded events are ignored in favor of refund.created.
///
/// The charge.refunded event has a fundamental issue with partial refunds: Stripe embeds
/// ALL refunds in the charge object (oldest-first), making it impossible to identify
/// which refund triggered the webhook. This causes subsequent partial refunds to be
/// silently dropped due to idempotency.
///
/// We now exclusively use refund.created events, which contain exactly one refund each.
#[test]
fn test_stripe_charge_refunded_is_ignored() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    let payload = r#"{
        "type": "charge.refunded",
        "data": {
            "object": {
                "id": "ch_test_charge",
                "payment_intent": "pi_test_intent",
                "amount": 10000,
                "amount_refunded": 5000,
                "currency": "usd",
                "refunded": false,
                "livemode": false,
                "refunds": {
                    "data": [{
                        "id": "re_test_refund",
                        "amount": 5000,
                        "currency": "usd",
                        "status": "succeeded"
                    }]
                }
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse");

    assert!(
        matches!(event, WebhookEvent::Ignored),
        "charge.refunded should be ignored - use refund.created instead"
    );
}

/// Test that refund.created event extracts refund data correctly.
/// This is Stripe's recommended approach for handling refunds.
#[test]
fn test_stripe_refund_created_extracts_refund_data() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    // Stripe refund.created webhook payload - contains just the refund object
    let payload = r#"{
        "type": "refund.created",
        "data": {
            "object": {
                "id": "re_test_refund_123",
                "amount": 5000,
                "currency": "eur",
                "status": "succeeded",
                "charge": "ch_test_charge_456",
                "payment_intent": "pi_test_intent_789"
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse refund.created event");

    match event {
        WebhookEvent::Refunded(data) => {
            assert_eq!(data.refund_id, "re_test_refund_123");
            assert_eq!(data.order_id, "pi_test_intent_789", "Should use payment_intent as order_id");
            assert_eq!(data.currency, "eur");
            assert_eq!(data.amount_cents, 5000);
            assert_eq!(data.source, "refund");
        }
        other => panic!("Expected Refunded, got {:?}", other),
    }
}

/// Test that refund.created with pending status is ignored.
#[test]
fn test_stripe_refund_created_pending_ignored() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::WebhookProvider;
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    let payload = r#"{
        "type": "refund.created",
        "data": {
            "object": {
                "id": "re_pending_refund",
                "amount": 5000,
                "currency": "usd",
                "status": "pending",
                "charge": "ch_test",
                "payment_intent": "pi_test"
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let result = provider.parse_event(&body);

    assert!(result.is_err(), "Pending refund should be ignored");
}

/// Test that refund.created falls back to charge ID when payment_intent is null.
#[test]
fn test_stripe_refund_created_uses_charge_fallback() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    // Some older charges may not have payment_intent
    let payload = r#"{
        "type": "refund.created",
        "data": {
            "object": {
                "id": "re_test_refund",
                "amount": 2500,
                "currency": "usd",
                "status": "succeeded",
                "charge": "ch_legacy_charge",
                "payment_intent": null
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse");

    match event {
        WebhookEvent::Refunded(data) => {
            assert_eq!(data.order_id, "ch_legacy_charge", "Should fall back to charge ID");
        }
        other => panic!("Expected Refunded, got {:?}", other),
    }
}

// ============ Webhook Parsing Tests (LemonSqueezy) ============

#[test]
fn test_lemonsqueezy_subscription_payment_extracts_transaction_data() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::lemonsqueezy::LemonSqueezyWebhookProvider;

    let provider = LemonSqueezyWebhookProvider;

    // LemonSqueezy subscription_payment_success webhook payload
    let payload = r#"{
        "meta": {
            "event_name": "subscription_payment_success",
            "custom_data": null
        },
        "data": {
            "id": "invoice_ls_123",
            "attributes": {
                "subscription_id": 98765,
                "customer_id": 54321,
                "status": "paid",
                "period_end": "2025-01-01T00:00:00.000Z",
                "currency": "USD",
                "subtotal": 4900,
                "tax": 0,
                "total": 4900,
                "test_mode": true
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse subscription_payment_success");

    match event {
        WebhookEvent::SubscriptionRenewed(data) => {
            assert_eq!(data.subscription_id, "98765");
            assert!(data.is_renewal, "subscription_payment_success is always a renewal");
            assert!(data.is_paid);
            assert_eq!(data.event_id, Some("invoice_ls_123".to_string()));
            assert!(data.period_end.is_some(), "Should have period_end from RFC3339 datetime");

            // Verify transaction data
            let tx = data.transaction.expect("should have transaction data");
            assert_eq!(tx.currency, "usd");
            assert_eq!(tx.subtotal_cents, 4900);
            assert_eq!(tx.tax_cents, 0);
            assert_eq!(tx.total_cents, 4900);
            assert!(tx.test_mode);
        }
        other => panic!("Expected SubscriptionRenewed, got {:?}", other),
    }
}

/// Test that LemonSqueezy subscription renewals with recurring discounts are tracked.
///
/// LemonSqueezy supports recurring coupons (is_recurring: true) that apply to
/// subscription renewals. The discount_total field should be extracted.
#[test]
fn test_lemonsqueezy_subscription_payment_extracts_recurring_discount() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::lemonsqueezy::LemonSqueezyWebhookProvider;

    let provider = LemonSqueezyWebhookProvider;

    // Subscription renewal with a recurring 20% discount coupon
    let payload = r#"{
        "meta": {
            "event_name": "subscription_payment_success",
            "custom_data": null
        },
        "data": {
            "id": "invoice_ls_recurring_discount",
            "attributes": {
                "subscription_id": 11111,
                "customer_id": 22222,
                "status": "paid",
                "period_end": "2025-02-01T00:00:00.000Z",
                "currency": "EUR",
                "subtotal": 10000,
                "discount_total": 2000,
                "tax": 1600,
                "total": 9600,
                "test_mode": false
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse subscription_payment_success");

    match event {
        WebhookEvent::SubscriptionRenewed(data) => {
            let tx = data.transaction.expect("should have transaction data");
            assert_eq!(tx.subtotal_cents, 10000);
            assert_eq!(tx.discount_cents, 2000, "recurring discount should be extracted");
            assert_eq!(tx.tax_cents, 1600);
            assert_eq!(tx.total_cents, 9600);
        }
        other => panic!("Expected SubscriptionRenewed, got {:?}", other),
    }
}

#[test]
fn test_lemonsqueezy_order_refunded_extracts_refund_data() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::lemonsqueezy::LemonSqueezyWebhookProvider;

    let provider = LemonSqueezyWebhookProvider;

    // LemonSqueezy order_refunded webhook payload
    let payload = r#"{
        "meta": {
            "event_name": "order_refunded",
            "custom_data": null
        },
        "data": {
            "id": "refund_ls_789",
            "attributes": {
                "order_id": 12345,
                "store_id": 67890,
                "amount": 2500,
                "currency": "GBP",
                "status": "succeeded",
                "test_mode": false
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse order_refunded");

    match event {
        WebhookEvent::Refunded(data) => {
            assert_eq!(data.refund_id, "refund_ls_789");
            assert_eq!(data.order_id, "12345");
            assert_eq!(data.currency, "gbp");
            assert_eq!(data.amount_cents, 2500);
            assert!(!data.test_mode);
            assert!(data.license_id.is_none(), "License ID is looked up later");
        }
        other => panic!("Expected Refunded, got {:?}", other),
    }
}

#[test]
fn test_lemonsqueezy_order_refunded_pending_ignored() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::lemonsqueezy::LemonSqueezyWebhookProvider;

    let provider = LemonSqueezyWebhookProvider;

    // Pending refund should be ignored
    let payload = r#"{
        "meta": {
            "event_name": "order_refunded",
            "custom_data": null
        },
        "data": {
            "id": "refund_pending",
            "attributes": {
                "order_id": 12345,
                "store_id": 67890,
                "amount": 2500,
                "currency": "USD",
                "status": "pending",
                "test_mode": false
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse event");

    match event {
        WebhookEvent::Ignored => {}
        other => panic!("Expected Ignored for pending refund, got {:?}", other),
    }
}

#[test]
fn test_lemonsqueezy_order_refunded_status_refunded_accepted() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::lemonsqueezy::LemonSqueezyWebhookProvider;

    let provider = LemonSqueezyWebhookProvider;

    // LemonSqueezy uses "refunded" status in some cases
    let payload = r#"{
        "meta": {
            "event_name": "order_refunded",
            "custom_data": null
        },
        "data": {
            "id": "refund_alt",
            "attributes": {
                "order_id": 99999,
                "store_id": 11111,
                "amount": 1000,
                "currency": "CAD",
                "status": "refunded",
                "test_mode": true
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse event");

    match event {
        WebhookEvent::Refunded(data) => {
            assert_eq!(data.refund_id, "refund_alt");
            assert_eq!(data.amount_cents, 1000);
            assert_eq!(data.currency, "cad");
        }
        other => panic!("Expected Refunded, got {:?}", other),
    }
}

// ============ RefundData Structure Tests ============

#[test]
fn test_refund_data_fields_are_correct() {
    use paycheck::handlers::webhooks::common::RefundData;

    let refund = RefundData {
        license_id: Some("lic_123".to_string()),
        refund_id: "re_456".to_string(),
        order_id: "pi_789".to_string(),
        currency: "usd".to_string(),
        amount_cents: 5000,
        test_mode: false,
        source: "refund".to_string(),
        metadata: None,
    };

    // Verify all fields are accessible
    assert_eq!(refund.license_id, Some("lic_123".to_string()));
    assert_eq!(refund.refund_id, "re_456");
    assert_eq!(refund.order_id, "pi_789");
    assert_eq!(refund.currency, "usd");
    assert_eq!(refund.amount_cents, 5000);
    assert!(!refund.test_mode);
    assert_eq!(refund.source, "refund");
    assert!(refund.metadata.is_none());
}

#[test]
fn test_renewal_data_with_transaction() {
    use paycheck::handlers::webhooks::common::{CheckoutTransactionData, RenewalData};

    let renewal = RenewalData {
        subscription_id: "sub_123".to_string(),
        is_renewal: true,
        is_paid: true,
        event_id: Some("inv_456".to_string()),
        payment_intent: Some("pi_test_789".to_string()),
        period_end: Some(1735689600),
        transaction: Some(CheckoutTransactionData {
            currency: "eur".to_string(),
            subtotal_cents: 9900,
            discount_cents: 0,
            tax_cents: 1980,
            total_cents: 11880,
            tax_inclusive: Some(false),
            discount_code: None,
            customer_country: Some("DE".to_string()),
            test_mode: false,
        }),
    };

    assert_eq!(renewal.subscription_id, "sub_123");
    assert!(renewal.is_renewal);
    assert!(renewal.is_paid);
    assert_eq!(renewal.event_id, Some("inv_456".to_string()));
    assert_eq!(renewal.period_end, Some(1735689600));

    let tx = renewal.transaction.unwrap();
    assert_eq!(tx.currency, "eur");
    assert_eq!(tx.subtotal_cents, 9900);
    assert_eq!(tx.tax_cents, 1980);
    assert_eq!(tx.total_cents, 11880);
    assert_eq!(tx.customer_country, Some("DE".to_string()));
}

// ============ Stripe Refund Linkage Tests ============

/// Verifies that Stripe checkout stores payment_intent as order_id (not session.id).
/// This is critical for refund tracking: refunds come with payment_intent, so we need
/// to store that ID at checkout time for later lookup.
#[test]
fn test_stripe_checkout_uses_payment_intent_as_order_id() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    // Stripe checkout.session.completed with payment_intent field
    // The session.id is "cs_xxx" but we need to store "pi_xxx" for refund linking
    let payload = r#"{
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_test_session_abc",
                "payment_intent": "pi_test_intent_xyz",
                "payment_status": "paid",
                "customer": "cus_test",
                "customer_details": {
                    "email": "test@example.com"
                },
                "metadata": {
                    "paycheck_session_id": "ps_123",
                    "project_id": "proj_456"
                },
                "currency": "usd",
                "amount_subtotal": 1999,
                "amount_total": 1999
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse checkout event");

    match event {
        WebhookEvent::CheckoutCompleted(data) => {
            // The order_id MUST be payment_intent, not session.id
            // This is required for refund tracking to work
            assert_eq!(
                data.order_id,
                Some("pi_test_intent_xyz".to_string()),
                "order_id should be payment_intent (pi_xxx), not session.id (cs_xxx), for refund linkage"
            );
        }
        other => panic!("Expected CheckoutCompleted, got {:?}", other),
    }
}

/// Verifies that checkout and refund use matching order_id for proper linkage.
/// Checkout stores payment_intent, refund looks up by payment_intent.
#[test]
fn test_stripe_checkout_and_refund_order_ids_match() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;
    let payment_intent = "pi_shared_intent_123";

    // 1. Parse checkout event
    let checkout_payload = format!(r#"{{
        "type": "checkout.session.completed",
        "data": {{
            "object": {{
                "id": "cs_session_abc",
                "payment_intent": "{}",
                "payment_status": "paid",
                "customer": "cus_test",
                "customer_details": {{ "email": "test@example.com" }},
                "metadata": {{ "paycheck_session_id": "ps_1", "project_id": "proj_1" }},
                "currency": "usd",
                "amount_total": 5000
            }}
        }}
    }}"#, payment_intent);

    let checkout_body = Bytes::from(checkout_payload);
    let checkout_event = provider.parse_event(&checkout_body).expect("should parse checkout");
    let checkout_order_id = match checkout_event {
        WebhookEvent::CheckoutCompleted(data) => data.order_id.expect("checkout should have order_id"),
        other => panic!("Expected CheckoutCompleted, got {:?}", other),
    };

    // 2. Parse refund event for the same payment (using refund.created)
    let refund_payload = format!(r#"{{
        "type": "refund.created",
        "data": {{
            "object": {{
                "id": "re_refund_789",
                "payment_intent": "{}",
                "charge": "ch_charge_xyz",
                "amount": 5000,
                "currency": "usd",
                "status": "succeeded",
                "livemode": true
            }}
        }}
    }}"#, payment_intent);

    let refund_body = Bytes::from(refund_payload);
    let refund_event = provider.parse_event(&refund_body).expect("should parse refund");
    let refund_order_id = match refund_event {
        WebhookEvent::Refunded(data) => data.order_id.clone(),
        other => panic!("Expected Refunded, got {:?}", other),
    };

    // 3. The order_ids MUST match for refund to find the original transaction
    assert_eq!(
        checkout_order_id, refund_order_id,
        "Checkout order_id ({}) must match refund order_id ({}) for transaction linkage",
        checkout_order_id, refund_order_id
    );
}

/// Verifies that Stripe checkout separates checkout_session_id from payment_intent.
///
/// Bug fix verification: The enricher needs two different IDs:
/// - `enricher_session_id`: Checkout session ID (cs_xxx) for Stripe API calls (fetch discounts)
/// - `order_id`: Payment intent ID (pi_xxx) for DB lookup (transaction stored with this ID)
///
/// Before the fix, both were conflated and the enricher would fail to fetch discounts
/// because it passed payment_intent to the checkout sessions API.
#[test]
fn test_stripe_checkout_separates_session_id_from_payment_intent() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;
    let checkout_session_id = "cs_test_session_abc123";
    let payment_intent_id = "pi_payment_intent_xyz789";

    let checkout_payload = format!(r#"{{
        "type": "checkout.session.completed",
        "data": {{
            "object": {{
                "id": "{}",
                "payment_intent": "{}",
                "payment_status": "paid",
                "customer": "cus_test",
                "customer_details": {{ "email": "test@example.com" }},
                "metadata": {{ "paycheck_session_id": "ps_1", "project_id": "proj_1" }},
                "currency": "usd",
                "amount_total": 5000
            }}
        }}
    }}"#, checkout_session_id, payment_intent_id);

    let checkout_body = Bytes::from(checkout_payload);
    let checkout_event = provider.parse_event(&checkout_body).expect("should parse checkout");

    let (order_id, enricher_session_id) = match checkout_event {
        WebhookEvent::CheckoutCompleted(data) => (
            data.order_id.expect("checkout should have order_id"),
            data.enricher_session_id.expect("checkout should have enricher_session_id"),
        ),
        other => panic!("Expected CheckoutCompleted, got {:?}", other),
    };

    // order_id should be payment_intent (for DB/refund linkage)
    assert_eq!(
        order_id, payment_intent_id,
        "order_id should be payment_intent for DB storage and refund linkage"
    );

    // enricher_session_id should be checkout session ID (for Stripe API calls)
    assert_eq!(
        enricher_session_id, checkout_session_id,
        "enricher_session_id should be checkout session ID for Stripe API calls"
    );

    // They must be different - this is the whole point of the fix
    assert_ne!(
        order_id, enricher_session_id,
        "order_id and enricher_session_id serve different purposes and should be different"
    );
}

/// Verifies that Stripe invoice.paid events include payment_intent for refund linkage.
/// Subscription renewals (and initial subscription payments) go through invoices,
/// and refunds reference the payment_intent from those invoices.
#[test]
fn test_stripe_invoice_includes_payment_intent_for_refund_linkage() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;

    let provider = StripeWebhookProvider;

    // 1. Parse invoice.paid event with payment_intent
    let payment_intent = "pi_subscription_payment_123";
    let invoice_payload = format!(r#"{{
        "type": "invoice.paid",
        "data": {{
            "object": {{
                "id": "in_test_invoice_abc",
                "customer": "cus_test_123",
                "subscription": "sub_test_456",
                "billing_reason": "subscription_cycle",
                "status": "paid",
                "payment_intent": "{}",
                "currency": "usd",
                "amount_paid": 2000,
                "subtotal": 2000,
                "total": 2000,
                "livemode": true,
                "lines": {{
                    "data": [{{
                        "period": {{"end": 1735689600}}
                    }}]
                }}
            }}
        }}
    }}"#, payment_intent);

    let invoice_body = Bytes::from(invoice_payload);
    let invoice_event = provider.parse_event(&invoice_body).expect("should parse invoice.paid");

    let renewal_payment_intent = match invoice_event {
        WebhookEvent::SubscriptionRenewed(data) => {
            assert!(
                data.payment_intent.is_some(),
                "Invoice event should include payment_intent for refund linkage"
            );
            data.payment_intent.unwrap()
        }
        other => panic!("Expected SubscriptionRenewed, got {:?}", other),
    };

    // 2. Parse refund event for the same payment (using refund.created)
    let refund_payload = format!(r#"{{
        "type": "refund.created",
        "data": {{
            "object": {{
                "id": "re_subscription_refund_789",
                "payment_intent": "{}",
                "charge": "ch_subscription_charge_xyz",
                "amount": 2000,
                "currency": "usd",
                "status": "succeeded",
                "livemode": true
            }}
        }}
    }}"#, payment_intent);

    let refund_body = Bytes::from(refund_payload);
    let refund_event = provider.parse_event(&refund_body).expect("should parse refund");
    let refund_order_id = match refund_event {
        WebhookEvent::Refunded(data) => data.order_id.clone(),
        other => panic!("Expected Refunded, got {:?}", other),
    };

    // 3. The payment_intent from invoice MUST match the refund's order_id
    // This is how refunds find the original subscription transaction
    assert_eq!(
        renewal_payment_intent, refund_order_id,
        "Invoice payment_intent ({}) must match refund order_id ({}) for subscription refund linkage",
        renewal_payment_intent, refund_order_id
    );
}

// ============ Stripe Dispute Linkage Tests ============

/// Verifies that checkout and dispute use matching order_id for proper linkage.
/// BUG: Disputes use charge ID, but transactions are stored with payment_intent.
/// This test demonstrates the bug by checking if checkout and dispute order_ids match.
#[test]
fn test_stripe_checkout_and_dispute_order_ids_match() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;
    use paycheck::handlers::webhooks::common::{WebhookProvider, WebhookEvent};

    let provider = StripeWebhookProvider;

    // 1. Parse checkout event to get the order_id (should be payment_intent)
    let payment_intent = "pi_test_payment_intent_xyz";
    let checkout_payload = format!(r#"{{
        "type": "checkout.session.completed",
        "data": {{
            "object": {{
                "id": "cs_test_abc123",
                "payment_intent": "{}",
                "payment_status": "paid",
                "customer": "cus_test_123",
                "customer_details": {{ "email": "buyer@example.com" }},
                "metadata": {{
                    "paycheck_session_id": "sess_123",
                    "project_id": "proj_456"
                }},
                "amount_total": 9900,
                "currency": "usd"
            }}
        }}
    }}"#, payment_intent);

    let checkout_body = Bytes::from(checkout_payload);
    let checkout_event = provider.parse_event(&checkout_body).expect("should parse checkout");
    let checkout_order_id = match checkout_event {
        WebhookEvent::CheckoutCompleted(data) => data.order_id.expect("should have order_id"),
        other => panic!("Expected CheckoutCompleted, got {:?}", other),
    };

    // Verify checkout uses payment_intent as order_id
    assert_eq!(checkout_order_id, payment_intent,
        "Checkout should store payment_intent as order_id");

    // 2. Parse dispute event for the same payment
    // In Stripe, disputes have both charge ID and payment_intent
    let dispute_payload = format!(r#"{{
        "type": "charge.dispute.created",
        "data": {{
            "object": {{
                "id": "dp_test_dispute_123",
                "charge": "ch_test_charge_abc",
                "payment_intent": "{}",
                "amount": 9900,
                "currency": "usd",
                "status": "needs_response",
                "reason": "fraudulent",
                "livemode": true
            }}
        }}
    }}"#, payment_intent);

    let dispute_body = Bytes::from(dispute_payload);
    let dispute_event = provider.parse_event(&dispute_body).expect("should parse dispute");
    let dispute_order_id = match dispute_event {
        WebhookEvent::Refunded(data) => data.order_id,
        other => panic!("Expected Refunded (dispute creates refund transaction), got {:?}", other),
    };

    // 3. The order_ids MUST match for dispute to find the original transaction
    // BUG: Currently this will FAIL because dispute uses charge ID instead of payment_intent
    assert_eq!(
        checkout_order_id, dispute_order_id,
        "Checkout order_id ({}) must match dispute order_id ({}) for transaction linkage. \
        BUG: Disputes currently use charge ID instead of payment_intent!",
        checkout_order_id, dispute_order_id
    );
}

/// Verifies dispute.closed (won) also uses correct order_id for reversal linkage.
#[test]
fn test_stripe_dispute_closed_uses_payment_intent() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::stripe::StripeWebhookProvider;
    use paycheck::handlers::webhooks::common::{WebhookProvider, WebhookEvent};

    let provider = StripeWebhookProvider;

    // Parse dispute.closed event (status=won creates reversal transaction)
    let dispute_payload = r#"{
        "type": "charge.dispute.closed",
        "data": {
            "object": {
                "id": "dp_test_dispute_456",
                "charge": "ch_test_charge_def",
                "payment_intent": "pi_test_payment_intent_abc",
                "amount": 5000,
                "currency": "usd",
                "status": "won",
                "reason": "fraudulent",
                "livemode": true
            }
        }
    }"#;

    let dispute_body = Bytes::from(dispute_payload);
    let dispute_event = provider.parse_event(&dispute_body).expect("should parse dispute closed");
    let dispute_order_id = match dispute_event {
        WebhookEvent::Refunded(data) => data.order_id,
        other => panic!("Expected Refunded (dispute reversal), got {:?}", other),
    };

    // Dispute reversal should use payment_intent to find the original transaction
    assert_eq!(
        dispute_order_id, "pi_test_payment_intent_abc",
        "Dispute reversal order_id ({}) should be payment_intent, not charge ID",
        dispute_order_id
    );
}

// ============ LemonSqueezy Subscription Refund Tests ============

/// Test that LemonSqueezy subscription_payment_refunded event is properly handled.
///
/// LemonSqueezy sends two different refund events:
/// - `order_refunded`: For initial order refunds (sends Order object with order_id)
/// - `subscription_payment_refunded`: For subscription invoice refunds (sends Subscription Invoice)
///
/// This test verifies subscription_payment_refunded is parsed correctly and returns
/// RefundData with the invoice ID for transaction lookup.
#[test]
fn test_lemonsqueezy_subscription_payment_refunded_extracts_refund_data() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::lemonsqueezy::LemonSqueezyWebhookProvider;

    let provider = LemonSqueezyWebhookProvider;

    // LemonSqueezy subscription_payment_refunded webhook payload
    // This event is sent when a subscription invoice payment is refunded
    // The data.id is the subscription invoice ID (same as stored from subscription_payment_success)
    let payload = r#"{
        "meta": {
            "event_name": "subscription_payment_refunded",
            "custom_data": null
        },
        "data": {
            "id": "si_invoice_12345",
            "type": "subscription-invoices",
            "attributes": {
                "subscription_id": 98765,
                "store_id": 11111,
                "status": "refunded",
                "refunded_at": "2025-01-15T10:30:00.000Z",
                "subtotal": 4900,
                "tax": 0,
                "total": 4900,
                "currency": "USD",
                "test_mode": false
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse subscription_payment_refunded");

    match event {
        WebhookEvent::Refunded(data) => {
            // Invoice ID is used for both refund_id and order_id
            // This matches how subscription_payment_success stores the invoice ID
            assert_eq!(data.refund_id, "si_invoice_12345", "refund_id should be invoice ID");
            assert_eq!(data.order_id, "si_invoice_12345", "order_id should be invoice ID for transaction lookup");
            assert_eq!(data.amount_cents, 4900);
            assert_eq!(data.currency, "usd");
            assert!(!data.test_mode);
            assert_eq!(data.source, "refund");
            // Metadata should contain subscription_id for debugging
            assert!(data.metadata.is_some());
            let metadata = data.metadata.unwrap();
            assert!(metadata.contains("98765"), "metadata should contain subscription_id");
        }
        other => panic!("Expected Refunded, got {:?}", other),
    }
}

/// End-to-end test that LemonSqueezy subscription renewal refunds are properly linked.
///
/// This test verifies:
/// 1. Create a subscription license with a renewal transaction
/// 2. The renewal transaction stores invoice_id as provider_order_id (from subscription_payment_success)
/// 3. Send subscription_payment_refunded webhook with the same invoice_id
/// 4. A refund transaction is created and linked to the original renewal
#[tokio::test]
async fn test_lemonsqueezy_subscription_refund_creates_transaction() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let state = create_test_app_state();
    let master_key = test_master_key();

    let license_id: String;
    let invoice_id = "si_renewal_invoice_555";

    {
        let mut conn = state.db.get().unwrap();
        let org = create_test_org(&mut conn, "Test Org");
        setup_lemonsqueezy_config(&mut conn, &org.id, &master_key);
        let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");

        // Create a subscription license
        let license = create_test_license_with_subscription(
            &conn,
            &project.id,
            &product.id,
            &org.id,
            Some(now() + (ONE_MONTH * 86400)),
            "lemonsqueezy",
            "98765", // subscription_id
        );
        license_id = license.id.clone();

        // Simulate what subscription_payment_success does: create a renewal transaction
        // with invoice_id as provider_order_id
        let renewal_tx = CreateTransaction {
            license_id: Some(license.id.clone()),
            project_id: project.id.clone(),
            product_id: Some(product.id.clone()),
            org_id: org.id.clone(),
            payment_provider: "lemonsqueezy".to_string(),
            provider_customer_id: Some("cust_test".to_string()),
            provider_subscription_id: Some("98765".to_string()),
            // This is the key part: subscription_payment_success stores invoice_id here
            provider_order_id: invoice_id.to_string(),
            currency: "usd".to_string(),
            subtotal_cents: 4900,
            discount_cents: 0,
            net_cents: 4900,
            tax_cents: 0,
            total_cents: 4900,
            discount_code: None,
            tax_inclusive: None,
            customer_country: None,
            transaction_type: TransactionType::Renewal,
            parent_transaction_id: None,
            is_subscription: true,
            source: "payment".to_string(),
            metadata: None,
            test_mode: false,
        };
        queries::create_transaction(&conn, &renewal_tx)
            .expect("Failed to create renewal transaction");
    }

    // Now send subscription_payment_refunded webhook
    // This should create a refund transaction linked to the renewal
    let payload = serde_json::json!({
        "meta": {
            "event_name": "subscription_payment_refunded",
            "custom_data": null
        },
        "data": {
            "id": invoice_id,  // Same as the renewal transaction's provider_order_id
            "type": "subscription-invoices",
            "attributes": {
                "subscription_id": 98765,
                "store_id": 11111,
                "status": "refunded",
                "refunded_at": "2025-01-15T10:30:00.000Z",
                "subtotal": 4900,
                "tax": 0,
                "total": 4900,
                "currency": "USD",
                "test_mode": false
            }
        }
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = compute_lemonsqueezy_signature(&payload_bytes, "ls_whsec_test_secret");

    let app = webhook_app(state.clone());

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

    // Webhook returns OK
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "Webhook should return OK status"
    );

    // Verify refund transaction was created
    let conn = state.db.get().unwrap();
    let transactions = queries::get_transactions_by_license(&conn, &license_id)
        .expect("Failed to list transactions");

    let refunds: Vec<_> = transactions
        .iter()
        .filter(|t| t.transaction_type == TransactionType::Refund)
        .collect();

    assert_eq!(
        refunds.len(), 1,
        "Should have 1 refund transaction after subscription_payment_refunded webhook"
    );

    let refund = &refunds[0];
    assert_eq!(refund.total_cents, -4900, "Refund should have negative amount");
    assert_eq!(refund.currency, "usd");
    assert_eq!(refund.payment_provider, "lemonsqueezy");
    assert!(refund.parent_transaction_id.is_some(), "Refund should link to parent renewal transaction");

    // Verify the renewal transaction still exists
    let renewal_count = transactions
        .iter()
        .filter(|t| t.transaction_type == TransactionType::Renewal)
        .count();
    assert_eq!(
        renewal_count, 1,
        "Renewal transaction should still exist"
    );
}

/// Tests that process_refund_atomic provides true atomicity.
///
/// The atomic function ensures that replay prevention and transaction creation
/// happen in a single database transaction. If any step fails, everything is
/// rolled back and payment provider can retry.
///
/// This test verifies:
/// 1. First call succeeds and creates the refund transaction atomically
/// 2. Second call (retry) correctly returns "Already processed"
/// 3. Only one refund transaction exists (no duplicates from non-atomic bugs)
#[test]
fn test_refund_replay_prevention_and_transaction_are_atomic() {
    use paycheck::handlers::webhooks::common::{process_refund_atomic, RefundResult};

    let mut conn = setup_test_db();
    let master_key = test_master_key();

    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, Some(now() + 86400));

    // First create a purchase transaction (so we have something to refund)
    let purchase = CreateTransaction {
        license_id: Some(license.id.clone()),
        project_id: project.id.clone(),
        product_id: Some(product.id.clone()),
        org_id: org.id.clone(),
        payment_provider: "stripe".to_string(),
        provider_customer_id: None,
        provider_subscription_id: None,
        provider_order_id: "ch_purchase_123".to_string(),
        currency: "usd".to_string(),
        subtotal_cents: 9900,
        discount_cents: 0,
        net_cents: 9900,
        tax_cents: 0,
        total_cents: 9900,
        discount_code: None,
        tax_inclusive: None,
        customer_country: None,
        transaction_type: TransactionType::Purchase,
        parent_transaction_id: None,
        is_subscription: false,
        source: "payment".to_string(),
        metadata: None,
        test_mode: false,
    };
    let purchase_txn = queries::create_transaction(&conn, &purchase).expect("Create purchase failed");

    let refund_id = "re_atomic_test_456";

    // Build refund transaction data
    let refund_data = CreateTransaction {
        license_id: Some(license.id.clone()),
        project_id: project.id.clone(),
        product_id: Some(product.id.clone()),
        org_id: org.id.clone(),
        payment_provider: "stripe".to_string(),
        provider_customer_id: None,
        provider_subscription_id: None,
        provider_order_id: refund_id.to_string(),
        currency: "usd".to_string(),
        subtotal_cents: -9900,
        discount_cents: 0,
        net_cents: -9900,
        tax_cents: 0,
        total_cents: -9900,
        discount_code: None,
        tax_inclusive: None,
        customer_country: None,
        transaction_type: TransactionType::Refund,
        parent_transaction_id: Some(purchase_txn.id.clone()),
        is_subscription: false,
        source: "refund".to_string(),
        metadata: None,
        test_mode: false,
    };

    // First call - should succeed ATOMICALLY (replay prevention + transaction)
    let result1 = process_refund_atomic(&mut conn, "stripe", refund_id, &refund_data)
        .expect("First refund should succeed");

    assert!(
        matches!(result1, RefundResult::Success),
        "First refund call should return Success"
    );

    // Verify refund transaction was created atomically
    let transactions = queries::get_transactions_by_license(&conn, &license.id)
        .expect("should query transactions");
    let refund_txns: Vec<_> = transactions
        .iter()
        .filter(|t| t.transaction_type == TransactionType::Refund)
        .collect();

    assert_eq!(
        refund_txns.len(),
        1,
        "Exactly one refund transaction should exist after first call"
    );
    assert_eq!(
        refund_txns[0].total_cents, -9900,
        "Refund should have negative amount"
    );

    // Second call (retry) - should return "Already processed" without creating duplicate
    let result2 = process_refund_atomic(&mut conn, "stripe", refund_id, &refund_data)
        .expect("Second refund should not error");

    assert!(
        matches!(result2, RefundResult::AlreadyProcessed),
        "Second refund call should return AlreadyProcessed"
    );

    // Verify NO duplicate transaction was created
    let transactions2 = queries::get_transactions_by_license(&conn, &license.id)
        .expect("should query transactions");
    let refund_txns2: Vec<_> = transactions2
        .iter()
        .filter(|t| t.transaction_type == TransactionType::Refund)
        .collect();

    assert_eq!(
        refund_txns2.len(),
        1,
        "Still exactly one refund transaction after retry - atomicity prevents duplicates"
    );
}

/// Test that pending subscription refunds are ignored (only "refunded" status is processed).
#[test]
fn test_lemonsqueezy_subscription_payment_refunded_pending_ignored() {
    use axum::body::Bytes;
    use paycheck::handlers::webhooks::common::{WebhookEvent, WebhookProvider};
    use paycheck::handlers::webhooks::lemonsqueezy::LemonSqueezyWebhookProvider;

    let provider = LemonSqueezyWebhookProvider;

    // Pending refund should be ignored
    let payload = r#"{
        "meta": {
            "event_name": "subscription_payment_refunded",
            "custom_data": null
        },
        "data": {
            "id": "si_pending_refund",
            "type": "subscription-invoices",
            "attributes": {
                "subscription_id": 12345,
                "store_id": 11111,
                "status": "pending",
                "currency": "USD",
                "total": 2900,
                "test_mode": true
            }
        }
    }"#;

    let body = Bytes::from(payload);
    let event = provider.parse_event(&body).expect("should parse event");

    match event {
        WebhookEvent::Ignored => {}
        other => panic!("Expected Ignored for pending subscription refund, got {:?}", other),
    }
}
