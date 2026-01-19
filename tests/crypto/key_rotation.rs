//! Tests for master key rotation
//!
//! These tests verify that all encrypted data is properly re-encrypted
//! when the master key is rotated.
//!
//! Note: Licenses are no longer encrypted, so only project private keys
//! and organization payment configs need rotation.

#[path = "../common/mod.rs"]
mod common;

use common::*;
use rusqlite::Connection;

// ============ Test Key Constants ============

/// Bytes for the "old" master key used before rotation
const OLD_KEY_BYTES: [u8; 32] = [1u8; 32];
/// Bytes for the "new" master key used after rotation
const NEW_KEY_BYTES: [u8; 32] = [2u8; 32];

/// Simulate key rotation for a project's private key
fn rotate_project_key(
    conn: &Connection,
    project_id: &str,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<(), String> {
    // Get project
    let project = queries::get_project_by_id(conn, project_id)
        .map_err(|e| e.to_string())?
        .ok_or("Project not found")?;

    // Decrypt with old key
    let plaintext = old_key
        .decrypt_private_key(&project.id, &project.private_key)
        .map_err(|e| format!("Failed to decrypt: {}", e))?;

    // Re-encrypt with new key
    let new_ciphertext = new_key
        .encrypt_private_key(&project.id, &plaintext)
        .map_err(|e| format!("Failed to encrypt: {}", e))?;

    // Update in database
    queries::update_project_private_key(conn, &project.id, &new_ciphertext)
        .map_err(|e| format!("Failed to update: {}", e))?;

    Ok(())
}

/// Simulate key rotation for all of an organization's service configs
fn rotate_org_service_configs(
    conn: &Connection,
    org_id: &str,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<(), String> {
    // Get all service configs for this org
    let configs = queries::list_all_org_service_configs(conn)
        .map_err(|e| format!("Failed to list service configs: {}", e))?
        .into_iter()
        .filter(|c| c.org_id == org_id)
        .collect::<Vec<_>>();

    for config in configs {
        // Decrypt with old key
        let plaintext = old_key
            .decrypt_private_key(&config.org_id, &config.config_encrypted)
            .map_err(|e| format!("Failed to decrypt {} config: {}", config.provider.as_str(), e))?;

        // Re-encrypt with new key
        let new_enc = new_key
            .encrypt_private_key(&config.org_id, &plaintext)
            .map_err(|e| format!("Failed to re-encrypt {} config: {}", config.provider.as_str(), e))?;

        // Update in database
        queries::update_org_service_config_encrypted(conn, &config.id, &new_enc)
            .map_err(|e| format!("Failed to update {} config: {}", config.provider.as_str(), e))?;
    }

    Ok(())
}

// ============ Project Private Key Rotation ============

#[test]
fn test_project_private_key_reencrypts_with_new_master_key() {
    let mut conn = setup_test_db();
    let old_key = MasterKey::from_bytes(OLD_KEY_BYTES);
    let new_key = MasterKey::from_bytes(NEW_KEY_BYTES);

    // Create org and project with old key
    let org = create_test_org(&mut conn, "Test Org");

    // Create project - encryption happens internally with correct project ID
    let (private_key_bytes, public_key) = jwt::generate_keypair();
    let input = CreateProject {
        name: "Test Project".to_string(),
        license_key_prefix: "TEST".to_string(),
        redirect_url: None,
        email_from: None,
        email_enabled: true,
        email_webhook_url: None,
    };
    let project = queries::create_project(
        &conn,
        &org.id,
        &input,
        &private_key_bytes,
        &public_key,
        &old_key,
    )
    .expect("Failed to create project");

    // Verify we can decrypt with old key
    let fetched = queries::get_project_by_id(&mut conn, &project.id)
        .unwrap()
        .unwrap();
    let decrypted = old_key
        .decrypt_private_key(&project.id, &fetched.private_key)
        .expect("Should decrypt with old key");
    assert_eq!(
        decrypted, private_key_bytes,
        "decrypted private key should match original plaintext before rotation"
    );

    // Rotate the key
    rotate_project_key(&mut conn, &project.id, &old_key, &new_key).expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_project_by_id(&mut conn, &project.id)
        .unwrap()
        .unwrap();
    let result = old_key.decrypt_private_key(&project.id, &fetched.private_key);
    assert!(
        result.is_err(),
        "old key should fail to decrypt after rotation"
    );

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&project.id, &fetched.private_key)
        .expect("New key should decrypt");
    assert_eq!(
        decrypted, private_key_bytes,
        "decrypted private key should match original plaintext after rotation with new key"
    );
}

// ============ Organization Payment Config Rotation ============

#[test]
fn test_org_stripe_config_reencrypts_with_new_master_key() {
    let mut conn = setup_test_db();
    let old_key = MasterKey::from_bytes(OLD_KEY_BYTES);
    let new_key = MasterKey::from_bytes(NEW_KEY_BYTES);

    // Create org
    let org = create_test_org(&mut conn, "Test Org");

    // Set up Stripe config with old key
    let stripe_config = r#"{"secret_key":"sk_test_123","publishable_key":"pk_test_123","webhook_secret":"whsec_123"}"#;
    let encrypted_stripe = old_key
        .encrypt_private_key(&org.id, stripe_config.as_bytes())
        .unwrap();

    queries::upsert_org_service_config(&conn, &org.id, ServiceProvider::Stripe, &encrypted_stripe)
        .unwrap();

    // Verify we can decrypt with old key
    let fetched = queries::get_org_service_config(&conn, &org.id, ServiceProvider::Stripe)
        .unwrap()
        .expect("Stripe config should exist");
    let decrypted = old_key
        .decrypt_private_key(&org.id, &fetched.config_encrypted)
        .expect("Should decrypt with old key");
    assert_eq!(
        decrypted,
        stripe_config.as_bytes(),
        "decrypted Stripe config should match original JSON before rotation"
    );

    // Rotate the key
    rotate_org_service_configs(&mut conn, &org.id, &old_key, &new_key)
        .expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_org_service_config(&conn, &org.id, ServiceProvider::Stripe)
        .unwrap()
        .expect("Stripe config should still exist");
    let result = old_key.decrypt_private_key(&org.id, &fetched.config_encrypted);
    assert!(
        result.is_err(),
        "old key should fail to decrypt Stripe config after rotation"
    );

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&org.id, &fetched.config_encrypted)
        .expect("New key should decrypt");
    assert_eq!(
        decrypted,
        stripe_config.as_bytes(),
        "decrypted Stripe config should match original JSON after rotation with new key"
    );
}

#[test]
fn test_org_lemonsqueezy_config_reencrypts_with_new_master_key() {
    let mut conn = setup_test_db();
    let old_key = MasterKey::from_bytes(OLD_KEY_BYTES);
    let new_key = MasterKey::from_bytes(NEW_KEY_BYTES);

    // Create org
    let org = create_test_org(&mut conn, "Test Org");

    // Set up LemonSqueezy config with old key
    let ls_config = r#"{"api_key":"ls_test_123","store_id":"12345","webhook_secret":"lswhsec_123"}"#;
    let encrypted_ls = old_key
        .encrypt_private_key(&org.id, ls_config.as_bytes())
        .unwrap();

    queries::upsert_org_service_config(&conn, &org.id, ServiceProvider::LemonSqueezy, &encrypted_ls)
        .unwrap();

    // Verify we can decrypt with old key
    let fetched = queries::get_org_service_config(&conn, &org.id, ServiceProvider::LemonSqueezy)
        .unwrap()
        .expect("LemonSqueezy config should exist");
    let decrypted = old_key
        .decrypt_private_key(&org.id, &fetched.config_encrypted)
        .expect("Should decrypt with old key");
    assert_eq!(
        decrypted,
        ls_config.as_bytes(),
        "decrypted LemonSqueezy config should match original JSON before rotation"
    );

    // Rotate the key
    rotate_org_service_configs(&mut conn, &org.id, &old_key, &new_key)
        .expect("Rotation should succeed");

    // Verify old key no longer works
    let fetched = queries::get_org_service_config(&conn, &org.id, ServiceProvider::LemonSqueezy)
        .unwrap()
        .expect("LemonSqueezy config should still exist");
    let result = old_key.decrypt_private_key(&org.id, &fetched.config_encrypted);
    assert!(
        result.is_err(),
        "old key should fail to decrypt LemonSqueezy config after rotation"
    );

    // Verify new key works
    let decrypted = new_key
        .decrypt_private_key(&org.id, &fetched.config_encrypted)
        .expect("New key should decrypt");
    assert_eq!(
        decrypted,
        ls_config.as_bytes(),
        "decrypted LemonSqueezy config should match original JSON after rotation with new key"
    );
}

// ============ Email HMAC Key Rotation (Issue 15 from security audit) ============

/// Simulate rotation of the email HMAC key (stored in system_config).
/// The HMAC key bytes are preserved, just re-encrypted with new master key.
fn rotate_email_hmac_key(
    conn: &Connection,
    old_key: &MasterKey,
    new_key: &MasterKey,
) -> Result<(), String> {
    let encrypted = queries::get_system_config(conn, EmailHasher::CONFIG_KEY)
        .map_err(|e| e.to_string())?
        .ok_or("Email HMAC key not found")?;

    // Decrypt with old key
    let plaintext = old_key
        .decrypt_private_key("system-config", &encrypted)
        .map_err(|e| format!("Failed to decrypt HMAC key: {}", e))?;

    // Re-encrypt with new key
    let new_encrypted = new_key
        .encrypt_private_key("system-config", &plaintext)
        .map_err(|e| format!("Failed to encrypt HMAC key: {}", e))?;

    // Update in database
    queries::set_system_config(conn, EmailHasher::CONFIG_KEY, &new_encrypted)
        .map_err(|e| format!("Failed to update HMAC key: {}", e))?;

    Ok(())
}

/// Test that email hashes remain valid after master key rotation.
/// Issue 15 from security audit: The HMAC key bytes must be preserved.
///
/// This is critical because:
/// - Email hashes are used for license lookup
/// - If the HMAC key changes, existing licenses become unlookupable
/// - The fix is to store the HMAC key encrypted (not derived from master key)
#[test]
fn test_email_hash_survives_master_key_rotation() {
    let mut conn = setup_test_db();
    let old_key = MasterKey::from_bytes(OLD_KEY_BYTES);
    let new_key = MasterKey::from_bytes(NEW_KEY_BYTES);

    // Generate and store an email HMAC key (encrypted with old master key)
    let hmac_key = EmailHasher::generate_key();
    let encrypted_hmac = old_key
        .encrypt_private_key("system-config", &hmac_key)
        .expect("Failed to encrypt HMAC key");

    queries::set_system_config(&mut conn, EmailHasher::CONFIG_KEY, &encrypted_hmac)
        .expect("Failed to store HMAC key");

    // Create email hasher and hash a test email
    let hasher_before = EmailHasher::from_bytes(hmac_key);
    let test_email = "customer@example.com";
    let hash_before = hasher_before.hash(test_email);

    // Perform master key rotation
    rotate_email_hmac_key(&mut conn, &old_key, &new_key).expect("Rotation should succeed");

    // Load the rotated HMAC key with new master key
    let rotated_encrypted = queries::get_system_config(&mut conn, EmailHasher::CONFIG_KEY)
        .expect("Failed to load rotated HMAC key")
        .expect("HMAC key should exist after rotation");

    let rotated_hmac_bytes = new_key
        .decrypt_private_key("system-config", &rotated_encrypted)
        .expect("Should decrypt with new master key");

    // The HMAC key bytes should be identical
    assert_eq!(
        rotated_hmac_bytes.as_slice(),
        &hmac_key,
        "HMAC key bytes must be preserved during rotation"
    );

    // Create hasher with rotated key and verify same email produces same hash
    let hmac_key_array: [u8; 32] = rotated_hmac_bytes
        .try_into()
        .expect("HMAC key should be 32 bytes");
    let hasher_after = EmailHasher::from_bytes(hmac_key_array);
    let hash_after = hasher_after.hash(test_email);

    assert_eq!(
        hash_before, hash_after,
        "Email hash must be identical before and after master key rotation"
    );
}

/// Test that old master key cannot decrypt HMAC key after rotation.
#[test]
fn test_old_key_cannot_decrypt_hmac_after_rotation() {
    let mut conn = setup_test_db();
    let old_key = MasterKey::from_bytes(OLD_KEY_BYTES);
    let new_key = MasterKey::from_bytes(NEW_KEY_BYTES);

    // Store HMAC key encrypted with old key
    let hmac_key = EmailHasher::generate_key();
    let encrypted_hmac = old_key
        .encrypt_private_key("system-config", &hmac_key)
        .expect("Failed to encrypt HMAC key");

    queries::set_system_config(&mut conn, EmailHasher::CONFIG_KEY, &encrypted_hmac)
        .expect("Failed to store HMAC key");

    // Rotate
    rotate_email_hmac_key(&mut conn, &old_key, &new_key).expect("Rotation should succeed");

    // Old key should fail
    let rotated_encrypted = queries::get_system_config(&mut conn, EmailHasher::CONFIG_KEY)
        .expect("Failed to load HMAC key")
        .expect("HMAC key should exist");

    let result = old_key.decrypt_private_key("system-config", &rotated_encrypted);
    assert!(
        result.is_err(),
        "Old master key should not decrypt HMAC key after rotation"
    );
}
