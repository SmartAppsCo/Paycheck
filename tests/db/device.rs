//! Database device operation tests

#[path = "../common/mod.rs"]
mod common;

use common::*;
use rusqlite::Connection;

// ============ Device Creation Tests ============

#[test]
fn test_create_device() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let device = create_test_device(&mut conn, &license.id, "device-uuid-123", DeviceType::Uuid);

    assert!(!device.id.is_empty(), "device should have a generated ID");
    assert_eq!(
        device.license_id, license.id,
        "device should be linked to the correct license"
    );
    assert_eq!(
        device.device_id, "device-uuid-123",
        "device_id should match the provided identifier"
    );
    assert_eq!(
        device.device_type,
        DeviceType::Uuid,
        "device_type should be Uuid"
    );
    assert!(!device.jti.is_empty(), "device should have a generated JTI");
    assert_eq!(
        device.name,
        Some("Test Device".to_string()),
        "device name should match the provided value"
    );
}

#[test]
fn test_create_device_machine_type() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let jti = uuid::Uuid::new_v4().to_string();
    let device = queries::create_device(
        &conn,
        &license.id,
        "machine-hwid-abc",
        DeviceType::Machine,
        &jti,
        Some("Desktop PC"),
    )
    .expect("Failed to create device");

    assert_eq!(
        device.device_type,
        DeviceType::Machine,
        "device_type should be Machine for hardware-derived IDs"
    );
    assert_eq!(
        device.device_id, "machine-hwid-abc",
        "device_id should match the provided hardware identifier"
    );
    assert_eq!(device.jti, jti, "JTI should match the provided value");
    assert_eq!(
        device.name,
        Some("Desktop PC".to_string()),
        "device name should match the provided value"
    );
}

#[test]
fn test_create_device_without_name() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let jti = uuid::Uuid::new_v4().to_string();
    let device = queries::create_device(
        &conn,
        &license.id,
        "device-id",
        DeviceType::Uuid,
        &jti,
        None, // No name
    )
    .expect("Failed to create device");

    assert!(
        device.name.is_none(),
        "device name should be None when not provided"
    );
}

// ============ Device Lookup Tests ============

#[test]
fn test_get_device_by_jti() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let created = create_test_device(&mut conn, &license.id, "device-123", DeviceType::Uuid);

    let fetched = queries::get_device_by_jti(&mut conn, &created.jti)
        .expect("Query failed")
        .expect("Device not found");

    assert_eq!(
        fetched.id, created.id,
        "fetched device ID should match the created device"
    );
    assert_eq!(fetched.jti, created.jti, "fetched device JTI should match");
    assert_eq!(
        fetched.device_id, created.device_id,
        "fetched device_id should match"
    );
}

#[test]
fn test_get_device_by_jti_not_found() {
    let mut conn = setup_test_db();

    let result = queries::get_device_by_jti(&mut conn, "nonexistent-jti").expect("Query failed");

    assert!(
        result.is_none(),
        "lookup by nonexistent JTI should return None"
    );
}

#[test]
fn test_get_device_for_license() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let created = create_test_device(&mut conn, &license.id, "device-123", DeviceType::Uuid);

    let fetched = queries::get_device_for_license(&mut conn, &license.id, "device-123")
        .expect("Query failed")
        .expect("Device not found");

    assert_eq!(
        fetched.id, created.id,
        "fetched device ID should match the created device"
    );
    assert_eq!(
        fetched.license_id, license.id,
        "fetched device should be linked to the correct license"
    );
    assert_eq!(
        fetched.device_id, "device-123",
        "fetched device_id should match"
    );
}

#[test]
fn test_get_device_for_license_wrong_device_id() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    create_test_device(&mut conn, &license.id, "device-123", DeviceType::Uuid);

    // Look up with wrong device_id
    let result =
        queries::get_device_for_license(&mut conn, &license.id, "wrong-device").expect("Query failed");

    assert!(
        result.is_none(),
        "lookup with wrong device_id should return None"
    );
}

#[test]
fn test_get_device_for_license_wrong_license() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license1 = create_test_license(&mut conn, &project.id, &product.id, None);
    let license2 = create_test_license(&mut conn, &project.id, &product.id, None);
    create_test_device(&mut conn, &license1.id, "device-123", DeviceType::Uuid);

    // Look up with wrong license_id
    let result =
        queries::get_device_for_license(&mut conn, &license2.id, "device-123").expect("Query failed");

    assert!(
        result.is_none(),
        "lookup with wrong license_id should return None"
    );
}

#[test]
fn test_list_devices_for_license() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    create_test_device(&mut conn, &license.id, "device-1", DeviceType::Uuid);
    create_test_device(&mut conn, &license.id, "device-2", DeviceType::Machine);
    create_test_device(&mut conn, &license.id, "device-3", DeviceType::Uuid);

    let devices = queries::list_devices_for_license(&mut conn, &license.id).expect("Query failed");

    assert_eq!(
        devices.len(),
        3,
        "should list all 3 devices for the license"
    );
}

#[test]
fn test_list_devices_for_license_empty() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    let devices = queries::list_devices_for_license(&mut conn, &license.id).expect("Query failed");

    assert!(
        devices.is_empty(),
        "license with no devices should return empty list"
    );
}

// ============ Device Uniqueness Tests ============

#[test]
fn test_device_id_unique_per_license() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    // Create first device
    create_test_device(&mut conn, &license.id, "device-123", DeviceType::Uuid);

    // Try to create second device with same device_id - should fail
    let jti2 = uuid::Uuid::new_v4().to_string();
    let result = queries::create_device(
        &conn,
        &license.id,
        "device-123", // Same device_id
        DeviceType::Uuid,
        &jti2,
        None,
    );

    assert!(
        result.is_err(),
        "duplicate device_id on same license should fail"
    );
}

#[test]
fn test_same_device_id_different_licenses() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license1 = create_test_license(&mut conn, &project.id, &product.id, None);
    let license2 = create_test_license(&mut conn, &project.id, &product.id, None);

    // Same device_id on different licenses should work
    let device1 = create_test_device(&mut conn, &license1.id, "shared-device", DeviceType::Uuid);
    let device2 = create_test_device(&mut conn, &license2.id, "shared-device", DeviceType::Uuid);

    assert_eq!(
        device1.device_id, device2.device_id,
        "both devices should have the same device_id"
    );
    assert_ne!(
        device1.license_id, device2.license_id,
        "devices should belong to different licenses"
    );
    assert_ne!(device1.jti, device2.jti, "devices should have unique JTIs");
}

// ============ Device JTI Tests ============

#[test]
fn test_jti_unique_across_devices() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    // Create multiple devices and ensure JTIs are unique
    let mut jtis = std::collections::HashSet::new();
    for i in 0..10 {
        let device = create_test_device(
            &conn,
            &license.id,
            &format!("device-{}", i),
            DeviceType::Uuid,
        );
        assert!(jtis.insert(device.jti), "Duplicate JTI generated");
    }
}

// ============ Device Deletion Tests ============

#[test]
fn test_delete_device() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let device = create_test_device(&mut conn, &license.id, "device-123", DeviceType::Uuid);

    let deleted = queries::delete_device(&mut conn, &device.id).expect("Delete failed");
    assert!(
        deleted,
        "delete_device should return true when device exists"
    );

    let result = queries::get_device_by_jti(&mut conn, &device.jti).expect("Query failed");
    assert!(
        result.is_none(),
        "deleted device should not be retrievable by JTI"
    );
}

#[test]
fn test_delete_device_not_found() {
    let mut conn = setup_test_db();

    let deleted = queries::delete_device(&mut conn, "nonexistent-id").expect("Delete failed");
    assert!(
        !deleted,
        "delete_device should return false for nonexistent ID"
    );
}

// ============ Cascade Delete Tests ============

#[test]
fn test_delete_license_cascades_to_devices() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);
    let device = create_test_device(&mut conn, &license.id, "device-123", DeviceType::Uuid);

    // Delete product which cascades to license
    queries::delete_product(&mut conn, &product.id).expect("Delete failed");

    let result = queries::get_device_by_jti(&mut conn, &device.jti).expect("Query failed");
    assert!(
        result.is_none(),
        "device should be deleted when parent product is deleted (cascade)"
    );
}

// ============ Acquire Device Atomic Tests ============

#[test]
fn test_acquire_device_atomic_new_device() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));

    let jti = uuid::Uuid::new_v4().to_string();
    let result = queries::acquire_device_atomic(
        &mut conn,
        &license.id,
        "new-device-1",
        DeviceType::Uuid,
        &jti,
        Some("My Laptop"),
        Some(5),  // device_limit
        Some(10), // activation_limit
        None,     // device_inactive_days
    );

    let result = result.expect("acquire_device_atomic should succeed for new device");
    match &result {
        queries::DeviceAcquisitionResult::Created(device) => {
            assert_eq!(device.device_id, "new-device-1");
            assert_eq!(device.device_type, DeviceType::Uuid);
            assert_eq!(device.jti, jti);
            assert_eq!(device.license_id, license.id);
            assert_eq!(device.name, Some("My Laptop".to_string()));
        }
        queries::DeviceAcquisitionResult::Existing(_) => {
            panic!("Expected Created variant, got Existing");
        }
    }

    // Verify activation_count was incremented
    let updated_license = queries::get_license_by_id(&conn, &license.id)
        .expect("query failed")
        .expect("license not found");
    assert_eq!(
        updated_license.activation_count, 1,
        "activation_count should be incremented to 1 after new device"
    );

    // Verify device is in the database
    let devices = queries::list_devices_for_license(&conn, &license.id).expect("query failed");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, "new-device-1");
}

#[test]
fn test_acquire_device_atomic_existing_device_same_id() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));

    // First acquisition - creates the device
    let jti1 = uuid::Uuid::new_v4().to_string();
    let result1 = queries::acquire_device_atomic(
        &mut conn,
        &license.id,
        "dev-1",
        DeviceType::Uuid,
        &jti1,
        Some("Laptop"),
        Some(5),
        Some(10),
        None,
    )
    .expect("first acquire should succeed");
    assert!(matches!(result1, queries::DeviceAcquisitionResult::Created(_)));

    let license_after_first = queries::get_license_by_id(&conn, &license.id)
        .expect("query failed")
        .expect("license not found");
    assert_eq!(license_after_first.activation_count, 1);

    // Second acquisition with same device_id but new JTI - should return Existing
    let jti2 = uuid::Uuid::new_v4().to_string();
    let result2 = queries::acquire_device_atomic(
        &mut conn,
        &license.id,
        "dev-1",
        DeviceType::Uuid,
        &jti2,
        Some("Laptop"),
        Some(5),
        Some(10),
        None,
    )
    .expect("second acquire should succeed");

    match &result2 {
        queries::DeviceAcquisitionResult::Existing(device) => {
            assert_eq!(device.jti, jti2, "JTI should be updated to the new value");
            assert_eq!(device.device_id, "dev-1");
        }
        queries::DeviceAcquisitionResult::Created(_) => {
            panic!("Expected Existing variant for same device_id, got Created");
        }
    }

    // activation_count should NOT have incremented (reactivation of same device)
    let license_after_second = queries::get_license_by_id(&conn, &license.id)
        .expect("query failed")
        .expect("license not found");
    assert_eq!(
        license_after_second.activation_count, 1,
        "activation_count should not increment for existing device reactivation"
    );

    // Old JTI should no longer resolve
    let old_lookup = queries::get_device_by_jti(&conn, &jti1).expect("query failed");
    assert!(
        old_lookup.is_none(),
        "old JTI should not resolve after device reactivation"
    );

    // New JTI should resolve
    let new_lookup = queries::get_device_by_jti(&conn, &jti2).expect("query failed");
    assert!(new_lookup.is_some(), "new JTI should resolve");
    assert_eq!(new_lookup.unwrap().device_id, "dev-1");
}

#[test]
fn test_acquire_device_atomic_device_limit_reached() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));

    let device_limit = 2;

    // Fill up to the device limit
    for i in 0..device_limit {
        let jti = uuid::Uuid::new_v4().to_string();
        queries::acquire_device_atomic(
            &mut conn,
            &license.id,
            &format!("device-{}", i),
            DeviceType::Uuid,
            &jti,
            None,
            Some(device_limit),
            None, // no activation limit
            None,
        )
        .expect("should succeed within device limit");
    }

    // Third device should fail
    let jti = uuid::Uuid::new_v4().to_string();
    let result = queries::acquire_device_atomic(
        &mut conn,
        &license.id,
        "device-overflow",
        DeviceType::Uuid,
        &jti,
        None,
        Some(device_limit),
        None,
        None,
    );

    assert!(result.is_err(), "should fail when device limit is reached");
    let err_msg = format!("{}", result.err().unwrap());
    assert!(
        err_msg.to_lowercase().contains("device limit"),
        "error should mention device limit, got: {}",
        err_msg
    );

    // Verify only 2 devices exist
    let devices = queries::list_devices_for_license(&conn, &license.id).expect("query failed");
    assert_eq!(devices.len(), 2, "only 2 devices should exist after limit rejection");
}

#[test]
fn test_acquire_device_atomic_activation_limit_reached() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));

    let activation_limit = 3;

    // Set activation_count to the limit via raw SQL
    conn.execute(
        "UPDATE licenses SET activation_count = ?1 WHERE id = ?2",
        rusqlite::params![activation_limit, &license.id],
    )
    .expect("failed to set activation_count");

    // Attempt to acquire a new device -- should fail due to activation limit
    let jti = uuid::Uuid::new_v4().to_string();
    let result = queries::acquire_device_atomic(
        &mut conn,
        &license.id,
        "new-device",
        DeviceType::Uuid,
        &jti,
        None,
        None,                    // no device limit
        Some(activation_limit),  // activation limit reached
        None,
    );

    assert!(
        result.is_err(),
        "should fail when activation limit is reached"
    );
    let err_msg = format!("{}", result.err().unwrap());
    assert!(
        err_msg.to_lowercase().contains("activation limit"),
        "error should mention activation limit, got: {}",
        err_msg
    );

    // Verify no device was created
    let devices = queries::list_devices_for_license(&conn, &license.id).expect("query failed");
    assert!(devices.is_empty(), "no device should be created when activation limit is reached");
}

#[test]
fn test_acquire_device_atomic_inactive_device_eviction() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));

    let device_limit = 2;
    let inactive_days = 30;

    // Create 2 devices (at the limit)
    let jti1 = uuid::Uuid::new_v4().to_string();
    let _result1 = queries::acquire_device_atomic(
        &mut conn,
        &license.id,
        "active-device",
        DeviceType::Uuid,
        &jti1,
        None,
        Some(device_limit),
        None,
        Some(inactive_days),
    )
    .expect("first device should succeed");

    let jti2 = uuid::Uuid::new_v4().to_string();
    queries::acquire_device_atomic(
        &mut conn,
        &license.id,
        "stale-device",
        DeviceType::Uuid,
        &jti2,
        None,
        Some(device_limit),
        None,
        Some(inactive_days),
    )
    .expect("second device should succeed");

    // Make one device inactive (last_seen 60 days ago)
    let sixty_days_ago = now() - (60 * 86400);
    conn.execute(
        "UPDATE devices SET last_seen_at = ?1 WHERE device_id = 'stale-device' AND license_id = ?2",
        rusqlite::params![sixty_days_ago, &license.id],
    )
    .expect("failed to set last_seen_at");

    // Acquiring a 3rd device should succeed because the stale device is not counted
    let jti3 = uuid::Uuid::new_v4().to_string();
    let result3 = queries::acquire_device_atomic(
        &mut conn,
        &license.id,
        "new-device",
        DeviceType::Uuid,
        &jti3,
        None,
        Some(device_limit),
        None,
        Some(inactive_days),
    );

    assert!(
        result3.is_ok(),
        "should succeed because inactive device is excluded from count: {:?}",
        result3.err()
    );
    assert!(matches!(
        result3.unwrap(),
        queries::DeviceAcquisitionResult::Created(_)
    ));

    // Total devices in DB is 3, but only 2 are "active" within the inactive_days window
    let all_devices = queries::list_devices_for_license(&conn, &license.id).expect("query failed");
    assert_eq!(all_devices.len(), 3, "all 3 devices should exist in DB");
}

#[test]
fn test_acquire_device_atomic_unlimited() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));

    // Create 20 devices with no limits (None = unlimited)
    for i in 0..20 {
        let jti = uuid::Uuid::new_v4().to_string();
        let result = queries::acquire_device_atomic(
            &mut conn,
            &license.id,
            &format!("device-{}", i),
            DeviceType::Uuid,
            &jti,
            None,
            None, // no device limit
            None, // no activation limit
            None,
        );
        assert!(
            result.is_ok(),
            "device {} should succeed with unlimited limits: {:?}",
            i,
            result.err()
        );
    }

    let devices = queries::list_devices_for_license(&conn, &license.id).expect("query failed");
    assert_eq!(devices.len(), 20, "all 20 devices should exist");

    let updated_license = queries::get_license_by_id(&conn, &license.id)
        .expect("query failed")
        .expect("license not found");
    assert_eq!(
        updated_license.activation_count, 20,
        "activation_count should be 20 after 20 new devices"
    );
}

#[test]
fn test_acquire_device_atomic_concurrent() {
    // This test verifies the IMMEDIATE transaction prevents TOCTOU races
    // by having multiple threads try to acquire devices on a license with device_limit=1.
    // Exactly one should succeed, the rest should fail.

    use std::sync::{Arc, Barrier};

    let device_limit = 1;
    let num_threads = 5;

    // We need a file-based DB for cross-thread access since in-memory DBs are per-connection.
    let db_path = format!("/tmp/claude/test_acquire_concurrent_{}.db", uuid::Uuid::new_v4());
    let conn = Connection::open(&db_path).expect("Failed to create test db");
    init_db(&conn).expect("Failed to init schema");

    let master_key = test_master_key();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "My App", &master_key);
    let product = create_test_product(&conn, &project.id, "Pro", "pro");
    let license = create_test_license(&conn, &project.id, &product.id, Some(future_timestamp(365)));
    let license_id = license.id.clone();

    drop(conn); // Close so threads can open their own connections

    let barrier = Arc::new(Barrier::new(num_threads));
    let db_path_arc = Arc::new(db_path.clone());

    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            let db_path = Arc::clone(&db_path_arc);
            let license_id = license_id.clone();

            std::thread::spawn(move || {
                let mut thread_conn =
                    Connection::open(db_path.as_str()).expect("thread failed to open db");
                thread_conn
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .expect("failed to set busy timeout");

                let jti = uuid::Uuid::new_v4().to_string();

                // Synchronize all threads to start at the same time
                barrier.wait();

                queries::acquire_device_atomic(
                    &mut thread_conn,
                    &license_id,
                    &format!("concurrent-device-{}", i),
                    DeviceType::Uuid,
                    &jti,
                    None,
                    Some(device_limit),
                    None,
                    None,
                )
                .is_ok()
            })
        })
        .collect();

    let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let success_count = results.iter().filter(|&&r| r).count();

    assert_eq!(
        success_count, 1,
        "exactly 1 of {} concurrent requests should succeed with device_limit=1, got {}",
        num_threads, success_count
    );

    // Verify DB state
    let verify_conn = Connection::open(&db_path).expect("failed to open db for verification");
    let devices =
        queries::list_devices_for_license(&verify_conn, &license_id).expect("query failed");
    assert_eq!(
        devices.len(),
        1,
        "exactly 1 device should exist in DB after concurrent race"
    );

    // Cleanup
    std::fs::remove_file(&db_path).ok();
}

// ============ Device Count Tests ============

#[test]
fn test_count_devices_for_license() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "My App", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro", "pro");
    let license = create_test_license(&mut conn, &project.id, &product.id, None);

    // Start with no devices
    let devices = queries::list_devices_for_license(&mut conn, &license.id).expect("Query failed");
    assert_eq!(devices.len(), 0, "new license should have 0 devices");

    // Add devices and verify count
    create_test_device(&mut conn, &license.id, "device-1", DeviceType::Uuid);
    let devices = queries::list_devices_for_license(&mut conn, &license.id).expect("Query failed");
    assert_eq!(
        devices.len(),
        1,
        "should have 1 device after first creation"
    );

    create_test_device(&mut conn, &license.id, "device-2", DeviceType::Uuid);
    let devices = queries::list_devices_for_license(&mut conn, &license.id).expect("Query failed");
    assert_eq!(
        devices.len(),
        2,
        "should have 2 devices after second creation"
    );
}
