//! Tests for panic safety in FromRow implementations.
//!
//! These tests verify that invalid enum values in the database are handled
//! gracefully rather than panicking. Before the fix, these tests demonstrate
//! the panic behavior. After the fix, they verify proper error handling.
//!
//! Note: These tests use a custom schema without CHECK constraints to simulate
//! data corruption scenarios that could occur from:
//! - Schema migrations
//! - Data imports from external sources
//! - Manual database recovery operations
//! - Legacy data from before constraints were added

#[path = "../common/mod.rs"]
mod common;

use common::*;
use rusqlite::Connection;

/// Create a test database with schema that has NO CHECK constraints on enum fields.
/// This simulates scenarios where invalid data could exist (migrations, imports, etc.)
fn setup_test_db_no_check_constraints() -> Connection {
    let conn = Connection::open_in_memory().expect("Failed to create in-memory database");

    // Minimal schema without CHECK constraints for testing enum parsing
    conn.execute_batch(
        r#"
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            operator_role TEXT,  -- No CHECK constraint!
            tags TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            deleted_at INTEGER,
            deleted_cascade_depth INTEGER
        );

        CREATE TABLE organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            payment_config_id TEXT,
            email_config_id TEXT,
            tags TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            deleted_at INTEGER,
            deleted_cascade_depth INTEGER
        );

        -- Org members WITHOUT CHECK constraint on role
        CREATE TABLE org_members (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            org_id TEXT NOT NULL REFERENCES organizations(id),
            role TEXT NOT NULL,  -- No CHECK constraint!
            created_at INTEGER NOT NULL,
            deleted_at INTEGER,
            deleted_cascade_depth INTEGER,
            UNIQUE(user_id, org_id)
        );

        CREATE TABLE api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            name TEXT NOT NULL,
            key_prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            user_manageable INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER,
            expires_at INTEGER,
            revoked_at INTEGER,
            UNIQUE(user_id, name)
        );

        -- API key scopes WITHOUT CHECK constraint on access
        CREATE TABLE api_key_scopes (
            id TEXT PRIMARY KEY,
            api_key_id TEXT NOT NULL REFERENCES api_keys(id),
            org_id TEXT NOT NULL REFERENCES organizations(id),
            project_id TEXT REFERENCES projects(id),
            access TEXT NOT NULL  -- No CHECK constraint!
        );

        CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES organizations(id),
            name TEXT NOT NULL,
            license_key_prefix TEXT NOT NULL,
            private_key BLOB NOT NULL,
            public_key TEXT NOT NULL,
            redirect_url TEXT,
            email_from TEXT,
            email_enabled INTEGER NOT NULL DEFAULT 1,
            email_webhook_url TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            deleted_at INTEGER,
            deleted_cascade_depth INTEGER
        );

        -- Project members WITHOUT CHECK constraint on role
        CREATE TABLE project_members (
            id TEXT PRIMARY KEY,
            org_member_id TEXT NOT NULL REFERENCES org_members(id),
            project_id TEXT NOT NULL REFERENCES projects(id),
            role TEXT NOT NULL,  -- No CHECK constraint!
            created_at INTEGER NOT NULL
        );

        CREATE TABLE products (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id),
            name TEXT NOT NULL,
            tier TEXT NOT NULL,
            license_exp_days INTEGER,
            updates_exp_days INTEGER,
            activation_limit INTEGER NOT NULL DEFAULT 5,
            device_limit INTEGER NOT NULL DEFAULT 3,
            features TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            deleted_at INTEGER,
            deleted_cascade_depth INTEGER
        );

        CREATE TABLE licenses (
            id TEXT PRIMARY KEY,
            email_hash TEXT,
            project_id TEXT NOT NULL REFERENCES projects(id),
            product_id TEXT NOT NULL REFERENCES products(id),
            customer_id TEXT,
            activation_count INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            updates_expires_at INTEGER,
            deleted_at INTEGER,
            deleted_cascade_depth INTEGER
        );

        -- Devices WITHOUT CHECK constraint on device_type
        CREATE TABLE devices (
            id TEXT PRIMARY KEY,
            license_id TEXT NOT NULL REFERENCES licenses(id),
            device_id TEXT NOT NULL,
            device_type TEXT NOT NULL,  -- No CHECK constraint!
            name TEXT,
            jti TEXT NOT NULL,
            activated_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL
        );
    "#,
    )
    .expect("Failed to create test schema");

    conn
}

/// Test that invalid OperatorRole in DB is handled gracefully (treated as None, not panic)
/// Note: operator_role is optional, so invalid values are safely ignored rather than erroring
#[test]
fn test_invalid_operator_role_treated_as_none() {
    let mut conn = setup_test_db_no_check_constraints();
    let now = now();

    // Insert user with INVALID operator_role directly via SQL
    conn.execute(
        "INSERT INTO users (id, email, name, operator_role, created_at, updated_at) VALUES ('u1', 'test@example.com', 'Test', 'invalid_role', ?1, ?1)",
        [now],
    ).unwrap();

    // Attempt to read the user - should succeed but treat invalid role as None
    let result = queries::get_user_by_id(&mut conn, "u1");

    // Should not panic, and should treat invalid role as None (not an operator)
    let user = result.expect("Should not panic on invalid operator_role").expect("User should be found");
    assert!(
        user.operator_role.is_none(),
        "invalid operator_role should be treated as None (not an operator)"
    );
}

/// Test that invalid OrgMemberRole in DB causes proper error (not panic)
#[test]
fn test_invalid_org_member_role_returns_error() {
    let mut conn = setup_test_db_no_check_constraints();
    let now = now();

    // Insert user, org, and member with INVALID role
    conn.execute(
        "INSERT INTO users (id, email, name, created_at, updated_at) VALUES ('u1', 'test@example.com', 'Test', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO organizations (id, name, created_at, updated_at) VALUES ('org1', 'Test Org', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO org_members (id, user_id, org_id, role, created_at) VALUES ('m1', 'u1', 'org1', 'bogus_role', ?1)",
        [now],
    ).unwrap();

    // Should return error, not panic
    let result = queries::get_org_member_by_id(&mut conn, "m1");
    assert!(
        result.is_err(),
        "reading org member with invalid role should return error, not panic"
    );
}

/// Test that invalid AccessLevel in API key scope causes proper error (not panic)
#[test]
fn test_invalid_access_level_returns_error() {
    let mut conn = setup_test_db_no_check_constraints();
    let now = now();

    // Insert user, org, api_key, and scope with INVALID access level
    conn.execute(
        "INSERT INTO users (id, email, name, created_at, updated_at) VALUES ('u1', 'test@example.com', 'Test', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO organizations (id, name, created_at, updated_at) VALUES ('org1', 'Test Org', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, created_at) VALUES ('ak1', 'u1', 'Test', 'pc_', 'hash', ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO api_key_scopes (id, api_key_id, org_id, access) VALUES ('s1', 'ak1', 'org1', 'superadmin')",
        [],
    ).unwrap();

    // Should return error, not panic
    let result = queries::get_api_key_scopes(&mut conn, "ak1");
    assert!(
        result.is_err(),
        "reading API key scope with invalid access level should return error, not panic"
    );
}

/// Test that invalid ProjectMemberRole in DB causes proper error (not panic)
#[test]
fn test_invalid_project_member_role_returns_error() {
    let mut conn = setup_test_db_no_check_constraints();
    let now = now();

    // Insert user, org, org_member, project, and project_member with INVALID role
    conn.execute(
        "INSERT INTO users (id, email, name, created_at, updated_at) VALUES ('u1', 'test@example.com', 'Test', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO organizations (id, name, created_at, updated_at) VALUES ('org1', 'Test Org', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO org_members (id, user_id, org_id, role, created_at) VALUES ('m1', 'u1', 'org1', 'member', ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO projects (id, org_id, name, license_key_prefix, private_key, public_key, created_at, updated_at) VALUES ('p1', 'org1', 'Test', 'TEST', X'00', 'pubkey', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO project_members (id, org_member_id, project_id, role, created_at) VALUES ('pm1', 'm1', 'p1', 'megaadmin', ?1)",
        [now],
    ).unwrap();

    // Should return error, not panic
    let result = queries::get_project_member_by_id(&mut conn, "pm1");
    assert!(
        result.is_err(),
        "reading project member with invalid role should return error, not panic"
    );
}

/// Test that invalid DeviceType in DB causes proper error (not panic)
#[test]
fn test_invalid_device_type_returns_error() {
    let mut conn = setup_test_db_no_check_constraints();
    let now = now();

    // Insert all required entities with a device having INVALID device_type
    conn.execute(
        "INSERT INTO users (id, email, name, created_at, updated_at) VALUES ('u1', 'test@example.com', 'Test', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO organizations (id, name, created_at, updated_at) VALUES ('org1', 'Test Org', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO projects (id, org_id, name, license_key_prefix, private_key, public_key, created_at, updated_at) VALUES ('p1', 'org1', 'Test', 'TEST', X'00', 'pubkey', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO products (id, project_id, name, tier, created_at) VALUES ('prod1', 'p1', 'Pro', 'pro', ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO licenses (id, project_id, product_id, created_at) VALUES ('lic1', 'p1', 'prod1', ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO devices (id, license_id, device_id, device_type, jti, activated_at, last_seen_at) VALUES ('d1', 'lic1', 'dev-001', 'quantum', 'jti1', ?1, ?1)",
        [now],
    ).unwrap();

    // Should return error, not panic
    let result = queries::list_devices_for_license(&mut conn, "lic1");
    assert!(
        result.is_err(),
        "reading device with invalid device_type should return error, not panic"
    );
}

/// Test that list operations handle invalid enum values gracefully
/// Note: Since operator_role is optional and invalid values are treated as None,
/// users with invalid operator_role won't appear in operator listings
#[test]
fn test_list_operators_filters_invalid_roles() {
    let conn = setup_test_db_no_check_constraints();
    let now = now();

    // Insert users with operator_role, one with invalid role
    conn.execute(
        "INSERT INTO users (id, email, name, operator_role, created_at, updated_at) VALUES ('u1', 'valid@example.com', 'Valid', 'admin', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO users (id, email, name, operator_role, created_at, updated_at) VALUES ('u2', 'bad@example.com', 'Bad', 'hacker', ?1, ?1)",
        [now],
    ).unwrap();

    // List should succeed - users with invalid roles are filtered out (only valid operators appear)
    // Note: list_operators queries WHERE operator_role IN ('owner', 'admin', 'view'),
    // so users with invalid roles like 'hacker' won't be returned
    let result = queries::list_operators(&conn);
    let operators = result.expect("list_operators should not panic");

    // Only the valid admin should appear
    assert_eq!(operators.len(), 1, "Only users with valid operator_role should be listed");
    assert_eq!(operators[0].email, "valid@example.com");
}

// Note: test_operator_with_user_invalid_role_returns_error removed - OperatorWithUser
// no longer exists; operators are now just users with operator_role set

/// Test that OrgMemberWithUser handles invalid role gracefully
#[test]
fn test_org_member_with_user_invalid_role_returns_error() {
    let mut conn = setup_test_db_no_check_constraints();
    let now = now();

    // Insert user, org, and member with invalid role
    conn.execute(
        "INSERT INTO users (id, email, name, created_at, updated_at) VALUES ('u1', 'test@example.com', 'Test', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO organizations (id, name, created_at, updated_at) VALUES ('org1', 'Test Org', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO org_members (id, user_id, org_id, role, created_at) VALUES ('m1', 'u1', 'org1', 'dictator', ?1)",
        [now],
    ).unwrap();

    // list_org_members returns OrgMemberWithUser
    let result = queries::list_org_members(&mut conn, "org1");
    assert!(
        result.is_err(),
        "listing org members with invalid role should return error, not panic"
    );

    // Also test get_org_member_with_user_by_user_and_org
    let result2 = queries::get_org_member_with_user_by_user_and_org(&mut conn, "u1", "org1");
    assert!(
        result2.is_err(),
        "reading OrgMemberWithUser with invalid role should return error, not panic"
    );
}

/// Test that get_user_with_roles handles invalid OrgMemberRole gracefully (not panic).
///
/// If the role value in the database is corrupted/invalid, the function should
/// return an error rather than panicking.
#[test]
fn test_get_user_with_roles_invalid_member_role_returns_error() {
    let conn = setup_test_db_no_check_constraints();
    let now = now();

    // Insert user, org, and member with INVALID role
    conn.execute(
        "INSERT INTO users (id, email, name, created_at, updated_at) VALUES ('u1', 'test@example.com', 'Test', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO organizations (id, name, created_at, updated_at) VALUES ('org1', 'Test Org', ?1, ?1)",
        [now],
    ).unwrap();
    conn.execute(
        "INSERT INTO org_members (id, user_id, org_id, role, created_at) VALUES ('m1', 'u1', 'org1', 'supervillain', ?1)",
        [now],
    ).unwrap();

    // get_user_with_roles should return an error, not panic
    let result = queries::get_user_with_roles(&conn, "u1");

    assert!(
        result.is_err(),
        "get_user_with_roles with invalid OrgMemberRole should return error, not panic"
    );
}
