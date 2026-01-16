//! Tests for API key creation atomicity and data integrity.
//!
//! These tests document potential race conditions and data integrity issues
//! in the `create_api_key` function. The TOCTOU (time-of-check-time-of-use)
//! pattern means validation and insertion are not atomic.

#[path = "../common/mod.rs"]
mod common;

use common::*;

/// Test that demonstrates orphaned API key scopes after membership deletion.
///
/// This test validates that when an API key is created with org scopes,
/// and the user's org membership is subsequently deleted, the API key
/// continues to exist with scopes pointing to an org the user no longer
/// belongs to.
///
/// This is a data integrity issue - the scopes reference a membership
/// relationship that no longer exists.
#[test]
fn test_api_key_scopes_become_orphaned_after_membership_deletion() {
    let mut conn = setup_test_db();

    // Create org and user as member
    let org = create_test_org(&mut conn, "Test Org");
    let (user, member, _) =
        create_test_org_member(&mut conn, &org.id, "test@example.com", OrgMemberRole::Admin);

    // Create API key with org scope (validation passes because user is member)
    let scope = CreateApiKeyScope {
        org_id: org.id.clone(),
        project_id: None,
        access: AccessLevel::Admin,
    };
    let (api_key, _raw_key) =
        queries::create_api_key(&mut conn, &user.id, "Scoped Key", None, true, Some(&[scope]))
            .expect("API key creation should succeed");

    // Verify scope exists
    let scopes_before = queries::get_api_key_scopes(&mut conn, &api_key.id).expect("Get scopes failed");
    assert_eq!(scopes_before.len(), 1, "should have 1 scope before deletion");
    assert_eq!(
        scopes_before[0].org_id, org.id,
        "scope should reference the org"
    );

    // Delete the org membership
    queries::delete_org_member(&mut conn, &member.id).expect("Delete member failed");

    // Verify membership is gone
    let member_after = queries::get_org_member_by_id(&mut conn, &member.id).expect("Query failed");
    assert!(
        member_after.is_none(),
        "membership should be deleted"
    );

    // API key still exists with orphaned scopes
    let scopes_after = queries::get_api_key_scopes(&mut conn, &api_key.id).expect("Get scopes failed");
    assert_eq!(
        scopes_after.len(),
        1,
        "API key scopes still exist after membership deletion - this is the data integrity issue"
    );
    assert_eq!(
        scopes_after[0].org_id, org.id,
        "scope still references org the user is no longer a member of"
    );

    // Verify the user is no longer a member of the org
    let is_still_member =
        queries::get_org_member_with_user_by_user_and_org(&mut conn, &user.id, &org.id)
            .expect("Query failed");
    assert!(
        is_still_member.is_none(),
        "user should not be a member of the org anymore"
    );

    // The API key exists with scopes that reference an org relationship that no longer exists
    // This demonstrates the data integrity issue - scopes are orphaned
}

/// Test that demonstrates the validation-insertion gap (TOCTOU window).
///
/// This test shows that validation queries and insertion queries are
/// executed separately, creating a window where the validated state
/// could change before insertion completes.
///
/// While we can't easily test the actual race condition, we can verify
/// that the operations are not wrapped in a transaction by checking
/// that multiple independent validations occur before any insertions.
#[test]
fn test_api_key_creation_validates_before_inserting() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Create two orgs with projects
    let org_a = create_test_org(&mut conn, "Org A");
    let org_b = create_test_org(&mut conn, "Org B");
    let _project_a = create_test_project(&mut conn, &org_a.id, "Project A", &master_key);
    let project_b = create_test_project(&mut conn, &org_b.id, "Project B", &master_key);

    // Create user as member of both orgs (note: create_test_org_member creates an API key)
    let (user, _, _) =
        create_test_org_member(&mut conn, &org_a.id, "test@example.com", OrgMemberRole::Admin);
    let member_b_input = CreateOrgMember {
        user_id: user.id.clone(),
        role: OrgMemberRole::Admin,
    };
    let _member_b =
        queries::create_org_member(&mut conn, &org_b.id, &member_b_input).expect("Create member failed");

    // Count existing keys (create_test_org_member creates one)
    let keys_before = queries::list_api_keys(&mut conn, &user.id, false).expect("List keys failed");
    let initial_key_count = keys_before.len();

    // Create scopes for both orgs - if first scope validation passes but
    // second fails, no API key should be created (all-or-nothing validation)
    let scope_a = CreateApiKeyScope {
        org_id: org_a.id.clone(),
        project_id: None,
        access: AccessLevel::Admin,
    };
    let scope_b_invalid = CreateApiKeyScope {
        org_id: org_b.id.clone(),
        project_id: Some("nonexistent_project".to_string()), // Invalid project
        access: AccessLevel::View,
    };

    // This should fail because second scope references nonexistent project
    let result = queries::create_api_key(
        &mut conn,
        &user.id,
        "Multi-scope Key",
        None,
        true,
        Some(&[scope_a.clone(), scope_b_invalid]),
    );

    assert!(
        result.is_err(),
        "API key creation should fail when any scope is invalid"
    );

    // Verify no new API key was created (all-or-nothing for validation)
    let keys_after_fail = queries::list_api_keys(&mut conn, &user.id, false).expect("List keys failed");
    assert_eq!(
        keys_after_fail.len(),
        initial_key_count,
        "no new API key should be created when validation fails"
    );

    // Now test with valid scopes for both orgs
    let scope_b_valid = CreateApiKeyScope {
        org_id: org_b.id.clone(),
        project_id: Some(project_b.id.clone()),
        access: AccessLevel::View,
    };

    let result = queries::create_api_key(
        &mut conn,
        &user.id,
        "Multi-scope Key",
        None,
        true,
        Some(&[scope_a, scope_b_valid]),
    );

    assert!(
        result.is_ok(),
        "API key creation should succeed with valid scopes"
    );

    let (api_key, _) = result.unwrap();
    let scopes = queries::get_api_key_scopes(&mut conn, &api_key.id).expect("Get scopes failed");
    assert_eq!(scopes.len(), 2, "should have 2 scopes");
}

/// Test that API key and scopes can be left in inconsistent state.
///
/// This test documents that if an error occurs after api_keys INSERT
/// but during api_key_scopes INSERT, we could end up with an API key
/// that has fewer scopes than intended.
///
/// Note: This is difficult to test without mocking database failures,
/// but we can document the expected behavior and verify the current
/// non-transactional structure.
#[test]
fn test_api_key_scopes_inserted_separately_from_key() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Create org and project
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

    // Create user as member
    let (user, _, _) =
        create_test_org_member(&mut conn, &org.id, "test@example.com", OrgMemberRole::Admin);

    // Create API key with multiple scopes
    let scopes = vec![
        CreateApiKeyScope {
            org_id: org.id.clone(),
            project_id: None,
            access: AccessLevel::Admin,
        },
        CreateApiKeyScope {
            org_id: org.id.clone(),
            project_id: Some(project.id.clone()),
            access: AccessLevel::View,
        },
    ];

    let (api_key, _) =
        queries::create_api_key(&mut conn, &user.id, "Multi-scope", None, true, Some(&scopes))
            .expect("Create failed");

    // Verify both scopes were created
    let created_scopes = queries::get_api_key_scopes(&mut conn, &api_key.id).expect("Get scopes failed");
    assert_eq!(
        created_scopes.len(),
        2,
        "both scopes should be created when no error occurs"
    );

    // Document: If a failure occurred between api_keys INSERT and the second
    // api_key_scopes INSERT, we would have an API key with only 1 scope instead
    // of 2. This cannot happen with proper transaction wrapping.
    //
    // The fix is to wrap the entire create_api_key function in a transaction
    // using conn.transaction_with_behavior(TransactionBehavior::Immediate)
    // similar to acquire_device_atomic().
}

/// Test that concurrent membership deletion during API key creation
/// could theoretically succeed (documents the TOCTOU window).
///
/// This test sets up a scenario and documents the race condition window,
/// even though we can't deterministically trigger the race in a unit test.
#[test]
fn test_documents_toctou_window_in_api_key_creation() {
    let mut conn = setup_test_db();

    // Setup: Create org and member
    let org = create_test_org(&mut conn, "Test Org");
    let (user, member, _) =
        create_test_org_member(&mut conn, &org.id, "test@example.com", OrgMemberRole::Admin);

    // The TOCTOU window exists in create_api_key():
    //
    // 1. VALIDATION PHASE (Time of Check):
    //    - Query: "SELECT 1 FROM organizations WHERE id = ?1"
    //    - Query: "SELECT 1 FROM org_members WHERE user_id = ?1 AND org_id = ?2"
    //    - Query: "SELECT org_id FROM projects WHERE id = ?1" (if project scope)
    //
    // 2. TOCTOU WINDOW: Between validation queries and INSERT
    //    - Another transaction could DELETE the org_member row here
    //    - Or DELETE the organization
    //    - Or DELETE the project
    //
    // 3. INSERTION PHASE (Time of Use):
    //    - INSERT INTO api_keys ...
    //    - INSERT INTO api_key_scopes ... (for each scope)
    //
    // If membership is deleted during the TOCTOU window, the API key
    // is created with scopes that reference a membership that no longer exists.

    // Simulate the "after" state by creating key, then deleting membership
    let scope = CreateApiKeyScope {
        org_id: org.id.clone(),
        project_id: None,
        access: AccessLevel::Admin,
    };

    // Step 1: Create API key (validation passes)
    let (api_key, _) =
        queries::create_api_key(&mut conn, &user.id, "Test Key", None, true, Some(&[scope]))
            .expect("Create should succeed");

    // Step 2: Simulate concurrent deletion (what could happen in TOCTOU window)
    queries::delete_org_member(&mut conn, &member.id).expect("Delete should succeed");

    // Step 3: Verify the inconsistent state
    let key_exists = queries::list_api_keys(&mut conn, &user.id, false)
        .expect("List failed")
        .iter()
        .any(|k| k.id == api_key.id);
    assert!(key_exists, "API key still exists");

    let scopes = queries::get_api_key_scopes(&mut conn, &api_key.id).expect("Get scopes failed");
    assert_eq!(scopes.len(), 1, "scope still exists");

    let membership = queries::get_org_member_with_user_by_user_and_org(&mut conn, &user.id, &org.id)
        .expect("Query failed");
    assert!(membership.is_none(), "but membership is gone");

    // This inconsistent state is what the TOCTOU vulnerability allows.
    // With proper transaction wrapping, either:
    // - Both API key + scopes are created (membership exists throughout), or
    // - Neither is created (membership deleted before commit)
}
