//! Tests for soft delete, restore, and purge functionality

#[path = "../common/mod.rs"]
mod common;

use common::{
    CreateOrgMember, LICENSE_VALID_DAYS, ONE_MONTH, OperatorRole, OrgMemberRole, ProjectMemberRole,
    create_test_license, create_test_operator, create_test_org, create_test_org_member,
    create_test_product, create_test_project, create_test_project_member, future_timestamp, now,
    queries, setup_test_db, test_master_key,
};

// ============ Soft Delete Mechanics ============

#[test]
fn test_soft_delete_user_sets_deleted_at_and_depth() {
    let mut conn = setup_test_db();
    let (user, _api_key) = create_test_operator(&mut conn, "test@example.com", OperatorRole::Admin);

    // Soft delete the user
    queries::soft_delete_user(&mut conn, &user.id).expect("Soft delete failed");

    // User should not be found via normal query
    let result = queries::get_user_by_id(&mut conn, &user.id).expect("Query failed");
    assert!(
        result.is_none(),
        "User should not be found after soft delete"
    );

    // User should be found via deleted query
    let deleted = queries::get_deleted_user_by_id(&mut conn, &user.id)
        .expect("Query failed")
        .expect("Deleted user should be found");

    assert!(deleted.deleted_at.is_some(), "deleted_at should be set");
    assert_eq!(
        deleted.deleted_cascade_depth,
        Some(0),
        "depth should be 0 for direct delete"
    );
}

// Note: test_soft_delete_user_cascades_to_operator removed - operators are now just
// users with operator_role set, not a separate entity that cascades

#[test]
fn test_get_user_with_roles_excludes_soft_deleted_user() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");
    let (user, _member, _api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    // User with roles should be found before soft delete
    let result = queries::get_user_with_roles(&conn, &user.id).expect("Query failed");
    assert!(
        result.is_some(),
        "User with roles should be found before soft delete"
    );

    // Soft delete the user
    queries::soft_delete_user(&mut conn, &user.id).expect("Soft delete failed");

    // User with roles should NOT be found after soft delete
    let result = queries::get_user_with_roles(&conn, &user.id).expect("Query failed");
    assert!(
        result.is_none(),
        "get_user_with_roles should exclude soft-deleted users"
    );
}

#[test]
fn test_get_user_with_roles_excludes_soft_deleted_memberships() {
    let mut conn = setup_test_db();
    let org1 = create_test_org(&mut conn, "Org 1");
    let org2 = create_test_org(&mut conn, "Org 2");

    // Create user as member of org1
    let (user, _member1, _api_key) =
        create_test_org_member(&mut conn, &org1.id, "member@test.com", OrgMemberRole::Owner);

    // Add user to org2 as well
    queries::create_org_member(
        &conn,
        &org2.id,
        &CreateOrgMember {
            user_id: user.id.clone(),
            role: OrgMemberRole::Admin,
        },
    )
    .unwrap();

    // User should have 2 memberships
    let result = queries::get_user_with_roles(&conn, &user.id)
        .expect("Query failed")
        .expect("User should be found");
    assert_eq!(result.memberships.len(), 2, "User should have 2 memberships");

    // Soft delete org2
    queries::soft_delete_organization(&mut conn, &org2.id).expect("Soft delete failed");

    // User should now only show 1 membership (org1)
    let result = queries::get_user_with_roles(&conn, &user.id)
        .expect("Query failed")
        .expect("User should still be found");
    assert_eq!(
        result.memberships.len(),
        1,
        "get_user_with_roles should exclude memberships in soft-deleted orgs"
    );
    assert_eq!(result.memberships[0].org_id, org1.id);
}

#[test]
fn test_soft_delete_user_cascades_to_org_members() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");
    let (user, member, _api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    // Soft delete the user
    queries::soft_delete_user(&mut conn, &user.id).expect("Soft delete failed");

    // Org member should not be found via normal query
    let result = queries::get_org_member_by_id(&mut conn, &member.id).expect("Query failed");
    assert!(
        result.is_none(),
        "Org member should not be found after user soft delete"
    );

    // Org member should be found via deleted query with depth > 0
    let deleted = queries::get_deleted_org_member_by_id(&mut conn, &member.id)
        .expect("Query failed")
        .expect("Deleted org member should be found");

    assert!(deleted.deleted_at.is_some(), "deleted_at should be set");
    assert_eq!(
        deleted.deleted_cascade_depth,
        Some(1),
        "depth should be 1 for cascade delete"
    );
}

#[test]
fn test_soft_delete_organization_cascades_to_children() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let (_user, member, _api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Owner);
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the organization
    queries::soft_delete_organization(&mut conn, &org.id).expect("Soft delete failed");

    // Org should not be found via normal query
    assert!(
        queries::get_organization_by_id(&mut conn, &org.id)
            .expect("Query failed")
            .is_none(),
        "Organization should not be found via normal query after soft delete"
    );

    // Org member should be cascade deleted (depth 1)
    let deleted_member = queries::get_deleted_org_member_by_id(&mut conn, &member.id)
        .expect("Query failed")
        .expect("Deleted member should be found");
    assert_eq!(
        deleted_member.deleted_cascade_depth,
        Some(1),
        "Org member should be cascade-deleted at depth 1"
    );

    // Project should be cascade deleted (depth 1)
    let deleted_project = queries::get_deleted_project_by_id(&mut conn, &project.id)
        .expect("Query failed")
        .expect("Deleted project should be found");
    assert_eq!(
        deleted_project.deleted_cascade_depth,
        Some(1),
        "Project should be cascade-deleted at depth 1"
    );

    // Product should be cascade deleted (depth 2)
    let deleted_product = queries::get_deleted_product_by_id(&mut conn, &product.id)
        .expect("Query failed")
        .expect("Deleted product should be found");
    assert_eq!(
        deleted_product.deleted_cascade_depth,
        Some(2),
        "Product should be cascade-deleted at depth 2"
    );

    // License should be cascade deleted (depth 3)
    let deleted_license = queries::get_deleted_license_by_id(&mut conn, &license.id)
        .expect("Query failed")
        .expect("Deleted license should be found");
    assert_eq!(
        deleted_license.deleted_cascade_depth,
        Some(3),
        "License should be cascade-deleted at depth 3"
    );
}

#[test]
fn test_soft_delete_project_cascades_to_products_and_licenses() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the project
    queries::soft_delete_project(&mut conn, &project.id).expect("Soft delete failed");

    // Project deleted at depth 0
    let deleted_project = queries::get_deleted_project_by_id(&mut conn, &project.id)
        .expect("Query failed")
        .expect("Deleted project should be found");
    assert_eq!(
        deleted_project.deleted_cascade_depth,
        Some(0),
        "Directly deleted project should have depth 0"
    );

    // Product cascade deleted at depth 1
    let deleted_product = queries::get_deleted_product_by_id(&mut conn, &product.id)
        .expect("Query failed")
        .expect("Deleted product should be found");
    assert_eq!(
        deleted_product.deleted_cascade_depth,
        Some(1),
        "Product should be cascade-deleted at depth 1"
    );

    // License cascade deleted at depth 2
    let deleted_license = queries::get_deleted_license_by_id(&mut conn, &license.id)
        .expect("Query failed")
        .expect("Deleted license should be found");
    assert_eq!(
        deleted_license.deleted_cascade_depth,
        Some(2),
        "License should be cascade-deleted at depth 2"
    );
}

#[test]
fn test_soft_delete_product_cascades_to_licenses() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the product
    queries::soft_delete_product(&mut conn, &product.id).expect("Soft delete failed");

    // Product deleted at depth 0
    let deleted_product = queries::get_deleted_product_by_id(&mut conn, &product.id)
        .expect("Query failed")
        .expect("Deleted product should be found");
    assert_eq!(
        deleted_product.deleted_cascade_depth,
        Some(0),
        "Directly deleted product should have depth 0"
    );

    // License cascade deleted at depth 1
    let deleted_license = queries::get_deleted_license_by_id(&mut conn, &license.id)
        .expect("Query failed")
        .expect("Deleted license should be found");
    assert_eq!(
        deleted_license.deleted_cascade_depth,
        Some(1),
        "License should be cascade-deleted at depth 1"
    );
}

// ============ Query Filtering Tests ============

#[test]
fn test_list_users_excludes_deleted_by_default() {
    let mut conn = setup_test_db();
    create_test_operator(&mut conn, "active1@example.com", OperatorRole::Admin);
    let (user_to_delete, _key) =
        create_test_operator(&mut conn, "deleted@example.com", OperatorRole::Admin);
    create_test_operator(&mut conn, "active2@example.com", OperatorRole::Admin);

    // Soft delete one user
    queries::soft_delete_user(&mut conn, &user_to_delete.id).expect("Soft delete failed");

    // List should exclude deleted user
    let (users, total) = queries::list_users_paginated(&mut conn, 100, 0, false).expect("Query failed");
    assert_eq!(total, 2, "Total should be 2 (excluding deleted)");
    assert_eq!(users.len(), 2, "Should return 2 users");
    assert!(
        users.iter().all(|u| u.email != "deleted@example.com"),
        "Deleted user should not appear in list"
    );
}

#[test]
fn test_list_users_includes_deleted_when_requested() {
    let mut conn = setup_test_db();
    create_test_operator(&mut conn, "active1@example.com", OperatorRole::Admin);
    let (user_to_delete, _key) =
        create_test_operator(&mut conn, "deleted@example.com", OperatorRole::Admin);
    create_test_operator(&mut conn, "active2@example.com", OperatorRole::Admin);

    // Soft delete one user
    queries::soft_delete_user(&mut conn, &user_to_delete.id).expect("Soft delete failed");

    // List with include_deleted=true should include all users
    let (users, total) = queries::list_users_paginated(&mut conn, 100, 0, true).expect("Query failed");
    assert_eq!(total, 3, "Total should be 3 (including deleted)");
    assert_eq!(users.len(), 3, "Should return all 3 users");
    assert!(
        users.iter().any(|u| u.email == "deleted@example.com"),
        "Deleted user should appear when include_deleted=true"
    );
}

#[test]
fn test_list_organizations_excludes_deleted_by_default() {
    let mut conn = setup_test_db();
    create_test_org(&mut conn, "Active Org 1");
    let org_to_delete = create_test_org(&mut conn, "Deleted Org");
    create_test_org(&mut conn, "Active Org 2");

    // Soft delete one org
    queries::soft_delete_organization(&mut conn, &org_to_delete.id).expect("Soft delete failed");

    // List should exclude deleted org
    let (orgs, total) =
        queries::list_organizations_paginated(&mut conn, 100, 0, false).expect("Query failed");
    assert_eq!(total, 2, "Total should be 2 (excluding deleted)");
    assert_eq!(orgs.len(), 2, "Should return 2 organizations");
    assert!(
        orgs.iter().all(|o| o.name != "Deleted Org"),
        "Deleted org should not appear in list"
    );
}

#[test]
fn test_list_organizations_includes_deleted_when_requested() {
    let mut conn = setup_test_db();
    create_test_org(&mut conn, "Active Org 1");
    let org_to_delete = create_test_org(&mut conn, "Deleted Org");
    create_test_org(&mut conn, "Active Org 2");

    // Soft delete one org
    queries::soft_delete_organization(&mut conn, &org_to_delete.id).expect("Soft delete failed");

    // List with include_deleted=true should include all orgs
    let (orgs, total) =
        queries::list_organizations_paginated(&mut conn, 100, 0, true).expect("Query failed");
    assert_eq!(total, 3, "Total should be 3 (including deleted)");
    assert_eq!(orgs.len(), 3, "Should return all 3 organizations");
    assert!(
        orgs.iter().any(|o| o.name == "Deleted Org"),
        "Deleted org should appear when include_deleted=true"
    );
}

// ============ Restore Tests ============

#[test]
fn test_restore_directly_deleted_user_succeeds_without_force() {
    let mut conn = setup_test_db();
    let (user, _api_key) = create_test_operator(&mut conn, "test@example.com", OperatorRole::Admin);

    // Soft delete the user
    queries::soft_delete_user(&mut conn, &user.id).expect("Soft delete failed");

    // Restore without force should succeed (depth 0)
    let result = queries::restore_user(&mut conn, &user.id, false);
    assert!(
        result.is_ok(),
        "Restore should succeed for directly deleted user"
    );

    // User should be found again
    let restored = queries::get_user_by_id(&mut conn, &user.id)
        .expect("Query failed")
        .expect("Restored user should be found");
    assert!(
        restored.deleted_at.is_none(),
        "deleted_at should be cleared"
    );
}

// Note: test_restore_cascade_deleted_operator_requires_force removed - operators are now just
// users with operator_role set, not a separate entity that cascades

// Note: test_restore_cascade_deleted_operator_succeeds_with_force removed - operators are now just
// users with operator_role set, not a separate entity that cascades

// Note: test_restore_user_also_restores_cascade_deleted_children (for operators) removed -
// operators are now just users with operator_role set, not a separate entity that cascades

#[test]
fn test_restore_organization_restores_entire_hierarchy() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let (_user, member, _api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Owner);
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the organization (cascades to all children)
    queries::soft_delete_organization(&mut conn, &org.id).expect("Soft delete failed");

    // Restore the organization
    queries::restore_organization(&mut conn, &org.id).expect("Restore failed");

    // All entities should be restored
    assert!(
        queries::get_organization_by_id(&mut conn, &org.id)
            .expect("Query failed")
            .is_some(),
        "Organization should be restored"
    );
    assert!(
        queries::get_org_member_by_id(&mut conn, &member.id)
            .expect("Query failed")
            .is_some(),
        "Org member should be restored with organization"
    );
    assert!(
        queries::get_project_by_id(&mut conn, &project.id)
            .expect("Query failed")
            .is_some(),
        "Project should be restored with organization"
    );
    assert!(
        queries::get_product_by_id(&mut conn, &product.id)
            .expect("Query failed")
            .is_some(),
        "Product should be restored with organization"
    );
    assert!(
        queries::get_license_by_id(&mut conn, &license.id)
            .expect("Query failed")
            .is_some(),
        "License should be restored with organization"
    );
}

#[test]
fn test_restore_project_restores_products_and_licenses() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete the project
    queries::soft_delete_project(&mut conn, &project.id).expect("Soft delete failed");

    // Restore the project
    queries::restore_project(&mut conn, &project.id, false).expect("Restore failed");

    // All entities should be restored
    assert!(
        queries::get_project_by_id(&mut conn, &project.id)
            .expect("Query failed")
            .is_some(),
        "Project should be restored"
    );
    assert!(
        queries::get_product_by_id(&mut conn, &product.id)
            .expect("Query failed")
            .is_some(),
        "Product should be restored with project"
    );
    assert!(
        queries::get_license_by_id(&mut conn, &license.id)
            .expect("Query failed")
            .is_some(),
        "License should be restored with project"
    );
}

// ============ Selective Cascade Restore Tests ============

#[test]
fn test_restore_only_restores_items_with_matching_timestamp() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product1 = create_test_product(&mut conn, &project.id, "Product 1", "tier1");
    let product2 = create_test_product(&mut conn, &project.id, "Product 2", "tier2");

    // Soft delete product1 directly
    queries::soft_delete_product(&mut conn, &product1.id).expect("Soft delete failed");

    // Wait a tiny bit to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Soft delete project (cascades to product2, not product1 which is already deleted)
    queries::soft_delete_project(&mut conn, &project.id).expect("Soft delete failed");

    // Restore project - should only restore product2 (cascade-deleted with project)
    // product1 was deleted separately and should stay deleted
    queries::restore_project(&mut conn, &project.id, false).expect("Restore failed");

    // Project should be restored
    assert!(
        queries::get_project_by_id(&mut conn, &project.id)
            .expect("Query failed")
            .is_some(),
        "Project should be restored"
    );

    // Product2 should be restored (was cascade-deleted with project)
    assert!(
        queries::get_product_by_id(&mut conn, &product2.id)
            .expect("Query failed")
            .is_some(),
        "Product2 should be restored (was cascade-deleted with project)"
    );

    // Product1 should still be deleted (was deleted separately before project)
    assert!(
        queries::get_product_by_id(&mut conn, &product1.id)
            .expect("Query failed")
            .is_none(),
        "Product1 should remain deleted (was deleted separately before project)"
    );
}

// ============ Purge Tests ============

#[test]
fn test_purge_removes_old_soft_deleted_records() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Old Deleted Org");

    // Soft delete the org
    queries::soft_delete_organization(&mut conn, &org.id).expect("Soft delete failed");

    // Manually set deleted_at to 100 days ago to simulate old deletion
    let old_timestamp = now() - (100 * 86400);
    conn.execute(
        "UPDATE organizations SET deleted_at = ?1 WHERE id = ?2",
        rusqlite::params![old_timestamp, org.id],
    )
    .expect("Update timestamp failed");

    // Purge with 30 day retention
    let result = queries::purge_soft_deleted_records(&mut conn, ONE_MONTH).expect("Purge failed");

    // Should have purged the organization
    assert!(result.organizations > 0, "Should have purged organization");

    // Org should be completely gone (not even as deleted)
    let gone = queries::get_deleted_organization_by_id(&mut conn, &org.id).expect("Query failed");
    assert!(
        gone.is_none(),
        "Org should be completely removed after purge"
    );
}

#[test]
fn test_purge_respects_retention_period() {
    let mut conn = setup_test_db();
    let old_org = create_test_org(&mut conn, "Old Org");
    let recent_org = create_test_org(&mut conn, "Recent Org");

    // Soft delete both
    queries::soft_delete_organization(&mut conn, &old_org.id).expect("Soft delete failed");
    queries::soft_delete_organization(&mut conn, &recent_org.id).expect("Soft delete failed");

    // Set old_org to 100 days ago
    let old_timestamp = now() - (100 * 86400);
    conn.execute(
        "UPDATE organizations SET deleted_at = ?1 WHERE id = ?2",
        rusqlite::params![old_timestamp, old_org.id],
    )
    .expect("Update timestamp failed");

    // Purge with 30 day retention
    queries::purge_soft_deleted_records(&mut conn, ONE_MONTH).expect("Purge failed");

    // Old org should be gone
    assert!(
        queries::get_deleted_organization_by_id(&mut conn, &old_org.id)
            .expect("Query failed")
            .is_none(),
        "Org deleted 100 days ago should be purged with 30-day retention"
    );

    // Recent org should still exist (as deleted)
    assert!(
        queries::get_deleted_organization_by_id(&mut conn, &recent_org.id)
            .expect("Query failed")
            .is_some(),
        "Recently deleted org should not be purged within retention period"
    );
}

#[test]
fn test_purge_respects_cascade_hierarchy() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Soft delete organization (cascades to all)
    queries::soft_delete_organization(&mut conn, &org.id).expect("Soft delete failed");

    // Set all to old timestamp
    let old_timestamp = now() - (100 * 86400);
    conn.execute(
        "UPDATE organizations SET deleted_at = ?1",
        rusqlite::params![old_timestamp],
    )
    .unwrap();
    conn.execute(
        "UPDATE projects SET deleted_at = ?1",
        rusqlite::params![old_timestamp],
    )
    .unwrap();
    conn.execute(
        "UPDATE products SET deleted_at = ?1",
        rusqlite::params![old_timestamp],
    )
    .unwrap();
    conn.execute(
        "UPDATE licenses SET deleted_at = ?1",
        rusqlite::params![old_timestamp],
    )
    .unwrap();

    // Purge
    let result = queries::purge_soft_deleted_records(&mut conn, ONE_MONTH).expect("Purge failed");

    // All should be purged
    assert!(result.licenses > 0, "Licenses should be purged");
    assert!(result.products > 0, "Products should be purged");
    assert!(result.projects > 0, "Projects should be purged");
    assert!(result.organizations > 0, "Organizations should be purged");

    // Verify nothing remains
    assert!(
        queries::get_deleted_license_by_id(&mut conn, &license.id)
            .expect("Query failed")
            .is_none(),
        "License should be completely removed after purge"
    );
    assert!(
        queries::get_deleted_product_by_id(&mut conn, &product.id)
            .expect("Query failed")
            .is_none(),
        "Product should be completely removed after purge"
    );
    assert!(
        queries::get_deleted_project_by_id(&mut conn, &project.id)
            .expect("Query failed")
            .is_none(),
        "Project should be completely removed after purge"
    );
    assert!(
        queries::get_deleted_organization_by_id(&mut conn, &org.id)
            .expect("Query failed")
            .is_none(),
        "Organization should be completely removed after purge"
    );
}

// ============ Hard Delete Tests ============

#[test]
fn test_hard_delete_user_completely_removes_all_data() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");
    let (user, _member, _api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Owner);

    // Hard delete the user
    queries::delete_user(&mut conn, &user.id).expect("Hard delete failed");

    // User should be completely gone (not even soft deleted)
    assert!(
        queries::get_user_by_id(&mut conn, &user.id)
            .expect("Query failed")
            .is_none(),
        "User should not be found via normal query after hard delete"
    );
    assert!(
        queries::get_deleted_user_by_id(&mut conn, &user.id)
            .expect("Query failed")
            .is_none(),
        "User should not be found via deleted query after hard delete"
    );
}

#[test]
fn test_hard_delete_organization_completely_removes_hierarchy() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let product = create_test_product(&mut conn, &project.id, "Pro Plan", "pro");
    let license = create_test_license(
        &conn,
        &project.id,
        &product.id,
        Some(future_timestamp(LICENSE_VALID_DAYS)),
    );

    // Hard delete the organization
    queries::delete_organization(&mut conn, &org.id).expect("Hard delete failed");

    // Everything should be completely gone
    assert!(
        queries::get_organization_by_id(&mut conn, &org.id)
            .expect("Query failed")
            .is_none(),
        "Organization should not be found via normal query after hard delete"
    );
    assert!(
        queries::get_deleted_organization_by_id(&mut conn, &org.id)
            .expect("Query failed")
            .is_none(),
        "Organization should not be found via deleted query after hard delete"
    );
    assert!(
        queries::get_project_by_id(&mut conn, &project.id)
            .expect("Query failed")
            .is_none(),
        "Project should be cascade-deleted with organization"
    );
    assert!(
        queries::get_product_by_id(&mut conn, &product.id)
            .expect("Query failed")
            .is_none(),
        "Product should be cascade-deleted with organization"
    );
    assert!(
        queries::get_license_by_id(&mut conn, &license.id)
            .expect("Query failed")
            .is_none(),
        "License should be cascade-deleted with organization"
    );
}

// ============ Edge Cases ============

#[test]
fn test_soft_delete_already_deleted_item_is_idempotent() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");

    // Soft delete twice
    queries::soft_delete_organization(&mut conn, &org.id).expect("First soft delete failed");
    let result = queries::soft_delete_organization(&mut conn, &org.id);

    // Should not error, but should not affect anything
    assert!(
        result.is_ok(),
        "Soft delete on already-deleted item should succeed (idempotent)"
    );
}

#[test]
fn test_restore_non_deleted_item_returns_false() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Test Org");

    // Try to restore a non-deleted org
    let result = queries::restore_organization(&mut conn, &org.id).expect("Query failed");

    // Should return false (nothing to restore)
    assert!(!result, "Restoring non-deleted item should return false");
}

#[test]
fn test_get_deleted_returns_none_for_active_item() {
    let mut conn = setup_test_db();
    let org = create_test_org(&mut conn, "Active Org");

    // get_deleted should return None for active (non-deleted) item
    let result = queries::get_deleted_organization_by_id(&mut conn, &org.id).expect("Query failed");
    assert!(
        result.is_none(),
        "get_deleted should return None for active item"
    );
}

#[test]
fn test_multiple_products_deleted_same_time_restore_correctly() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);

    // Create multiple products
    let product1 = create_test_product(&mut conn, &project.id, "Product 1", "tier1");
    let product2 = create_test_product(&mut conn, &project.id, "Product 2", "tier2");
    let product3 = create_test_product(&mut conn, &project.id, "Product 3", "tier3");

    // Soft delete the project (cascades to all products at the same time)
    queries::soft_delete_project(&mut conn, &project.id).expect("Soft delete failed");

    // Verify all products are cascade-deleted
    assert!(
        queries::get_product_by_id(&mut conn, &product1.id)
            .expect("Query failed")
            .is_none(),
        "Product 1 should not be found after project soft delete"
    );
    assert!(
        queries::get_product_by_id(&mut conn, &product2.id)
            .expect("Query failed")
            .is_none(),
        "Product 2 should not be found after project soft delete"
    );
    assert!(
        queries::get_product_by_id(&mut conn, &product3.id)
            .expect("Query failed")
            .is_none(),
        "Product 3 should not be found after project soft delete"
    );

    // Restore the project
    queries::restore_project(&mut conn, &project.id, false).expect("Restore failed");

    // All products should be restored
    assert!(
        queries::get_product_by_id(&mut conn, &product1.id)
            .expect("Query failed")
            .is_some(),
        "Product 1 should be restored with project"
    );
    assert!(
        queries::get_product_by_id(&mut conn, &product2.id)
            .expect("Query failed")
            .is_some(),
        "Product 2 should be restored with project"
    );
    assert!(
        queries::get_product_by_id(&mut conn, &product3.id)
            .expect("Query failed")
            .is_some(),
        "Product 3 should be restored with project"
    );
}

// ============ Defense in Depth: JOIN Query Filtering ============

/// Test that list_project_members filters out members whose org_member is soft-deleted.
///
/// This tests defense-in-depth: even if cascade logic fails or DB state becomes
/// inconsistent, JOIN queries should still filter out soft-deleted parent records.
///
/// The bug: list_project_members checks pm.deleted_at IS NULL but not om.deleted_at,
/// so it could return project members whose org_member was soft-deleted if the
/// cascade to project_members failed.
#[test]
fn test_list_project_members_excludes_deleted_org_member() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Setup: org -> project -> org_member -> project_member
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let (user, org_member, _api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);
    let project_member =
        create_test_project_member(&mut conn, &org_member.id, &project.id, ProjectMemberRole::View);

    // Verify project member is visible initially
    let members = queries::list_project_members(&conn, &project.id).expect("Query failed");
    assert_eq!(members.len(), 1, "Should have 1 project member initially");
    assert_eq!(members[0].id, project_member.id);

    // Soft-delete the org_member (this should cascade to project_member)
    queries::soft_delete_org_member(&mut conn, &org_member.id).expect("Soft delete failed");

    // Normal case: cascade worked, project_member is also deleted
    let members_after_cascade =
        queries::list_project_members(&conn, &project.id).expect("Query failed");
    assert_eq!(
        members_after_cascade.len(),
        0,
        "Should have 0 project members after org_member soft delete (cascade worked)"
    );

    // Simulate inconsistent state: manually "restore" project_member without restoring org_member
    // This simulates a cascade failure or manual DB manipulation
    conn.execute(
        "UPDATE project_members SET deleted_at = NULL, deleted_cascade_depth = NULL WHERE id = ?1",
        rusqlite::params![project_member.id],
    )
    .expect("Manual restore failed");

    // BUG TEST: list_project_members should still return 0 because org_member is deleted
    // If this returns 1, the bug exists (query doesn't check om.deleted_at)
    let members_inconsistent =
        queries::list_project_members(&conn, &project.id).expect("Query failed");

    assert_eq!(
        members_inconsistent.len(),
        0,
        "BUG: list_project_members returned a project member whose org_member is soft-deleted. \
         The query should check om.deleted_at IS NULL for defense-in-depth."
    );
}

/// Test that list_project_members filters out members whose user is soft-deleted.
///
/// Similar to above, but tests the user -> org_member -> project_member chain.
#[test]
fn test_list_project_members_excludes_deleted_user() {
    let mut conn = setup_test_db();
    let master_key = test_master_key();

    // Setup: org -> project -> user -> org_member -> project_member
    let org = create_test_org(&mut conn, "Test Org");
    let project = create_test_project(&mut conn, &org.id, "Test Project", &master_key);
    let (user, org_member, _api_key) =
        create_test_org_member(&mut conn, &org.id, "member@test.com", OrgMemberRole::Member);
    let project_member =
        create_test_project_member(&mut conn, &org_member.id, &project.id, ProjectMemberRole::View);

    // Soft-delete the user (cascades to org_member, which cascades to project_member)
    queries::soft_delete_user(&mut conn, &user.id).expect("Soft delete failed");

    // Simulate inconsistent state: manually "restore" both org_member and project_member
    // but leave user deleted
    conn.execute(
        "UPDATE org_members SET deleted_at = NULL, deleted_cascade_depth = NULL WHERE id = ?1",
        rusqlite::params![org_member.id],
    )
    .expect("Manual restore org_member failed");
    conn.execute(
        "UPDATE project_members SET deleted_at = NULL, deleted_cascade_depth = NULL WHERE id = ?1",
        rusqlite::params![project_member.id],
    )
    .expect("Manual restore project_member failed");

    // BUG TEST: list_project_members should return 0 because user is deleted
    let members = queries::list_project_members(&conn, &project.id).expect("Query failed");

    assert_eq!(
        members.len(),
        0,
        "BUG: list_project_members returned a project member whose user is soft-deleted. \
         The query should check u.deleted_at IS NULL for defense-in-depth."
    );
}
