use super::helpers::*;

#[tokio::test]
async fn admin_operator_can_impersonate_org_member() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an operator with admin role
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org and member
    let org = create_test_org(&mut conn, "Test Org");
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "user@org.com", OrgMemberRole::Owner);

    // Operator impersonates the member (using user_id)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin operator should be able to impersonate org member"
    );
}

#[tokio::test]
async fn owner_operator_can_impersonate_org_member() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let (_user, operator_key) =
        create_test_operator(&mut conn, "owner@platform.com", OperatorRole::Owner);

    let org = create_test_org(&mut conn, "Test Org");
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "user@org.com", OrgMemberRole::Owner);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "owner operator should be able to impersonate org member"
    );
}

#[tokio::test]
async fn view_operator_cannot_impersonate() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let (_user, operator_key) =
        create_test_operator(&mut conn, "view@platform.com", OperatorRole::View);

    let org = create_test_org(&mut conn, "Test Org");
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "user@org.com", OrgMemberRole::Owner);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "view operator should not be allowed to impersonate org members"
    );
}

#[tokio::test]
async fn operator_can_access_org_endpoints_directly() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    let org = create_test_org(&mut conn, "Test Org");
    let (_user2, _member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "user@org.com", OrgMemberRole::Owner);

    // Operators with admin+ role can access org endpoints directly (without impersonation)
    // They get synthetic owner-level access
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin operator should access org endpoints directly with synthetic owner access"
    );
}

#[tokio::test]
async fn view_operator_cannot_access_org_endpoints_directly() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // View-only operator should NOT be able to access org endpoints
    let (_user, operator_key) =
        create_test_operator(&mut conn, "viewer@platform.com", OperatorRole::View);

    let org = create_test_org(&mut conn, "Test Org");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "view operator should not have direct access to org endpoints"
    );
}

#[tokio::test]
async fn cannot_impersonate_member_from_different_org() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    let org1 = create_test_org(&mut conn, "Org 1");
    let org2 = create_test_org(&mut conn, "Org 2");

    // Member is in org1
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org1.id, "user@org1.com", OrgMemberRole::Owner);

    // Try to access org2's endpoints while impersonating org1's member (user not in org2)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org2.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // User is not a member of org2 - return FORBIDDEN to avoid leaking membership info
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "impersonating member of org1 should not grant access to org2"
    );
}

#[tokio::test]
async fn impersonation_respects_member_permissions() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    let org = create_test_org(&mut conn, "Test Org");
    // Member role can't create org members (owner-only operation)
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    // Create a user to add as org member
    let new_user = create_test_user(&mut conn, "new@org.com", "New Member");

    // Try to create org member while impersonating a member-role user
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id": "{}", "role": "member"}}"#,
                    new_user.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden because the impersonated member doesn't have owner role
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "impersonating member-role user should not allow owner-only operations"
    );
}

#[tokio::test]
async fn impersonating_nonexistent_member_returns_forbidden() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    let org = create_test_org(&mut conn, "Test Org");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", "nonexistent-member-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Return FORBIDDEN (not NOT_FOUND) to avoid leaking membership information
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "impersonating nonexistent user should return forbidden"
    );
}

/// Operators cannot impersonate other operators on operator API endpoints.
/// The X-On-Behalf-Of header is only for impersonating org members on org endpoints.
#[tokio::test]
async fn operator_cannot_impersonate_another_operator() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    // Create two operators - one admin and one owner
    let (target_user, _target_key) =
        create_test_operator(&mut conn, "owner@platform.com", OperatorRole::Owner);
    let (_user2, admin_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Admin tries to access owner-only endpoint by "impersonating" the owner
    // This should fail because operator impersonation doesn't exist
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators")
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("X-On-Behalf-Of", &target_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should still be FORBIDDEN - the X-On-Behalf-Of header has no effect
    // on operator endpoints, so admin still can't access owner-only endpoints
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "X-On-Behalf-Of header should have no effect on operator endpoints"
    );
}

// ========================================================================
// Edge Case Tests
// ========================================================================

/// Soft-deleted org members should not be impersonatable.
#[tokio::test]
async fn test_operator_cannot_impersonate_deleted_member() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org and member
    let org = create_test_org(&mut conn, "Test Org");
    let (member_user, member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "user@org.com", OrgMemberRole::Owner);

    // Soft-delete the member
    paycheck::db::queries::soft_delete_org_member(&mut conn, &member.id)
        .expect("Failed to soft-delete member");

    // Try to impersonate the deleted member
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - deleted members cannot be impersonated
    // Return FORBIDDEN (not NOT_FOUND) to avoid leaking membership information
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "soft-deleted members should not be impersonatable"
    );
}

/// Operators can impersonate themselves if they are also org members.
/// This is a valid use case (e.g., operator who is also a customer).
#[tokio::test]
async fn test_operator_can_impersonate_self_as_org_member() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (op_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org and add the operator as a member
    let org = create_test_org(&mut conn, "Test Org");
    let member_input = paycheck::models::CreateOrgMember {
        user_id: op_user.id.clone(),
        role: OrgMemberRole::Member,
    };
    paycheck::db::queries::create_org_member(&mut conn, &org.id, &member_input)
        .expect("Failed to create org member");

    // Impersonate self
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &op_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should succeed - self-impersonation is valid when user is both operator and org member
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "operator should be able to impersonate self when also an org member"
    );
}

/// Users that exist but have no org memberships cannot be impersonated.
#[tokio::test]
async fn test_operator_cannot_impersonate_user_not_in_any_org() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create a user with no org memberships
    let orphan_user = create_test_user(&mut conn, "orphan@test.com", "Orphan User");

    // Create an org (no members added for orphan_user)
    let org = create_test_org(&mut conn, "Test Org");

    // Try to impersonate the orphan user
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &orphan_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - user is not a member of the org
    // Return FORBIDDEN (not NOT_FOUND) to avoid leaking membership information
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "users without org membership should not be impersonatable"
    );
}

/// HTTP headers are case-insensitive per spec, so X-ON-BEHALF-OF should work.
#[tokio::test]
async fn test_impersonation_header_case_insensitive() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org and member
    let org = create_test_org(&mut conn, "Test Org");
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "user@org.com", OrgMemberRole::Owner);

    // Use uppercase header name
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-ON-BEHALF-OF", &member_user.id) // All caps
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should work - HTTP headers are case-insensitive
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "X-ON-BEHALF-OF (uppercase) header should work per HTTP case-insensitivity"
    );
}

/// Non-UUID values in X-On-Behalf-Of should be handled gracefully.
#[tokio::test]
async fn test_impersonation_with_invalid_user_id_format() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org
    let org = create_test_org(&mut conn, "Test Org");

    // Use invalid user_id format
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", "not-a-valid-uuid!")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return FORBIDDEN (not NOT_FOUND) to avoid leaking membership info
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "invalid user_id format in X-On-Behalf-Of should return forbidden gracefully"
    );
}

// ========================================================================
// Privilege Boundary Tests
// ========================================================================

/// When impersonating a member with limited role, operations should respect that role.
#[tokio::test]
async fn test_impersonation_respects_target_member_role() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org with a member-role user (not owner)
    let org = create_test_org(&mut conn, "Test Org");
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "member@org.com", OrgMemberRole::Member);

    // Create another user to try to add
    let new_user = create_test_user(&mut conn, "new@org.com", "New User");

    // Try to create org member while impersonating a member-role user
    // This should fail because member role cannot create new members
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id": "{}", "role": "member"}}"#,
                    new_user.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    // Member role cannot create org members - should be forbidden
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "impersonated member-role should not be able to create org members"
    );
}

/// Operators impersonating an owner can perform owner-only actions.
/// The audit trail records the impersonator for accountability.
#[tokio::test]
async fn test_operator_can_impersonate_as_owner() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org with an owner
    let org = create_test_org(&mut conn, "Test Org");
    let (owner_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

    // Create a user to add as member
    let new_user = create_test_user(&mut conn, "new@org.com", "New User");

    // Impersonate the owner and create a new org member
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &owner_user.id)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id": "{}", "role": "member"}}"#,
                    new_user.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should succeed - impersonating an owner grants owner permissions
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "impersonating owner should allow owner-only operations like creating members"
    );
}

/// When an operator has a scoped API key, impersonation bypasses the API key scope.
/// This is current behavior: operator impersonation uses operator privileges,
/// and the only check is that the target user is a member of the requested org.
///
/// Note: This test documents current behavior. If API key scopes should restrict
/// operator impersonation, the middleware would need to be updated.
#[tokio::test]
async fn test_impersonation_with_scoped_api_key_bypasses_scope() {
    use tower::Service;

    let (mut app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator (with default full-access key)
    let (op_user, _full_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create two orgs
    let org1 = create_test_org(&mut conn, "Org 1");
    let org2 = create_test_org(&mut conn, "Org 2");

    // Add members to both orgs
    let (member1_user, _member1, _member1_key) =
        create_test_org_member(&mut conn, &org1.id, "user1@org.com", OrgMemberRole::Owner);
    let (member2_user, _member2, _member2_key) =
        create_test_org_member(&mut conn, &org2.id, "user2@org.com", OrgMemberRole::Owner);

    // Create a scoped API key for the operator that only allows access to org1
    let scoped_key = create_api_key_with_org_scope(
        &mut conn,
        &op_user.id,
        &org1.id,
        paycheck::models::AccessLevel::Admin,
    );

    // Test 1: Impersonate member in org1 - works as expected
    let response1 = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org1.id))
                .header("Authorization", format!("Bearer {}", scoped_key))
                .header("X-On-Behalf-Of", &member1_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response1.status(),
        StatusCode::OK,
        "impersonation within scoped key's org should succeed"
    );

    // Test 2: Impersonate member in org2 - currently succeeds because
    // operator impersonation bypasses API key scopes.
    // The only requirement is that the target user is a member of the org.
    let response2 = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org2.id))
                .header("Authorization", format!("Bearer {}", scoped_key))
                .header("X-On-Behalf-Of", &member2_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Current behavior: impersonation bypasses API key scopes
    assert_eq!(
        response2.status(),
        StatusCode::OK,
        "impersonation bypasses API key scopes (documented current behavior)"
    );
}

/// API key scopes DO apply for non-impersonated operator access (synthetic access).
#[tokio::test]
async fn test_scoped_api_key_restricts_synthetic_access() {
    use tower::Service;

    let (mut app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (op_user, _full_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create two orgs
    let org1 = create_test_org(&mut conn, "Org 1");
    let org2 = create_test_org(&mut conn, "Org 2");

    // Create a scoped API key for the operator that only allows access to org1
    let scoped_key = create_api_key_with_org_scope(
        &mut conn,
        &op_user.id,
        &org1.id,
        paycheck::models::AccessLevel::Admin,
    );

    // Test 1: Synthetic access to org1 - should work
    let response1 = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org1.id))
                .header("Authorization", format!("Bearer {}", scoped_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response1.status(),
        StatusCode::OK,
        "scoped API key should allow synthetic access to its allowed org"
    );

    // Test 2: Synthetic access to org2 - should fail (key scope)
    let response2 = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org2.id))
                .header("Authorization", format!("Bearer {}", scoped_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - API key doesn't have access to org2
    assert_eq!(
        response2.status(),
        StatusCode::FORBIDDEN,
        "scoped API key should deny synthetic access to orgs outside its scope"
    );
}

// ========================================================================
// Cross-Org Impersonation Tests
// ========================================================================

/// Cannot impersonate a member of org_a and then access org_b.
#[tokio::test]
async fn test_cannot_impersonate_member_then_access_different_org() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create two orgs
    let org_a = create_test_org(&mut conn, "Org A");
    let org_b = create_test_org(&mut conn, "Org B");

    // Create member in org_a only
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);

    // Try to access org_b while impersonating a member of org_a
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org_b.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - the impersonated user is not a member of org_b
    // Return FORBIDDEN (not NOT_FOUND) to avoid leaking membership information
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "impersonating org_a member should not grant access to org_b"
    );
}

/// The impersonation lookup is per-request based on the org_id in the URL path.
/// A user must be a member of the org they're being impersonated for.
#[tokio::test]
async fn test_impersonation_requires_member_in_requested_org() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create org_a with the member
    let org_a = create_test_org(&mut conn, "Org A");
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);

    // Create org_b (member is NOT in this org)
    let org_b = create_test_org(&mut conn, "Org B");

    // Try to impersonate the member for org_b (where they're not a member)
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org_b.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Return FORBIDDEN (not NOT_FOUND) to avoid leaking membership information
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "impersonation target must be a member of the requested org"
    );
}

// ========================================================================
// Synthetic Operator Access Tests
// ========================================================================

/// When X-On-Behalf-Of header is present but refers to a non-member,
/// the middleware should NOT fall through to synthetic access.
#[tokio::test]
async fn test_synthetic_access_blocked_when_impersonation_header_present() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator (would normally get synthetic access)
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org
    let org = create_test_org(&mut conn, "Test Org");

    // Create a user who is NOT a member of the org
    let non_member = create_test_user(&mut conn, "random@test.com", "Random User");

    // Try to impersonate the non-member
    // This should fail with NOT_FOUND, not fall through to synthetic access
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &non_member.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be FORBIDDEN (impersonation failed) not OK (synthetic access)
    // This proves impersonation path takes precedence and doesn't fall through
    // Using FORBIDDEN instead of NOT_FOUND to avoid leaking membership info
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "failed impersonation should not fall through to synthetic access"
    );
}

/// View-role operators should not get synthetic owner access to org endpoints.
#[tokio::test]
async fn test_view_operator_no_synthetic_access() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create a view-only operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "viewer@platform.com", OperatorRole::View);

    // Create an org
    let org = create_test_org(&mut conn, "Test Org");

    // View operators should NOT get synthetic access to org endpoints
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be FORBIDDEN - view operators don't get synthetic access
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "view operator should not get synthetic access to org endpoints"
    );
}

/// Verify that synthetic access grants owner-level permissions.
#[tokio::test]
async fn test_synthetic_access_grants_owner_permissions() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator (NOT a member of any org)
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org (operator is NOT a member)
    let org = create_test_org(&mut conn, "Test Org");

    // Create a user to add as member
    let new_user = create_test_user(&mut conn, "new@org.com", "New User");

    // Try to create an org member using synthetic access (owner-only operation)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orgs/{}/members", org.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id": "{}", "role": "member"}}"#,
                    new_user.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should succeed - synthetic access grants owner-level permissions
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "synthetic access should grant owner-level permissions for admin+ operators"
    );
}

// ========================================================================
// Self-Role Escalation Prevention Tests
// ========================================================================

/// An operator who is also an org member cannot use impersonation to escalate
/// their own org role. This is a critical security boundary.
///
/// Attack scenario:
/// 1. Operator (user_id: "op123") has "member" role in org
/// 2. Org has an owner (user_id: "owner456")
/// 3. Operator impersonates owner: X-On-Behalf-Of: owner456
/// 4. Operator calls PUT /orgs/{org}/members/op123 with {"role": "owner"}
/// 5. Without proper check, this would escalate operator's own role
#[tokio::test]
async fn test_operator_cannot_escalate_own_role_via_impersonation() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator who is ALSO an org member with limited role
    let (op_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create an org
    let org = create_test_org(&mut conn, "Test Org");

    // Add the operator as an org member with "member" role (not owner)
    let member_input = paycheck::models::CreateOrgMember {
        user_id: op_user.id.clone(),
        role: OrgMemberRole::Member,
    };
    paycheck::db::queries::create_org_member(&mut conn, &org.id, &member_input)
        .expect("Failed to create org member");

    // Create another user who IS the org owner
    let (owner_user, _owner_member, _owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

    // Attack: Impersonate the owner and try to change operator's own role to owner
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/orgs/{}/members/{}", org.id, op_user.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &owner_user.id) // Impersonate the owner
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"role": "owner"}"#)) // Try to escalate self to owner
                .unwrap(),
        )
        .await
        .unwrap();

    // This MUST fail - operators cannot escalate their own role via impersonation
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "operator should not be able to escalate their own role via impersonation"
    );
}

/// Even when not impersonating, the "cannot change own role" check should work.
/// This verifies the base case that the check is actually functioning.
#[tokio::test]
async fn test_owner_cannot_change_own_role_directly() {
    let (app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an org with an owner
    let org = create_test_org(&mut conn, "Test Org");
    let (_owner_user, _owner_member, owner_key) =
        create_test_org_member(&mut conn, &org.id, "owner@org.com", OrgMemberRole::Owner);

    // Owner tries to change their own role
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/orgs/{}/members/{}", org.id, _owner_user.id))
                .header("Authorization", format!("Bearer {}", owner_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"role": "member"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - can't change your own role
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "owner should not be able to change their own role"
    );
}

// ========================================================================
// Information Leakage Prevention Tests
// ========================================================================

/// Failed impersonation should not reveal whether a user is a member of an org.
///
/// Security issue: If we return different status codes for "user exists but not in org"
/// vs "user in org", an operator could probe org membership by checking response codes.
///
/// Fix: Return 403 Forbidden for all impersonation failures (not 404 Not Found).
/// This doesn't reveal whether the user exists in the org or not.
#[tokio::test]
async fn test_impersonation_failure_does_not_leak_membership_status() {
    use tower::Service;

    let (mut app, state) = org_app();
    let mut conn = state.db.get().unwrap();

    // Create an admin operator
    let (_user, operator_key) =
        create_test_operator(&mut conn, "admin@platform.com", OperatorRole::Admin);

    // Create two orgs
    let org_a = create_test_org(&mut conn, "Org A");
    let org_b = create_test_org(&mut conn, "Org B");

    // Create a member in org_a only
    let (member_user, _member, _member_key) =
        create_test_org_member(&mut conn, &org_a.id, "user@orga.com", OrgMemberRole::Owner);

    // Create a user who is not a member of any org
    let orphan_user = create_test_user(&mut conn, "orphan@test.com", "Orphan User");

    // Case 1: User exists but is not in org_b
    let response1 = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org_b.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &member_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Case 2: User exists but has no org memberships at all
    let response2 = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org_b.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", &orphan_user.id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Case 3: User ID doesn't exist at all
    let response3 = app
        .call(
            Request::builder()
                .method("GET")
                .uri(format!("/orgs/{}/members", org_b.id))
                .header("Authorization", format!("Bearer {}", operator_key))
                .header("X-On-Behalf-Of", "nonexistent-user-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // All three cases should return the SAME status code (403 Forbidden)
    // This prevents information leakage about org membership
    assert_eq!(
        response1.status(),
        StatusCode::FORBIDDEN,
        "impersonating user not in target org should return 403 (not 404)"
    );
    assert_eq!(
        response2.status(),
        StatusCode::FORBIDDEN,
        "impersonating user with no org memberships should return 403 (not 404)"
    );
    assert_eq!(
        response3.status(),
        StatusCode::FORBIDDEN,
        "impersonating nonexistent user should return 403 (not 404)"
    );

    // Verify all responses are identical (same status code prevents oracle)
    assert_eq!(
        response1.status(),
        response2.status(),
        "response for 'user in different org' should match 'user with no orgs'"
    );
    assert_eq!(
        response2.status(),
        response3.status(),
        "response for 'user with no orgs' should match 'nonexistent user'"
    );
}
