use super::helpers::*;

// ------------------------------------------------------------------------
// Missing/Invalid Token Tests
// ------------------------------------------------------------------------

#[tokio::test]
async fn missing_token_returns_401() {
    let (app, _state) = operator_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "request without Authorization header should return 401"
    );
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let (app, _state) = operator_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators")
                .header("Authorization", "Bearer invalid-token-12345")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "invalid API key should return 401"
    );
}

#[tokio::test]
async fn malformed_auth_header_returns_401() {
    let (app, _state) = operator_app();

    // Missing "Bearer " prefix
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators")
                .header("Authorization", "some-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Authorization header without Bearer prefix should return 401"
    );
}

// ------------------------------------------------------------------------
// Non-Operator Rejection
// ------------------------------------------------------------------------

/// A valid user with a valid API key but NO operator role should get 401,
/// not 403. The middleware checks operator_role.is_none() and returns
/// UNAUTHORIZED to avoid revealing the user's existence as a non-operator.
#[tokio::test]
async fn non_operator_user_api_key_returns_401() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    // Create a plain user (not an operator) with a valid API key
    let user = create_test_user(&mut conn, "nonadmin@test.com", "Non-Operator User");
    let (_api_key_record, raw_key) =
        paycheck::db::queries::create_api_key(&mut conn, &user.id, "Default", None, true, None)
            .expect("Failed to create API key");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators/audit-logs")
                .header("Authorization", format!("Bearer {}", raw_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The key is valid and the user exists, but they have no operator role.
    // Middleware returns 401 (not 403) for non-operators.
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "valid user without operator role should get 401 on operator endpoints"
    );
}

// ------------------------------------------------------------------------
// Owner-Only Endpoints (/operators/*)
// ------------------------------------------------------------------------

#[tokio::test]
async fn view_role_cannot_access_operator_list() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, view_key) =
        create_test_operator(&mut conn, "view@test.com", OperatorRole::View);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators")
                .header("Authorization", format!("Bearer {}", view_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "view role should not access operator list (owner-only endpoint)"
    );
}

#[tokio::test]
async fn admin_role_cannot_access_operator_list() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators")
                .header("Authorization", format!("Bearer {}", admin_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "admin role should not access operator list (owner-only endpoint)"
    );
}

#[tokio::test]
async fn owner_role_can_access_operator_list() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, owner_key) =
        create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators")
                .header("Authorization", format!("Bearer {}", owner_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "owner role should access operator list"
    );
}

#[tokio::test]
async fn admin_cannot_create_operator() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

    // Create a user to add as operator
    let new_user = create_test_user(&mut conn, "new@test.com", "New Op");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id": "{}", "role": "view"}}"#,
                    new_user.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "admin role should not create operators (owner-only action)"
    );
}

#[tokio::test]
async fn owner_can_create_operator() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, owner_key) =
        create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);

    // Create a user to add as operator
    let new_user = create_test_user(&mut conn, "new@test.com", "New Op");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header("Authorization", format!("Bearer {}", owner_key))
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"user_id": "{}", "role": "view"}}"#,
                    new_user.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "owner role should create operators successfully"
    );
}

// ------------------------------------------------------------------------
// Admin-Level Endpoints (/operators/organizations/*)
// ------------------------------------------------------------------------

#[tokio::test]
async fn view_role_cannot_list_organizations() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, view_key) =
        create_test_operator(&mut conn, "view@test.com", OperatorRole::View);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators/organizations")
                .header("Authorization", format!("Bearer {}", view_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "view role should not list organizations (admin+ required)"
    );
}

#[tokio::test]
async fn admin_role_can_list_organizations() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators/organizations")
                .header("Authorization", format!("Bearer {}", admin_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin role should list organizations"
    );
}

#[tokio::test]
async fn owner_role_can_list_organizations() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, owner_key) =
        create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators/organizations")
                .header("Authorization", format!("Bearer {}", owner_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "owner role should list organizations"
    );
}

#[tokio::test]
async fn view_cannot_create_organization() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, view_key) =
        create_test_operator(&mut conn, "view@test.com", OperatorRole::View);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/organizations")
                .header("Authorization", format!("Bearer {}", view_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name": "New Org"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "view role should not create organizations (admin+ required)"
    );
}

#[tokio::test]
async fn admin_can_create_organization() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/organizations")
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name": "New Org"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin role should create organizations successfully"
    );
}

// ------------------------------------------------------------------------
// View-Level Endpoints (/operators/audit-logs)
// ------------------------------------------------------------------------

#[tokio::test]
async fn view_role_can_access_audit_logs() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, view_key) =
        create_test_operator(&mut conn, "view@test.com", OperatorRole::View);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators/audit-logs")
                .header("Authorization", format!("Bearer {}", view_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "view role should access audit logs (view+ required)"
    );
}

#[tokio::test]
async fn admin_role_can_access_audit_logs() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators/audit-logs")
                .header("Authorization", format!("Bearer {}", admin_key))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin role should access audit logs"
    );
}

#[tokio::test]
async fn missing_token_cannot_access_audit_logs() {
    let (app, _state) = operator_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/operators/audit-logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "request without Authorization header should not access audit logs"
    );
}

// ------------------------------------------------------------------------
// Tag Endpoints (Admin+ Only)
// ------------------------------------------------------------------------

#[tokio::test]
async fn view_role_cannot_update_user_tags() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_view_user, view_key) =
        create_test_operator(&mut conn, "view@test.com", OperatorRole::View);
    let target_user = create_test_user(&mut conn, "target@test.com", "Target User");

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/operators/users/{}/tags", target_user.id))
                .header("Authorization", format!("Bearer {}", view_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["suspended"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "view role should not update user tags (admin+ required)"
    );
}

#[tokio::test]
async fn view_role_cannot_update_org_tags() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_view_user, view_key) =
        create_test_operator(&mut conn, "view@test.com", OperatorRole::View);
    let org = create_test_org(&mut conn, "Test Org");

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/operators/organizations/{}/tags", org.id))
                .header("Authorization", format!("Bearer {}", view_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["disabled"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "view role should not update org tags (admin+ required)"
    );
}

#[tokio::test]
async fn admin_role_can_update_user_tags() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_admin_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
    let target_user = create_test_user(&mut conn, "target@test.com", "Target User");

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/operators/users/{}/tags", target_user.id))
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["suspended"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin role should update user tags successfully"
    );

    // Verify tag was actually added
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["tags"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("suspended")),
        "response should contain the added tag"
    );
}

#[tokio::test]
async fn admin_role_can_update_org_tags() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_admin_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);
    let org = create_test_org(&mut conn, "Test Org");

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/operators/organizations/{}/tags", org.id))
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["disabled"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin role should update org tags successfully"
    );

    // Verify tag was actually added
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["tags"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("disabled")),
        "response should contain the added tag"
    );
}

#[tokio::test]
async fn owner_role_can_update_user_tags() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_owner_user, owner_key) =
        create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
    let target_user = create_test_user(&mut conn, "target@test.com", "Target User");

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/operators/users/{}/tags", target_user.id))
                .header("Authorization", format!("Bearer {}", owner_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["vip", "beta"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "owner role should update user tags successfully"
    );
}

#[tokio::test]
async fn owner_role_can_update_org_tags() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_owner_user, owner_key) =
        create_test_operator(&mut conn, "owner@test.com", OperatorRole::Owner);
    let org = create_test_org(&mut conn, "Test Org");

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/operators/organizations/{}/tags", org.id))
                .header("Authorization", format!("Bearer {}", owner_key))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"add": ["overage", "checkout_blocked"], "remove": []}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "owner role should update org tags successfully"
    );
}

#[tokio::test]
async fn update_user_tags_returns_404_for_nonexistent_user() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_admin_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/operators/users/nonexistent-user-id/tags")
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["test"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "updating tags for nonexistent user should return 404"
    );
}

#[tokio::test]
async fn update_org_tags_returns_404_for_nonexistent_org() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let (_admin_user, admin_key) =
        create_test_operator(&mut conn, "admin@test.com", OperatorRole::Admin);

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/operators/organizations/nonexistent-org-id/tags")
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["test"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "updating tags for nonexistent org should return 404"
    );
}

#[tokio::test]
async fn missing_token_cannot_update_user_tags() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let target_user = create_test_user(&mut conn, "target@test.com", "Target User");

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/operators/users/{}/tags", target_user.id))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["test"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "request without token should not update user tags"
    );
}

#[tokio::test]
async fn missing_token_cannot_update_org_tags() {
    let (app, state) = operator_app();
    let mut conn = state.db.get().unwrap();

    let org = create_test_org(&mut conn, "Test Org");

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/operators/organizations/{}/tags", org.id))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add": ["test"], "remove": []}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "request without token should not update org tags"
    );
}
