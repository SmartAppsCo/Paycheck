//! Tests for email format validation.
//!
//! These tests verify that email addresses are validated for proper format,
//! not just non-emptiness. Invalid emails should be rejected.

#[path = "../common/mod.rs"]
mod common;
use common::*;

use paycheck::models::{CreateUser, UpdateUser};

/// Test that invalid email format is rejected in CreateUser
#[test]
fn test_create_user_rejects_invalid_email_format() {
    let invalid_emails = vec![
        "notanemail",
        "user@",
        "@example.com",
        "user@nodot",
        "@@@@",
        "user@.com",
        "user@com.",
        "user name@example.com", // space in local part
    ];

    for email in invalid_emails {
        let user = CreateUser {
            email: email.to_string(),
            name: "Test User".to_string(),
        };

        let result = user.validate();
        assert!(
            result.is_err(),
            "email '{}' should be rejected as invalid format",
            email
        );
    }
}

/// Test that valid email formats are accepted in CreateUser
#[test]
fn test_create_user_accepts_valid_email_format() {
    let valid_emails = vec![
        "user@example.com",
        "user+tag@example.com",
        "user.name@example.com",
        "user@sub.example.com",
        "user@sub.domain.example.com",
        "u@e.co",
        "USER@EXAMPLE.COM",
    ];

    for email in valid_emails {
        let user = CreateUser {
            email: email.to_string(),
            name: "Test User".to_string(),
        };

        let result = user.validate();
        assert!(
            result.is_ok(),
            "email '{}' should be accepted as valid format, got: {:?}",
            email,
            result.err()
        );
    }
}

/// Test that invalid email format is rejected in UpdateUser
#[test]
fn test_update_user_rejects_invalid_email_format() {
    let invalid_emails = vec!["notanemail", "user@", "@example.com", "user@nodot"];

    for email in invalid_emails {
        let update = UpdateUser {
            email: Some(email.to_string()),
            name: None,
        };

        let result = update.validate();
        assert!(
            result.is_err(),
            "email '{}' should be rejected as invalid format in UpdateUser",
            email
        );
    }
}

/// Test that UpdateUser accepts valid emails
#[test]
fn test_update_user_accepts_valid_email_format() {
    let update = UpdateUser {
        email: Some("user@example.com".to_string()),
        name: None,
    };

    assert!(
        update.validate().is_ok(),
        "valid email should be accepted in UpdateUser"
    );
}

/// Test that UpdateUser with None email (no change) passes validation
#[test]
fn test_update_user_none_email_passes() {
    let update = UpdateUser {
        email: None,
        name: Some("New Name".to_string()),
    };

    assert!(
        update.validate().is_ok(),
        "UpdateUser with None email should pass validation"
    );
}

// ============================================================================
// CRLF INJECTION TESTS
// ============================================================================

/// Test that email validation rejects CRLF injection attempts.
///
/// CRLF in email addresses can enable email header injection when the value
/// is passed to an email service (e.g., Resend). An attacker could inject
/// additional headers like BCC to redirect emails.
///
/// Note: The current test cases happen to be rejected because they contain
/// two '@' symbols (the injected `@evil.com`). A CRLF payload without a
/// second '@' (e.g., "user@example.com\r\nSubject: spam") would bypass
/// `validate_email_format` since it has no control character checks.
#[test]
fn test_email_rejects_crlf_injection() {
    let crlf_emails = vec![
        // CRLF header injection
        "user@example.com\r\nBCC: attacker@evil.com",
        // LF injection
        "user@example.com\nBCC: attacker@evil.com",
        // CR injection
        "user@example.com\rBCC: attacker@evil.com",
    ];

    for email in crlf_emails {
        let user = CreateUser {
            email: email.to_string(),
            name: "Test User".to_string(),
        };

        let result = user.validate();
        assert!(
            result.is_err(),
            "email with CRLF injection '{}' should be rejected",
            email.escape_debug()
        );
    }
}

/// Test that email validation rejects null bytes.
///
/// Null bytes in email addresses can cause truncation in C-based email
/// libraries, potentially sending to a different address than intended.
#[test]
fn test_email_rejects_null_bytes() {
    let null_emails = vec![
        "user\x00@evil.com",
        "user@evil\x00.com",
    ];

    for email in null_emails {
        let user = CreateUser {
            email: email.to_string(),
            name: "Test User".to_string(),
        };

        let result = user.validate();
        assert!(
            result.is_err(),
            "email with null byte '{}' should be rejected",
            email.escape_debug()
        );
    }
}

/// Test that email validation enforces RFC 5321 length limits.
///
/// - Local part (before @): max 64 characters
/// - Total email length: max 254 characters (RFC 5321 path limit)
#[test]
fn test_email_length_limits() {
    // Local part > 64 chars should fail
    let long_local = format!("{}@example.com", "a".repeat(65));
    let user = CreateUser {
        email: long_local.clone(),
        name: "Test User".to_string(),
    };
    assert!(
        user.validate().is_err(),
        "local part > 64 chars should be rejected: {}",
        long_local
    );

    // Total > 254 chars should fail
    let long_total = format!("user@{}.com", "a".repeat(250));
    let user = CreateUser {
        email: long_total.clone(),
        name: "Test User".to_string(),
    };
    assert!(
        user.validate().is_err(),
        "email > 254 chars should be rejected (len={})",
        long_total.len()
    );

    // Exactly 254 chars should pass (boundary)
    // Need: local@domain.com where total = 254
    // "user@" = 5 chars, ".com" = 4 chars, so domain label = 254 - 5 - 4 = 245
    let boundary_email = format!("user@{}.com", "a".repeat(245));
    assert_eq!(boundary_email.len(), 254);
    let user = CreateUser {
        email: boundary_email.clone(),
        name: "Test User".to_string(),
    };
    assert!(
        user.validate().is_ok(),
        "email of exactly 254 chars should be accepted (len={})",
        boundary_email.len()
    );
}

// ============================================================================
// INTEGRATION TEST: ACTIVATION ENDPOINT WITH CRLF EMAIL
// ============================================================================

/// Integration test: POST /activation/request-code with CRLF-injected email.
///
/// The activation endpoint accepts raw email input and passes it directly
/// to the email service (Resend API). If CRLF characters are not stripped
/// or rejected, an attacker could inject email headers.
#[tokio::test]
async fn test_activation_endpoint_crlf_email() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let state = create_test_app_state();
    let app = public_app(state.clone());

    // Create a project so we have a valid public_key
    let conn = state.db.get().unwrap();
    let org = create_test_org(&conn, "Test Org");
    let project = create_test_project(&conn, &org.id, "Test Project", &state.master_key);
    drop(conn);

    // Send activation request with CRLF-injected email
    let body = serde_json::json!({
        "email": "user@example.com\r\nBCC: attacker@evil.com",
        "public_key": project.public_key
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/activation/request-code")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // The endpoint should reject malformed emails with 400, not process them.
    // If it returns 200, the CRLF email was accepted and potentially passed
    // to the email service.
    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "CRLF-injected email should be rejected with 400, not silently accepted"
    );
}
