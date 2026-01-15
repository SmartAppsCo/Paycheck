//! Tests for email format validation.
//!
//! These tests verify that email addresses are validated for proper format,
//! not just non-emptiness. Invalid emails should be rejected.

#[path = "../common/mod.rs"]
mod common;

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
