//! Security tests for SSRF (Server-Side Request Forgery) prevention.
//!
//! Webhook URLs (feedback_webhook_url, crash_webhook_url, email_webhook_url)
//! are configured by org admins and used for outbound HTTP requests.
//! Without validation, attackers could set these to target:
//! - Internal services (127.0.0.1, localhost, 10.x.x.x, 192.168.x.x, 172.16-31.x.x)
//! - Cloud metadata endpoints (169.254.169.254)
//! - Other sensitive internal resources
//!
//! These tests verify that dangerous URLs are rejected at configuration time.

use paycheck::models::{CreateProject, UpdateProject};

// ============================================================================
// URL Validation Tests - Verifying Protection
// ============================================================================

/// Test: Localhost URLs are rejected
#[test]
fn test_webhook_url_localhost_is_rejected() {
    let dangerous_urls = vec![
        ("http://localhost:8080/webhook", "HTTP localhost"),
        ("https://localhost:8080/webhook", "HTTPS localhost"),
        ("https://127.0.0.1:8080/webhook", "loopback IP"),
        ("https://127.0.0.1/admin", "loopback without port"),
        ("https://[::1]/webhook", "IPv6 loopback"),
    ];

    for (url, desc) in dangerous_urls {
        let project = CreateProject {
            name: "Test Project".to_string(),
            license_key_prefix: "TEST".to_string(),
            redirect_url: None,
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
            feedback_webhook_url: Some(url.to_string()),
            feedback_email: None,
            crash_webhook_url: None,
            crash_email: None,
        };

        let result = project.validate();
        assert!(
            result.is_err(),
            "Localhost URL '{}' ({}) should be rejected",
            url,
            desc
        );
    }
}

/// Test: Private IP ranges are rejected
#[test]
fn test_webhook_url_private_ips_are_rejected() {
    let dangerous_urls = vec![
        // 10.0.0.0/8 - Private network
        ("https://10.0.0.1/internal", "10.x.x.x range"),
        ("https://10.255.255.255/admin", "10.x.x.x range end"),
        // 172.16.0.0/12 - Private network
        ("https://172.16.0.1/service", "172.16.x.x range start"),
        ("https://172.31.255.255/api", "172.31.x.x range end"),
        // 192.168.0.0/16 - Private network
        ("https://192.168.1.1/router", "192.168.x.x range"),
        ("https://192.168.0.100:8080/internal", "192.168.x.x with port"),
    ];

    for (url, desc) in dangerous_urls {
        let project = CreateProject {
            name: "Test Project".to_string(),
            license_key_prefix: "TEST".to_string(),
            redirect_url: None,
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
            feedback_webhook_url: Some(url.to_string()),
            feedback_email: None,
            crash_webhook_url: None,
            crash_email: None,
        };

        let result = project.validate();
        assert!(
            result.is_err(),
            "Private IP URL '{}' ({}) should be rejected",
            url,
            desc
        );
    }
}

/// Test: Cloud metadata endpoints are rejected
#[test]
fn test_webhook_url_cloud_metadata_is_rejected() {
    let dangerous_urls = vec![
        // AWS metadata endpoint
        (
            "https://169.254.169.254/latest/meta-data/",
            "AWS metadata",
        ),
        (
            "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "AWS credentials",
        ),
        // Link-local range
        ("https://169.254.0.1/", "link-local"),
        ("https://169.254.255.255/", "link-local end"),
    ];

    for (url, desc) in dangerous_urls {
        let project = CreateProject {
            name: "Test Project".to_string(),
            license_key_prefix: "TEST".to_string(),
            redirect_url: None,
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
            feedback_webhook_url: Some(url.to_string()),
            feedback_email: None,
            crash_webhook_url: None,
            crash_email: None,
        };

        let result = project.validate();
        assert!(
            result.is_err(),
            "Cloud metadata URL '{}' ({}) should be rejected",
            url,
            desc
        );
    }
}

/// Test: HTTP URLs are rejected (must use HTTPS)
#[test]
fn test_webhook_url_http_is_rejected() {
    let http_urls = vec![
        "http://example.com/webhook",
        "http://myapp.com/feedback",
        "http://api.service.io/events",
    ];

    for url in http_urls {
        let project = CreateProject {
            name: "Test Project".to_string(),
            license_key_prefix: "TEST".to_string(),
            redirect_url: None,
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
            feedback_webhook_url: Some(url.to_string()),
            feedback_email: None,
            crash_webhook_url: None,
            crash_email: None,
        };

        let result = project.validate();
        assert!(
            result.is_err(),
            "HTTP URL '{}' should be rejected (must use HTTPS)",
            url
        );
    }
}

/// Test: UpdateProject also validates webhook URLs
#[test]
fn test_update_project_webhook_url_validation() {
    let dangerous_urls = vec![
        "https://localhost/admin",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/internal",
        "http://example.com/webhook", // HTTP not allowed
    ];

    for url in dangerous_urls {
        let update = UpdateProject {
            name: None,
            license_key_prefix: None,
            redirect_url: None,
            email_from: None,
            email_enabled: None,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
            feedback_webhook_url: Some(Some(url.to_string())),
            feedback_email: None,
            crash_webhook_url: None,
            crash_email: None,
        };

        let result = update.validate();
        assert!(
            result.is_err(),
            "Dangerous URL '{}' should be rejected in UpdateProject",
            url
        );
    }
}

/// Test: Clearing a webhook URL (Some(None)) is allowed
#[test]
fn test_update_project_clearing_webhook_url_is_allowed() {
    let update = UpdateProject {
        name: None,
        license_key_prefix: None,
        redirect_url: None,
        email_from: None,
        email_enabled: None,
        email_webhook_url: None,
        payment_config_id: None,
        email_config_id: None,
        feedback_webhook_url: Some(None), // Clearing the URL
        feedback_email: None,
        crash_webhook_url: Some(None), // Clearing the URL
        crash_email: None,
    };

    let result = update.validate();
    assert!(
        result.is_ok(),
        "Clearing webhook URLs (Some(None)) should be allowed"
    );
}

// ============================================================================
// All webhook URL fields are validated
// ============================================================================

/// Test: All three webhook URL fields are validated
#[test]
fn test_all_webhook_url_fields_are_validated() {
    let dangerous_url = "https://169.254.169.254/latest/meta-data/";

    // Test feedback_webhook_url
    let project1 = CreateProject {
        name: "Test".to_string(),
        license_key_prefix: "TEST".to_string(),
        redirect_url: None,
        email_from: None,
        email_enabled: true,
        email_webhook_url: None,
        payment_config_id: None,
        email_config_id: None,
        feedback_webhook_url: Some(dangerous_url.to_string()),
        feedback_email: None,
        crash_webhook_url: None,
        crash_email: None,
    };
    assert!(
        project1.validate().is_err(),
        "feedback_webhook_url should reject cloud metadata URL"
    );

    // Test crash_webhook_url
    let project2 = CreateProject {
        name: "Test".to_string(),
        license_key_prefix: "TEST".to_string(),
        redirect_url: None,
        email_from: None,
        email_enabled: true,
        email_webhook_url: None,
        payment_config_id: None,
        email_config_id: None,
        feedback_webhook_url: None,
        feedback_email: None,
        crash_webhook_url: Some(dangerous_url.to_string()),
        crash_email: None,
    };
    assert!(
        project2.validate().is_err(),
        "crash_webhook_url should reject cloud metadata URL"
    );

    // Test email_webhook_url
    let project3 = CreateProject {
        name: "Test".to_string(),
        license_key_prefix: "TEST".to_string(),
        redirect_url: None,
        email_from: None,
        email_enabled: true,
        email_webhook_url: Some(dangerous_url.to_string()),
        payment_config_id: None,
        email_config_id: None,
        feedback_webhook_url: None,
        feedback_email: None,
        crash_webhook_url: None,
        crash_email: None,
    };
    assert!(
        project3.validate().is_err(),
        "email_webhook_url should reject cloud metadata URL"
    );
}

// ============================================================================
// Valid URLs are accepted
// ============================================================================

/// Test: Valid external HTTPS URLs are accepted
#[test]
fn test_valid_external_https_urls_are_accepted() {
    let valid_urls = vec![
        "https://myapp.com/webhook",
        "https://api.example.com/paycheck/feedback",
        "https://webhooks.myservice.io/v1/events",
        "https://hooks.slack.com/services/xxx/yyy/zzz",
    ];

    for url in valid_urls {
        let project = CreateProject {
            name: "Test".to_string(),
            license_key_prefix: "TEST".to_string(),
            redirect_url: None,
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
            feedback_webhook_url: Some(url.to_string()),
            feedback_email: None,
            crash_webhook_url: None,
            crash_email: None,
        };

        assert!(
            project.validate().is_ok(),
            "Valid external HTTPS URL '{}' should be accepted",
            url
        );
    }
}

/// Test: No webhook URL (None) is valid
#[test]
fn test_no_webhook_url_is_valid() {
    let project = CreateProject {
        name: "Test".to_string(),
        license_key_prefix: "TEST".to_string(),
        redirect_url: None,
        email_from: None,
        email_enabled: true,
        email_webhook_url: None,
        payment_config_id: None,
        email_config_id: None,
        feedback_webhook_url: None,
        feedback_email: None,
        crash_webhook_url: None,
        crash_email: None,
    };

    assert!(
        project.validate().is_ok(),
        "Project without webhook URLs should be valid"
    );
}

// ============================================================================
// Edge cases and bypass attempts
// ============================================================================

/// Test: DNS rebinding-style hostnames are blocked
#[test]
fn test_dns_rebinding_hostnames_blocked() {
    // These hostnames start with IP-like prefixes that could be DNS rebinding attempts
    let suspicious_urls = vec![
        "https://127.0.0.1.nip.io/webhook",
        "https://10.0.0.1.xip.io/internal",
        "https://192.168.1.1.sslip.io/admin",
        "https://169.254.169.254.example.com/metadata",
    ];

    for url in suspicious_urls {
        let project = CreateProject {
            name: "Test".to_string(),
            license_key_prefix: "TEST".to_string(),
            redirect_url: None,
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
            feedback_webhook_url: Some(url.to_string()),
            feedback_email: None,
            crash_webhook_url: None,
            crash_email: None,
        };

        assert!(
            project.validate().is_err(),
            "DNS rebinding-style hostname '{}' should be rejected",
            url
        );
    }
}

/// Test: Invalid URLs are rejected
#[test]
fn test_invalid_urls_are_rejected() {
    let invalid_urls = vec![
        "not-a-url",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "",
    ];

    for url in invalid_urls {
        if url.is_empty() {
            continue; // Empty string would need different handling
        }
        let project = CreateProject {
            name: "Test".to_string(),
            license_key_prefix: "TEST".to_string(),
            redirect_url: None,
            email_from: None,
            email_enabled: true,
            email_webhook_url: None,
            payment_config_id: None,
            email_config_id: None,
            feedback_webhook_url: Some(url.to_string()),
            feedback_email: None,
            crash_webhook_url: None,
            crash_email: None,
        };

        assert!(
            project.validate().is_err(),
            "Invalid URL '{}' should be rejected",
            url
        );
    }
}
