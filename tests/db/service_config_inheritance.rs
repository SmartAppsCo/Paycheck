//! Tests for three-level service config inheritance (product → project → org)
//!
//! These tests verify that payment and email configs follow the correct
//! inheritance hierarchy when looking up effective configs.

#[path = "../common/mod.rs"]
mod common;

use common::*;
use paycheck::db::queries;
use paycheck::models::*;

/// Test helper: Create a service config and return its ID
fn create_config(
    conn: &rusqlite::Connection,
    org_id: &str,
    name: &str,
    provider: ServiceProvider,
    master_key: &MasterKey,
) -> String {
    let config_data = match provider {
        ServiceProvider::Stripe => {
            let cfg = StripeConfig {
                secret_key: format!("sk_test_{}", name),
                publishable_key: format!("pk_test_{}", name),
                webhook_secret: format!("whsec_{}", name),
            };
            serde_json::to_vec(&cfg).unwrap()
        }
        ServiceProvider::LemonSqueezy => {
            let cfg = LemonSqueezyConfig {
                api_key: format!("ls_key_{}", name),
                store_id: format!("store_{}", name),
                webhook_secret: format!("ls_whsec_{}", name),
            };
            serde_json::to_vec(&cfg).unwrap()
        }
        ServiceProvider::Resend => {
            // Resend expects just the API key as a string
            let cfg = format!("re_key_{}", name);
            serde_json::to_vec(&cfg).unwrap()
        }
    };

    let encrypted = master_key
        .encrypt_private_key(org_id, &config_data)
        .expect("Failed to encrypt config");

    let config = queries::create_service_config(conn, org_id, name, provider, &encrypted)
        .expect("Failed to create service config");
    config.id
}

// ============ Payment Config Inheritance Tests ============

mod payment_config {
    use super::*;

    #[test]
    fn test_org_level_only() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Create and assign org-level Stripe config
        let org_config_id = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        // Reload org with updated config
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();

        // Verify effective config comes from org
        let result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at org level");
        let (config, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Org);
        assert!(config.secret_key.contains("OrgStripe"));
    }

    #[test]
    fn test_project_overrides_org() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Create org-level config
        let org_config_id = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        // Create project-level config that overrides org
        let project_config_id = create_config(&conn, &org.id, "ProjectStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_config_id, &project.id],
        ).unwrap();

        // Reload entities
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();

        // Verify effective config comes from project
        let result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at project level");
        let (config, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Project, "Config should come from project, not org");
        assert!(config.secret_key.contains("ProjectStripe"), "Should use project config");
    }

    #[test]
    fn test_product_overrides_project_and_org() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Create configs at all three levels
        let org_config_id = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        let project_config_id = create_config(&conn, &org.id, "ProjectStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_config_id, &project.id],
        ).unwrap();

        let product_config_id = create_config(&conn, &org.id, "ProductStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE products SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&product_config_id, &product.id],
        ).unwrap();

        // Reload entities
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();
        let product = queries::get_product_by_id(&conn, &product.id).unwrap().unwrap();

        // Verify effective config comes from product
        let result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at product level");
        let (config, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Product, "Config should come from product");
        assert!(config.secret_key.contains("ProductStripe"), "Should use product config");
    }

    #[test]
    fn test_no_config_returns_none() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // No configs set at any level
        let result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_none(), "Should return None when no config exists");
    }

    #[test]
    fn test_has_effective_payment_config_check() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Initially no configs
        let has_stripe = queries::has_effective_payment_config(&conn, &product, &project, &org, ServiceProvider::Stripe)
            .expect("Query failed");
        assert!(!has_stripe, "Should not have Stripe config initially");

        // Add Stripe at org level
        let org_config_id = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();

        let has_stripe = queries::has_effective_payment_config(&conn, &product, &project, &org, ServiceProvider::Stripe)
            .expect("Query failed");
        assert!(has_stripe, "Should have Stripe config at org level");

        // Check for LemonSqueezy (not configured)
        let has_ls = queries::has_effective_payment_config(&conn, &product, &project, &org, ServiceProvider::LemonSqueezy)
            .expect("Query failed");
        assert!(!has_ls, "Should not have LemonSqueezy config");
    }

    #[test]
    fn test_different_providers_at_different_levels() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Org has Stripe, Project has LemonSqueezy
        let org_stripe_id = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_stripe_id, &org.id],
        ).unwrap();

        let project_ls_id = create_config(&conn, &org.id, "ProjectLS", ServiceProvider::LemonSqueezy, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_ls_id, &project.id],
        ).unwrap();

        // Reload
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();

        // Should find LemonSqueezy at project level when asking for LS
        let ls_result = queries::get_effective_ls_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        assert!(ls_result.is_some(), "Should find LemonSqueezy config");
        let (_, source) = ls_result.unwrap();
        assert_eq!(source, ConfigSource::Project);

        // Should NOT find Stripe because project's config is LS (not Stripe)
        // The lookup checks the config's actual provider, not just presence
        let stripe_result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        // Project has LS, so Stripe should fall through to org
        assert!(stripe_result.is_some(), "Should find Stripe config at org level");
        let (_, source) = stripe_result.unwrap();
        assert_eq!(source, ConfigSource::Org, "Stripe should come from org since project is LS");
    }

    #[test]
    fn test_lemonsqueezy_three_level_inheritance() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Create LS configs at all three levels
        let org_config_id = create_config(&conn, &org.id, "OrgLS", ServiceProvider::LemonSqueezy, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        let project_config_id = create_config(&conn, &org.id, "ProjectLS", ServiceProvider::LemonSqueezy, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_config_id, &project.id],
        ).unwrap();

        let product_config_id = create_config(&conn, &org.id, "ProductLS", ServiceProvider::LemonSqueezy, &master_key);
        conn.execute(
            "UPDATE products SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&product_config_id, &product.id],
        ).unwrap();

        // Reload entities
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();
        let product = queries::get_product_by_id(&conn, &product.id).unwrap().unwrap();

        // Verify effective config comes from product
        let result = queries::get_effective_ls_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find LS config at product level");
        let (config, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Product, "LemonSqueezy config should come from product");
        assert!(config.api_key.contains("ProductLS"), "Should use product LS config");
    }

    #[test]
    fn test_product_null_falls_through_to_project() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Set project config but not product config
        let project_config_id = create_config(&conn, &org.id, "ProjectStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_config_id, &project.id],
        ).unwrap();

        // Reload
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();
        // product.payment_config_id is already None

        let result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at project level");
        let (config, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Project, "Should fall through to project level");
        assert!(config.secret_key.contains("ProjectStripe"));
    }

    #[test]
    fn test_project_null_falls_through_to_org() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Set only org config
        let org_config_id = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        // Reload
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        // project.payment_config_id is already None
        // product.payment_config_id is already None

        let result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at org level");
        let (config, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Org, "Should fall through to org level");
        assert!(config.secret_key.contains("OrgStripe"));
    }
}

// ============ Email Config Inheritance Tests ============

mod email_config {
    use super::*;

    #[test]
    fn test_org_level_only() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Create and assign org-level Resend config
        let org_config_id = create_config(&conn, &org.id, "OrgResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE organizations SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        // Reload org
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();

        // Verify effective config comes from org
        let result = queries::get_effective_email_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at org level");
        let (api_key, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Org);
        assert!(api_key.contains("OrgResend"), "Should use org's Resend key");
    }

    #[test]
    fn test_project_overrides_org() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Create org-level config
        let org_config_id = create_config(&conn, &org.id, "OrgResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE organizations SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        // Create project-level config that overrides org
        let project_config_id = create_config(&conn, &org.id, "ProjectResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE projects SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_config_id, &project.id],
        ).unwrap();

        // Reload entities
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();

        // Verify effective config comes from project
        let result = queries::get_effective_email_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at project level");
        let (api_key, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Project, "Config should come from project, not org");
        assert!(api_key.contains("ProjectResend"), "Should use project config");
    }

    #[test]
    fn test_product_overrides_project_and_org() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Create configs at all three levels
        let org_config_id = create_config(&conn, &org.id, "OrgResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE organizations SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        let project_config_id = create_config(&conn, &org.id, "ProjectResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE projects SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_config_id, &project.id],
        ).unwrap();

        let product_config_id = create_config(&conn, &org.id, "ProductResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE products SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&product_config_id, &product.id],
        ).unwrap();

        // Reload entities
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();
        let product = queries::get_product_by_id(&conn, &product.id).unwrap().unwrap();

        // Verify effective config comes from product
        let result = queries::get_effective_email_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at product level");
        let (api_key, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Product, "Config should come from product");
        assert!(api_key.contains("ProductResend"), "Should use product config");
    }

    #[test]
    fn test_no_config_returns_none() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // No configs set at any level
        let result = queries::get_effective_email_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_none(), "Should return None when no config exists");
    }

    #[test]
    fn test_product_null_falls_through_to_project() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Set project config but not product config
        let project_config_id = create_config(&conn, &org.id, "ProjectResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE projects SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_config_id, &project.id],
        ).unwrap();

        // Reload
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();
        // product.email_config_id is already None

        let result = queries::get_effective_email_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at project level");
        let (api_key, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Project, "Should fall through to project level");
        assert!(api_key.contains("ProjectResend"));
    }

    #[test]
    fn test_project_null_falls_through_to_org() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Set only org config
        let org_config_id = create_config(&conn, &org.id, "OrgResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE organizations SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        // Reload
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        // project.email_config_id is already None
        // product.email_config_id is already None

        let result = queries::get_effective_email_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");

        assert!(result.is_some(), "Should find config at org level");
        let (api_key, source) = result.unwrap();
        assert_eq!(source, ConfigSource::Org, "Should fall through to org level");
        assert!(api_key.contains("OrgResend"));
    }
}

// ============ Cross-cutting Tests ============

mod cross_cutting {
    use super::*;

    #[test]
    fn test_multiple_projects_different_configs() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");

        // Create two projects with different payment configs
        let project1 = create_test_project(&conn, &org.id, "Project 1", &master_key);
        let project2 = create_test_project(&conn, &org.id, "Project 2", &master_key);

        let product1 = create_test_product(&conn, &project1.id, "Product 1", "pro");
        let product2 = create_test_product(&conn, &project2.id, "Product 2", "pro");

        // Project 1 uses Stripe
        let stripe_config_id = create_config(&conn, &org.id, "P1Stripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&stripe_config_id, &project1.id],
        ).unwrap();

        // Project 2 uses LemonSqueezy
        let ls_config_id = create_config(&conn, &org.id, "P2LS", ServiceProvider::LemonSqueezy, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&ls_config_id, &project2.id],
        ).unwrap();

        // Reload
        let project1 = queries::get_project_by_id(&conn, &project1.id).unwrap().unwrap();
        let project2 = queries::get_project_by_id(&conn, &project2.id).unwrap().unwrap();

        // Verify Project 1 gets Stripe
        let result1 = queries::get_effective_stripe_config(&conn, &product1, &project1, &org, &master_key)
            .expect("Query failed");
        assert!(result1.is_some());
        let (config, source) = result1.unwrap();
        assert_eq!(source, ConfigSource::Project);
        assert!(config.secret_key.contains("P1Stripe"));

        // Verify Project 2 gets LemonSqueezy
        let result2 = queries::get_effective_ls_config(&conn, &product2, &project2, &org, &master_key)
            .expect("Query failed");
        assert!(result2.is_some());
        let (_, source) = result2.unwrap();
        assert_eq!(source, ConfigSource::Project);
    }

    #[test]
    fn test_multiple_products_same_project_different_configs() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);

        // Create two products
        let product1 = create_test_product(&conn, &project.id, "Product A", "basic");
        let product2 = create_test_product(&conn, &project.id, "Product B", "premium");

        // Project has default Stripe config
        let project_stripe_id = create_config(&conn, &org.id, "ProjectStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_stripe_id, &project.id],
        ).unwrap();

        // Product 2 overrides with its own Stripe config (maybe different account)
        let product2_stripe_id = create_config(&conn, &org.id, "Product2Stripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE products SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&product2_stripe_id, &product2.id],
        ).unwrap();

        // Reload
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();
        let product2 = queries::get_product_by_id(&conn, &product2.id).unwrap().unwrap();

        // Product 1 should use project's config
        let result1 = queries::get_effective_stripe_config(&conn, &product1, &project, &org, &master_key)
            .expect("Query failed");
        assert!(result1.is_some());
        let (config, source) = result1.unwrap();
        assert_eq!(source, ConfigSource::Project);
        assert!(config.secret_key.contains("ProjectStripe"));

        // Product 2 should use its own config
        let result2 = queries::get_effective_stripe_config(&conn, &product2, &project, &org, &master_key)
            .expect("Query failed");
        assert!(result2.is_some());
        let (config, source) = result2.unwrap();
        assert_eq!(source, ConfigSource::Product);
        assert!(config.secret_key.contains("Product2Stripe"));
    }

    #[test]
    fn test_cleared_config_returns_none() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Create and assign org-level config
        let org_config_id = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_config_id, &org.id],
        ).unwrap();

        // Verify config works initially
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        assert!(result.is_some(), "Should find config initially");

        // Clear the config reference (set to NULL)
        conn.execute(
            "UPDATE organizations SET payment_config_id = NULL WHERE id = ?1",
            rusqlite::params![&org.id],
        ).unwrap();

        // Reload org
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        assert!(org.payment_config_id.is_none(), "payment_config_id should be NULL after clearing");

        // Should return None now
        let result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        assert!(result.is_none(), "Should return None after config cleared");
    }

    #[test]
    fn test_config_deletion_blocked_when_in_use() {
        let mut conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");

        // Create a config
        let config_id = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);

        // Assign it to org
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&config_id, &org.id],
        ).unwrap();

        // Try to delete - should fail because it's in use
        let result = queries::soft_delete_service_config(&mut conn, &config_id);
        assert!(result.is_err(), "Should not be able to delete config that is in use");

        // Clear the reference first
        conn.execute(
            "UPDATE organizations SET payment_config_id = NULL WHERE id = ?1",
            rusqlite::params![&org.id],
        ).unwrap();

        // Now deletion should succeed
        let result = queries::soft_delete_service_config(&mut conn, &config_id);
        assert!(result.is_ok(), "Should be able to delete config after clearing references");
    }

    #[test]
    fn test_mixed_payment_and_email_configs_independent() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Payment: Stripe at org, LS at product (skipping project)
        let org_stripe = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&org_stripe, &org.id],
        ).unwrap();

        let product_ls = create_config(&conn, &org.id, "ProductLS", ServiceProvider::LemonSqueezy, &master_key);
        conn.execute(
            "UPDATE products SET payment_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&product_ls, &product.id],
        ).unwrap();

        // Email: Resend at project only (skipping org and product)
        let project_resend = create_config(&conn, &org.id, "ProjectResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE projects SET email_config_id = ?1 WHERE id = ?2",
            rusqlite::params![&project_resend, &project.id],
        ).unwrap();

        // Reload
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();
        let product = queries::get_product_by_id(&conn, &product.id).unwrap().unwrap();

        // Payment: LS should come from product
        let ls_result = queries::get_effective_ls_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        assert!(ls_result.is_some());
        let (_, source) = ls_result.unwrap();
        assert_eq!(source, ConfigSource::Product, "LemonSqueezy should come from product");

        // Payment: Stripe should come from org (product is LS, not Stripe)
        let stripe_result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        assert!(stripe_result.is_some());
        let (_, source) = stripe_result.unwrap();
        assert_eq!(source, ConfigSource::Org, "Stripe should come from org");

        // Email: Resend should come from project
        let email_result = queries::get_effective_email_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        assert!(email_result.is_some());
        let (api_key, source) = email_result.unwrap();
        assert_eq!(source, ConfigSource::Project, "Email should come from project");
        assert!(api_key.contains("ProjectResend"));
    }

    #[test]
    fn test_all_configs_at_product_level() {
        let conn = setup_test_db();
        let master_key = test_master_key();
        let org = create_test_org(&conn, "Test Org");
        let project = create_test_project(&conn, &org.id, "Test Project", &master_key);
        let product = create_test_product(&conn, &project.id, "Test Product", "pro");

        // Set configs at all levels but verify product level wins

        // Org level
        let org_stripe = create_config(&conn, &org.id, "OrgStripe", ServiceProvider::Stripe, &master_key);
        let org_resend = create_config(&conn, &org.id, "OrgResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE organizations SET payment_config_id = ?1, email_config_id = ?2 WHERE id = ?3",
            rusqlite::params![&org_stripe, &org_resend, &org.id],
        ).unwrap();

        // Project level
        let project_stripe = create_config(&conn, &org.id, "ProjectStripe", ServiceProvider::Stripe, &master_key);
        let project_resend = create_config(&conn, &org.id, "ProjectResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE projects SET payment_config_id = ?1, email_config_id = ?2 WHERE id = ?3",
            rusqlite::params![&project_stripe, &project_resend, &project.id],
        ).unwrap();

        // Product level
        let product_stripe = create_config(&conn, &org.id, "ProductStripe", ServiceProvider::Stripe, &master_key);
        let product_resend = create_config(&conn, &org.id, "ProductResend", ServiceProvider::Resend, &master_key);
        conn.execute(
            "UPDATE products SET payment_config_id = ?1, email_config_id = ?2 WHERE id = ?3",
            rusqlite::params![&product_stripe, &product_resend, &product.id],
        ).unwrap();

        // Reload
        let org = queries::get_organization_by_id(&conn, &org.id).unwrap().unwrap();
        let project = queries::get_project_by_id(&conn, &project.id).unwrap().unwrap();
        let product = queries::get_product_by_id(&conn, &product.id).unwrap().unwrap();

        // Both payment and email should come from product
        let stripe_result = queries::get_effective_stripe_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        assert!(stripe_result.is_some());
        let (config, source) = stripe_result.unwrap();
        assert_eq!(source, ConfigSource::Product);
        assert!(config.secret_key.contains("ProductStripe"));

        let email_result = queries::get_effective_email_config(&conn, &product, &project, &org, &master_key)
            .expect("Query failed");
        assert!(email_result.is_some());
        let (api_key, source) = email_result.unwrap();
        assert_eq!(source, ConfigSource::Product);
        assert!(api_key.contains("ProductResend"));
    }
}
