mod api_keys;
mod audit_logs;
mod licenses;
mod members;
mod product_provider_link;
mod products;
mod project_members;
mod projects;
mod service_configs;

pub use api_keys::*;
pub use audit_logs::*;
pub use licenses::*;
pub use members::*;
pub use product_provider_link::*;
pub use products::*;
pub use project_members::*;
pub use projects::*;
pub use service_configs::*;

use axum::{
    Router, middleware,
    routing::{delete, get, patch, post, put},
};

use crate::config::RateLimitConfig;
use crate::db::AppState;
use crate::middleware::{org_member_auth, org_member_project_auth};
use crate::rate_limit;

pub fn router(state: AppState, rate_limit_config: RateLimitConfig) -> Router<AppState> {
    // Org-level routes (members management, service configs, audit logs, api keys)
    let org_routes = Router::new()
        .route("/orgs/{org_id}/members", post(create_org_member))
        .route("/orgs/{org_id}/members", get(list_org_members))
        .route("/orgs/{org_id}/members/{user_id}", get(get_org_member))
        .route("/orgs/{org_id}/members/{user_id}", put(update_org_member))
        .route(
            "/orgs/{org_id}/members/{user_id}",
            delete(delete_org_member),
        )
        .route(
            "/orgs/{org_id}/members/{user_id}/restore",
            post(restore_org_member),
        )
        // Member API keys
        .route(
            "/orgs/{org_id}/members/{user_id}/api-keys",
            post(api_keys::create_api_key),
        )
        .route(
            "/orgs/{org_id}/members/{user_id}/api-keys",
            get(api_keys::list_api_keys),
        )
        .route(
            "/orgs/{org_id}/members/{user_id}/api-keys/{key_id}",
            delete(api_keys::revoke_api_key),
        )
        .route("/orgs/{org_id}/projects", post(create_project))
        .route("/orgs/{org_id}/projects", get(list_projects))
        // Service configs (named configs pool at org level)
        .route(
            "/orgs/{org_id}/service-configs",
            post(create_service_config).get(list_service_configs),
        )
        .route(
            "/orgs/{org_id}/service-configs/{config_id}",
            get(get_service_config).put(update_service_config).delete(delete_service_config),
        )
        // Audit logs (org-scoped, any org member can view their org's logs)
        .route("/orgs/{org_id}/audit-logs", get(query_org_audit_logs))
        // Payment provider config (masked view, admin only)
        .route("/orgs/{org_id}/payment-provider", get(get_payment_config))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            org_member_auth,
        ));

    // Project-level routes
    let project_routes = Router::new()
        .route("/orgs/{org_id}/projects/{project_id}", get(get_project))
        .route("/orgs/{org_id}/projects/{project_id}", put(update_project))
        .route(
            "/orgs/{org_id}/projects/{project_id}",
            delete(delete_project),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/restore",
            post(restore_project),
        )
        // Project members
        .route(
            "/orgs/{org_id}/projects/{project_id}/members",
            post(create_project_member),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members",
            get(list_project_members),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members/{user_id}",
            get(get_project_member),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members/{user_id}",
            put(update_project_member),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/members/{user_id}",
            delete(delete_project_member),
        )
        // Products
        .route(
            "/orgs/{org_id}/projects/{project_id}/products",
            post(create_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products",
            get(list_products),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}",
            get(get_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}",
            put(update_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}",
            delete(delete_product),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/restore",
            post(restore_product),
        )
        // Product provider links
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/provider-links",
            post(create_provider_link),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/provider-links",
            get(list_provider_links),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/provider-links/{link_id}",
            get(get_provider_link_handler),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/provider-links/{link_id}",
            put(update_provider_link_handler),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/products/{product_id}/provider-links/{link_id}",
            delete(delete_provider_link_handler),
        )
        // Licenses
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses",
            get(list_licenses),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses",
            post(create_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}",
            get(get_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}",
            patch(update_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}/revoke",
            post(revoke_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}/restore",
            post(restore_license),
        )
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}/send-code",
            post(send_activation_code),
        )
        // Device management (for remote deactivation of lost devices)
        .route(
            "/orgs/{org_id}/projects/{project_id}/licenses/{license_id}/devices/{device_id}",
            delete(deactivate_device_admin),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            org_member_project_auth,
        ));

    let merged = org_routes.merge(project_routes);

    // Apply rate limiting if configured (skip if rpm is 0, useful for tests)
    if rate_limit_config.org_ops_rpm > 0 {
        merged.layer(rate_limit::org_ops_layer(rate_limit_config.org_ops_rpm))
    } else {
        merged
    }
}
