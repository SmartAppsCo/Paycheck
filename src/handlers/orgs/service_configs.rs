//! Service configs CRUD handlers for named configs at org level.
//!
//! Service configs are a reusable pool of external service configurations (Stripe, LemonSqueezy, Resend)
//! that can be referenced from organizations, projects, and products.

use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{
    ActorType, AuditAction, LemonSqueezyConfig, LemonSqueezyConfigMasked,
    ServiceCategory, ServiceConfig, ServiceProvider, StripeConfig, StripeConfigMasked,
};
use crate::util::AuditLogBuilder;

/// Path parameters for service config routes
#[derive(Debug, Deserialize)]
pub struct ServiceConfigPath {
    pub org_id: String,
    pub config_id: String,
}

/// Query parameters for listing service configs
#[derive(Debug, Deserialize)]
pub struct ListServiceConfigsQuery {
    /// Filter by category (payment or email)
    pub category: Option<String>,
    /// Filter by provider (stripe, lemonsqueezy, resend)
    pub provider: Option<String>,
}

/// Request body for creating a service config
#[derive(Debug, Deserialize)]
pub struct CreateServiceConfigRequest {
    /// User-friendly name for this config
    pub name: String,
    /// Provider type
    pub provider: String,
    /// Stripe config (required if provider is "stripe")
    #[serde(default)]
    pub stripe_config: Option<StripeConfig>,
    /// LemonSqueezy config (required if provider is "lemonsqueezy")
    #[serde(default)]
    pub ls_config: Option<LemonSqueezyConfig>,
    /// Resend API key (required if provider is "resend")
    #[serde(default)]
    pub resend_api_key: Option<String>,
}

/// Request body for updating a service config
#[derive(Debug, Deserialize)]
pub struct UpdateServiceConfigRequest {
    /// New name (optional)
    pub name: Option<String>,
    /// Stripe config (optional, replaces existing)
    #[serde(default)]
    pub stripe_config: Option<StripeConfig>,
    /// LemonSqueezy config (optional, replaces existing)
    #[serde(default)]
    pub ls_config: Option<LemonSqueezyConfig>,
    /// Resend API key (optional, replaces existing)
    #[serde(default)]
    pub resend_api_key: Option<String>,
}

/// Public view of a service config (with masked credentials)
#[derive(Debug, Serialize)]
pub struct ServiceConfigPublic {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub category: ServiceCategory,
    pub provider: ServiceProvider,
    /// Masked config for display
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stripe_config: Option<StripeConfigMasked>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ls_config: Option<LemonSqueezyConfigMasked>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resend_api_key: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Convert a ServiceConfig to its public form with masked credentials
fn config_to_public(
    config: ServiceConfig,
    state: &AppState,
) -> Result<ServiceConfigPublic> {
    let (stripe_config, ls_config, resend_api_key) = match config.provider {
        ServiceProvider::Stripe => {
            let stripe = config.decrypt_stripe_config(&state.master_key)?;
            (Some(StripeConfigMasked::from(&stripe)), None, None)
        }
        ServiceProvider::LemonSqueezy => {
            let ls = config.decrypt_ls_config(&state.master_key)?;
            (None, Some(LemonSqueezyConfigMasked::from(&ls)), None)
        }
        ServiceProvider::Resend => {
            // Mask the API key (show first 8 and last 4 chars)
            let api_key = config.decrypt_resend_api_key(&state.master_key)?;
            let masked = if api_key.len() <= 12 {
                "*".repeat(api_key.len().min(8))
            } else {
                format!("{}...{}", &api_key[..8], &api_key[api_key.len() - 4..])
            };
            (None, None, Some(masked))
        }
    };

    Ok(ServiceConfigPublic {
        id: config.id,
        org_id: config.org_id,
        name: config.name,
        category: config.category,
        provider: config.provider,
        stripe_config,
        ls_config,
        resend_api_key,
        created_at: config.created_at,
        updated_at: config.updated_at,
    })
}

pub async fn create_service_config(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(input): Json<CreateServiceConfigRequest>,
) -> Result<Json<ServiceConfigPublic>> {
    ctx.require_admin()?;

    // Validate name
    if input.name.trim().is_empty() {
        return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
    }

    // Parse provider
    let provider: ServiceProvider = input.provider.parse()
        .map_err(|_| AppError::BadRequest(msg::INVALID_PROVIDER.into()))?;

    // Get the config payload based on provider
    let encrypted = match provider {
        ServiceProvider::Stripe => {
            let config = input.stripe_config
                .ok_or_else(|| AppError::BadRequest("stripe_config is required for stripe provider".into()))?;
            let json = serde_json::to_string(&config)?;
            state.master_key.encrypt_private_key(&org_id, json.as_bytes())?
        }
        ServiceProvider::LemonSqueezy => {
            let config = input.ls_config
                .ok_or_else(|| AppError::BadRequest("ls_config is required for lemonsqueezy provider".into()))?;
            let json = serde_json::to_string(&config)?;
            state.master_key.encrypt_private_key(&org_id, json.as_bytes())?
        }
        ServiceProvider::Resend => {
            let api_key = input.resend_api_key
                .ok_or_else(|| AppError::BadRequest("resend_api_key is required for resend provider".into()))?;
            state.master_key.encrypt_private_key(&org_id, api_key.as_bytes())?
        }
    };

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let config = queries::create_service_config(&conn, &org_id, &input.name, provider, &encrypted)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::CreateServiceConfig)
        .resource("service_config", &config.id)
        .org(&org_id)
        .details(&serde_json::json!({
            "name": input.name,
            "provider": provider.as_str(),
            "impersonator": ctx.impersonator_json()
        }))
        .names(&ctx.audit_names().resource(input.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(config_to_public(config, &state)?))
}

pub async fn list_service_configs(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(query): Query<ListServiceConfigsQuery>,
) -> Result<Json<Vec<ServiceConfigPublic>>> {
    let conn = state.db.get()?;

    let configs = if let Some(ref category_str) = query.category {
        let category: ServiceCategory = category_str.parse()
            .map_err(|_| AppError::BadRequest("Invalid category".into()))?;
        queries::list_service_configs_for_org_by_category(&conn, &org_id, category)?
    } else if let Some(ref provider_str) = query.provider {
        let provider: ServiceProvider = provider_str.parse()
            .map_err(|_| AppError::BadRequest(msg::INVALID_PROVIDER.into()))?;
        queries::list_service_configs_for_org_by_provider(&conn, &org_id, provider)?
    } else {
        queries::list_service_configs_for_org(&conn, &org_id)?
    };

    let public_configs: Result<Vec<_>> = configs
        .into_iter()
        .map(|c| config_to_public(c, &state))
        .collect();

    Ok(Json(public_configs?))
}

pub async fn get_service_config(
    State(state): State<AppState>,
    Path(path): Path<ServiceConfigPath>,
) -> Result<Json<ServiceConfigPublic>> {
    let conn = state.db.get()?;

    let config = queries::get_service_config_by_id(&conn, &path.config_id)?
        .or_not_found("Service config not found")?;

    // Verify config belongs to this org
    if config.org_id != path.org_id {
        return Err(AppError::NotFound("Service config not found".into()));
    }

    Ok(Json(config_to_public(config, &state)?))
}

pub async fn update_service_config(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    headers: HeaderMap,
    Path(path): Path<ServiceConfigPath>,
    Json(input): Json<UpdateServiceConfigRequest>,
) -> Result<Json<ServiceConfigPublic>> {
    ctx.require_admin()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get existing config
    let existing = queries::get_service_config_by_id(&conn, &path.config_id)?
        .or_not_found("Service config not found")?;

    // Verify config belongs to this org
    if existing.org_id != path.org_id {
        return Err(AppError::NotFound("Service config not found".into()));
    }

    // Validate name if provided
    if let Some(ref name) = input.name {
        if name.trim().is_empty() {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
    }

    // Encrypt new config if provided
    let encrypted = match existing.provider {
        ServiceProvider::Stripe => {
            input.stripe_config.as_ref().map(|config| {
                let json = serde_json::to_string(config)?;
                state.master_key.encrypt_private_key(&path.org_id, json.as_bytes())
            }).transpose()?
        }
        ServiceProvider::LemonSqueezy => {
            input.ls_config.as_ref().map(|config| {
                let json = serde_json::to_string(config)?;
                state.master_key.encrypt_private_key(&path.org_id, json.as_bytes())
            }).transpose()?
        }
        ServiceProvider::Resend => {
            input.resend_api_key.as_ref().map(|api_key| {
                state.master_key.encrypt_private_key(&path.org_id, api_key.as_bytes())
            }).transpose()?
        }
    };

    let config = queries::update_service_config(
        &conn,
        &path.config_id,
        input.name.as_deref(),
        encrypted.as_deref(),
    )?.or_not_found("Service config not found")?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::UpdateServiceConfig)
        .resource("service_config", &config.id)
        .org(&path.org_id)
        .details(&serde_json::json!({
            "old_name": existing.name,
            "new_name": input.name,
            "config_updated": encrypted.is_some(),
            "impersonator": ctx.impersonator_json()
        }))
        .names(&ctx.audit_names().resource(config.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(config_to_public(config, &state)?))
}

pub async fn delete_service_config(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    headers: HeaderMap,
    Path(path): Path<ServiceConfigPath>,
) -> Result<Json<serde_json::Value>> {
    ctx.require_admin()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get existing config
    let existing = queries::get_service_config_by_id(&conn, &path.config_id)?
        .or_not_found("Service config not found")?;

    // Verify config belongs to this org
    if existing.org_id != path.org_id {
        return Err(AppError::NotFound("Service config not found".into()));
    }

    // Soft delete (will fail if still in use)
    queries::soft_delete_service_config(&conn, &path.config_id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::DeleteServiceConfig)
        .resource("service_config", &path.config_id)
        .org(&path.org_id)
        .details(&serde_json::json!({
            "name": existing.name,
            "provider": existing.provider.as_str(),
            "impersonator": ctx.impersonator_json()
        }))
        .names(&ctx.audit_names().resource(existing.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
