//! Operator support endpoints for debugging customer issues.

use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Path};
use crate::models::{LemonSqueezyConfig, LicenseWithProduct, ServiceCategory, StripeConfig};

/// A single payment config entry with full (unmasked) credentials
#[derive(Debug, Serialize)]
pub struct FullPaymentConfigEntry {
    pub config_id: String,
    pub name: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stripe_config: Option<StripeConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ls_config: Option<LemonSqueezyConfig>,
}

#[derive(Debug, Serialize)]
pub struct FullPaymentConfigResponse {
    pub org_id: String,
    pub org_name: String,
    /// All payment configs for this organization (full credentials, not masked)
    pub configs: Vec<FullPaymentConfigEntry>,
}

/// Get full (unmasked) payment provider configurations for an organization.
/// This is for operator support staff to debug customer payment issues.
/// Returns ALL named payment configs (there can be multiple per org now).
pub async fn get_org_payment_config(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
) -> Result<Json<FullPaymentConfigResponse>> {
    let conn = state.db.get()?;

    let org = queries::get_organization_by_id(&conn, &org_id)?.or_not_found(msg::ORG_NOT_FOUND)?;

    // Get all payment-category configs for this org
    let payment_configs = queries::list_service_configs_for_org_by_category(&conn, &org_id, ServiceCategory::Payment)?;

    let mut configs = Vec::with_capacity(payment_configs.len());
    for config in payment_configs {
        let (stripe_config, ls_config) = match config.provider.as_str() {
            "stripe" => {
                let stripe = config.decrypt_stripe_config(&state.master_key)?;
                (Some(stripe), None)
            }
            "lemonsqueezy" => {
                let ls = config.decrypt_ls_config(&state.master_key)?;
                (None, Some(ls))
            }
            _ => (None, None),
        };
        configs.push(FullPaymentConfigEntry {
            config_id: config.id,
            name: config.name,
            provider: config.provider.as_str().to_string(),
            stripe_config,
            ls_config,
        });
    }

    tracing::info!(
        "OPERATOR: Retrieved {} payment configs for organization {} ({})",
        configs.len(),
        org.name,
        org_id
    );

    Ok(Json(FullPaymentConfigResponse {
        org_id,
        org_name: org.name,
        configs,
    }))
}

#[derive(Debug, Deserialize)]
pub struct LicenseLookupPath {
    pub org_id: String,
    pub project_id: String,
}

#[derive(Debug, Deserialize)]
pub struct LicenseLookupQuery {
    /// Customer email to look up
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LicenseLookupResponse {
    pub org_id: String,
    pub org_name: String,
    pub project_id: String,
    pub project_name: String,
    pub licenses: Vec<LicenseWithProduct>,
}

/// GET /operators/organizations/{org_id}/projects/{project_id}/licenses/lookup?email=...
/// Look up all licenses for a customer by email (for super admin support).
/// Returns ALL licenses including expired and revoked.
pub async fn lookup_licenses_by_email(
    State(state): State<AppState>,
    Path(path): Path<LicenseLookupPath>,
    Query(query): Query<LicenseLookupQuery>,
) -> Result<Json<LicenseLookupResponse>> {
    let conn = state.db.get()?;

    // Verify org exists
    let org =
        queries::get_organization_by_id(&conn, &path.org_id)?.or_not_found(msg::ORG_NOT_FOUND)?;

    // Verify project exists and belongs to org
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .or_not_found(msg::PROJECT_NOT_FOUND)?;

    if project.org_id != path.org_id {
        return Err(AppError::NotFound(
            "Project not found in this organization".into(),
        ));
    }

    // Look up all licenses by email hash (use high limit since filtered by email)
    let email_hash = state.email_hasher.hash(&query.email);
    let (licenses, _total) = queries::get_all_licenses_by_email_hash_for_admin_paginated(
        &conn,
        &path.project_id,
        &email_hash,
        100, // Max 100 licenses per email lookup
        0,
    )?;

    tracing::info!(
        "OPERATOR: License lookup by email for org {} project {} ({} results)",
        org.name,
        project.name,
        licenses.len()
    );

    Ok(Json(LicenseLookupResponse {
        org_id: path.org_id,
        org_name: org.name,
        project_id: path.project_id,
        project_name: project.name,
        licenses,
    }))
}
