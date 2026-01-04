use axum::extract::State;
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Query};

/// Query parameters for GET /license
#[derive(Debug, Deserialize)]
pub struct LicenseQuery {
    /// Public key - identifies the project (preferred)
    #[serde(default)]
    pub public_key: Option<String>,
    /// Project ID - deprecated, use public_key instead
    #[serde(default)]
    pub project_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LicenseDeviceInfo {
    pub device_id: String,
    pub device_type: String,
    pub name: Option<String>,
    pub activated_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Serialize)]
pub struct LicenseResponse {
    pub status: LicenseStatus,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub updates_expires_at: Option<i64>,
    pub activation_count: i32,
    pub activation_limit: i32,
    pub device_count: i32,
    pub device_limit: i32,
    pub devices: Vec<LicenseDeviceInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Active,
    Expired,
    Revoked,
}

/// Resolve project ID from public_key or project_id, returning an error if neither is provided.
fn resolve_project_id(
    conn: &rusqlite::Connection,
    public_key: Option<&str>,
    project_id: Option<&str>,
) -> Result<String> {
    if let Some(public_key) = public_key {
        let project = queries::get_project_by_public_key(conn, public_key)?
            .ok_or_else(|| AppError::NotFound("Project not found".into()))?;
        Ok(project.id)
    } else if let Some(project_id) = project_id {
        Ok(project_id.to_string())
    } else {
        Err(AppError::BadRequest(
            "Either public_key or project_id is required".into(),
        ))
    }
}

/// GET /license - Get license info
/// License key is passed in Authorization header, never exposed in URL
pub async fn get_license_info(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<LicenseQuery>,
) -> Result<Json<LicenseResponse>> {
    let conn = state.db.get()?;
    let license_key = auth.token();

    // Resolve project ID from public_key or project_id
    let project_id = resolve_project_id(
        &conn,
        query.public_key.as_deref(),
        query.project_id.as_deref(),
    )?;

    // Get the license key
    let license = queries::get_license_key_by_key(&conn, license_key, &state.master_key)?
        .ok_or_else(|| AppError::NotFound("License key not found".into()))?;

    // Get the product to verify project and get limits
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::Internal("Product not found".into()))?;

    // Verify project matches
    if product.project_id != project_id {
        return Err(AppError::NotFound("License key not found".into()));
    }

    // Determine status
    let now = chrono::Utc::now().timestamp();
    let status = if license.revoked {
        LicenseStatus::Revoked
    } else if license.expires_at.map(|exp| exp < now).unwrap_or(false) {
        LicenseStatus::Expired
    } else {
        LicenseStatus::Active
    };

    // Get all devices for this license
    let devices = queries::list_devices_for_license(&conn, &license.id)?;
    let device_count = devices.len() as i32;

    let device_infos: Vec<LicenseDeviceInfo> = devices
        .into_iter()
        .map(|d| LicenseDeviceInfo {
            device_id: d.device_id,
            device_type: match d.device_type {
                crate::models::DeviceType::Uuid => "uuid".to_string(),
                crate::models::DeviceType::Machine => "machine".to_string(),
            },
            name: d.name,
            activated_at: d.activated_at,
            last_seen_at: d.last_seen_at,
        })
        .collect();

    Ok(Json(LicenseResponse {
        status,
        created_at: license.created_at,
        expires_at: license.expires_at,
        updates_expires_at: license.updates_expires_at,
        activation_count: license.activation_count,
        activation_limit: product.activation_limit,
        device_count,
        device_limit: product.device_limit,
        devices: device_infos,
    }))
}
