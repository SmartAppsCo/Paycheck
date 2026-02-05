use axum::extract::State;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::Json;
use crate::jwt::verify_token_allow_expired;

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    /// Public key - identifies the project
    pub public_key: String,
    /// Full JWT token - verified server-side to extract JTI
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updates_exp: Option<i64>,
}

pub async fn validate_license(
    State(state): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>> {
    let conn = state.db.get()?;

    // Helper for invalid responses - no reason given to prevent information disclosure
    let invalid_response = || {
        Json(ValidateResponse {
            valid: false,
            reason: None,
            license_exp: None,
            updates_exp: None,
        })
    };

    // Look up project by public key
    let project = match queries::get_project_by_public_key(&conn, &req.public_key)? {
        Some(p) => p,
        None => return Ok(invalid_response()),
    };
    let project_id = project.id.clone();

    // Check if org is disabled
    if let Some(ref tag) = state.disable_public_api_tag {
        if let Some(org) = queries::get_organization_by_id(&conn, &project.org_id)? {
            if org.tags.contains(tag) {
                return Err(AppError::ServiceUnavailable(
                    "Organization is currently unavailable".into(),
                ));
            }
        }
    }

    // Verify the JWT signature and extract claims
    // Uses allow_expired because the JWT's `exp` is a short freshness window,
    // but the license itself might still be valid (checked below via license.expires_at)
    let claims = match verify_token_allow_expired(&req.token, &project.public_key) {
        Ok(c) => c,
        Err(_) => {
            // Invalid signature, malformed token, or wrong issuer
            return Ok(invalid_response());
        }
    };

    // Extract the JTI from the verified claims
    let jti: String = match &claims.jwt_id {
        Some(jti) => jti.clone(),
        None => return Ok(invalid_response()),
    };

    // Find the device by JTI
    let device = match queries::get_device_by_jti(&conn, &jti)? {
        Some(d) => d,
        None => return Ok(invalid_response()),
    };

    // Get the license
    let license = match queries::get_license_by_id(&conn, &device.license_id)? {
        Some(l) => l,
        None => return Ok(invalid_response()),
    };

    // Check if license is revoked
    if license.revoked {
        return Ok(invalid_response());
    }

    // Check if this specific JTI is revoked
    if queries::is_jti_revoked(&conn, &jti)? {
        return Ok(invalid_response());
    }

    // Check if license has expired
    if let Some(expires_at) = license.expires_at
        && Utc::now().timestamp() > expires_at
    {
        return Ok(invalid_response());
    }

    // Verify project matches
    if license.project_id != project_id {
        return Ok(invalid_response());
    }

    // Update last seen (only if stale)
    queries::update_device_last_seen(&conn, &device.id, device.last_seen_at)?;

    Ok(Json(ValidateResponse {
        valid: true,
        reason: None,
        license_exp: license.expires_at,
        updates_exp: license.updates_expires_at,
    }))
}
