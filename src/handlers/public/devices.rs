use axum::{extract::State, http::HeaderMap};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use serde::Serialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::Json;
use crate::jwt;
use crate::models::{ActorType, AuditAction, AuditLogNames};
use crate::util::AuditLogBuilder;

#[derive(Debug, Serialize)]
pub struct DeactivateResponse {
    pub deactivated: bool,
    pub remaining_devices: i32,
}

/// POST /devices/deactivate - Self-deactivation
/// Requires JWT in Authorization header - device can only deactivate itself
/// For remote deactivation of lost devices, use the org admin API
pub async fn deactivate_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<DeactivateResponse>> {
    let conn = state.db.get()?;
    let token = auth.token();

    // First, decode the token without verification to get the product_id
    // We need this to look up the project and its public key
    let unverified_claims = jwt::decode_unverified(token)?;

    // Look up the product to get the project
    let product = queries::get_product_by_id(&conn, &unverified_claims.product_id)?
        .ok_or_else(|| AppError::BadRequest(msg::INVALID_TOKEN_PRODUCT.into()))?;

    // Get the project to get the public key
    let project = queries::get_project_by_id(&conn, &product.project_id)?
        .ok_or_else(|| AppError::Internal(msg::PROJECT_NOT_FOUND.into()))?;

    // Get org for audit logging
    let org = queries::get_organization_by_id(&conn, &project.org_id)?
        .ok_or_else(|| AppError::Internal(msg::ORG_NOT_FOUND.into()))?;

    // Now verify the JWT signature with the project's public key
    // Also validates issuer ("paycheck")
    let verified_claims = jwt::verify_token(token, &project.public_key)?;

    // Extract JTI from verified claims
    let jti = verified_claims
        .jwt_id
        .ok_or_else(|| AppError::BadRequest(msg::INVALID_TOKEN_MISSING_JTI.into()))?;

    // Look up the device by JTI
    let device = queries::get_device_by_jti(&conn, &jti)?
        .or_not_found(msg::DEVICE_NOT_FOUND_OR_DEACTIVATED)?;
    let device_id = device.id.clone();
    let device_name = device.name.clone();

    // Get the license to add revoked JTI
    let license = queries::get_license_by_id(&conn, &device.license_id)?
        .ok_or_else(|| AppError::Internal(msg::LICENSE_NOT_FOUND.into()))?;

    // Check if this JTI is already revoked
    if queries::is_jti_revoked(&conn, &jti)? {
        return Err(AppError::Forbidden(
            "This device has already been deactivated".into(),
        ));
    }

    // Add the device's JTI to revoked list so the token can't be used anymore
    queries::add_revoked_jti(&conn, &license.id, &jti, Some("self-deactivated via API"))?;

    // Delete the device record
    queries::delete_device(&conn, &device.id)?;

    // Get remaining device count
    let remaining = queries::count_devices_for_license(&conn, &license.id)?;

    // Audit log the self-deactivation
    let audit_conn = state.audit.get()?;
    if let Err(e) = AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::Public, None)
        .action(AuditAction::DeactivateDevice)
        .resource("device", &device_id)
        .details(&serde_json::json!({
            "license_id": license.id,
            "product_id": product.id,
            "self_deactivated": true,
        }))
        .org(&org.id)
        .project(&project.id)
        .names(&AuditLogNames {
            resource_name: device_name,
            org_name: Some(org.name),
            project_name: Some(project.name),
            ..Default::default()
        })
        .save()
    {
        tracing::warn!("Failed to write device deactivation audit log: {}", e);
    }

    Ok(Json(DeactivateResponse {
        deactivated: true,
        remaining_devices: remaining,
    }))
}
