use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    Json,
};
use serde::Serialize;

use crate::db::{queries, DbPool};
use crate::error::{AppError, Result};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, Device, LicenseKeyWithProduct};

fn extract_request_info(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    (ip, user_agent)
}

#[derive(serde::Deserialize)]
pub struct LicensePath {
    pub org_id: String,
    pub project_id: String,
    pub key: String,
}

#[derive(Serialize)]
pub struct LicenseWithDevices {
    #[serde(flatten)]
    pub license: LicenseKeyWithProduct,
    pub devices: Vec<Device>,
}

pub async fn list_licenses(
    State(pool): State<DbPool>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
) -> Result<Json<Vec<LicenseKeyWithProduct>>> {
    let conn = pool.get()?;
    let licenses = queries::list_license_keys_for_project(&conn, &path.project_id)?;
    Ok(Json(licenses))
}

pub async fn get_license(
    State(pool): State<DbPool>,
    Path(path): Path<LicensePath>,
) -> Result<Json<LicenseWithDevices>> {
    let conn = pool.get()?;

    let license = queries::get_license_key_by_key(&conn, &path.key)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("License not found".into()));
    }

    let devices = queries::list_devices_for_license(&conn, &license.id)?;

    Ok(Json(LicenseWithDevices {
        license: LicenseKeyWithProduct {
            license,
            product_name: product.name,
            project_id: product.project_id,
        },
        devices,
    }))
}

pub async fn revoke_license(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = pool.get()?;

    let license = queries::get_license_key_by_key(&conn, &path.key)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .ok_or_else(|| AppError::NotFound("License not found".into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound("License not found".into()));
    }

    if license.revoked {
        return Err(AppError::BadRequest("License is already revoked".into()));
    }

    queries::revoke_license_key(&conn, &license.id)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &conn,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "revoke_license",
        "license_key",
        &license.id,
        Some(&serde_json::json!({
            "key": license.key,
            "email": license.email,
        })),
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "revoked": true })))
}
