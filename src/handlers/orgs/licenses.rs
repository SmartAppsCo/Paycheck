use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Deserializer, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Path, RestoreRequest};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, AuditAction, CreateLicense, Device, LicenseWithProduct};
use crate::pagination::Paginated;
use crate::util::{AuditLogBuilder, LicenseExpirations};

#[derive(serde::Deserialize)]
pub struct LicensePath {
    pub org_id: String,
    pub project_id: String,
    pub license_id: String,
}

#[derive(serde::Deserialize)]
pub struct LicenseDevicePath {
    pub org_id: String,
    pub project_id: String,
    pub license_id: String,
    pub device_id: String,
}

#[derive(Serialize)]
pub struct LicenseWithDevices {
    #[serde(flatten)]
    pub license: LicenseWithProduct,
    pub devices: Vec<Device>,
    /// Number of devices currently counted against device_limit.
    /// If product has device_inactive_days set, only devices seen within that window count.
    pub active_device_count: i32,
    /// Total device count regardless of activity
    pub total_device_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct ListLicensesQuery {
    /// Filter licenses by customer email (for support lookups)
    pub email: Option<String>,
    /// Filter by payment provider order ID (for support lookups via receipt)
    pub payment_provider_order_id: Option<String>,
    /// Filter by developer-managed customer ID (for linking to your own user system)
    pub customer_id: Option<String>,
    /// Max results to return (default 50, max 100)
    pub limit: Option<i64>,
    /// Offset for pagination (default 0)
    pub offset: Option<i64>,
}

impl ListLicensesQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

/// GET /orgs/{org_id}/projects/{project_id}/licenses
/// List licenses for a project with pagination, optionally filtered by email, payment order ID, or customer ID.
/// When filtering, returns ALL licenses including expired/revoked (for support lookups).
pub async fn list_licenses(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    Query(query): Query<ListLicensesQuery>,
) -> Result<Json<Paginated<LicenseWithProduct>>> {
    let conn = state.db.get()?;

    let limit = query.limit();
    let offset = query.offset();

    let (licenses, total) = if let Some(email) = query.email {
        // Support lookup by email - includes expired/revoked
        let email_hash = state.email_hasher.hash(&email);
        queries::get_all_licenses_by_email_hash_for_admin_paginated(
            &conn,
            &path.project_id,
            &email_hash,
            limit,
            offset,
        )?
    } else if let Some(ref order_id) = query.payment_provider_order_id {
        // Support lookup by payment provider order ID (e.g., from receipt) - includes expired/revoked
        queries::get_licenses_by_payment_order_id_paginated(
            &conn,
            &path.project_id,
            order_id,
            limit,
            offset,
        )?
    } else if let Some(ref customer_id) = query.customer_id {
        // Lookup by developer-managed customer ID (for linking to your own user system)
        queries::get_licenses_by_customer_id_paginated(
            &conn,
            &path.project_id,
            customer_id,
            limit,
            offset,
        )?
    } else {
        // Default: list all licenses for project
        queries::list_licenses_for_project_paginated(&conn, &path.project_id, limit, offset)?
    };

    Ok(Json(Paginated::new(licenses, total, limit, offset)))
}

/// Request body for creating a license directly (for bulk/trial licenses)
#[derive(Debug, Deserialize)]
pub struct CreateLicenseBody {
    /// Product ID to create the license for
    pub product_id: String,
    /// Email address for the license (optional - enables license recovery via email)
    #[serde(default)]
    pub email: Option<String>,
    /// Developer-managed customer identifier (optional)
    /// Use this to link licenses to your own user/account system
    #[serde(default)]
    pub customer_id: Option<String>,
    /// Override license expiration (days from now, null for perpetual)
    /// If not specified, uses product's license_exp_days
    #[serde(default)]
    pub license_exp_days: Option<Option<i32>>,
    /// Override updates expiration (days from now)
    /// If not specified, uses product's updates_exp_days
    #[serde(default)]
    pub updates_exp_days: Option<Option<i32>>,
    /// Number of licenses to create (default: 1, max: 100)
    #[serde(default = "default_count")]
    pub count: i32,
}

fn default_count() -> i32 {
    1
}

#[derive(Debug, Serialize)]
pub struct CreateLicenseResponse {
    pub items: Vec<CreatedLicenseWithDetails>,
}

#[derive(Debug, Serialize)]
pub struct CreatedLicenseWithDetails {
    #[serde(flatten)]
    pub license: LicenseWithProduct,
    /// Activation code for immediate use (30 min TTL)
    pub activation_code: String,
    pub activation_code_expires_at: i64,
}

/// POST /orgs/{org_id}/projects/{project_id}/licenses
/// Create one or more licenses directly (for bulk/trial licenses)
/// Useful for gift cards, bulk purchases, or trial generation
pub async fn create_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(body): Json<CreateLicenseBody>,
) -> Result<Json<CreateLicenseResponse>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    // Validate count
    if body.count < 1 || body.count > 100 {
        return Err(AppError::BadRequest(
            "Count must be between 1 and 100".into(),
        ));
    }

    // Validate expiration days are non-negative (prevents creating already-expired licenses)
    if let Some(Some(days)) = body.license_exp_days
        && days < 0
    {
        return Err(AppError::BadRequest(
            "license_exp_days must be non-negative".into(),
        ));
    }
    if let Some(Some(days)) = body.updates_exp_days
        && days < 0
    {
        return Err(AppError::BadRequest(
            "updates_exp_days must be non-negative".into(),
        ));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify product exists and belongs to this project
    let product = queries::get_product_by_id(&conn, &body.product_id)?
        .or_not_found(msg::PRODUCT_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(
            "Product not found in this project".into(),
        ));
    }

    // Get project for activation code prefix
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .or_not_found(msg::PROJECT_NOT_FOUND)?;

    // Compute email hash if email provided
    let email_hash = body.email.as_ref().map(|e| state.email_hasher.hash(e));

    // Compute expirations (use override if provided, otherwise use product defaults)
    let now = chrono::Utc::now().timestamp();
    let license_exp_days = body.license_exp_days.unwrap_or(product.license_exp_days);
    let updates_exp_days = body.updates_exp_days.unwrap_or(product.updates_exp_days);
    let exps = LicenseExpirations::from_days(license_exp_days, updates_exp_days, now);

    let mut created_licenses = Vec::with_capacity(body.count as usize);

    for _ in 0..body.count {
        let license = queries::create_license(
            &conn,
            &project.id,
            &body.product_id,
            &CreateLicense {
                email_hash: email_hash.clone(),
                customer_id: body.customer_id.clone(),
                expires_at: exps.license_exp,
                updates_expires_at: exps.updates_exp,
            },
        )?;

        // Generate activation code for immediate use
        let code =
            queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)?;

        created_licenses.push(CreatedLicenseWithDetails {
            license: LicenseWithProduct {
                license,
                product_name: product.name.clone(),
            },
            activation_code: code.code,
            activation_code_expires_at: code.expires_at,
        });

        // Audit log for each license
        AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
            .actor(ActorType::User, Some(&ctx.member.user_id))
            .action(AuditAction::CreateLicense)
            .resource("license", &created_licenses.last().unwrap().license.license.id)
            .details(&serde_json::json!({
                "product_id": body.product_id,
                "expires_at": exps.license_exp,
                "has_email": email_hash.is_some(),
                "impersonator": ctx.impersonator_json()
            }))
            .org(&path.org_id)
            .project(&path.project_id)
            .names(&ctx.audit_names().project(project.name.clone()))
            .auth_method(&ctx.auth_method)
            .save()?;
    }

    tracing::info!(
        "Created {} license(s) for product {} (project: {})",
        created_licenses.len(),
        body.product_id,
        path.project_id
    );

    Ok(Json(CreateLicenseResponse {
        items: created_licenses,
    }))
}

/// Deserialize a double Option field where:
/// - Field absent in JSON → None (don't update)
/// - Field present with null → Some(None) (set to NULL in DB)
/// - Field present with value → Some(Some(value)) (set to value)
fn deserialize_optional_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value: Option<T> = Option::deserialize(deserializer)?;
    Ok(Some(value))
}

/// Request body for updating a license
#[derive(Debug, Deserialize)]
pub struct UpdateLicenseBody {
    /// New email to hash and store (fixes typo'd purchase email)
    pub email: Option<String>,
    /// Developer-managed customer identifier
    pub customer_id: Option<String>,
    /// License expiration timestamp (null = perpetual)
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub expires_at: Option<Option<i64>>,
    /// Updates expiration timestamp (null = all versions)
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    pub updates_expires_at: Option<Option<i64>>,
}

/// PUT /orgs/{org_id}/projects/{project_id}/licenses/{license_id}
/// Update a license's fields.
pub async fn update_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
    Json(body): Json<UpdateLicenseBody>,
) -> Result<Json<LicenseWithProduct>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get the license
    let mut license = queries::get_license_by_id(&conn, &path.license_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::LICENSE_NOT_FOUND.into()));
    }

    // Fetch project for audit log context
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .or_not_found(msg::PROJECT_NOT_FOUND)?;

    // Track changes for audit log
    let mut changes = serde_json::Map::new();

    // Update email hash if provided
    if let Some(ref email) = body.email {
        let new_email_hash = state.email_hasher.hash(email);
        changes.insert(
            "old_email_hash".to_string(),
            serde_json::json!(license.email_hash),
        );
        license.email_hash = Some(new_email_hash);
    }

    // Update customer_id if provided
    if let Some(ref customer_id) = body.customer_id {
        changes.insert(
            "old_customer_id".to_string(),
            serde_json::json!(license.customer_id),
        );
        license.customer_id = Some(customer_id.clone());
    }

    // Update expires_at if provided (Option<Option<i64>> to allow setting to null)
    if let Some(expires_at) = body.expires_at {
        changes.insert(
            "old_expires_at".to_string(),
            serde_json::json!(license.expires_at),
        );
        license.expires_at = expires_at;
    }

    // Update updates_expires_at if provided
    if let Some(updates_expires_at) = body.updates_expires_at {
        changes.insert(
            "old_updates_expires_at".to_string(),
            serde_json::json!(license.updates_expires_at),
        );
        license.updates_expires_at = updates_expires_at;
    }

    // Only update if there are changes
    if !changes.is_empty() {
        queries::update_license(
            &conn,
            &license.id,
            license.email_hash.as_deref(),
            license.customer_id.as_deref(),
            license.expires_at,
            license.updates_expires_at,
        )?;

        changes.insert(
            "impersonator".to_string(),
            ctx.impersonator_json().unwrap_or(serde_json::Value::Null),
        );

        AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
            .actor(ActorType::User, Some(&ctx.member.user_id))
            .action(AuditAction::UpdateLicense)
            .resource("license", &license.id)
            .details(&serde_json::Value::Object(changes))
            .org(&path.org_id)
            .project(&path.project_id)
            .names(&ctx.audit_names().project(project.name.clone()))
            .auth_method(&ctx.auth_method)
            .save()?;

        tracing::info!(
            "License updated by admin: {} (project: {})",
            license.id,
            path.project_id
        );
    }

    Ok(Json(LicenseWithProduct {
        license,
        product_name: product.name,
    }))
}

pub async fn get_license(
    State(state): State<AppState>,
    Path(path): Path<LicensePath>,
) -> Result<Json<LicenseWithDevices>> {
    let conn = state.db.get()?;

    let license = queries::get_license_by_id(&conn, &path.license_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::LICENSE_NOT_FOUND.into()));
    }

    let devices = queries::list_devices_for_license(&conn, &license.id)?;
    let total_device_count = devices.len() as i32;
    let active_device_count =
        queries::count_active_devices_for_license(&conn, &license.id, product.device_inactive_days)?;

    Ok(Json(LicenseWithDevices {
        license: LicenseWithProduct {
            license,
            product_name: product.name,
        },
        devices,
        active_device_count,
        total_device_count,
    }))
}

pub async fn revoke_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let license = queries::get_license_by_id(&conn, &path.license_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::LICENSE_NOT_FOUND.into()));
    }

    if license.revoked {
        return Err(AppError::BadRequest(msg::LICENSE_ALREADY_REVOKED.into()));
    }

    // Fetch project for audit log context
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .or_not_found(msg::PROJECT_NOT_FOUND)?;

    queries::revoke_license(&conn, &license.id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::RevokeLicense)
        .resource("license", &license.id)
        .details(&serde_json::json!({
            "impersonator": ctx.impersonator_json()
        }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().project(project.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}

#[derive(Serialize)]
pub struct SendActivationCodeResponse {
    pub code: String,
    pub expires_at: i64,
    pub message: &'static str,
}

/// POST /orgs/{org_id}/projects/{project_id}/licenses/{license_id}/send-code
/// Generate an activation code for a license (for manual distribution to customer)
pub async fn send_activation_code(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
) -> Result<Json<SendActivationCodeResponse>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let license = queries::get_license_by_id(&conn, &path.license_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::LICENSE_NOT_FOUND.into()));
    }

    if license.revoked {
        return Err(AppError::BadRequest(msg::LICENSE_REVOKED.into()));
    }

    // Get project for activation code prefix
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .or_not_found(msg::PROJECT_NOT_FOUND)?;

    // Create activation code
    let code = queries::create_activation_code(&conn, &license.id, &project.license_key_prefix)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::GenerateActivationCode)
        .resource("license", &license.id)
        .details(&serde_json::json!({
            "expires_at": code.expires_at,
            "impersonator": ctx.impersonator_json()
        }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().project(project.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(SendActivationCodeResponse {
        code: code.code,
        expires_at: code.expires_at,
        message: "Provide this code to the customer (expires in 30 minutes)",
    }))
}

#[derive(Serialize)]
pub struct DeactivateDeviceResponse {
    pub deactivated: bool,
    pub device_id: String,
    pub remaining_devices: i32,
}

/// Remote device deactivation for org admins
/// Used for lost device recovery when user contacts support
pub async fn deactivate_device_admin(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicenseDevicePath>,
    headers: HeaderMap,
) -> Result<Json<DeactivateDeviceResponse>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Get the license
    let license = queries::get_license_by_id(&conn, &path.license_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    // Verify license belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &license.product_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::LICENSE_NOT_FOUND.into()));
    }

    // Find the device
    let device = queries::get_device_for_license(&conn, &license.id, &path.device_id)?
        .or_not_found(msg::DEVICE_NOT_FOUND)?;

    // Add the device's JTI to revoked list so the token can't be used anymore
    let details = format!("admin remote deactivation by user {}", ctx.member.user_id);
    queries::add_revoked_jti(&conn, &license.id, &device.jti, Some(&details))?;

    // Delete the device record
    queries::delete_device(&conn, &device.id)?;

    // Get remaining device count
    let remaining = queries::count_devices_for_license(&conn, &license.id)?;

    // Audit log
    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::DeactivateDevice)
        .resource("device", &device.id)
        .details(&serde_json::json!({
            "license_id": license.id,
            "device_id": path.device_id,
            "device_name": device.name,
            "reason": "admin_remote_deactivation",
            "impersonator": ctx.impersonator_json()
        }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(device.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    tracing::info!(
        "Device deactivated by admin: {} on license {} (project: {})",
        path.device_id,
        license.id,
        path.project_id
    );

    Ok(Json(DeactivateDeviceResponse {
        deactivated: true,
        device_id: path.device_id,
        remaining_devices: remaining,
    }))
}

/// Restore a soft-deleted license
pub async fn restore_license(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<LicensePath>,
    headers: HeaderMap,
    Json(input): Json<RestoreRequest>,
) -> Result<Json<LicenseWithDevices>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_deleted_license_by_id(&conn, &path.license_id)?
        .or_not_found(msg::DELETED_LICENSE_NOT_FOUND)?;

    // Verify it belongs to a product in this project
    let product = queries::get_product_by_id(&conn, &existing.product_id)?
        .ok_or_else(|| AppError::NotFound(msg::DELETED_LICENSE_PRODUCT_NOT_FOUND.into()))?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::DELETED_LICENSE_NOT_FOUND.into()));
    }

    queries::restore_license(&conn, &path.license_id, input.force)?;

    // Build LicenseWithDevices response
    let license = queries::get_license_by_id(&conn, &path.license_id)?
        .ok_or_else(|| AppError::Internal(msg::LICENSE_NOT_FOUND_AFTER_RESTORE.into()))?;
    let devices = queries::list_devices_for_license(&conn, &license.id)?;
    let total_device_count = devices.len() as i32;
    let active_device_count =
        queries::count_active_devices_for_license(&conn, &license.id, product.device_inactive_days)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::RestoreLicense)
        .resource("license", &path.license_id)
        .details(&serde_json::json!({
            "product_id": existing.product_id,
            "force": input.force,
            "impersonator": ctx.impersonator_json()
        }))
        .org(&path.org_id)
        .project(&path.project_id)
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(LicenseWithDevices {
        license: LicenseWithProduct {
            license,
            product_name: product.name,
        },
        devices,
        active_device_count,
        total_device_count,
    }))
}
