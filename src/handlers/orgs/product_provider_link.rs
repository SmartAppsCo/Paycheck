use axum::{
    extract::{Extension, State},
    http::HeaderMap,
};

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{
    ActorType, AuditAction, CreateProviderLink, ProductProviderLink, UpdateProviderLink,
};
use crate::util::AuditLogBuilder;

#[derive(serde::Deserialize)]
pub struct ProviderLinkPath {
    pub org_id: String,
    pub project_id: String,
    pub product_id: String,
}

#[derive(serde::Deserialize)]
pub struct ProviderLinkItemPath {
    pub org_id: String,
    pub project_id: String,
    pub product_id: String,
    pub link_id: String,
}

pub async fn create_provider_link(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProviderLinkPath>,
    headers: HeaderMap,
    Json(input): Json<CreateProviderLink>,
) -> Result<Json<ProductProviderLink>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify product exists and belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .or_not_found(msg::PRODUCT_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::PRODUCT_NOT_FOUND.into()));
    }

    // Check if link already exists for this provider
    if queries::get_provider_link(&conn, &path.product_id, &input.provider)?.is_some() {
        return Err(AppError::BadRequest(format!(
            "Provider link for '{}' already exists",
            input.provider
        )));
    }

    let link = queries::create_provider_link(&conn, &path.product_id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::CreateProviderLink)
        .resource("provider_link", &link.id)
        .details(&serde_json::json!({ "product_id": path.product_id, "provider": input.provider }))
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(product.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(link))
}

pub async fn list_provider_links(
    State(state): State<AppState>,
    Path(path): Path<ProviderLinkPath>,
) -> Result<Json<Vec<ProductProviderLink>>> {
    let conn = state.db.get()?;

    // Verify product exists and belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .or_not_found(msg::PRODUCT_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::PRODUCT_NOT_FOUND.into()));
    }

    let links = queries::get_provider_links_for_product(&conn, &path.product_id)?;
    Ok(Json(links))
}

pub async fn get_provider_link_handler(
    State(state): State<AppState>,
    Path(path): Path<ProviderLinkItemPath>,
) -> Result<Json<ProductProviderLink>> {
    let conn = state.db.get()?;

    let link = queries::get_provider_link_by_id(&conn, &path.link_id)?
        .or_not_found(msg::PROVIDER_LINK_NOT_FOUND)?;

    // Verify it belongs to the specified product
    if link.product_id != path.product_id {
        return Err(AppError::NotFound(msg::PROVIDER_LINK_NOT_FOUND.into()));
    }

    // Verify product belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .or_not_found(msg::PRODUCT_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::PRODUCT_NOT_FOUND.into()));
    }

    Ok(Json(link))
}

pub async fn update_provider_link_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProviderLinkItemPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateProviderLink>,
) -> Result<Json<ProductProviderLink>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    input.validate()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_provider_link_by_id(&conn, &path.link_id)?
        .or_not_found(msg::PROVIDER_LINK_NOT_FOUND)?;

    // Verify it belongs to the specified product
    if existing.product_id != path.product_id {
        return Err(AppError::NotFound(msg::PROVIDER_LINK_NOT_FOUND.into()));
    }

    // Verify product belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .or_not_found(msg::PRODUCT_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::PRODUCT_NOT_FOUND.into()));
    }

    queries::update_provider_link(&conn, &path.link_id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::UpdateProviderLink)
        .resource("provider_link", &path.link_id)
        .details(
            &serde_json::json!({ "product_id": path.product_id, "provider": existing.provider }),
        )
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(product.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    let link = queries::get_provider_link_by_id(&conn, &path.link_id)?
        .or_not_found(msg::PROVIDER_LINK_NOT_FOUND)?;

    Ok(Json(link))
}

pub async fn delete_provider_link_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProviderLinkItemPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden(msg::INSUFFICIENT_PERMISSIONS.into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_provider_link_by_id(&conn, &path.link_id)?
        .or_not_found(msg::PROVIDER_LINK_NOT_FOUND)?;

    // Verify it belongs to the specified product
    if existing.product_id != path.product_id {
        return Err(AppError::NotFound(msg::PROVIDER_LINK_NOT_FOUND.into()));
    }

    // Verify product belongs to this project
    let product = queries::get_product_by_id(&conn, &path.product_id)?
        .or_not_found(msg::PRODUCT_NOT_FOUND)?;

    if product.project_id != path.project_id {
        return Err(AppError::NotFound(msg::PRODUCT_NOT_FOUND.into()));
    }

    queries::delete_provider_link(&conn, &path.link_id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::DeleteProviderLink)
        .resource("provider_link", &path.link_id)
        .details(
            &serde_json::json!({ "product_id": path.product_id, "provider": existing.provider }),
        )
        .org(&path.org_id)
        .project(&path.project_id)
        .names(&ctx.audit_names().resource(product.name.clone()))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
