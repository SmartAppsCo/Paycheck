use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::{queries, AppState};
use crate::db::queries::ProductWithPaymentConfig;
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreateProduct, UpdateProduct};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::audit_log;

#[derive(serde::Deserialize)]
pub struct ProductPath {
    pub org_id: String,
    pub project_id: String,
    pub id: String,
}

pub async fn create_product(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(input): Json<CreateProduct>,
) -> Result<Json<ProductWithPaymentConfig>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let product = queries::create_product(&conn, &path.project_id, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "create_product",
        "product",
        &product.id,
        Some(&serde_json::json!({ "name": input.name, "tier": input.tier })),
        Some(&path.org_id),
        Some(&path.project_id),
        &ctx.audit_names().resource(product.name.clone()),
    )?;

    // Return with empty payment config (none configured yet)
    Ok(Json(ProductWithPaymentConfig {
        product,
        payment_config: vec![],
    }))
}

pub async fn list_products(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<ProductWithPaymentConfig>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (products, total) =
        queries::list_products_with_config_paginated(&conn, &path.project_id, limit, offset)?;
    Ok(Json(Paginated::new(products, total, limit, offset)))
}

pub async fn get_product(
    State(state): State<AppState>,
    Path(path): Path<ProductPath>,
) -> Result<Json<ProductWithPaymentConfig>> {
    let conn = state.db.get()?;
    let product = queries::get_product_with_config(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if product.product.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    Ok(Json(product))
}

pub async fn update_product(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProductPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateProduct>,
) -> Result<Json<ProductWithPaymentConfig>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_product_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if existing.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    queries::update_product(&conn, &path.id, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "update_product",
        "product",
        &path.id,
        Some(&serde_json::json!({ "name": input.name, "tier": input.tier })),
        Some(&path.org_id),
        Some(&path.project_id),
        &ctx.audit_names().resource(existing.name.clone()),
    )?;

    let product = queries::get_product_with_config(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    Ok(Json(product))
}

pub async fn delete_product(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProductPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_product_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Product not found".into()))?;

    if existing.project_id != path.project_id {
        return Err(AppError::NotFound("Product not found".into()));
    }

    queries::delete_product(&conn, &path.id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "delete_product",
        "product",
        &path.id,
        Some(&serde_json::json!({ "name": existing.name })),
        Some(&path.org_id),
        Some(&path.project_id),
        &ctx.audit_names().resource(existing.name.clone()),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
