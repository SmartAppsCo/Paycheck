use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::Serialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, CreateOperator, Operator, UpdateOperator};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::audit_log;

#[derive(Serialize)]
pub struct OperatorCreated {
    pub operator: Operator,
    pub api_key: String,
}

pub async fn create_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateOperator>,
) -> Result<Json<OperatorCreated>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let (operator, api_key) = queries::create_operator(&conn, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        None, // Operators don't use impersonation
        &headers,
        "create_operator",
        "operator",
        &operator.id,
        Some(&serde_json::json!({ "email": input.email, "role": input.role })),
        None,
        None,
        &ctx.audit_names().resource(operator.name.clone()),
    )?;

    Ok(Json(OperatorCreated { operator, api_key }))
}

pub async fn list_operators(
    State(state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<Operator>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (operators, total) = queries::list_operators_paginated(&conn, limit, offset)?;
    Ok(Json(Paginated::new(operators, total, limit, offset)))
}

pub async fn get_operator(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Operator>> {
    let conn = state.db.get()?;
    let operator = queries::get_operator_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;
    Ok(Json(operator))
}

pub async fn update_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateOperator>,
) -> Result<Json<Operator>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-demotion
    if id == ctx.operator.id && input.role.is_some() {
        return Err(AppError::BadRequest("Cannot change your own role".into()));
    }

    let _existing = queries::get_operator_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    queries::update_operator(&conn, &id, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        None, // Operators don't use impersonation
        &headers,
        "update_operator",
        "operator",
        &id,
        Some(&serde_json::json!({ "name": input.name, "role": input.role })),
        None,
        None,
        &ctx.audit_names().resource(input.name.clone()),
    )?;

    let operator = queries::get_operator_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    Ok(Json(operator))
}

pub async fn delete_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-deletion
    if id == ctx.operator.id {
        return Err(AppError::BadRequest("Cannot delete yourself".into()));
    }

    let existing = queries::get_operator_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    queries::delete_operator(&conn, &id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        None, // Operators don't use impersonation
        &headers,
        "delete_operator",
        "operator",
        &id,
        Some(&serde_json::json!({ "email": existing.email })),
        None,
        None,
        &ctx.audit_names().resource(existing.name.clone()),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
