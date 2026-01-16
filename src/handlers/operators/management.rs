use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, AuditAction, CreateOperator, UpdateOperator, User};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::AuditLogBuilder;

/// Grant operator role to a user.
/// The user must already exist in the users table.
/// No API key is created - use Console or create one separately.
pub async fn create_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateOperator>,
) -> Result<Json<User>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify the user exists and doesn't already have an operator role
    let user = queries::get_user_by_id(&conn, &input.user_id)?
        .ok_or_else(|| AppError::BadRequest(msg::USER_NOT_FOUND.into()))?;

    if user.operator_role.is_some() {
        return Err(AppError::BadRequest("User is already an operator".into()));
    }

    let updated_user = queries::grant_operator_role(&conn, &input.user_id, input.role)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::CreateOperator)
        .resource("operator", &input.user_id)
        .details(&serde_json::json!({
            "user_id": input.user_id,
            "email": user.email,
            "role": input.role
        }))
        .names(&ctx.audit_names().resource_user(&user.name, &user.email))
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(updated_user))
}

/// List operators (users with operator_role set)
pub async fn list_operators(
    State(state): State<AppState>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<User>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (operators, total) = queries::list_operators_paginated(&conn, limit, offset)?;
    Ok(Json(Paginated::new(operators, total, limit, offset)))
}

/// Get an operator by user_id
pub async fn get_operator(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<User>> {
    let conn = state.db.get()?;
    let user = queries::get_user_by_id(&conn, &user_id)?
        .or_not_found(msg::USER_NOT_FOUND)?;

    if user.operator_role.is_none() {
        return Err(AppError::NotFound(msg::NOT_OPERATOR.into()));
    }

    Ok(Json(user))
}

pub async fn update_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(input): Json<UpdateOperator>,
) -> Result<Json<User>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-demotion
    if user_id == ctx.user.id && input.role.is_some() {
        return Err(AppError::BadRequest(msg::CANNOT_CHANGE_OWN_ROLE.into()));
    }

    let existing = queries::get_user_by_id(&conn, &user_id)?
        .or_not_found(msg::USER_NOT_FOUND)?;

    if existing.operator_role.is_none() {
        return Err(AppError::NotFound(msg::NOT_OPERATOR.into()));
    }

    let updated_user = if let Some(role) = input.role {
        queries::update_operator_role(&conn, &user_id, role)?
            .ok_or_else(|| AppError::Internal(msg::USER_NOT_FOUND_AFTER_UPDATE.into()))?
    } else {
        existing.clone()
    };

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::UpdateOperator)
        .resource("operator", &user_id)
        .details(&serde_json::json!({ "role": input.role }))
        .names(
            &ctx.audit_names()
                .resource_user(&existing.name, &existing.email),
        )
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(updated_user))
}

pub async fn delete_operator(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-deletion
    if user_id == ctx.user.id {
        return Err(AppError::BadRequest(msg::CANNOT_DELETE_SELF.into()));
    }

    let existing = queries::get_user_by_id(&conn, &user_id)?
        .or_not_found(msg::USER_NOT_FOUND)?;

    if existing.operator_role.is_none() {
        return Err(AppError::NotFound(msg::NOT_OPERATOR.into()));
    }

    queries::revoke_operator_role(&conn, &user_id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.user.id))
        .action(AuditAction::DeleteOperator)
        .resource("operator", &user_id)
        .details(&serde_json::json!({
            "user_id": user_id,
            "email": existing.email
        }))
        .names(
            &ctx.audit_names()
                .resource_user(&existing.name, &existing.email),
        )
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}
