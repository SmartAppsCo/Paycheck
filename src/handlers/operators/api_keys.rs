use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, ApiKeyCreated, ApiKeyInfo, CreateApiKey};
use crate::pagination::Paginated;
use crate::util::audit_log;

#[derive(Deserialize)]
pub struct OperatorApiKeyPath {
    pub operator_id: String,
}

#[derive(Deserialize)]
pub struct OperatorApiKeyIdPath {
    pub operator_id: String,
    pub key_id: String,
}

#[derive(Deserialize)]
pub struct ApiKeyQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl ApiKeyQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

/// Create a new API key for an operator
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    Path(path): Path<OperatorApiKeyPath>,
    headers: HeaderMap,
    Json(input): Json<CreateApiKey>,
) -> Result<Json<ApiKeyCreated>> {
    // Only owner can manage other operators' keys, or operator can manage their own
    if path.operator_id != ctx.operator.id {
        if !ctx.operator.role.can_manage_operators() {
            return Err(AppError::Forbidden(
                "Only owners can manage other operators' API keys".into(),
            ));
        }
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify operator exists
    let operator = queries::get_operator_by_id(&conn, &path.operator_id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    let (key_record, full_key) = queries::create_operator_api_key(
        &conn,
        &path.operator_id,
        &input.name,
        input.expires_in_days,
    )?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        None, // Operators don't use impersonation
        &headers,
        "create_api_key",
        "operator_api_key",
        &key_record.id,
        Some(&serde_json::json!({
            "operator_id": path.operator_id,
            "operator_email": operator.email,
            "name": input.name
        })),
        None,
        None,
        &ctx.audit_names().resource(input.name.clone()),
    )?;

    Ok(Json(ApiKeyCreated {
        id: key_record.id,
        name: key_record.name,
        key: full_key,
        prefix: key_record.prefix,
        created_at: key_record.created_at,
        expires_at: key_record.expires_at,
    }))
}

/// List API keys for an operator
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    Path(path): Path<OperatorApiKeyPath>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Paginated<ApiKeyInfo>>> {
    // Only owner can see other operators' keys, or operator can see their own
    if path.operator_id != ctx.operator.id {
        if !ctx.operator.role.can_manage_operators() {
            return Err(AppError::Forbidden(
                "Only owners can view other operators' API keys".into(),
            ));
        }
    }

    let conn = state.db.get()?;

    // Verify operator exists
    queries::get_operator_by_id(&conn, &path.operator_id)?
        .ok_or_else(|| AppError::NotFound("Operator not found".into()))?;

    let limit = query.limit();
    let offset = query.offset();
    let (keys, total) = queries::list_operator_api_keys_paginated(
        &conn,
        &path.operator_id,
        limit,
        offset,
    )?;

    let items: Vec<ApiKeyInfo> = keys.into_iter().map(ApiKeyInfo::from).collect();
    Ok(Json(Paginated::new(items, total, limit, offset)))
}

/// Revoke a specific API key
pub async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    Path(path): Path<OperatorApiKeyIdPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    // Only owner can revoke other operators' keys, or operator can revoke their own
    if path.operator_id != ctx.operator.id {
        if !ctx.operator.role.can_manage_operators() {
            return Err(AppError::Forbidden(
                "Only owners can revoke other operators' API keys".into(),
            ));
        }
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify key exists and belongs to the right operator
    let key = queries::get_operator_api_key_by_id(&conn, &path.key_id)?
        .ok_or_else(|| AppError::NotFound("API key not found".into()))?;

    if key.operator_id != path.operator_id {
        return Err(AppError::NotFound("API key not found".into()));
    }

    queries::revoke_operator_api_key(&conn, &path.key_id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        None, // Operators don't use impersonation
        &headers,
        "revoke_api_key",
        "operator_api_key",
        &path.key_id,
        Some(&serde_json::json!({
            "operator_id": path.operator_id,
            "key_name": key.name
        })),
        None,
        None,
        &ctx.audit_names().resource(key.name.clone()),
    )?;

    Ok(Json(serde_json::json!({ "revoked": true })))
}
