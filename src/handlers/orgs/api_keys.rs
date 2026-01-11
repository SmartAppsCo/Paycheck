use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, ApiKeyCreated, ApiKeyInfo, CreateApiKey};
use crate::pagination::Paginated;
use crate::util::audit_log;

#[derive(Deserialize)]
pub struct MemberApiKeyPath {
    pub org_id: String,
    pub member_id: String,
}

#[derive(Deserialize)]
pub struct MemberApiKeyIdPath {
    pub org_id: String,
    pub member_id: String,
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

/// Create a new API key for an org member
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<MemberApiKeyPath>,
    headers: HeaderMap,
    Json(input): Json<CreateApiKey>,
) -> Result<Json<ApiKeyCreated>> {
    // Only owner can manage other members' keys, or member can manage their own
    if path.member_id != ctx.member.id {
        ctx.require_owner()?;
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify member exists and belongs to org
    let member = queries::get_org_member_by_id(&conn, &path.member_id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if member.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    let (key_record, full_key) = queries::create_org_member_api_key(
        &conn,
        &path.member_id,
        &input.name,
        input.expires_in_days,
    )?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "create_api_key",
        "org_member_api_key",
        &key_record.id,
        Some(&serde_json::json!({
            "member_id": path.member_id,
            "name": input.name
        })),
        Some(&path.org_id),
        None,
        &ctx.audit_names().resource(key_record.name.clone()),
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

/// List API keys for an org member
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<MemberApiKeyPath>,
    Query(query): Query<ApiKeyQuery>,
) -> Result<Json<Paginated<ApiKeyInfo>>> {
    // Only owner can see other members' keys, or member can see their own
    if path.member_id != ctx.member.id {
        ctx.require_owner()?;
    }

    let conn = state.db.get()?;

    // Verify member exists and belongs to org
    let member = queries::get_org_member_by_id(&conn, &path.member_id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if member.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    let limit = query.limit();
    let offset = query.offset();
    let (keys, total) = queries::list_org_member_api_keys_paginated(
        &conn,
        &path.member_id,
        limit,
        offset,
    )?;

    let items: Vec<ApiKeyInfo> = keys.into_iter().map(ApiKeyInfo::from).collect();
    Ok(Json(Paginated::new(items, total, limit, offset)))
}

/// Revoke a specific API key
pub async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<MemberApiKeyIdPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    // Only owner can revoke other members' keys, or member can revoke their own
    if path.member_id != ctx.member.id {
        ctx.require_owner()?;
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify key exists and belongs to the right member
    let key = queries::get_org_member_api_key_by_id(&conn, &path.key_id)?
        .ok_or_else(|| AppError::NotFound("API key not found".into()))?;

    if key.org_member_id != path.member_id {
        return Err(AppError::NotFound("API key not found".into()));
    }

    // Verify member belongs to org
    let member = queries::get_org_member_by_id(&conn, &path.member_id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if member.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    queries::revoke_org_member_api_key(&conn, &path.key_id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "revoke_api_key",
        "org_member_api_key",
        &path.key_id,
        Some(&serde_json::json!({
            "member_id": path.member_id,
            "key_name": key.name
        })),
        Some(&path.org_id),
        None,
        &ctx.audit_names().resource(key.name.clone()),
    )?;

    Ok(Json(serde_json::json!({ "revoked": true })))
}
