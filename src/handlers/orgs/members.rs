use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::Serialize;

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, ApiKeyCreated, CreateOrgMember, OrgMember, UpdateOrgMember};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::audit_log;

#[derive(Serialize)]
pub struct OrgMemberCreated {
    pub member: OrgMember,
    pub api_key: ApiKeyCreated,
}

pub async fn create_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CreateOrgMember>,
) -> Result<Json<OrgMemberCreated>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let member = queries::create_org_member(&conn, &org_id, &input)?;

    // Create a default API key for the new member
    let (key_record, full_key) = queries::create_org_member_api_key(
        &conn,
        &member.id,
        "Default",
        None, // No expiration
    )?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "create_org_member",
        "org_member",
        &member.id,
        Some(&serde_json::json!({
            "email": input.email,
            "role": input.role,
            "external_user_id": input.external_user_id
        })),
        Some(&org_id),
        None,
        &ctx.audit_names().resource(member.name.clone()),
    )?;

    Ok(Json(OrgMemberCreated {
        member,
        api_key: ApiKeyCreated {
            id: key_record.id,
            name: key_record.name,
            key: full_key,
            prefix: key_record.prefix,
            created_at: key_record.created_at,
            expires_at: key_record.expires_at,
        },
    }))
}

pub async fn list_org_members(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<OrgMember>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (members, total) = queries::list_org_members_paginated(&conn, &org_id, limit, offset)?;
    Ok(Json(Paginated::new(members, total, limit, offset)))
}

#[derive(serde::Deserialize)]
pub struct OrgMemberPath {
    pub org_id: String,
    pub id: String,
}

pub async fn get_org_member(
    State(state): State<AppState>,
    Path(path): Path<OrgMemberPath>,
) -> Result<Json<OrgMember>> {
    let conn = state.db.get()?;
    let member = queries::get_org_member_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if member.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    Ok(Json(member))
}

pub async fn update_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<OrgMemberPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateOrgMember>,
) -> Result<Json<OrgMember>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_org_member_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if existing.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    // Prevent changing your own role
    if path.id == ctx.member.id && input.role.is_some() {
        return Err(AppError::BadRequest("Cannot change your own role".into()));
    }

    queries::update_org_member(&conn, &path.id, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "update_org_member",
        "org_member",
        &path.id,
        Some(&serde_json::json!({ "name": input.name, "role": input.role })),
        Some(&path.org_id),
        None,
        &ctx.audit_names().resource(existing.name.clone()),
    )?;

    let member = queries::get_org_member_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    Ok(Json(member))
}

pub async fn delete_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<OrgMemberPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent self-deletion
    if path.id == ctx.member.id {
        return Err(AppError::BadRequest("Cannot delete yourself".into()));
    }

    let existing = queries::get_org_member_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Member not found".into()))?;

    if existing.org_id != path.org_id {
        return Err(AppError::NotFound("Member not found".into()));
    }

    queries::delete_org_member(&conn, &path.id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "delete_org_member",
        "org_member",
        &path.id,
        Some(&serde_json::json!({ "email": existing.email })),
        Some(&path.org_id),
        None,
        &ctx.audit_names().resource(existing.name.clone()),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
