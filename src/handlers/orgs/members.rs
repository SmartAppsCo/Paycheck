use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::{AppState, queries};
use crate::error::{AppError, OptionExt, Result, msg};
use crate::extractors::{Json, Path, RestoreRequest};
use crate::middleware::OrgMemberContext;
use crate::models::{
    ActorType, AuditAction, CreateOrgMember, OrgMemberWithUser, UpdateOrgMember,
};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::AuditLogBuilder;

/// Create an org member (link a user to an org with a role).
/// The user must already exist in the users table.
/// No API key is created - use Console or create one separately.
pub async fn create_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CreateOrgMember>,
) -> Result<Json<OrgMemberWithUser>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify the user exists
    let user = queries::get_user_by_id(&conn, &input.user_id)?
        .ok_or_else(|| AppError::BadRequest(msg::USER_NOT_FOUND.into()))?;

    let member = queries::create_org_member(&conn, &org_id, &input)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::CreateOrgMember)
        .resource("org_member", &member.id)
        .details(&serde_json::json!({
            "user_id": input.user_id,
            "email": user.email,
            "role": input.role,
            "impersonator": ctx.impersonator_json()
        }))
        .org(&org_id)
        .names(&ctx.audit_names().resource_user(&user.name, &user.email))
        .auth_method(&ctx.auth_method)
        .save()?;

    // Return enriched member with user details
    let member_with_user =
        queries::get_org_member_with_user_by_user_and_org(&conn, &input.user_id, &org_id)?
            .ok_or_else(|| AppError::Internal("Failed to fetch created member".into()))?;

    Ok(Json(member_with_user))
}

/// List org members with user details
pub async fn list_org_members(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<OrgMemberWithUser>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (members, total) =
        queries::list_org_members_with_user_paginated(&conn, &org_id, limit, offset)?;
    Ok(Json(Paginated::new(members, total, limit, offset)))
}

#[derive(serde::Deserialize)]
pub struct OrgMemberPath {
    pub org_id: String,
    pub user_id: String,
}

/// Get an org member with user details by user_id
pub async fn get_org_member(
    State(state): State<AppState>,
    Path(path): Path<OrgMemberPath>,
) -> Result<Json<OrgMemberWithUser>> {
    let conn = state.db.get()?;
    let member =
        queries::get_org_member_with_user_by_user_and_org(&conn, &path.user_id, &path.org_id)?
            .or_not_found(msg::NOT_ORG_MEMBER)?;

    Ok(Json(member))
}

pub async fn update_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<OrgMemberPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateOrgMember>,
) -> Result<Json<OrgMemberWithUser>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Prevent changing your own role
    if path.user_id == ctx.member.user_id && input.role.is_some() {
        return Err(AppError::BadRequest(msg::CANNOT_CHANGE_OWN_ROLE.into()));
    }

    let mut member =
        queries::get_org_member_with_user_by_user_and_org(&conn, &path.user_id, &path.org_id)?
            .or_not_found(msg::NOT_ORG_MEMBER)?;

    let updated = queries::update_org_member(&conn, &member.id, &input)?
        .or_not_found(msg::NOT_ORG_MEMBER)?;

    // Apply known changes to avoid re-fetching
    member.role = updated.role;
    member.updated_at = updated.updated_at;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::UpdateOrgMember)
        .resource("org_member", &member.id)
        .details(&serde_json::json!({
            "role": input.role,
            "impersonator": ctx.impersonator_json()
        }))
        .org(&path.org_id)
        .names(
            &ctx.audit_names()
                .resource_user(&member.name, &member.email),
        )
        .auth_method(&ctx.auth_method)
        .save()?;

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
    if path.user_id == ctx.member.user_id {
        return Err(AppError::BadRequest(msg::CANNOT_DELETE_SELF.into()));
    }

    let existing =
        queries::get_org_member_with_user_by_user_and_org(&conn, &path.user_id, &path.org_id)?
            .or_not_found(msg::NOT_ORG_MEMBER)?;

    queries::soft_delete_org_member(&conn, &existing.id)?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::DeleteOrgMember)
        .resource("org_member", &existing.id)
        .details(&serde_json::json!({
            "user_id": path.user_id,
            "email": existing.email,
            "impersonator": ctx.impersonator_json()
        }))
        .org(&path.org_id)
        .names(
            &ctx.audit_names()
                .resource_user(&existing.name, &existing.email),
        )
        .auth_method(&ctx.auth_method)
        .save()?;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Restore a soft-deleted org member
pub async fn restore_org_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<OrgMemberPath>,
    headers: HeaderMap,
    Json(input): Json<RestoreRequest>,
) -> Result<Json<OrgMemberWithUser>> {
    ctx.require_owner()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing =
        queries::get_deleted_org_member_by_user_and_org(&conn, &path.user_id, &path.org_id)?
            .or_not_found(msg::DELETED_MEMBER_NOT_FOUND)?;

    queries::restore_org_member(&conn, &existing.id, input.force)?;

    // Get user info for audit log
    let user = queries::get_user_by_id(&conn, &path.user_id)?
        .ok_or_else(|| AppError::Internal(msg::USER_NOT_FOUND.into()))?;

    AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, &headers)
        .actor(ActorType::User, Some(&ctx.member.user_id))
        .action(AuditAction::RestoreOrgMember)
        .resource("org_member", &existing.id)
        .details(&serde_json::json!({
            "user_id": path.user_id,
            "force": input.force,
            "impersonator": ctx.impersonator_json()
        }))
        .org(&path.org_id)
        .names(&ctx.audit_names().resource_user(&user.name, &user.email))
        .auth_method(&ctx.auth_method)
        .save()?;

    let member =
        queries::get_org_member_with_user_by_user_and_org(&conn, &path.user_id, &path.org_id)?
            .ok_or_else(|| AppError::Internal(msg::MEMBER_NOT_FOUND_AFTER_RESTORE.into()))?;

    Ok(Json(member))
}
