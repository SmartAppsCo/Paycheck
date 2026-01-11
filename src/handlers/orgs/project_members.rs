use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OrgMemberContext;
use crate::models::{
    ActorType, CreateProjectMember, ProjectMemberWithDetails, UpdateProjectMember,
};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::audit_log;

#[derive(serde::Deserialize)]
pub struct ProjectMemberPath {
    pub org_id: String,
    pub project_id: String,
    pub id: String,
}

pub async fn create_project_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(input): Json<CreateProjectMember>,
) -> Result<Json<ProjectMemberWithDetails>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify the org member exists and belongs to the same org
    let target_member = queries::get_org_member_by_id(&conn, &input.org_member_id)?
        .ok_or_else(|| AppError::NotFound("Org member not found".into()))?;

    if target_member.org_id != path.org_id {
        return Err(AppError::BadRequest(
            "Member does not belong to this organization".into(),
        ));
    }

    // Check if already a project member
    if queries::get_project_member(&conn, &input.org_member_id, &path.project_id)?.is_some() {
        return Err(AppError::Conflict(
            "Member is already added to this project".into(),
        ));
    }

    let project_member = queries::create_project_member(&conn, &path.project_id, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "create_project_member",
        "project_member",
        &project_member.id,
        Some(
            &serde_json::json!({ "org_member_id": input.org_member_id, "project_id": path.project_id, "role": input.role }),
        ),
        Some(&path.org_id),
        Some(&path.project_id),
        &ctx.audit_names().resource(target_member.name.clone()),
    )?;

    Ok(Json(ProjectMemberWithDetails {
        id: project_member.id,
        org_member_id: project_member.org_member_id,
        project_id: project_member.project_id,
        role: project_member.role,
        created_at: project_member.created_at,
        email: target_member.email,
        name: target_member.name,
    }))
}

pub async fn list_project_members(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<ProjectMemberWithDetails>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();
    let (members, total) =
        queries::list_project_members_paginated(&conn, &path.project_id, limit, offset)?;
    Ok(Json(Paginated::new(members, total, limit, offset)))
}

pub async fn get_project_member(
    State(state): State<AppState>,
    Path(path): Path<ProjectMemberPath>,
) -> Result<Json<ProjectMemberWithDetails>> {
    let conn = state.db.get()?;

    let member = queries::get_project_member_by_id(&conn, &path.id)?
        .ok_or_else(|| AppError::NotFound("Project member not found".into()))?;

    // Verify it belongs to the specified project
    if member.project_id != path.project_id {
        return Err(AppError::NotFound("Project member not found".into()));
    }

    Ok(Json(member))
}

pub async fn update_project_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProjectMemberPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateProjectMember>,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let updated = queries::update_project_member(&conn, &path.id, &path.project_id, &input)?;
    if !updated {
        return Err(AppError::NotFound("Project member not found".into()));
    }

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "update_project_member",
        "project_member",
        &path.id,
        Some(&serde_json::json!({ "role": input.role })),
        Some(&path.org_id),
        Some(&path.project_id),
        &ctx.audit_names(),
    )?;

    Ok(Json(serde_json::json!({ "updated": true })))
}

pub async fn delete_project_member(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProjectMemberPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let deleted = queries::delete_project_member(&conn, &path.id, &path.project_id)?;
    if !deleted {
        return Err(AppError::NotFound("Project member not found".into()));
    }

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "delete_project_member",
        "project_member",
        &path.id,
        None,
        Some(&path.org_id),
        Some(&path.project_id),
        &ctx.audit_names(),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
