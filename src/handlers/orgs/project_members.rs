use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    Json,
};

use crate::db::{queries, DbPool};
use crate::error::{AppError, Result};
use crate::middleware::OrgMemberContext;
use crate::models::{ActorType, CreateProjectMember, ProjectMemberWithDetails, UpdateProjectMember};

fn extract_request_info(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    (ip, user_agent)
}

#[derive(serde::Deserialize)]
pub struct ProjectMemberPath {
    pub org_id: String,
    pub project_id: String,
    pub id: String,
}

pub async fn create_project_member(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(input): Json<CreateProjectMember>,
) -> Result<Json<ProjectMemberWithDetails>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = pool.get()?;

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

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &conn,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "create_project_member",
        "project_member",
        &project_member.id,
        Some(&serde_json::json!({
            "org_member_id": input.org_member_id,
            "project_id": path.project_id,
            "role": input.role,
        })),
        ip.as_deref(),
        ua.as_deref(),
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
    State(pool): State<DbPool>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
) -> Result<Json<Vec<ProjectMemberWithDetails>>> {
    let conn = pool.get()?;
    let members = queries::list_project_members(&conn, &path.project_id)?;
    Ok(Json(members))
}

pub async fn update_project_member(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProjectMemberPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateProjectMember>,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = pool.get()?;

    queries::update_project_member(&conn, &path.id, &input)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &conn,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "update_project_member",
        "project_member",
        &path.id,
        Some(&serde_json::json!({
            "role": input.role,
        })),
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "updated": true })))
}

pub async fn delete_project_member(
    State(pool): State<DbPool>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<ProjectMemberPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = pool.get()?;

    queries::delete_project_member(&conn, &path.id)?;

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &conn,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        "delete_project_member",
        "project_member",
        &path.id,
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
