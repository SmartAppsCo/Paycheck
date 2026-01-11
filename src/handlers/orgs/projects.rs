use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::jwt;
use crate::middleware::OrgMemberContext;
use crate::models::{
    ActorType, CreateProject, LemonSqueezyConfigMasked, ProjectPublic, StripeConfigMasked,
    UpdateProject,
};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::audit_log;

pub async fn create_project(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CreateProject>,
) -> Result<Json<ProjectPublic>> {
    ctx.require_admin()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Look up org for audit log
    let org = queries::get_organization_by_id(&conn, &org_id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Generate Ed25519 key pair
    let (private_key, public_key) = jwt::generate_keypair();

    let project = queries::create_project(
        &conn,
        &org_id,
        &input,
        &private_key,
        &public_key,
        &state.master_key,
    )?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "create_project",
        "project",
        &project.id,
        Some(&serde_json::json!({ "name": input.name })),
        Some(&org_id),
        Some(&project.id),
        &ctx.audit_names()
            .resource(project.name.clone())
            .org(org.name),
    )?;

    Ok(Json(project.into()))
}

pub async fn list_projects(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<ProjectPublic>>> {
    let conn = state.db.get()?;
    let limit = pagination.limit();
    let offset = pagination.offset();

    // Filter based on access
    let (projects, total) = if ctx.member.role.has_implicit_project_access() {
        queries::list_projects_for_org_paginated(&conn, &org_id, limit, offset)?
    } else {
        // For 'member' role, only show projects they're explicitly added to
        queries::list_accessible_projects_for_member_paginated(
            &conn,
            &org_id,
            &ctx.member.id,
            limit,
            offset,
        )?
    };

    let items: Vec<ProjectPublic> = projects.into_iter().map(Into::into).collect();
    Ok(Json(Paginated::new(items, total, limit, offset)))
}

pub async fn get_project(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
) -> Result<Json<ProjectPublic>> {
    let conn = state.db.get()?;
    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    if project.org_id != path.org_id {
        return Err(AppError::NotFound("Project not found".into()));
    }

    Ok(Json(project.into()))
}

pub async fn update_project(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
    Json(input): Json<UpdateProject>,
) -> Result<Json<ProjectPublic>> {
    if !ctx.can_write_project() {
        return Err(AppError::Forbidden("Insufficient permissions".into()));
    }

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Look up org and project for audit log
    let org = queries::get_organization_by_id(&conn, &path.org_id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;
    let existing = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    queries::update_project(&conn, &path.project_id, &input)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "update_project",
        "project",
        &path.project_id,
        Some(&serde_json::json!({ "name": input.name })),
        Some(&path.org_id),
        Some(&path.project_id),
        &ctx.audit_names()
            .resource(existing.name)
            .org(org.name),
    )?;

    let project = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    Ok(Json(project.into()))
}

pub async fn delete_project(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    ctx.require_admin()?;

    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Look up org and project for audit log
    let org = queries::get_organization_by_id(&conn, &path.org_id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;
    let existing = queries::get_project_by_id(&conn, &path.project_id)?
        .ok_or_else(|| AppError::NotFound("Project not found".into()))?;

    queries::delete_project(&conn, &path.project_id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::OrgMember,
        Some(&ctx.member.id),
        ctx.impersonated_by.as_deref(),
        &headers,
        "delete_project",
        "project",
        &path.project_id,
        Some(&serde_json::json!({ "name": existing.name })),
        Some(&path.org_id),
        Some(&path.project_id),
        &ctx.audit_names()
            .resource(existing.name)
            .org(org.name),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

#[derive(Debug, serde::Serialize)]
pub struct PaymentConfigResponse {
    pub org_id: String,
    pub stripe_config: Option<StripeConfigMasked>,
    pub ls_config: Option<LemonSqueezyConfigMasked>,
    pub payment_provider: Option<String>,
}

/// Get payment provider configuration for the organization (masked for security)
pub async fn get_payment_config(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgMemberContext>,
    Path(org_id): Path<String>,
) -> Result<Json<PaymentConfigResponse>> {
    // Only admins can view payment config
    ctx.require_admin()?;

    let conn = state.db.get()?;
    let org = queries::get_organization_by_id(&conn, &org_id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    let stripe_config = org
        .decrypt_stripe_config(&state.master_key)?
        .as_ref()
        .map(StripeConfigMasked::from);

    let ls_config = org
        .decrypt_ls_config(&state.master_key)?
        .as_ref()
        .map(LemonSqueezyConfigMasked::from);

    Ok(Json(PaymentConfigResponse {
        org_id,
        stripe_config,
        ls_config,
        payment_provider: org.payment_provider,
    }))
}
