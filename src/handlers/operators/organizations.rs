use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

use crate::db::{AppState, queries};
use crate::error::{AppError, Result};
use crate::extractors::{Json, Path};
use crate::middleware::OperatorContext;
use crate::models::{
    ActorType, CreateOrgMember, CreateOrganization, OrgMember, OrgMemberRole, Organization,
    UpdateOrganization,
};
use crate::pagination::{Paginated, PaginationQuery};
use crate::util::audit_log;

#[derive(Serialize)]
pub struct OrganizationCreated {
    pub organization: Organization,
    /// Owner member (if owner_email provided). No API key - use Console or create one later.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<OrgMember>,
}

pub async fn create_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Json(input): Json<CreateOrganization>,
) -> Result<Json<OrganizationCreated>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;
    let organization = queries::create_organization(&conn, &input)?;

    // If owner email is provided, create the first org member as owner
    // No API key is created - owner uses Console (impersonation) or creates a key later
    let owner = if let (Some(email), Some(name)) = (&input.owner_email, &input.owner_name) {
        let member = queries::create_org_member(
            &conn,
            &organization.id,
            &CreateOrgMember {
                email: email.clone(),
                name: name.clone(),
                role: OrgMemberRole::Owner,
                external_user_id: input.external_user_id.clone(),
            },
            "", // Deprecated parameter
        )?;
        Some(member)
    } else {
        None
    };

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        None, // Operators don't use impersonation
        &headers,
        "create_organization",
        "organization",
        &organization.id,
        Some(&serde_json::json!({
            "name": input.name,
            "owner_email": input.owner_email,
            "external_user_id": input.external_user_id
        })),
        None, // No org context - the org IS the resource
        None,
        &ctx.audit_names().resource(organization.name.clone()),
    )?;

    Ok(Json(OrganizationCreated { organization, owner }))
}

/// Query parameters for listing organizations
#[derive(Deserialize)]
pub struct ListOrgsQuery {
    /// Filter by external user ID (returns orgs where user is a member)
    pub external_user_id: Option<String>,
    /// Pagination: max items to return (default: 50, max: 100)
    pub limit: Option<i64>,
    /// Pagination: items to skip (default: 0)
    pub offset: Option<i64>,
}

impl ListOrgsQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

pub async fn list_organizations(
    State(state): State<AppState>,
    Query(query): Query<ListOrgsQuery>,
) -> Result<Json<Paginated<Organization>>> {
    let conn = state.db.get()?;
    let limit = query.limit();
    let offset = query.offset();

    let (organizations, total) = if let Some(external_user_id) = &query.external_user_id {
        // Filter by external user ID - returns orgs where user is a member
        queries::list_orgs_by_external_user_id_paginated(&conn, external_user_id, limit, offset)?
    } else {
        queries::list_organizations_paginated(&conn, limit, offset)?
    };

    Ok(Json(Paginated::new(organizations, total, limit, offset)))
}

pub async fn get_organization(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Organization>> {
    let conn = state.db.get()?;
    let organization = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;
    Ok(Json(organization))
}

pub async fn update_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateOrganization>,
) -> Result<Json<Organization>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    // Verify organization exists
    let existing = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    queries::update_organization(&conn, &id, &input, &state.master_key)?;

    // Fetch updated organization
    let organization = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::Internal("Organization not found after update".into()))?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        None, // Operators don't use impersonation
        &headers,
        "update_organization",
        "organization",
        &id,
        Some(
            &serde_json::json!({ "old_name": existing.name, "new_name": input.name, "stripe_updated": input.stripe_config.is_some(), "ls_updated": input.ls_config.is_some() }),
        ),
        None, // No org context - the org IS the resource
        None,
        &ctx.audit_names().resource(organization.name.clone()),
    )?;

    Ok(Json(organization))
}

pub async fn delete_organization(
    State(state): State<AppState>,
    Extension(ctx): Extension<OperatorContext>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let conn = state.db.get()?;
    let audit_conn = state.audit.get()?;

    let existing = queries::get_organization_by_id(&conn, &id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    queries::delete_organization(&conn, &id)?;

    audit_log(
        &audit_conn,
        state.audit_log_enabled,
        ActorType::Operator,
        Some(&ctx.operator.id),
        None, // Operators don't use impersonation
        &headers,
        "delete_organization",
        "organization",
        &id,
        Some(&serde_json::json!({ "name": existing.name })),
        None, // No org context - the org IS the resource
        None,
        &ctx.audit_names().resource(existing.name.clone()),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// List members of an organization (operator endpoint - no impersonation needed)
pub async fn list_org_members(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Paginated<OrgMember>>> {
    let conn = state.db.get()?;

    // Verify organization exists
    queries::get_organization_by_id(&conn, &org_id)?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    let limit = pagination.limit();
    let offset = pagination.offset();
    let (members, total) = queries::list_org_members_paginated(&conn, &org_id, limit, offset)?;
    Ok(Json(Paginated::new(members, total, limit, offset)))
}
