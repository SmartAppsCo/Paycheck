use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    Json,
};
use serde::Serialize;

use crate::db::{queries, AppState};
use crate::error::{AppError, Result};
use crate::middleware::OperatorContext;
use crate::models::{ActorType, CreateOrganization, OrgMemberRole, Organization, CreateOrgMember};

#[derive(Serialize)]
pub struct OrganizationCreated {
    pub organization: Organization,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_api_key: Option<String>,
}

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
    let owner_api_key = if let (Some(email), Some(name)) = (&input.owner_email, &input.owner_name) {
        let api_key = queries::generate_api_key();
        queries::create_org_member(
            &conn,
            &organization.id,
            &CreateOrgMember {
                email: email.clone(),
                name: name.clone(),
                role: OrgMemberRole::Owner,
            },
            &api_key,
        )?;
        Some(api_key)
    } else {
        None
    };

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        ActorType::Operator,
        Some(&ctx.operator.id),
        "create_organization",
        "organization",
        &organization.id,
        Some(&serde_json::json!({
            "name": input.name,
            "owner_email": input.owner_email,
        })),
        Some(&organization.id),
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(OrganizationCreated {
        organization,
        owner_api_key,
    }))
}

pub async fn list_organizations(State(state): State<AppState>) -> Result<Json<Vec<Organization>>> {
    let conn = state.db.get()?;
    let organizations = queries::list_organizations(&conn)?;
    Ok(Json(organizations))
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

    let (ip, ua) = extract_request_info(&headers);
    queries::create_audit_log(
        &audit_conn,
        ActorType::Operator,
        Some(&ctx.operator.id),
        "delete_organization",
        "organization",
        &id,
        Some(&serde_json::json!({
            "name": existing.name,
        })),
        Some(&id),
        None,
        ip.as_deref(),
        ua.as_deref(),
    )?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
