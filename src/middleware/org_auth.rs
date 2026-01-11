use std::collections::HashMap;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::db::{AppState, queries};
use crate::models::{AuditLogNames, OrgMember, OrgMemberRole, OperatorRole, ProjectMemberRole};
use crate::util::extract_bearer_token;

/// Header name for operator impersonation
const ON_BEHALF_OF_HEADER: &str = "x-on-behalf-of";

#[derive(Clone)]
pub struct OrgMemberContext {
    pub member: OrgMember,
    pub project_role: Option<ProjectMemberRole>,
    /// If set, this request is being made by an operator on behalf of the member
    pub impersonated_by: Option<String>,
    /// Name of the impersonating operator (for audit logs)
    pub impersonator_name: Option<String>,
}

impl OrgMemberContext {
    pub fn require_owner(&self) -> Result<(), StatusCode> {
        if self.member.role.can_manage_members() {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }

    pub fn require_admin(&self) -> Result<(), StatusCode> {
        if matches!(
            self.member.role,
            OrgMemberRole::Owner | OrgMemberRole::Admin
        ) {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }

    pub fn can_write_project(&self) -> bool {
        matches!(
            self.member.role,
            OrgMemberRole::Owner | OrgMemberRole::Admin
        ) || matches!(self.project_role, Some(ProjectMemberRole::Admin))
    }

    /// Returns true if this request is being impersonated by an operator
    pub fn is_impersonated(&self) -> bool {
        self.impersonated_by.is_some()
    }

    /// Get audit log names pre-populated with the member's name and impersonator info.
    /// Chain with `.resource()`, `.org()`, `.project()` to add more context.
    pub fn audit_names(&self) -> AuditLogNames {
        AuditLogNames {
            actor_name: Some(self.member.name.clone()),
            impersonator_name: self.impersonator_name.clone(),
            ..Default::default()
        }
    }
}

/// Attempt to authenticate as an operator impersonating an org member.
/// Returns Some((member, operator_id, operator_name)) if impersonation is valid, None if not an impersonation attempt.
fn try_operator_impersonation(
    state: &AppState,
    api_key: &str,
    on_behalf_of: Option<&str>,
    org_id: &str,
) -> Result<Option<(OrgMember, String, Option<String>)>, StatusCode> {
    // Check if this looks like an operator key (starts with pco_)
    if !api_key.starts_with("pco_") {
        return Ok(None);
    }

    // Must have X-On-Behalf-Of header for impersonation
    let member_id = match on_behalf_of {
        Some(id) => id,
        None => return Err(StatusCode::UNAUTHORIZED), // Operator key without impersonation header
    };

    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Verify operator exists and has appropriate role
    let operator = queries::get_operator_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Only admin+ operators can impersonate
    if !matches!(operator.role, OperatorRole::Owner | OperatorRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Load the target org member
    let member = queries::get_org_member_by_id(&conn, member_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify the member belongs to the specified org
    if member.org_id != org_id {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Some((member, operator.id, Some(operator.name.clone()))))
}

pub async fn org_member_auth(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let org_id = params.get("org_id").ok_or(StatusCode::BAD_REQUEST)?;

    let api_key = extract_bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let on_behalf_of = request
        .headers()
        .get(ON_BEHALF_OF_HEADER)
        .and_then(|v| v.to_str().ok());

    // Try operator impersonation first
    if let Some((member, operator_id, operator_name)) =
        try_operator_impersonation(&state, api_key, on_behalf_of, org_id)?
    {
        request.extensions_mut().insert(OrgMemberContext {
            member,
            project_role: None,
            impersonated_by: Some(operator_id),
            impersonator_name: operator_name,
        });
        return Ok(next.run(request).await);
    }

    // Normal org member authentication
    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let member = queries::get_org_member_by_api_key(&conn, api_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if member.org_id != *org_id {
        return Err(StatusCode::FORBIDDEN);
    }

    request.extensions_mut().insert(OrgMemberContext {
        member,
        project_role: None,
        impersonated_by: None,
        impersonator_name: None,
    });

    Ok(next.run(request).await)
}

/// Path struct for handlers that need org_id and project_id.
/// Note: The middleware uses HashMap extraction to support routes with extra params.
#[derive(Clone, serde::Deserialize)]
pub struct OrgProjectPath {
    pub org_id: String,
    pub project_id: String,
}

pub async fn org_member_project_auth(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let org_id = params.get("org_id").ok_or(StatusCode::BAD_REQUEST)?;
    let project_id = params.get("project_id").ok_or(StatusCode::BAD_REQUEST)?;

    let api_key = extract_bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let on_behalf_of = request
        .headers()
        .get(ON_BEHALF_OF_HEADER)
        .and_then(|v| v.to_str().ok());

    let conn = state
        .db
        .get()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Try operator impersonation first
    let (member, impersonated_by, impersonator_name) =
        if let Some((member, operator_id, operator_name)) =
            try_operator_impersonation(&state, api_key, on_behalf_of, org_id)?
        {
            (member, Some(operator_id), operator_name)
        } else {
            // Normal org member authentication
            let member = queries::get_org_member_by_api_key(&conn, api_key)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::UNAUTHORIZED)?;

            if member.org_id != *org_id {
                return Err(StatusCode::FORBIDDEN);
            }
            (member, None, None)
        };

    // Check project exists and belongs to org
    let project = queries::get_project_by_id(&conn, project_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if project.org_id != *org_id {
        return Err(StatusCode::NOT_FOUND);
    }

    // Get project-level role if exists
    let project_role = if member.role.has_implicit_project_access() {
        None // Owner/admin have implicit access, no need for project_members entry
    } else {
        queries::get_project_member(&conn, &member.id, project_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .map(|pm| pm.role)
    };

    // Check if member has any access to this project
    if !member.role.has_implicit_project_access() && project_role.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    request.extensions_mut().insert(OrgMemberContext {
        member,
        project_role,
        impersonated_by,
        impersonator_name,
    });

    Ok(next.run(request).await)
}
