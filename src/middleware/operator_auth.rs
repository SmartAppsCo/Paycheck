use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::db::{AppState, queries};
use crate::models::{AuditLogNames, OperatorRole, User};
use crate::util::extract_bearer_token;

use super::AuthMethod;

#[derive(Clone)]
pub struct OperatorContext {
    pub user: User,
    /// How the request was authenticated
    pub auth_method: AuthMethod,
}

impl OperatorContext {
    /// Get the user's operator role. Panics if user is not an operator.
    pub fn role(&self) -> OperatorRole {
        self.user
            .operator_role
            .expect("OperatorContext should only be created for users with operator_role")
    }

    /// Get audit log names pre-populated with the user's name and email.
    /// Chain with `.resource()`, `.org()`, `.project()` to add more context.
    pub fn audit_names(&self) -> AuditLogNames {
        AuditLogNames {
            user_name: Some(self.user.name.clone()),
            user_email: Some(self.user.email.clone()),
            ..Default::default()
        }
    }
}

/// Authenticate operator from bearer token (API key).
/// Returns (User, AuthMethod) if authentication succeeds.
fn authenticate_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(User, AuthMethod), StatusCode> {
    let token = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let conn = state.db.get().map_err(|e| {
        tracing::error!("Failed to get database connection: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (user, api_key_record) = queries::get_user_by_api_key(&conn, token)
        .map_err(|e| {
            tracing::error!("Failed to look up API key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if user is an operator
    if user.operator_role.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let auth_method = AuthMethod {
        key_id: api_key_record.id,
        key_prefix: api_key_record.prefix,
    };

    Ok((user, auth_method))
}

pub async fn operator_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (user, auth_method) = authenticate_operator(&state, request.headers())?;

    request
        .extensions_mut()
        .insert(OperatorContext { user, auth_method });
    Ok(next.run(request).await)
}

pub async fn require_owner_role(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (user, auth_method) = authenticate_operator(&state, request.headers())?;

    if !matches!(user.operator_role, Some(OperatorRole::Owner)) {
        return Err(StatusCode::FORBIDDEN);
    }

    request
        .extensions_mut()
        .insert(OperatorContext { user, auth_method });
    Ok(next.run(request).await)
}

pub async fn require_admin_role(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (user, auth_method) = authenticate_operator(&state, request.headers())?;

    if !matches!(
        user.operator_role,
        Some(OperatorRole::Owner) | Some(OperatorRole::Admin)
    ) {
        return Err(StatusCode::FORBIDDEN);
    }

    request
        .extensions_mut()
        .insert(OperatorContext { user, auth_method });
    Ok(next.run(request).await)
}
