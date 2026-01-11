use axum::extract::State;

use crate::db::{AppState, queries};
use crate::error::Result;
use crate::extractors::{Json, Query};
use crate::models::{AuditLogQuery, AuditLogResponse};
use crate::pagination::Paginated;

pub async fn query_audit_logs(
    State(state): State<AppState>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<Paginated<AuditLogResponse>>> {
    let limit = query.limit();
    let offset = query.offset();
    let conn = state.audit.get()?;
    let (logs, total) = queries::query_audit_logs(&conn, &query)?;
    let responses: Vec<AuditLogResponse> = logs.into_iter().map(Into::into).collect();
    Ok(Json(Paginated::new(responses, total, limit, offset)))
}

/// Query audit logs and return as plain text (one entry per line).
///
/// Supports the same filtering and pagination as the JSON endpoint.
pub async fn query_audit_logs_text(
    State(state): State<AppState>,
    Query(query): Query<AuditLogQuery>,
) -> Result<String> {
    let conn = state.audit.get()?;
    let (logs, _total) = queries::query_audit_logs(&conn, &query)?;

    Ok(logs
        .iter()
        .map(|log| log.formatted())
        .collect::<Vec<_>>()
        .join("\n"))
}
