use axum::{
    extract::{Query, State},
    Json,
};

use crate::db::{queries, DbPool};
use crate::error::Result;
use crate::models::{AuditLog, AuditLogQuery};

pub async fn query_audit_logs(
    State(pool): State<DbPool>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<Vec<AuditLog>>> {
    let conn = pool.get()?;
    let logs = queries::query_audit_logs(&conn, &query)?;
    Ok(Json(logs))
}
