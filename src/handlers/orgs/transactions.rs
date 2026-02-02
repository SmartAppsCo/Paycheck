use axum::extract::{Query, State};
use serde::Deserialize;

use crate::db::{AppState, queries};
use crate::error::{OptionExt, Result, msg};
use crate::extractors::{Json, Path};
use crate::models::{Transaction, TransactionFilters, TransactionStats, TransactionType};
use crate::pagination::Paginated;

#[derive(Deserialize)]
pub struct OrgPath {
    pub org_id: String,
}

#[derive(Deserialize)]
pub struct TransactionPath {
    pub org_id: String,
    pub project_id: String,
    pub transaction_id: String,
}

#[derive(Deserialize)]
pub struct LicenseTransactionsPath {
    pub org_id: String,
    pub project_id: String,
    pub license_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ListTransactionsQuery {
    /// Filter by product ID
    pub product_id: Option<String>,
    /// Filter by transaction type (purchase, renewal, refund)
    pub transaction_type: Option<TransactionType>,
    /// Filter by payment provider (stripe, lemonsqueezy)
    pub payment_provider: Option<String>,
    /// Filter by start date (unix timestamp)
    pub start_date: Option<i64>,
    /// Filter by end date (unix timestamp)
    pub end_date: Option<i64>,
    /// Filter test mode transactions (default: include all)
    pub test_mode: Option<bool>,
    /// Max results to return (default 50, max 100)
    pub limit: Option<i64>,
    /// Offset for pagination (default 0)
    pub offset: Option<i64>,
}

impl ListTransactionsQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }

    fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }

    fn to_filters(&self, project_id: Option<String>) -> TransactionFilters {
        TransactionFilters {
            project_id,
            product_id: self.product_id.clone(),
            license_id: None,
            transaction_type: self.transaction_type,
            payment_provider: self.payment_provider.clone(),
            start_date: self.start_date,
            end_date: self.end_date,
            test_mode: self.test_mode,
        }
    }
}

/// GET /orgs/{org_id}/projects/{project_id}/transactions
/// List transactions for a project with pagination and filters.
pub async fn list_project_transactions(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    Query(query): Query<ListTransactionsQuery>,
) -> Result<Json<Paginated<Transaction>>> {
    let conn = state.db.get()?;

    let limit = query.limit();
    let offset = query.offset();

    // Use org-level query with project filter for consistent filtering
    let filters = query.to_filters(Some(path.project_id.clone()));
    let (transactions, total) =
        queries::get_transactions_by_org_paginated(&conn, &path.org_id, &filters, limit, offset)?;

    Ok(Json(Paginated::new(transactions, total, limit, offset)))
}

/// GET /orgs/{org_id}/projects/{project_id}/transactions/{transaction_id}
/// Get a specific transaction by ID.
pub async fn get_transaction(
    State(state): State<AppState>,
    Path(path): Path<TransactionPath>,
) -> Result<Json<Transaction>> {
    let conn = state.db.get()?;

    let transaction = queries::get_transaction(&conn, &path.transaction_id)?
        .or_not_found(msg::TRANSACTION_NOT_FOUND)?;

    // Verify transaction belongs to the specified project
    if transaction.project_id != path.project_id {
        return Err(crate::error::AppError::NotFound(
            msg::TRANSACTION_NOT_FOUND.into(),
        ));
    }

    Ok(Json(transaction))
}

/// GET /orgs/{org_id}/projects/{project_id}/licenses/{license_id}/transactions
/// List all transactions for a specific license.
pub async fn list_license_transactions(
    State(state): State<AppState>,
    Path(path): Path<LicenseTransactionsPath>,
) -> Result<Json<Vec<Transaction>>> {
    let conn = state.db.get()?;

    // Verify license exists and belongs to project
    let license = queries::get_license_by_id(&conn, &path.license_id)?
        .or_not_found(msg::LICENSE_NOT_FOUND)?;

    if license.project_id != path.project_id {
        return Err(crate::error::AppError::NotFound(
            msg::LICENSE_NOT_FOUND.into(),
        ));
    }

    let transactions = queries::get_transactions_by_license(&conn, &path.license_id)?;

    Ok(Json(transactions))
}

/// GET /orgs/{org_id}/transactions
/// List all transactions for an org (aggregate across all projects).
pub async fn list_org_transactions(
    State(state): State<AppState>,
    Path(path): Path<OrgPath>,
    Query(query): Query<ListTransactionsQuery>,
) -> Result<Json<Paginated<Transaction>>> {
    let conn = state.db.get()?;

    let limit = query.limit();
    let offset = query.offset();

    let filters = query.to_filters(None);
    let (transactions, total) =
        queries::get_transactions_by_org_paginated(&conn, &path.org_id, &filters, limit, offset)?;

    Ok(Json(Paginated::new(transactions, total, limit, offset)))
}

/// GET /orgs/{org_id}/transactions/stats
/// Get aggregate transaction statistics for an org.
pub async fn get_org_transaction_stats(
    State(state): State<AppState>,
    Path(path): Path<OrgPath>,
    Query(query): Query<ListTransactionsQuery>,
) -> Result<Json<TransactionStats>> {
    let conn = state.db.get()?;

    let stats = queries::get_transaction_stats(
        &conn,
        &path.org_id,
        None, // No project filter for org-level stats
        query.product_id.as_deref(),
        query.start_date,
        query.end_date,
        query.test_mode,
    )?;

    Ok(Json(stats))
}

/// GET /orgs/{org_id}/projects/{project_id}/transactions/stats
/// Get aggregate transaction statistics for a project.
pub async fn get_project_transaction_stats(
    State(state): State<AppState>,
    Path(path): Path<crate::middleware::OrgProjectPath>,
    Query(query): Query<ListTransactionsQuery>,
) -> Result<Json<TransactionStats>> {
    let conn = state.db.get()?;

    let stats = queries::get_transaction_stats(
        &conn,
        &path.org_id,
        Some(&path.project_id),
        query.product_id.as_deref(),
        query.start_date,
        query.end_date,
        query.test_mode,
    )?;

    Ok(Json(stats))
}
