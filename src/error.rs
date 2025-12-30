use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl From<StatusCode> for AppError {
    fn from(code: StatusCode) -> Self {
        match code {
            StatusCode::UNAUTHORIZED => AppError::Unauthorized,
            StatusCode::FORBIDDEN => AppError::Forbidden("Access denied".into()),
            StatusCode::NOT_FOUND => AppError::NotFound("Resource not found".into()),
            _ => AppError::Internal(format!("Status: {}", code)),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error, details) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "Not found", Some(msg.clone())),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "Bad request", Some(msg.clone())),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized", None),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "Forbidden", Some(msg.clone())),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "Conflict", Some(msg.clone())),
            AppError::Database(e) => {
                tracing::error!("Database error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error", None)
            }
            AppError::Pool(e) => {
                tracing::error!("Pool error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error", None)
            }
            AppError::Json(e) => {
                tracing::error!("JSON error: {}", e);
                (StatusCode::BAD_REQUEST, "Invalid JSON", Some(e.to_string()))
            }
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error", None)
            }
        };

        let body = ErrorResponse {
            error: error.to_string(),
            details,
        };

        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
