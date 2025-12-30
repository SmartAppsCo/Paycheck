// Public API handlers (SDK/client-facing)
// These will be implemented in Phase 7

use axum::{routing::get, Json, Router};
use serde::Serialize;

use crate::db::DbPool;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub fn router() -> Router<DbPool> {
    Router::new()
        .route("/health", get(health))
        // Future endpoints:
        // .route("/buy", get(buy))
        // .route("/callback", get(callback))
        // .route("/redeem", get(redeem))
        // .route("/validate", get(validate))
        // .route("/devices", get(list_devices))
        // .route("/devices/deactivate", post(deactivate_device))
}
