// Payment provider webhook handlers
// These will be implemented in Phase 8

use axum::Router;

use crate::db::DbPool;

pub fn router() -> Router<DbPool> {
    Router::new()
    // Future endpoints:
    // .route("/webhook/stripe", post(stripe_webhook))
    // .route("/webhook/lemonsqueezy", post(lemonsqueezy_webhook))
}
