mod operators;
mod organizations;
mod audit_logs;

pub use operators::*;
pub use organizations::*;
pub use audit_logs::*;

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};

use crate::db::DbPool;
use crate::middleware::{operator_auth, require_admin_role, require_owner_role};

pub fn router(pool: DbPool) -> Router<DbPool> {
    Router::new()
        // Operator management (owner only)
        .route("/operators", post(create_operator))
        .route("/operators", get(list_operators))
        .route("/operators/{id}", get(get_operator))
        .route("/operators/{id}", put(update_operator))
        .route("/operators/{id}", delete(delete_operator))
        .layer(middleware::from_fn_with_state(pool.clone(), require_owner_role))
        .merge(
            Router::new()
                // Organization management (admin+)
                .route("/operators/organizations", post(create_organization))
                .route("/operators/organizations", get(list_organizations))
                .route("/operators/organizations/{id}", get(get_organization))
                .route("/operators/organizations/{id}", delete(delete_organization))
                .layer(middleware::from_fn_with_state(pool.clone(), require_admin_role)),
        )
        .merge(
            Router::new()
                // Audit logs (view+)
                .route("/operators/audit-logs", get(query_audit_logs))
                .layer(middleware::from_fn_with_state(pool.clone(), operator_auth)),
        )
}
