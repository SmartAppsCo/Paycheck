mod config;
mod db;
mod error;
mod handlers;
mod jwt;
mod middleware;
mod models;
mod payments;

use axum::Router;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;
use crate::db::{create_pool, init_db, queries};
use crate::models::{ActorType, CreateOperator, OperatorRole};

fn bootstrap_first_operator(pool: &db::DbPool, email: &str) {
    let conn = pool.get().expect("Failed to get db connection for bootstrap");

    let count = queries::count_operators(&conn).expect("Failed to count operators");
    if count > 0 {
        tracing::info!("Operators already exist, skipping bootstrap");
        return;
    }

    let api_key = queries::generate_api_key();

    let input = CreateOperator {
        email: email.to_string(),
        name: "Bootstrap Operator".to_string(),
        role: OperatorRole::Owner,
    };

    let operator = queries::create_operator(&conn, &input, &api_key, None)
        .expect("Failed to create bootstrap operator");

    queries::create_audit_log(
        &conn,
        ActorType::System,
        None,
        "bootstrap_operator",
        "operator",
        &operator.id,
        Some(&serde_json::json!({
            "email": email,
            "role": "owner",
        })),
        None,
        None,
    )
    .expect("Failed to create audit log for bootstrap");

    tracing::info!("============================================");
    tracing::info!("BOOTSTRAP OPERATOR CREATED");
    tracing::info!("Email: {}", email);
    tracing::info!("API Key: {}", api_key);
    tracing::info!("============================================");
    tracing::info!("SAVE THIS API KEY - IT WILL NOT BE SHOWN AGAIN");
    tracing::info!("============================================");
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "paycheck=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env();

    if config.dev_mode {
        tracing::info!("Running in DEVELOPMENT mode");
    }

    // Create database connection pool
    let pool = create_pool(&config.database_path).expect("Failed to create database pool");

    // Initialize database schema
    {
        let conn = pool.get().expect("Failed to get connection");
        init_db(&conn).expect("Failed to initialize database");
    }

    // Bootstrap first operator if configured
    if let Some(ref email) = config.bootstrap_operator_email {
        bootstrap_first_operator(&pool, email);
    }

    // Build the application router
    let app = Router::new()
        // Public endpoints (no auth)
        .merge(handlers::public::router())
        // Webhook endpoints (provider-specific auth)
        .merge(handlers::webhooks::router())
        // Operator API (operator key auth)
        .merge(handlers::operators::router(pool.clone()))
        // Organization API (org member key auth)
        .merge(handlers::orgs::router(pool.clone()))
        .layer(TraceLayer::new_for_http())
        .with_state(pool);

    // Start the server
    let addr = config.addr();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    tracing::info!("Paycheck server listening on {}", addr);

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}
