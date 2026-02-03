//! Common webhook handling infrastructure for payment providers.
//!
//! This module provides a trait-based approach to unify Stripe and LemonSqueezy
//! webhook handlers, reducing code duplication while preserving provider-specific logic.

use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};
use rusqlite::Connection;

use crate::crypto::{EmailHasher, MasterKey};
use crate::db::{AppState, queries};
use crate::error::AppError;
use crate::metering::{spawn_sales_metering, SalesMeteringEvent};
use crate::models::{
    ActorType, AuditAction, AuditLogNames, CreateLicense, CreateTransaction, License,
    Organization, PaymentSession, Product, Project, TransactionType,
};
use crate::util::{AuditLogBuilder, LicenseExpirations};

/// Helper to unwrap DB query results with consistent error handling.
fn db_lookup<T>(
    result: Result<Option<T>, AppError>,
    not_found_msg: &'static str,
) -> Result<T, WebhookResult> {
    match result {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Err((StatusCode::OK, not_found_msg)),
        Err(e) => {
            tracing::error!("DB error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"))
        }
    }
}

/// Helper for subscription lookup with warning log on not found.
fn lookup_license_by_subscription<P: WebhookProvider>(
    provider: &P,
    conn: &Connection,
    subscription_id: &str,
) -> Result<License, WebhookResult> {
    match queries::get_license_by_subscription(conn, provider.provider_name(), subscription_id) {
        Ok(Some(l)) => Ok(l),
        Ok(None) => {
            tracing::warn!(
                "No license found for {} subscription: {}",
                provider.provider_name(),
                subscription_id
            );
            Err((StatusCode::OK, "License not found for subscription"))
        }
        Err(e) => {
            tracing::error!("DB error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"))
        }
    }
}

/// Result type for webhook operations.
pub type WebhookResult = (StatusCode, &'static str);

/// Data extracted from a checkout/order completion event.
#[derive(Debug)]
pub struct CheckoutData {
    pub session_id: String,
    pub project_id: String,
    pub customer_id: Option<String>,
    /// Customer email from payment provider (for license recovery via email)
    pub customer_email: Option<String>,
    pub subscription_id: Option<String>,
    /// Provider's order ID for DB storage and refund linkage.
    /// Stripe: payment_intent (pi_xxx) for refund webhook matching.
    /// LemonSqueezy: order ID.
    pub order_id: Option<String>,
    /// Provider-specific session ID for API enrichment calls.
    /// Stripe: checkout session ID (cs_xxx) for fetching discount codes.
    /// Not used by LemonSqueezy.
    pub enricher_session_id: Option<String>,
    /// Transaction data extracted from the payment provider
    pub transaction: Option<CheckoutTransactionData>,
}

/// Transaction data extracted from payment provider checkout events.
/// All amounts are in cents.
#[derive(Debug, Default)]
pub struct CheckoutTransactionData {
    /// Currency code (lowercase, e.g., "usd", "eur")
    pub currency: String,
    /// Amount before discounts and tax
    pub subtotal_cents: i64,
    /// Discount amount applied
    pub discount_cents: i64,
    /// Tax amount
    pub tax_cents: i64,
    /// Final total charged
    pub total_cents: i64,
    /// Whether tax is included in subtotal
    pub tax_inclusive: Option<bool>,
    /// Discount/coupon code used
    pub discount_code: Option<String>,
    /// Customer's country code (e.g., "US", "GB")
    pub customer_country: Option<String>,
    /// Whether this is a test mode transaction
    pub test_mode: bool,
}

/// Data extracted from a subscription renewal event.
#[derive(Debug)]
pub struct RenewalData {
    pub subscription_id: String,
    /// Whether this is an actual renewal vs initial subscription creation
    pub is_renewal: bool,
    pub is_paid: bool,
    /// Unique event/invoice ID for replay prevention
    pub event_id: Option<String>,
    /// PaymentIntent used to pay this invoice.
    /// Critical for refund linkage - refunds reference payment_intent.
    pub payment_intent: Option<String>,
    /// Billing period end from the payment provider (Unix timestamp).
    /// More accurate than calculating from product settings.
    pub period_end: Option<i64>,
    /// Transaction data for revenue tracking (amount, currency, etc.)
    pub transaction: Option<CheckoutTransactionData>,
}

/// Data extracted from a subscription cancellation event.
#[derive(Debug)]
pub struct CancellationData {
    pub subscription_id: String,
}

/// Data extracted from a refund event.
#[derive(Debug)]
pub struct RefundData {
    /// The license ID to associate the refund with (looked up via charge/order)
    pub license_id: Option<String>,
    /// Provider's unique refund/event ID for replay prevention
    pub refund_id: String,
    /// Original order/charge ID for linking to purchase
    pub order_id: String,
    /// Currency code (lowercase)
    pub currency: String,
    /// Amount refunded in cents (positive value - will be stored as negative)
    pub amount_cents: i64,
    /// Whether this is a test mode transaction
    pub test_mode: bool,
    /// Source type: "refund", "dispute", or "dispute_reversal"
    pub source: String,
    /// Optional metadata (JSON) for disputes: {"dispute_id": "dp_xxx", "reason": "fraudulent"}
    pub metadata: Option<String>,
}

/// Parsed webhook event with provider-agnostic data.
#[derive(Debug)]
pub enum WebhookEvent {
    /// Initial checkout/order completed - creates license
    CheckoutCompleted(CheckoutData),
    /// Subscription renewed - extends license
    SubscriptionRenewed(RenewalData),
    /// Subscription cancelled - license expires naturally
    SubscriptionCancelled(CancellationData),
    /// Refund processed - creates negative transaction record
    Refunded(RefundData),
    /// Event type not relevant to license management
    Ignored,
}

/// Trait for payment provider webhook handling.
///
/// Implementors provide provider-specific parsing and signature verification,
/// while the common processing logic handles license creation/renewal.
pub trait WebhookProvider: Send + Sync {
    /// Provider name for logging and database storage (e.g., "stripe", "lemonsqueezy")
    fn provider_name(&self) -> &'static str;

    /// Extract signature from request headers.
    fn extract_signature(&self, headers: &HeaderMap) -> Result<String, WebhookResult>;

    /// Verify webhook signature against payment configuration.
    /// Uses hierarchical lookup: project-level config first, then org-level fallback.
    /// The connection is passed so implementations can fetch configs from the service configs table.
    fn verify_signature(
        &self,
        conn: &Connection,
        project: &Project,
        org: &Organization,
        master_key: &MasterKey,
        body: &Bytes,
        signature: &str,
    ) -> Result<bool, WebhookResult>;

    /// Parse the webhook payload into a provider-agnostic event.
    fn parse_event(&self, body: &Bytes) -> Result<WebhookEvent, WebhookResult>;

    /// Spawn a background task to enrich transaction data after commit.
    /// Default implementation does nothing. Override to fetch additional data
    /// from the payment provider API (e.g., discount codes from Stripe).
    ///
    /// - `provider_order_id`: ID used for DB lookup (Stripe: payment_intent, LS: order ID)
    /// - `enricher_session_id`: ID for provider API calls (Stripe: checkout session cs_xxx)
    fn spawn_enricher(
        &self,
        _state: AppState,
        _project_id: String,
        _org_id: String,
        _provider_order_id: String,
        _enricher_session_id: Option<String>,
    ) {
        // Default: no-op
    }
}

/// Process a checkout completion event - creates license only.
///
/// Device creation is deferred to activation time (/redeem endpoint).
/// Uses a transaction to atomically claim the payment session AND create the license.
/// This prevents race conditions and ensures retryability if license creation fails.
pub fn process_checkout(
    conn: &mut Connection,
    email_hasher: &EmailHasher,
    provider: &str,
    project: &Project,
    payment_session: &PaymentSession,
    product: &Product,
    data: &CheckoutData,
) -> WebhookResult {
    // Compute email hash for license recovery via email
    let email_hash = data.customer_email.as_ref().map(|e| email_hasher.hash(e));

    if email_hash.is_none() {
        tracing::warn!(
            "No email in checkout for session {} - license will not be recoverable via email",
            data.session_id
        );
    }

    // Compute expirations from product settings
    let now = chrono::Utc::now().timestamp();
    let exps = LicenseExpirations::from_product(product, now);

    // Use a transaction to atomically claim session AND create license.
    // If license creation fails, the session claim is rolled back so Stripe can retry.
    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to start transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    // Atomically claim this payment session BEFORE creating any resources.
    // This prevents race conditions where concurrent webhooks could all create licenses.
    match queries::try_claim_payment_session(&tx, &data.session_id) {
        Ok(true) => {
            // Successfully claimed - proceed with license creation
        }
        Ok(false) => {
            // Already claimed by another request - no need to commit, just return
            return (StatusCode::OK, "Already processed");
        }
        Err(e) => {
            tracing::error!("Failed to claim payment session: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    }

    // Create license (no user-facing key - email hash is the identity)
    // Payment provider info is stored in the transactions table
    let license = match queries::create_license(
        &tx,
        &project.id,
        &payment_session.product_id,
        &CreateLicense {
            email_hash,
            customer_id: payment_session.customer_id.clone(),
            expires_at: exps.license_exp,
            updates_expires_at: exps.updates_exp,
        },
    ) {
        Ok(l) => l,
        Err(e) => {
            // Transaction will be rolled back on drop, allowing retry
            tracing::error!("Failed to create license: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create license",
            );
        }
    };

    // Create transaction record with payment details (inside atomic scope)
    // This ensures license and transaction are created together or not at all.
    // Critical for refund linkage - refunds look up by provider_order_id.
    if let Some(tx_data) = &data.transaction {
        // Calculate net_cents (subtotal - discount)
        let net_cents = tx_data.subtotal_cents - tx_data.discount_cents;

        let transaction = CreateTransaction {
            license_id: Some(license.id.clone()),
            project_id: project.id.clone(),
            product_id: Some(payment_session.product_id.clone()),
            org_id: project.org_id.clone(),
            payment_provider: provider.to_string(),
            provider_customer_id: data.customer_id.clone(),
            provider_subscription_id: data.subscription_id.clone(),
            provider_order_id: data.order_id.clone().unwrap_or_default(),
            currency: tx_data.currency.clone(),
            subtotal_cents: tx_data.subtotal_cents,
            discount_cents: tx_data.discount_cents,
            net_cents,
            tax_cents: tx_data.tax_cents,
            total_cents: tx_data.total_cents,
            discount_code: tx_data.discount_code.clone(),
            tax_inclusive: tx_data.tax_inclusive,
            customer_country: tx_data.customer_country.clone(),
            transaction_type: TransactionType::Purchase,
            parent_transaction_id: None,
            is_subscription: data.subscription_id.is_some(),
            source: "payment".to_string(),
            metadata: None,
            test_mode: tx_data.test_mode,
        };

        if let Err(e) = queries::create_transaction(&tx, &transaction) {
            // Transaction creation failed - roll back everything so Stripe can retry
            tracing::error!("Failed to create transaction record: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create transaction",
            );
        }
    } else {
        tracing::warn!(
            "No transaction data in checkout for session {} - payment details not recorded",
            data.session_id
        );
    }

    // Commit the transaction - session claim, license, and transaction are now permanent
    if let Err(e) = tx.commit() {
        tracing::error!("Failed to commit transaction: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Database error");
    }

    // Link license to payment session for efficient callback lookup
    // This is outside the atomic scope intentionally - it's a convenience optimization
    // for the callback endpoint, not critical data. Callback will fall back to search.
    if let Err(e) = queries::set_payment_session_license(conn, &data.session_id, &license.id) {
        tracing::error!("Failed to link license to session: {}", e);
        // Non-fatal - callback will fall back to search
    }

    // NOTE: Device creation is deferred to activation time (/redeem endpoint).
    // This separates purchase from activation - user may buy on phone, activate on desktop.

    tracing::info!(
        "{} checkout completed: session={}, license_id={}, subscription={:?}",
        provider,
        data.session_id,
        license.id,
        data.subscription_id
    );

    (StatusCode::OK, "OK")
}

/// Atomic result from renewal processing
pub enum RenewalResult {
    /// New renewal processed successfully
    Success { license_exp: Option<i64> },
    /// Event was already processed (idempotent)
    AlreadyProcessed,
}

/// Process a subscription renewal ATOMICALLY - replay prevention, license extension,
/// and transaction creation all happen in a single database transaction.
///
/// This ensures that either ALL operations succeed or NONE do, allowing payment
/// provider retries to work correctly if any step fails.
///
/// Returns `RenewalResult::Success` with the new license expiration, or
/// `RenewalResult::AlreadyProcessed` if this event was already handled.
pub fn process_renewal_atomic(
    conn: &mut Connection,
    provider: &str,
    product: &Product,
    license: &License,
    subscription_id: &str,
    event_id: Option<&str>,
    period_end: Option<i64>,
    transaction_data: Option<&CreateTransaction>,
) -> Result<RenewalResult, WebhookResult> {
    // Start a database transaction for atomicity
    let tx = conn.transaction().map_err(|e| {
        tracing::error!("Failed to start transaction: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    // 1. Replay attack prevention (inside transaction - rolls back if later steps fail)
    if let Some(eid) = event_id {
        match queries::try_record_webhook_event(&tx, provider, eid) {
            Ok(true) => {
                // New event - proceed with processing
            }
            Ok(false) => {
                // Already processed - no need to commit, just return
                return Ok(RenewalResult::AlreadyProcessed);
            }
            Err(e) => {
                tracing::error!("Failed to record webhook event: {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
            }
        }
    }

    // 2. Calculate new expirations
    let now = chrono::Utc::now().timestamp();
    let fallback_exps = LicenseExpirations::from_product(product, now);

    let license_exp = period_end.or(fallback_exps.license_exp);
    let updates_exp = match (period_end, product.license_exp_days, product.updates_exp_days) {
        (Some(pe), Some(_), Some(upd_days)) => Some(pe + (upd_days as i64 * 86400)),
        (Some(pe), Some(lic_days), None) if lic_days > 0 => {
            fallback_exps.updates_exp.map(|_| pe)
        }
        _ => fallback_exps.updates_exp,
    };

    // 3. Extend license expiration
    if let Err(e) = queries::extend_license_expiration(&tx, &license.id, license_exp, updates_exp) {
        tracing::error!("Failed to extend license: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to extend license",
        ));
    }

    // 4. Create transaction record (if data provided)
    if let Some(tx_data) = transaction_data {
        if let Err(e) = queries::create_transaction(&tx, tx_data) {
            tracing::error!("Failed to create renewal transaction: {}", e);
            // Transaction will be rolled back - retry can work
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create transaction",
            ));
        }
    }

    // 5. Commit - all or nothing
    tx.commit().map_err(|e| {
        tracing::error!("Failed to commit renewal transaction: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    tracing::info!(
        "{} subscription renewed: subscription={}, license_id={}, new_expires_at={:?}{}",
        provider,
        subscription_id,
        license.id,
        license_exp,
        if period_end.is_some() { " (from provider)" } else { " (calculated)" }
    );

    Ok(RenewalResult::Success { license_exp })
}

/// Process a subscription cancellation event - just logs, license expires naturally.
pub fn process_cancellation(
    provider: &str,
    license_id: &str,
    license_expires_at: Option<i64>,
    subscription_id: &str,
) -> WebhookResult {
    tracing::info!(
        "{} subscription cancelled: subscription={}, license_id={}, expires_at={:?} (will expire naturally)",
        provider,
        subscription_id,
        license_id,
        license_expires_at
    );

    (StatusCode::OK, "OK")
}

/// Atomic result from refund processing
pub enum RefundResult {
    /// New refund processed successfully
    Success,
    /// Event was already processed (idempotent)
    AlreadyProcessed,
}

/// Process a refund ATOMICALLY - replay prevention and transaction creation
/// happen in a single database transaction.
///
/// This ensures that either ALL operations succeed or NONE do, allowing payment
/// provider retries to work correctly if any step fails.
///
/// Returns `RefundResult::Success` on success, or `RefundResult::AlreadyProcessed`
/// if this event was already handled.
pub fn process_refund_atomic(
    conn: &mut Connection,
    provider: &str,
    refund_id: &str,
    transaction_data: &CreateTransaction,
) -> Result<RefundResult, WebhookResult> {
    // Start a database transaction for atomicity
    let tx = conn.transaction().map_err(|e| {
        tracing::error!("Failed to start transaction: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    // 1. Replay attack prevention (inside transaction - rolls back if later steps fail)
    match queries::try_record_webhook_event(&tx, provider, refund_id) {
        Ok(true) => {
            // New event - proceed with processing
        }
        Ok(false) => {
            // Already processed - no need to commit, just return
            return Ok(RefundResult::AlreadyProcessed);
        }
        Err(e) => {
            tracing::error!("Failed to record webhook event: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
        }
    }

    // 2. Create refund transaction record
    if let Err(e) = queries::create_transaction(&tx, transaction_data) {
        tracing::error!("Failed to create refund transaction: {}", e);
        // Transaction will be rolled back - retry can work
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create refund transaction",
        ));
    }

    // 3. Commit - all or nothing
    tx.commit().map_err(|e| {
        tracing::error!("Failed to commit refund transaction: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    Ok(RefundResult::Success)
}

/// Generic webhook handler that delegates to provider-specific implementations.
pub async fn handle_webhook<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    headers: HeaderMap,
    body: Bytes,
) -> WebhookResult {
    // Extract signature
    let signature = match provider.extract_signature(&headers) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Parse the event
    let event = match provider.parse_event(&body) {
        Ok(e) => e,
        Err(e) => return e,
    };

    // Handle based on event type
    match event {
        WebhookEvent::CheckoutCompleted(data) => {
            handle_checkout(provider, state, &headers, &body, &signature, data)
                .await
                .unwrap_or_else(|e| e)
        }
        WebhookEvent::SubscriptionRenewed(data) => {
            handle_renewal(provider, state, &headers, &body, &signature, data)
                .await
                .unwrap_or_else(|e| e)
        }
        WebhookEvent::SubscriptionCancelled(data) => {
            handle_cancellation(provider, state, &headers, &body, &signature, data)
                .await
                .unwrap_or_else(|e| e)
        }
        WebhookEvent::Refunded(data) => {
            handle_refund(provider, state, &headers, &body, &signature, data)
                .await
                .unwrap_or_else(|e| e)
        }
        WebhookEvent::Ignored => (StatusCode::OK, "Event ignored"),
    }
}

async fn handle_checkout<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    signature: &str,
    data: CheckoutData,
) -> Result<WebhookResult, WebhookResult> {
    let mut conn = state.db.get().map_err(|e| {
        tracing::error!("DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let project = db_lookup(
        queries::get_project_by_id(&conn, &data.project_id),
        "Project not found",
    )?;

    let org = db_lookup(
        queries::get_organization_by_id(&conn, &project.org_id),
        "Organization not found",
    )?;

    // Verify signature using hierarchical config (project first, then org)
    match provider.verify_signature(&conn, &project, &org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Invalid signature")),
        Err(e) => return Err(e),
    }

    let payment_session = db_lookup(
        queries::get_payment_session(&conn, &data.session_id),
        "Payment session not found",
    )?;

    let product = db_lookup(
        queries::get_product_by_id(&conn, &payment_session.product_id),
        "Product not found",
    )?;

    let result = process_checkout(
        &mut conn,
        &state.email_hasher,
        provider.provider_name(),
        &project,
        &payment_session,
        &product,
        &data,
    );

    // Audit log and metering on successful checkout (license created)
    if result.0 == StatusCode::OK && result.1 == "OK" {
        // Re-fetch session to get the linked license_id
        let license_id = queries::get_payment_session(&conn, &data.session_id)
            .ok()
            .flatten()
            .and_then(|s| s.license_id);

        if let Some(ref license_id) = license_id {
            let audit_conn = state.audit.get().map_err(|e| {
                tracing::error!("Audit DB connection error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            })?;

            if let Err(e) = AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, headers)
                .actor(ActorType::Public, None)
                .action(AuditAction::ReceiveCheckoutWebhook)
                .resource("license", license_id)
                .details(&serde_json::json!({
                    "provider": provider.provider_name(),
                    "session_id": data.session_id,
                    "product_id": product.id,
                    "customer_email": data.customer_email,
                    "subscription_id": data.subscription_id,
                    "order_id": data.order_id,
                }))
                .org(&org.id)
                .project(&project.id)
                .names(&AuditLogNames {
                    org_name: Some(org.name.clone()),
                    project_name: Some(project.name.clone()),
                    ..Default::default()
                })
                .save()
            {
                tracing::warn!("Failed to write checkout audit log: {}", e);
            }
        }

        // Spawn enricher to fetch additional data from payment provider API
        // (e.g., discount codes that aren't in the webhook payload)
        if let Some(order_id) = data.order_id.clone() {
            provider.spawn_enricher(
                state.clone(),
                project.id.clone(),
                org.id.clone(),
                order_id,
                data.enricher_session_id.clone(),
            );
        }

        // Fire-and-forget sales metering event
        if let (Some(tx_data), Some(license_id)) = (&data.transaction, license_id) {
            spawn_sales_metering(
                state.http_client.clone(),
                state.metering_webhook_url.clone(),
                SalesMeteringEvent {
                    event: "purchase".to_string(),
                    org_id: org.id.clone(),
                    project_id: project.id.clone(),
                    product_id: payment_session.product_id.clone(),
                    license_id,
                    transaction_id: data.order_id.clone().unwrap_or_else(|| data.session_id.clone()),
                    payment_provider: provider.provider_name().to_string(),
                    amount_cents: tx_data.total_cents,
                    currency: tx_data.currency.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                },
            );
        }
    }

    Ok(result)
}

async fn handle_renewal<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    signature: &str,
    data: RenewalData,
) -> Result<WebhookResult, WebhookResult> {
    // Skip if not a renewal (initial subscription handled by checkout)
    if !data.is_renewal {
        return Ok((StatusCode::OK, "Initial subscription - handled by checkout"));
    }

    if !data.is_paid {
        return Ok((StatusCode::OK, "Invoice not paid"));
    }

    // Get mutable connection for atomic transaction
    let mut conn = state.db.get().map_err(|e| {
        tracing::error!("DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let license = lookup_license_by_subscription(provider, &conn, &data.subscription_id)?;
    let product = db_lookup(
        queries::get_product_by_id(&conn, &license.product_id),
        "Product not found",
    )?;
    let project = db_lookup(
        queries::get_project_by_id(&conn, &product.project_id),
        "Project not found",
    )?;
    let org = db_lookup(
        queries::get_organization_by_id(&conn, &project.org_id),
        "Organization not found",
    )?;

    // Verify signature using hierarchical config (project first, then org)
    match provider.verify_signature(&conn, &project, &org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Invalid signature")),
        Err(e) => return Err(e),
    }

    // Build transaction data if provided (for atomic creation with license extension)
    let transaction_data = data.transaction.as_ref().map(|tx_data| {
        let net_cents = tx_data.subtotal_cents - tx_data.discount_cents;
        CreateTransaction {
            license_id: Some(license.id.clone()),
            project_id: project.id.clone(),
            product_id: Some(license.product_id.clone()),
            org_id: org.id.clone(),
            payment_provider: provider.provider_name().to_string(),
            provider_customer_id: license.customer_id.clone(),
            provider_subscription_id: Some(data.subscription_id.clone()),
            // Use payment_intent for refund linkage - refunds reference this ID.
            // Falls back to event_id (invoice.id) for providers without payment_intent.
            provider_order_id: data.payment_intent.clone().or(data.event_id.clone()).unwrap_or_default(),
            currency: tx_data.currency.clone(),
            subtotal_cents: tx_data.subtotal_cents,
            discount_cents: tx_data.discount_cents,
            net_cents,
            tax_cents: tx_data.tax_cents,
            total_cents: tx_data.total_cents,
            discount_code: tx_data.discount_code.clone(),
            tax_inclusive: tx_data.tax_inclusive,
            customer_country: tx_data.customer_country.clone(),
            transaction_type: TransactionType::Renewal,
            parent_transaction_id: None,
            is_subscription: true,
            source: "payment".to_string(),
            metadata: None,
            test_mode: tx_data.test_mode,
        }
    });

    // Process renewal ATOMICALLY - replay prevention, license extension, and
    // transaction creation all happen in a single database transaction.
    // If any step fails, everything is rolled back and payment provider can retry.
    let renewal_result = process_renewal_atomic(
        &mut conn,
        provider.provider_name(),
        &product,
        &license,
        &data.subscription_id,
        data.event_id.as_deref(),
        data.period_end,
        transaction_data.as_ref(),
    )?;

    // Determine the result for response and post-processing
    let (result, license_exp) = match renewal_result {
        RenewalResult::AlreadyProcessed => {
            return Ok((StatusCode::OK, "Already processed"));
        }
        RenewalResult::Success { license_exp } => {
            ((StatusCode::OK, "OK"), license_exp)
        }
    };

    // Fire-and-forget sales metering event (only on new successful renewal)
    if let Some(tx_data) = &data.transaction {
        spawn_sales_metering(
            state.http_client.clone(),
            state.metering_webhook_url.clone(),
            SalesMeteringEvent {
                event: "renewal".to_string(),
                org_id: org.id.clone(),
                project_id: project.id.clone(),
                product_id: license.product_id.clone(),
                license_id: license.id.clone(),
                transaction_id: data.event_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                payment_provider: provider.provider_name().to_string(),
                amount_cents: tx_data.total_cents,
                currency: tx_data.currency.clone(),
                timestamp: chrono::Utc::now().timestamp(),
            },
        );
    }

    // Audit log on successful renewal
    let audit_conn = state.audit.get().map_err(|e| {
        tracing::error!("Audit DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    if let Err(e) = AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, headers)
        .actor(ActorType::Public, None)
        .action(AuditAction::ReceiveRenewalWebhook)
        .resource("license", &license.id)
        .details(&serde_json::json!({
            "provider": provider.provider_name(),
            "subscription_id": data.subscription_id,
            "event_id": data.event_id,
            "product_id": product.id,
            "new_expires_at": license_exp,
            "period_end_from_provider": data.period_end.is_some(),
        }))
        .org(&org.id)
        .project(&project.id)
        .names(&AuditLogNames {
            org_name: Some(org.name.clone()),
            project_name: Some(project.name.clone()),
            ..Default::default()
        })
        .save()
    {
        tracing::warn!("Failed to write renewal audit log: {}", e);
    }

    Ok(result)
}

async fn handle_cancellation<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    signature: &str,
    data: CancellationData,
) -> Result<WebhookResult, WebhookResult> {
    let conn = state.db.get().map_err(|e| {
        tracing::error!("DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    let license = lookup_license_by_subscription(provider, &conn, &data.subscription_id)?;
    let product = db_lookup(
        queries::get_product_by_id(&conn, &license.product_id),
        "Product not found",
    )?;
    let project = db_lookup(
        queries::get_project_by_id(&conn, &product.project_id),
        "Project not found",
    )?;
    let org = db_lookup(
        queries::get_organization_by_id(&conn, &project.org_id),
        "Organization not found",
    )?;

    // Verify signature using hierarchical config (project first, then org)
    match provider.verify_signature(&conn, &project, &org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Invalid signature")),
        Err(e) => return Err(e),
    }

    let result = process_cancellation(
        provider.provider_name(),
        &license.id,
        license.expires_at,
        &data.subscription_id,
    );

    // Audit log on successful cancellation
    if result.0 == StatusCode::OK {
        let audit_conn = state.audit.get().map_err(|e| {
            tracing::error!("Audit DB connection error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        })?;

        if let Err(e) = AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, headers)
            .actor(ActorType::Public, None)
            .action(AuditAction::ReceiveCancellationWebhook)
            .resource("license", &license.id)
            .details(&serde_json::json!({
                "provider": provider.provider_name(),
                "subscription_id": data.subscription_id,
                "product_id": product.id,
                "expires_at": license.expires_at,
            }))
            .org(&org.id)
            .project(&project.id)
            .names(&AuditLogNames {
                org_name: Some(org.name.clone()),
                project_name: Some(project.name.clone()),
                ..Default::default()
            })
            .save()
        {
            tracing::warn!("Failed to write cancellation audit log: {}", e);
        }
    }

    Ok(result)
}

async fn handle_refund<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    signature: &str,
    data: RefundData,
) -> Result<WebhookResult, WebhookResult> {
    let mut conn = state.db.get().map_err(|e| {
        tracing::error!("DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    // Look up the original transaction by order_id to find the license
    let original_transaction = match queries::get_transaction_by_provider_order(
        &conn,
        provider.provider_name(),
        &data.order_id,
    ) {
        Ok(Some(t)) => t,
        Ok(None) => {
            tracing::warn!(
                "No transaction found for {} order_id: {} - refund cannot be linked",
                provider.provider_name(),
                data.order_id
            );
            // Return OK to prevent retries - we can't link this refund to a transaction
            return Ok((StatusCode::OK, "Original transaction not found"));
        }
        Err(e) => {
            tracing::error!("DB error looking up transaction: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
        }
    };

    // Get the license, project, and org for signature verification
    let license = match &original_transaction.license_id {
        Some(license_id) => db_lookup(
            queries::get_license_by_id(&conn, license_id),
            "License not found",
        )?,
        None => {
            tracing::warn!(
                "Original transaction {} has no license_id - refund will be recorded without license link",
                original_transaction.id
            );
            // We can still record the refund, just without a license link
            // But we need project/org for signature verification
            let project = db_lookup(
                queries::get_project_by_id(&conn, &original_transaction.project_id),
                "Project not found",
            )?;
            let org = db_lookup(
                queries::get_organization_by_id(&conn, &project.org_id),
                "Organization not found",
            )?;

            // Verify signature
            match provider.verify_signature(&conn, &project, &org, &state.master_key, body, signature) {
                Ok(true) => {}
                Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Invalid signature")),
                Err(e) => return Err(e),
            }

            // Process refund without license (needs mutable conn for atomic processing)
            return process_refund_no_license(
                provider,
                state,
                headers,
                &mut conn,
                &data,
                &original_transaction,
                &project,
                &org,
            );
        }
    };

    let product = db_lookup(
        queries::get_product_by_id(&conn, &license.product_id),
        "Product not found",
    )?;
    let project = db_lookup(
        queries::get_project_by_id(&conn, &product.project_id),
        "Project not found",
    )?;
    let org = db_lookup(
        queries::get_organization_by_id(&conn, &project.org_id),
        "Organization not found",
    )?;

    // Verify signature using hierarchical config (project first, then org)
    match provider.verify_signature(&conn, &project, &org, &state.master_key, body, signature) {
        Ok(true) => {}
        Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Invalid signature")),
        Err(e) => return Err(e),
    }

    // Build refund transaction record (negative amounts)
    let transaction = CreateTransaction {
        license_id: Some(license.id.clone()),
        project_id: project.id.clone(),
        product_id: Some(license.product_id.clone()),
        org_id: org.id.clone(),
        payment_provider: provider.provider_name().to_string(),
        provider_customer_id: license.customer_id.clone(),
        provider_subscription_id: original_transaction.provider_subscription_id.clone(),
        provider_order_id: data.refund_id.clone(),
        currency: data.currency.clone(),
        subtotal_cents: -(data.amount_cents),
        discount_cents: 0,
        net_cents: -(data.amount_cents),
        tax_cents: 0,
        total_cents: -(data.amount_cents),
        discount_code: None,
        tax_inclusive: None,
        customer_country: original_transaction.customer_country.clone(),
        transaction_type: TransactionType::Refund,
        parent_transaction_id: Some(original_transaction.id.clone()),
        is_subscription: original_transaction.is_subscription,
        source: data.source.clone(),
        metadata: data.metadata.clone(),
        test_mode: data.test_mode,
    };

    // Process refund ATOMICALLY - replay prevention and transaction creation
    // happen in a single database transaction.
    let refund_result = process_refund_atomic(
        &mut conn,
        provider.provider_name(),
        &data.refund_id,
        &transaction,
    )?;

    if matches!(refund_result, RefundResult::AlreadyProcessed) {
        return Ok((StatusCode::OK, "Already processed"));
    }

    tracing::info!(
        "{} refund processed: refund_id={}, order_id={}, license_id={}, amount={} {}",
        provider.provider_name(),
        data.refund_id,
        data.order_id,
        license.id,
        data.amount_cents,
        data.currency
    );

    // Determine metering event type based on source
    let metering_event = match data.source.as_str() {
        "dispute" => "dispute",
        "dispute_reversal" => "dispute_reversal",
        _ => "refund",
    };

    // Fire-and-forget sales metering event
    spawn_sales_metering(
        state.http_client.clone(),
        state.metering_webhook_url.clone(),
        SalesMeteringEvent {
            event: metering_event.to_string(),
            org_id: org.id.clone(),
            project_id: project.id.clone(),
            product_id: license.product_id.clone(),
            license_id: license.id.clone(),
            transaction_id: data.refund_id.clone(),
            payment_provider: provider.provider_name().to_string(),
            amount_cents: -(data.amount_cents), // Negative for refunds/disputes
            currency: data.currency.clone(),
            timestamp: chrono::Utc::now().timestamp(),
        },
    );

    // Determine audit action based on source
    let audit_action = match data.source.as_str() {
        "dispute" | "dispute_reversal" => AuditAction::ReceiveDisputeWebhook,
        _ => AuditAction::ReceiveRefundWebhook,
    };

    // Audit log
    let audit_conn = state.audit.get().map_err(|e| {
        tracing::error!("Audit DB connection error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
    })?;

    if let Err(e) = AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, headers)
        .actor(ActorType::Public, None)
        .action(audit_action)
        .resource("license", &license.id)
        .details(&serde_json::json!({
            "provider": provider.provider_name(),
            "refund_id": data.refund_id,
            "order_id": data.order_id,
            "amount_cents": data.amount_cents,
            "currency": data.currency,
            "product_id": license.product_id,
            "parent_transaction_id": original_transaction.id,
        }))
        .org(&org.id)
        .project(&project.id)
        .names(&AuditLogNames {
            org_name: Some(org.name.clone()),
            project_name: Some(project.name.clone()),
            ..Default::default()
        })
        .save()
    {
        tracing::warn!("Failed to write refund audit log: {}", e);
    }

    Ok((StatusCode::OK, "OK"))
}

/// Helper for processing refunds when we can't find a linked license.
/// Still records the transaction for revenue tracking.
fn process_refund_no_license<P: WebhookProvider>(
    provider: &P,
    state: &AppState,
    headers: &HeaderMap,
    conn: &mut Connection,
    data: &RefundData,
    original_transaction: &crate::models::Transaction,
    project: &Project,
    org: &Organization,
) -> Result<WebhookResult, WebhookResult> {
    // Build refund transaction without license link
    let transaction = CreateTransaction {
        license_id: None,
        project_id: project.id.clone(),
        product_id: original_transaction.product_id.clone(),
        org_id: org.id.clone(),
        payment_provider: provider.provider_name().to_string(),
        provider_customer_id: original_transaction.provider_customer_id.clone(),
        provider_subscription_id: original_transaction.provider_subscription_id.clone(),
        provider_order_id: data.refund_id.clone(),
        currency: data.currency.clone(),
        subtotal_cents: -(data.amount_cents),
        discount_cents: 0,
        net_cents: -(data.amount_cents),
        tax_cents: 0,
        total_cents: -(data.amount_cents),
        discount_code: None,
        tax_inclusive: None,
        customer_country: original_transaction.customer_country.clone(),
        transaction_type: TransactionType::Refund,
        parent_transaction_id: Some(original_transaction.id.clone()),
        is_subscription: original_transaction.is_subscription,
        source: data.source.clone(),
        metadata: data.metadata.clone(),
        test_mode: data.test_mode,
    };

    // Process refund ATOMICALLY - replay prevention and transaction creation
    // happen in a single database transaction.
    let refund_result = process_refund_atomic(
        conn,
        provider.provider_name(),
        &data.refund_id,
        &transaction,
    )?;

    if matches!(refund_result, RefundResult::AlreadyProcessed) {
        return Ok((StatusCode::OK, "Already processed"));
    }

    tracing::info!(
        "{} refund processed (no license link): refund_id={}, order_id={}, amount={} {}",
        provider.provider_name(),
        data.refund_id,
        data.order_id,
        data.amount_cents,
        data.currency
    );

    // Determine metering event type based on source
    let metering_event = match data.source.as_str() {
        "dispute" => "dispute",
        "dispute_reversal" => "dispute_reversal",
        _ => "refund",
    };

    // Fire metering event (without license_id)
    spawn_sales_metering(
        state.http_client.clone(),
        state.metering_webhook_url.clone(),
        SalesMeteringEvent {
            event: metering_event.to_string(),
            org_id: org.id.clone(),
            project_id: project.id.clone(),
            product_id: original_transaction.product_id.clone().unwrap_or_default(),
            license_id: String::new(),
            transaction_id: data.refund_id.clone(),
            payment_provider: provider.provider_name().to_string(),
            amount_cents: -(data.amount_cents),
            currency: data.currency.clone(),
            timestamp: chrono::Utc::now().timestamp(),
        },
    );

    // Determine audit action based on source
    let audit_action = match data.source.as_str() {
        "dispute" | "dispute_reversal" => AuditAction::ReceiveDisputeWebhook,
        _ => AuditAction::ReceiveRefundWebhook,
    };

    // Audit log
    if let Ok(audit_conn) = state.audit.get() {
        let _ = AuditLogBuilder::new(&audit_conn, state.audit_log_enabled, headers)
            .actor(ActorType::Public, None)
            .action(audit_action)
            .resource("transaction", &original_transaction.id)
            .details(&serde_json::json!({
                "provider": provider.provider_name(),
                "refund_id": data.refund_id,
                "order_id": data.order_id,
                "amount_cents": data.amount_cents,
                "currency": data.currency,
                "parent_transaction_id": original_transaction.id,
                "source": data.source,
                "no_license_link": true,
            }))
            .org(&org.id)
            .project(&project.id)
            .names(&AuditLogNames {
                org_name: Some(org.name.clone()),
                project_name: Some(project.name.clone()),
                ..Default::default()
            })
            .save();
    }

    Ok((StatusCode::OK, "OK"))
}