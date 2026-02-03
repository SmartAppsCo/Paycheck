use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use rusqlite::Connection;

use crate::crypto::MasterKey;
use crate::db::{AppState, queries};
use crate::models::{Organization, Project};
use crate::payments::{
    StripeCheckoutSession, StripeClient, StripeDispute, StripeInvoice, StripeRefundEvent,
    StripeSubscription, StripeWebhookEvent,
};

use super::common::{
    CancellationData, CheckoutData, CheckoutTransactionData, RefundData, RenewalData, WebhookEvent,
    WebhookProvider, WebhookResult, handle_webhook,
};

/// Enrich a Stripe transaction with data that requires API calls.
/// This runs as a background task after the webhook handler returns.
///
/// - `checkout_session_id`: Stripe checkout session ID (cs_xxx) for API calls
/// - `provider_order_id`: Payment intent ID (pi_xxx) for DB lookup
async fn enrich_stripe_transaction(
    state: &AppState,
    project_id: &str,
    org_id: &str,
    checkout_session_id: &str,
    provider_order_id: &str,
) {
    // Get DB connection
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Stripe enricher: failed to get DB connection: {}", e);
            return;
        }
    };

    // Load project and org for config lookup
    let project = match queries::get_project_by_id(&conn, project_id) {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::warn!("Stripe enricher: project not found: {}", project_id);
            return;
        }
        Err(e) => {
            tracing::warn!("Stripe enricher: failed to load project: {}", e);
            return;
        }
    };

    let org = match queries::get_organization_by_id(&conn, org_id) {
        Ok(Some(o)) => o,
        Ok(None) => {
            tracing::warn!("Stripe enricher: org not found: {}", org_id);
            return;
        }
        Err(e) => {
            tracing::warn!("Stripe enricher: failed to load org: {}", e);
            return;
        }
    };

    // Get Stripe config
    let stripe_config = match queries::get_stripe_config_for_webhook(&conn, &project, &org, &state.master_key) {
        Ok(Some((config, _))) => config,
        Ok(None) => {
            tracing::warn!("Stripe enricher: no Stripe config found");
            return;
        }
        Err(e) => {
            tracing::warn!("Stripe enricher: failed to get Stripe config: {}", e);
            return;
        }
    };

    // Fetch discount code from Stripe API
    let client = StripeClient::new(&stripe_config);
    let discount_code = match client.get_checkout_session_discounts(checkout_session_id).await {
        Ok(Some(code)) => code,
        Ok(None) => {
            // No discount code - nothing to enrich
            return;
        }
        Err(e) => {
            tracing::warn!("Stripe enricher: failed to fetch discounts: {}", e);
            return;
        }
    };

    // Update the transaction with the discount code.
    // Uses provider_order_id (payment_intent) since that's how transactions are stored.
    if let Err(e) = queries::update_transaction_discount_code(&conn, provider_order_id, &discount_code) {
        tracing::warn!("Stripe enricher: failed to update transaction: {}", e);
        return;
    }

    tracing::info!(
        "Stripe enricher: updated transaction {} with discount code {} (session: {})",
        provider_order_id,
        discount_code,
        checkout_session_id
    );
}

/// Stripe webhook provider implementation.
pub struct StripeWebhookProvider;

impl WebhookProvider for StripeWebhookProvider {
    fn provider_name(&self) -> &'static str {
        "stripe"
    }

    fn extract_signature(&self, headers: &HeaderMap) -> Result<String, WebhookResult> {
        headers
            .get("stripe-signature")
            .ok_or((StatusCode::BAD_REQUEST, "Missing stripe-signature header"))?
            .to_str()
            .map(|s| s.to_string())
            .map_err(|e| {
                tracing::debug!("Invalid UTF-8 in Stripe signature header: {}", e);
                (StatusCode::BAD_REQUEST, "Invalid signature header")
            })
    }

    fn verify_signature(
        &self,
        conn: &Connection,
        project: &Project,
        org: &Organization,
        master_key: &MasterKey,
        body: &Bytes,
        signature: &str,
    ) -> Result<bool, WebhookResult> {
        // Handle both missing and corrupted configs gracefully by returning 200 OK.
        // This prevents payment providers from retrying indefinitely on 5xx errors
        // and avoids leaking internal state about config status.
        // Uses 2-level lookup for webhooks: project → org (no product context in webhooks).
        let stripe_config = match queries::get_stripe_config_for_webhook(conn, project, org, master_key) {
            Ok(Some((config, _source))) => config,
            Ok(None) => return Err((StatusCode::OK, "Stripe not configured")),
            Err(e) => {
                tracing::error!("Failed to decrypt Stripe config for project {} / org {}: {}", project.id, org.id, e);
                // Return OK to prevent retry storms - treat corrupted config as unusable
                return Err((StatusCode::OK, "Stripe config unavailable"));
            }
        };

        let client = StripeClient::new(&stripe_config);
        client
            .verify_webhook_signature(body, signature)
            .map_err(|e| {
                tracing::error!("Signature verification error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Signature verification failed",
                )
            })
    }

    fn parse_event(&self, body: &Bytes) -> Result<WebhookEvent, WebhookResult> {
        let event: StripeWebhookEvent = serde_json::from_slice(body).map_err(|e| {
            tracing::error!("Failed to parse Stripe webhook: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid JSON")
        })?;

        match event.event_type.as_str() {
            "checkout.session.completed" => parse_checkout_completed(&event),
            "invoice.paid" => parse_invoice_paid(&event),
            "customer.subscription.deleted" => parse_subscription_deleted(&event),
            "refund.created" => parse_refund_created(&event),
            "charge.dispute.created" => parse_dispute_created(&event),
            "charge.dispute.closed" => parse_dispute_closed(&event),
            _ => Ok(WebhookEvent::Ignored),
        }
    }

    fn spawn_enricher(
        &self,
        state: AppState,
        project_id: String,
        org_id: String,
        provider_order_id: String,
        enricher_session_id: Option<String>,
    ) {
        // enricher_session_id is the checkout session ID (cs_xxx) for Stripe API calls.
        // provider_order_id is the payment_intent (pi_xxx) for DB lookup.
        let checkout_session_id = match enricher_session_id {
            Some(id) => id,
            None => {
                tracing::warn!(
                    "Stripe enricher called without checkout_session_id, skipping enrichment"
                );
                return;
            }
        };

        tokio::spawn(async move {
            enrich_stripe_transaction(
                &state,
                &project_id,
                &org_id,
                &checkout_session_id,  // For Stripe API call
                &provider_order_id,    // For DB lookup
            )
            .await;
        });
    }
}

fn parse_checkout_completed(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let session: StripeCheckoutSession = serde_json::from_value(event.data.object.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse checkout session: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid checkout session")
        })?;

    // Check payment status
    if session.payment_status != "paid" {
        return Ok(WebhookEvent::Ignored);
    }

    let session_id = session
        .metadata
        .paycheck_session_id
        .ok_or((StatusCode::OK, "No paycheck session ID"))?;
    let project_id = session
        .metadata
        .project_id
        .ok_or((StatusCode::OK, "No project ID"))?;

    // Get email and address from customer_details (entered during checkout)
    let (customer_email, customer_country) = session
        .customer_details
        .as_ref()
        .map(|d| {
            let country = d.address.as_ref().and_then(|a| a.country.clone());
            (d.email.clone(), country)
        })
        .unwrap_or((None, None));

    // Extract transaction data if available
    let transaction = match (session.currency, session.amount_total) {
        (Some(currency), Some(total)) => {
            let subtotal = session.amount_subtotal.unwrap_or(total);
            let (discount, tax) = session
                .total_details
                .as_ref()
                .map(|d| {
                    (
                        d.amount_discount.unwrap_or(0),
                        d.amount_tax.unwrap_or(0),
                    )
                })
                .unwrap_or((0, 0));

            Some(CheckoutTransactionData {
                currency: currency.to_lowercase(),
                subtotal_cents: subtotal,
                discount_cents: discount,
                tax_cents: tax,
                total_cents: total,
                tax_inclusive: None, // Stripe doesn't provide this directly
                discount_code: None, // Would need to fetch from Stripe API
                customer_country,
                test_mode: session.livemode.map(|l| !l).unwrap_or(false),
            })
        }
        _ => None,
    };

    // Capture checkout session ID for enricher API calls (e.g., fetching discount codes).
    // This must be extracted before session.id is potentially consumed by order_id fallback.
    let enricher_session_id = Some(session.id.clone());

    // Use payment_intent as order_id for refund linkage.
    // Refunds come with payment_intent ID, so we need to store that at checkout.
    // For subscription mode (no payment_intent), fall back to session.id.
    let order_id = session.payment_intent.or(Some(session.id));

    Ok(WebhookEvent::CheckoutCompleted(CheckoutData {
        session_id,
        project_id,
        customer_id: session.customer,
        customer_email,
        subscription_id: session.subscription,
        order_id,
        enricher_session_id,
        transaction,
    }))
}

fn parse_invoice_paid(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let invoice: StripeInvoice =
        serde_json::from_value(event.data.object.clone()).map_err(|e| {
            tracing::error!("Failed to parse invoice: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid invoice")
        })?;

    // Extract period_end before any moves
    let period_end = invoice.period_end();

    let subscription_id = match invoice.subscription.clone() {
        Some(id) => id,
        None => return Ok(WebhookEvent::Ignored),
    };

    // Determine if this is a renewal
    let is_renewal = match invoice.billing_reason.as_deref() {
        Some("subscription_cycle") | Some("subscription_update") => true,
        Some("subscription_create") => false,
        _ => return Ok(WebhookEvent::Ignored),
    };

    // Extract transaction data for revenue tracking
    let transaction = match (invoice.currency.as_ref(), invoice.total) {
        (Some(currency), Some(total)) => {
            let subtotal = invoice.subtotal.unwrap_or(total);
            let tax = invoice.tax.unwrap_or(0);
            // Use total_discount_amounts from Stripe instead of calculating.
            // The old calculation (subtotal + tax - total) assumed additive tax,
            // which breaks for inclusive tax (common in EU) - it double-counts tax.
            let discount = invoice.total_discount();

            Some(CheckoutTransactionData {
                currency: currency.to_lowercase(),
                subtotal_cents: subtotal,
                discount_cents: discount,
                tax_cents: tax,
                total_cents: total,
                tax_inclusive: None,
                discount_code: None, // Would need API call to fetch
                customer_country: None, // Not in invoice
                test_mode: invoice.livemode.map(|l| !l).unwrap_or(false),
            })
        }
        _ => None,
    };

    Ok(WebhookEvent::SubscriptionRenewed(RenewalData {
        subscription_id,
        is_renewal,
        is_paid: invoice.status == "paid",
        // Use invoice ID as unique event identifier for replay prevention
        event_id: Some(invoice.id),
        // Use payment_intent for refund linkage - refunds reference this ID
        payment_intent: invoice.payment_intent,
        // Use Stripe's billing period end for accurate expiration
        period_end,
        transaction,
    }))
}

/// Parse refund.created event - Stripe's recommended way to handle refunds.
/// Each refund.created event contains exactly one refund, making it ideal for
/// tracking partial refunds correctly.
fn parse_refund_created(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let refund: StripeRefundEvent =
        serde_json::from_value(event.data.object.clone()).map_err(|e| {
            tracing::error!("Failed to parse refund: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid refund")
        })?;

    // Only process succeeded refunds
    if refund.status != "succeeded" {
        return Err((StatusCode::OK, "Refund not succeeded"));
    }

    // Prefer payment_intent for order linkage, fall back to charge ID
    let order_id = refund
        .payment_intent
        .or(refund.charge)
        .ok_or_else(|| {
            tracing::error!("Refund {} has no payment_intent or charge", refund.id);
            (StatusCode::BAD_REQUEST, "Refund missing payment reference")
        })?;

    Ok(WebhookEvent::Refunded(RefundData {
        license_id: None, // Will be looked up via order_id
        refund_id: refund.id,
        order_id,
        currency: refund.currency.to_lowercase(),
        amount_cents: refund.amount,
        test_mode: !refund.livemode,
        source: "refund".to_string(),
        metadata: None,
    }))
}

fn parse_dispute_created(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let dispute: StripeDispute = serde_json::from_value(event.data.object.clone()).map_err(|e| {
        tracing::error!("Failed to parse dispute: {}", e);
        (StatusCode::BAD_REQUEST, "Invalid dispute")
    })?;

    // Build metadata JSON with dispute details
    let metadata = serde_json::json!({
        "dispute_id": dispute.id,
        "reason": dispute.reason,
    });

    Ok(WebhookEvent::Refunded(RefundData {
        license_id: None, // Will be looked up via payment_intent
        refund_id: dispute.id.clone(), // Use dispute ID for idempotency
        order_id: dispute.payment_intent.unwrap_or_else(|| dispute.charge.clone()),
        currency: dispute.currency.to_lowercase(),
        amount_cents: dispute.amount,
        test_mode: !dispute.livemode,
        source: "dispute".to_string(),
        metadata: Some(metadata.to_string()),
    }))
}

fn parse_dispute_closed(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let dispute: StripeDispute = serde_json::from_value(event.data.object.clone()).map_err(|e| {
        tracing::error!("Failed to parse dispute: {}", e);
        (StatusCode::BAD_REQUEST, "Invalid dispute")
    })?;

    // Only create a reversal transaction if the dispute was won
    if dispute.status != "won" {
        // Lost disputes: audit log only, no financial reversal needed
        // (The original dispute debit already took the money)
        tracing::info!(
            "Stripe dispute closed with status '{}': dispute_id={}, amount={}",
            dispute.status,
            dispute.id,
            dispute.amount
        );
        return Ok(WebhookEvent::Ignored);
    }

    // Dispute won - create a positive reversal transaction
    let metadata = serde_json::json!({
        "dispute_id": dispute.id,
    });

    // Use a different ID for the reversal to avoid idempotency collision with the original dispute
    let reversal_id = format!("{}_reversal", dispute.id);

    Ok(WebhookEvent::Refunded(RefundData {
        license_id: None,
        refund_id: reversal_id,
        order_id: dispute.payment_intent.unwrap_or_else(|| dispute.charge.clone()),
        currency: dispute.currency.to_lowercase(),
        amount_cents: -(dispute.amount), // Negative to create positive transaction (reversal)
        test_mode: !dispute.livemode,
        source: "dispute_reversal".to_string(),
        metadata: Some(metadata.to_string()),
    }))
}

fn parse_subscription_deleted(event: &StripeWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let subscription: StripeSubscription = serde_json::from_value(event.data.object.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse subscription: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid subscription")
        })?;

    Ok(WebhookEvent::SubscriptionCancelled(CancellationData {
        subscription_id: subscription.id,
    }))
}

/// Axum handler for Stripe webhooks.
pub async fn handle_stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    handle_webhook(&StripeWebhookProvider, &state, headers, body).await
}
