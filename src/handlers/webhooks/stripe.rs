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
    StripeCheckoutSession, StripeClient, StripeInvoice, StripeSubscription, StripeWebhookEvent,
};

use super::common::{
    CancellationData, CheckoutData, CheckoutTransactionData, RenewalData, WebhookEvent,
    WebhookProvider, WebhookResult, handle_webhook,
};

/// Enrich a Stripe transaction with data that requires API calls.
/// This runs as a background task after the webhook handler returns.
async fn enrich_stripe_transaction(
    state: &AppState,
    project_id: &str,
    org_id: &str,
    checkout_session_id: &str,
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

    // Update the transaction with the discount code
    if let Err(e) = queries::update_transaction_discount_code(&conn, checkout_session_id, &discount_code) {
        tracing::warn!("Stripe enricher: failed to update transaction: {}", e);
        return;
    }

    tracing::info!(
        "Stripe enricher: updated transaction {} with discount code {}",
        checkout_session_id,
        discount_code
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
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature header"))
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
            _ => Ok(WebhookEvent::Ignored),
        }
    }

    fn spawn_enricher(
        &self,
        state: AppState,
        project_id: String,
        org_id: String,
        provider_order_id: String,
    ) {
        tokio::spawn(async move {
            enrich_stripe_transaction(&state, &project_id, &org_id, &provider_order_id).await;
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

    Ok(WebhookEvent::CheckoutCompleted(CheckoutData {
        session_id,
        project_id,
        customer_id: session.customer,
        customer_email,
        subscription_id: session.subscription,
        order_id: Some(session.id),
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

    let subscription_id = match invoice.subscription {
        Some(id) => id,
        None => return Ok(WebhookEvent::Ignored),
    };

    // Determine if this is a renewal
    let is_renewal = match invoice.billing_reason.as_deref() {
        Some("subscription_cycle") | Some("subscription_update") => true,
        Some("subscription_create") => false,
        _ => return Ok(WebhookEvent::Ignored),
    };

    Ok(WebhookEvent::SubscriptionRenewed(RenewalData {
        subscription_id,
        is_renewal,
        is_paid: invoice.status == "paid",
        // Use invoice ID as unique event identifier for replay prevention
        event_id: Some(invoice.id),
        // Use Stripe's billing period end for accurate expiration
        period_end,
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
