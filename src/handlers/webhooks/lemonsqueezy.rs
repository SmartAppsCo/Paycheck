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
    LemonSqueezyClient, LemonSqueezyOrderAttributes, LemonSqueezyRefundAttributes,
    LemonSqueezySubscriptionInvoiceAttributes, LemonSqueezySubscriptionInvoiceRefundAttributes,
    LemonSqueezyWebhookEvent,
};

use super::common::{
    CancellationData, CheckoutData, CheckoutTransactionData, RefundData, RenewalData, WebhookEvent,
    WebhookProvider, WebhookResult, handle_webhook,
};

/// LemonSqueezy webhook provider implementation.
pub struct LemonSqueezyWebhookProvider;

impl WebhookProvider for LemonSqueezyWebhookProvider {
    fn provider_name(&self) -> &'static str {
        "lemonsqueezy"
    }

    fn extract_signature(&self, headers: &HeaderMap) -> Result<String, WebhookResult> {
        headers
            .get("x-signature")
            .ok_or((StatusCode::BAD_REQUEST, "Missing x-signature header"))?
            .to_str()
            .map(|s| s.to_string())
            .map_err(|e| {
                tracing::debug!("Invalid UTF-8 in LemonSqueezy signature header: {}", e);
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
        let ls_config = match queries::get_ls_config_for_webhook(conn, project, org, master_key) {
            Ok(Some((config, _source))) => config,
            Ok(None) => return Err((StatusCode::OK, "LemonSqueezy not configured")),
            Err(e) => {
                tracing::error!(
                    "Failed to decrypt LemonSqueezy config for project {} / org {}: {}",
                    project.id,
                    org.id,
                    e
                );
                // Return OK to prevent retry storms - treat corrupted config as unusable
                return Err((StatusCode::OK, "LemonSqueezy config unavailable"));
            }
        };

        let client = LemonSqueezyClient::new(&ls_config);
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
        let event: LemonSqueezyWebhookEvent = serde_json::from_slice(body).map_err(|e| {
            tracing::error!("Failed to parse LemonSqueezy webhook: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid JSON")
        })?;

        match event.meta.event_name.as_str() {
            "order_created" => parse_order_created(&event),
            "subscription_payment_success" => parse_subscription_payment(&event),
            "subscription_cancelled" => parse_subscription_cancelled(&event),
            "order_refunded" => parse_order_refunded(&event),
            "subscription_payment_refunded" => parse_subscription_payment_refunded(&event),
            _ => Ok(WebhookEvent::Ignored),
        }
    }
}

fn parse_order_created(event: &LemonSqueezyWebhookEvent) -> Result<WebhookEvent, WebhookResult> {
    let order: LemonSqueezyOrderAttributes = serde_json::from_value(event.data.attributes.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse order attributes: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid order attributes")
        })?;

    // Check order status
    if order.status != "paid" {
        return Ok(WebhookEvent::Ignored);
    }

    let custom_data = event
        .meta
        .custom_data
        .as_ref()
        .ok_or((StatusCode::OK, "No custom data"))?;

    let session_id = custom_data
        .paycheck_session_id
        .clone()
        .ok_or((StatusCode::OK, "No paycheck session ID"))?;
    let project_id = custom_data
        .project_id
        .clone()
        .ok_or((StatusCode::OK, "No project ID"))?;

    // Extract subscription ID if this is a subscription order
    let subscription_id = order
        .first_order_item
        .as_ref()
        .and_then(|item| item.subscription_id)
        .map(|id| id.to_string());

    // Extract transaction data if available
    let transaction = match (order.currency.as_ref(), order.total) {
        (Some(currency), Some(total)) => {
            let subtotal = order.subtotal.unwrap_or(total);
            let discount = order.discount_total.unwrap_or(0);
            let tax = order.tax.unwrap_or(0);

            Some(CheckoutTransactionData {
                currency: currency.to_lowercase(),
                subtotal_cents: subtotal,
                discount_cents: discount,
                tax_cents: tax,
                total_cents: total,
                tax_inclusive: order.tax_inclusive,
                discount_code: order.discount_code.clone(),
                customer_country: order.user_country.clone(),
                test_mode: order.test_mode.unwrap_or(false),
            })
        }
        _ => None,
    };

    Ok(WebhookEvent::CheckoutCompleted(CheckoutData {
        session_id,
        project_id,
        customer_id: order.customer_id.map(|id| id.to_string()),
        customer_email: order.user_email,
        subscription_id,
        order_id: Some(event.data.id.clone()),
        enricher_session_id: None, // LemonSqueezy doesn't need API enrichment
        transaction,
    }))
}

fn parse_subscription_payment(
    event: &LemonSqueezyWebhookEvent,
) -> Result<WebhookEvent, WebhookResult> {
    let invoice: LemonSqueezySubscriptionInvoiceAttributes =
        serde_json::from_value(event.data.attributes.clone()).map_err(|e| {
            tracing::error!("Failed to parse subscription invoice: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid subscription invoice")
        })?;

    // Extract transaction data for revenue tracking
    let transaction = match (invoice.currency.as_ref(), invoice.total) {
        (Some(currency), Some(total)) => {
            let subtotal = invoice.subtotal.unwrap_or(total);
            let discount = invoice.discount_total.unwrap_or(0);
            let tax = invoice.tax.unwrap_or(0);

            Some(CheckoutTransactionData {
                currency: currency.to_lowercase(),
                subtotal_cents: subtotal,
                discount_cents: discount,
                tax_cents: tax,
                total_cents: total,
                tax_inclusive: None,
                discount_code: None,
                customer_country: None,
                test_mode: invoice.test_mode.unwrap_or(false),
            })
        }
        _ => None,
    };

    Ok(WebhookEvent::SubscriptionRenewed(RenewalData {
        subscription_id: invoice.subscription_id.to_string(),
        // LemonSqueezy subscription_payment_success is always a renewal
        // Initial payment comes via order_created
        is_renewal: true,
        is_paid: invoice.status == "paid",
        // Use invoice ID (data.id) as unique event identifier for replay prevention
        event_id: Some(event.data.id.clone()),
        // LemonSqueezy uses order_id for refund linkage, not payment_intent
        payment_intent: None,
        // Use LemonSqueezy's billing period end for accurate expiration
        period_end: invoice.period_end_timestamp(),
        transaction,
    }))
}

fn parse_order_refunded(
    event: &LemonSqueezyWebhookEvent,
) -> Result<WebhookEvent, WebhookResult> {
    let refund: LemonSqueezyRefundAttributes =
        serde_json::from_value(event.data.attributes.clone()).map_err(|e| {
            tracing::error!("Failed to parse refund attributes: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid refund attributes")
        })?;

    // Only process successful refunds
    if refund.status != "succeeded" && refund.status != "refunded" {
        return Ok(WebhookEvent::Ignored);
    }

    Ok(WebhookEvent::Refunded(RefundData {
        license_id: None, // Will be looked up via order_id
        refund_id: event.data.id.clone(),
        order_id: refund.order_id.to_string(),
        currency: refund.currency.to_lowercase(),
        amount_cents: refund.amount,
        test_mode: refund.test_mode.unwrap_or(false),
        source: "refund".to_string(),
        metadata: None,
    }))
}

fn parse_subscription_cancelled(
    event: &LemonSqueezyWebhookEvent,
) -> Result<WebhookEvent, WebhookResult> {
    // For subscription events, the subscription ID is in data.id
    Ok(WebhookEvent::SubscriptionCancelled(CancellationData {
        subscription_id: event.data.id.clone(),
    }))
}

/// Parse subscription_payment_refunded event.
///
/// LemonSqueezy sends this when a subscription invoice payment is refunded.
/// The data.id is the subscription invoice ID, which matches the ID stored
/// from subscription_payment_success (used as provider_order_id in transactions).
fn parse_subscription_payment_refunded(
    event: &LemonSqueezyWebhookEvent,
) -> Result<WebhookEvent, WebhookResult> {
    let invoice: LemonSqueezySubscriptionInvoiceRefundAttributes =
        serde_json::from_value(event.data.attributes.clone()).map_err(|e| {
            tracing::error!("Failed to parse subscription invoice refund attributes: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid subscription invoice refund attributes")
        })?;

    // Only process completed refunds
    if invoice.status != "refunded" {
        return Ok(WebhookEvent::Ignored);
    }

    // Use invoice ID (data.id) as order_id for transaction lookup.
    // This matches how subscription_payment_success stores the invoice ID.
    let amount = invoice.total.unwrap_or(0);
    let currency = invoice.currency.as_deref().unwrap_or("usd").to_lowercase();

    Ok(WebhookEvent::Refunded(RefundData {
        license_id: None, // Will be looked up via invoice_id (order_id)
        refund_id: event.data.id.clone(), // Invoice ID as unique refund identifier
        order_id: event.data.id.clone(),  // Invoice ID for transaction lookup
        currency,
        amount_cents: amount,
        test_mode: invoice.test_mode.unwrap_or(false),
        source: "refund".to_string(),
        metadata: Some(serde_json::json!({
            "subscription_id": invoice.subscription_id.to_string(),
            "event_type": "subscription_payment_refunded"
        }).to_string()),
    }))
}

/// Axum handler for LemonSqueezy webhooks.
pub async fn handle_lemonsqueezy_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    handle_webhook(&LemonSqueezyWebhookProvider, &state, headers, body).await
}
