use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{AppError, Result, msg};
use crate::models::StripeConfig;

type HmacSha256 = Hmac<Sha256>;

// Note: We use Stripe's pre-configured prices (linked_id = price_xxx)
// instead of ad-hoc price_data. This keeps all payment products
// organized in the Stripe dashboard.

#[derive(Debug, Deserialize)]
struct CreateCheckoutSessionResponse {
    id: String,
    url: String,
}

#[derive(Debug, Clone)]
pub struct StripeClient {
    client: Client,
    secret_key: String,
    webhook_secret: String,
}

impl StripeClient {
    pub fn new(config: &StripeConfig) -> Self {
        Self {
            client: Client::new(),
            secret_key: config.secret_key.clone(),
            webhook_secret: config.webhook_secret.clone(),
        }
    }

    /// Create a Stripe checkout session using a pre-configured price.
    ///
    /// `price_id` is the Stripe Price ID (e.g., "price_1ABC...") configured in
    /// your Stripe dashboard. This creates organized payments in Stripe instead
    /// of ad-hoc "one-time" charges scattered across the dashboard.
    pub async fn create_checkout_session(
        &self,
        session_id: &str,
        project_id: &str,
        product_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<(String, String)> {
        let response = self
            .client
            .post("https://api.stripe.com/v1/checkout/sessions")
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&[
                ("mode", "payment"),
                ("success_url", success_url),
                ("cancel_url", cancel_url),
                ("line_items[0][price]", price_id),
                ("line_items[0][quantity]", "1"),
                ("metadata[paycheck_session_id]", session_id),
                ("metadata[project_id]", project_id),
                ("metadata[product_id]", product_id),
            ])
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Stripe API error: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Stripe API error: {}",
                error_text
            )));
        }

        let session: CreateCheckoutSessionResponse = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse Stripe response: {}", e)))?;

        Ok((session.id, session.url))
    }

    /// Fetch a checkout session with expanded discount data.
    /// Used by the enricher to get discount codes that aren't in the webhook payload.
    pub async fn get_checkout_session_discounts(
        &self,
        session_id: &str,
    ) -> Result<Option<String>> {
        let url = format!(
            "https://api.stripe.com/v1/checkout/sessions/{}?expand[]=discounts.promotion_code",
            session_id
        );

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.secret_key, None::<&str>)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Stripe API error: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            tracing::warn!(
                "Stripe discount enrichment failed for session {}: {} - {} (discount code may be missing from transaction)",
                session_id, status, error_text
            );
            return Ok(None);
        }

        #[derive(Deserialize)]
        struct DiscountResponse {
            discounts: Option<Vec<DiscountItem>>,
        }
        #[derive(Deserialize)]
        struct DiscountItem {
            promotion_code: Option<PromotionCode>,
        }
        #[derive(Deserialize)]
        struct PromotionCode {
            code: Option<String>,
        }

        let session: DiscountResponse = response
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse Stripe response: {}", e)))?;

        // Extract the first discount code if present
        let code = session
            .discounts
            .and_then(|d| d.into_iter().next())
            .and_then(|d| d.promotion_code)
            .and_then(|p| p.code);

        Ok(code)
    }

    /// Maximum age of a webhook timestamp before it's rejected (in seconds).
    /// Stripe recommends 300 seconds (5 minutes).
    const WEBHOOK_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

    pub fn verify_webhook_signature(&self, payload: &[u8], signature: &str) -> Result<bool> {
        // Stripe signature format: t=timestamp,v1=signature
        let parts: Vec<&str> = signature.split(',').collect();

        let mut timestamp = None;
        let mut sig_v1 = None;

        for part in parts {
            if let Some(t) = part.strip_prefix("t=") {
                timestamp = Some(t);
            } else if let Some(s) = part.strip_prefix("v1=") {
                sig_v1 = Some(s);
            }
        }

        let timestamp_str =
            timestamp.ok_or_else(|| AppError::BadRequest(msg::INVALID_SIGNATURE_FORMAT.into()))?;
        let sig_v1 =
            sig_v1.ok_or_else(|| AppError::BadRequest(msg::INVALID_SIGNATURE_FORMAT.into()))?;

        // Parse and validate timestamp to prevent replay attacks.
        // Reject webhooks older than WEBHOOK_TIMESTAMP_TOLERANCE_SECS.
        let timestamp: i64 = timestamp_str
            .parse()
            .map_err(|_| AppError::BadRequest(msg::INVALID_TIMESTAMP_IN_SIGNATURE.into()))?;

        let now = chrono::Utc::now().timestamp();
        let age = now - timestamp;

        if age > Self::WEBHOOK_TIMESTAMP_TOLERANCE_SECS {
            tracing::warn!(
                "Stripe webhook rejected: timestamp too old (age={}s, max={}s)",
                age,
                Self::WEBHOOK_TIMESTAMP_TOLERANCE_SECS
            );
            return Ok(false);
        }

        // Also reject timestamps from the future (clock skew tolerance: 60 seconds)
        if age < -60 {
            tracing::warn!(
                "Stripe webhook rejected: timestamp in the future (age={}s)",
                age
            );
            return Ok(false);
        }

        // Construct signed payload
        let signed_payload = format!("{}.{}", timestamp_str, String::from_utf8_lossy(payload));

        // Compute expected signature
        let mut mac = HmacSha256::new_from_slice(self.webhook_secret.as_bytes())
            .map_err(|_| AppError::Internal(msg::INVALID_WEBHOOK_SECRET.into()))?;
        mac.update(signed_payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        // Use constant-time comparison to prevent timing attacks.
        // An attacker could otherwise measure response times to progressively
        // discover the correct signature byte-by-byte.
        let expected_bytes = expected.as_bytes();
        let provided_bytes = sig_v1.as_bytes();

        // Length check is not constant-time, but that's fine - signature length
        // is not secret (it's always 64 hex chars for SHA-256)
        if expected_bytes.len() != provided_bytes.len() {
            return Ok(false);
        }

        Ok(expected_bytes.ct_eq(provided_bytes).into())
    }
}

/// Generic Stripe webhook event - object is parsed based on event_type
#[derive(Debug, Deserialize)]
pub struct StripeWebhookEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}

// ============ checkout.session.completed ============

#[derive(Debug, Deserialize)]
pub struct StripeCheckoutSession {
    pub id: String,
    pub mode: Option<String>, // "payment" or "subscription"
    pub payment_status: String,
    /// Payment intent ID (pi_xxx) - present for one-time payments.
    /// Used as order_id for refund linkage (refunds reference payment_intent).
    pub payment_intent: Option<String>,
    pub customer: Option<String>,
    /// Pre-filled email (if set when creating session)
    pub customer_email: Option<String>,
    /// Customer details collected during checkout (contains the actual email entered)
    pub customer_details: Option<StripeCustomerDetails>,
    pub subscription: Option<String>, // Present for subscription mode
    pub metadata: StripeMetadata,
    /// Currency code (e.g., "usd", "eur")
    pub currency: Option<String>,
    /// Amount before discounts and tax (in cents)
    pub amount_subtotal: Option<i64>,
    /// Final amount charged (in cents)
    pub amount_total: Option<i64>,
    /// Breakdown of tax and discounts
    pub total_details: Option<StripeTotalDetails>,
    /// Test mode indicator
    pub livemode: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct StripeCustomerDetails {
    pub email: Option<String>,
    pub name: Option<String>,
    pub address: Option<StripeAddress>,
}

#[derive(Debug, Deserialize)]
pub struct StripeAddress {
    pub country: Option<String>,
}

/// Breakdown of discounts and taxes in a checkout session
#[derive(Debug, Deserialize)]
pub struct StripeTotalDetails {
    /// Total discount amount (in cents)
    pub amount_discount: Option<i64>,
    /// Total tax amount (in cents)
    pub amount_tax: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct StripeMetadata {
    pub paycheck_session_id: Option<String>,
    pub project_id: Option<String>,
    pub product_id: Option<String>,
}

// ============ invoice.paid ============

#[derive(Debug, Deserialize)]
pub struct StripeInvoicePeriod {
    pub end: i64,
}

#[derive(Debug, Deserialize)]
pub struct StripeInvoiceLineItem {
    pub period: StripeInvoicePeriod,
}

#[derive(Debug, Deserialize)]
pub struct StripeInvoiceLines {
    pub data: Vec<StripeInvoiceLineItem>,
}

#[derive(Debug, Deserialize)]
pub struct StripeInvoice {
    pub id: String,
    pub customer: Option<String>,
    pub subscription: Option<String>,
    pub billing_reason: Option<String>, // "subscription_create", "subscription_cycle", etc.
    pub status: String,                 // "paid", "open", etc.
    pub lines: Option<StripeInvoiceLines>,
    /// Currency code (lowercase, e.g., "usd")
    pub currency: Option<String>,
    /// Amount paid in cents
    pub amount_paid: Option<i64>,
    /// Subtotal before tax/discounts in cents
    pub subtotal: Option<i64>,
    /// Tax amount in cents
    pub tax: Option<i64>,
    /// Total amount in cents
    pub total: Option<i64>,
    /// Whether this is a test mode invoice
    pub livemode: Option<bool>,
}

impl StripeInvoice {
    /// Get the billing period end from the first line item.
    pub fn period_end(&self) -> Option<i64> {
        self.lines
            .as_ref()
            .and_then(|l| l.data.first())
            .map(|item| item.period.end)
    }
}

// ============ customer.subscription.deleted ============

#[derive(Debug, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub customer: Option<String>,
    pub status: String, // "active", "canceled", etc.
}

// ============ charge.refunded ============

#[derive(Debug, Deserialize)]
pub struct StripeRefund {
    pub id: String,
    /// Amount refunded in cents
    pub amount: i64,
    /// Currency code (lowercase)
    pub currency: String,
    /// Status of the refund
    pub status: String, // "succeeded", "pending", "failed", etc.
}

#[derive(Debug, Deserialize)]
pub struct StripeRefundList {
    pub data: Vec<StripeRefund>,
}

#[derive(Debug, Deserialize)]
pub struct StripeCharge {
    pub id: String,
    /// Payment intent ID (used to look up checkout session)
    pub payment_intent: Option<String>,
    /// Amount in cents
    pub amount: i64,
    /// Amount refunded in cents
    pub amount_refunded: i64,
    /// Currency code (lowercase)
    pub currency: String,
    /// Whether fully refunded
    pub refunded: bool,
    /// Whether this is a test mode charge
    pub livemode: bool,
    /// List of refunds on this charge
    pub refunds: Option<StripeRefundList>,
}
