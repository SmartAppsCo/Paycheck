//! Usage metering webhook support.
//!
//! When configured via `PAYCHECK_METERING_WEBHOOK_URL`, Paycheck emits usage events
//! for billing purposes. This enables the hosted solution to track usage externally
//! while keeping the core lean.
//!
//! **What gets metered:**
//! - Emails: Activation, feedback, and crash emails (with delivery method for billing)
//! - Sales: Purchases, renewals, refunds (all transactions)

use std::time::Duration;

use reqwest::Client;
use serde::Serialize;

/// Retry delays in milliseconds for metering webhooks.
/// Quick retries (100ms, 200ms) to avoid blocking user flow.
/// Total worst case: 300ms.
const METERING_RETRY_DELAYS: &[u64] = &[100, 200];

/// Email metering event payload (owned version for async spawning).
#[derive(Debug, Clone, Serialize)]
pub struct EmailMeteringEvent {
    /// Event type: "activation_sent", "feedback_sent", "crash_sent"
    pub event: String,
    /// Organization ID
    pub org_id: String,
    /// Project ID
    pub project_id: String,
    /// License ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_id: Option<String>,
    /// Product ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    /// How the email was delivered: "system_key", "org_key", "webhook"
    pub delivery_method: String,
    /// Unix timestamp
    pub timestamp: i64,
    /// Idempotency key (activation_code_id or generated UUID)
    pub idempotency_key: String,
}

/// Sales metering event payload (owned version for async spawning).
#[derive(Debug, Clone, Serialize)]
pub struct SalesMeteringEvent {
    /// Event type: "purchase", "renewal", "refund"
    pub event: String,
    /// Organization ID
    pub org_id: String,
    /// Project ID
    pub project_id: String,
    /// Product ID
    pub product_id: String,
    /// License ID
    pub license_id: String,
    /// Transaction ID (serves as idempotency key)
    pub transaction_id: String,
    /// Payment provider: "stripe", "lemonsqueezy"
    pub payment_provider: String,
    /// Amount in cents (positive for purchase/renewal, negative for refund)
    pub amount_cents: i64,
    /// Currency code (lowercase, e.g., "usd")
    pub currency: String,
    /// Unix timestamp
    pub timestamp: i64,
}

/// Send a metering event to the configured webhook URL.
///
/// Uses quick retries (100ms, 200ms delays) to avoid blocking user flow.
/// This is fire-and-forget - failures are logged but don't affect the main operation.
pub async fn send_metering_event<T: Serialize>(client: &Client, url: &str, event: &T) {
    for (attempt, delay_ms) in std::iter::once(&0u64)
        .chain(METERING_RETRY_DELAYS.iter())
        .enumerate()
    {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
        }

        match client
            .post(url)
            .json(event)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if attempt > 0 {
                    tracing::debug!("Metering webhook succeeded after {} retries", attempt);
                }
                return;
            }
            Ok(resp) => {
                tracing::debug!("Metering webhook returned {}", resp.status());
            }
            Err(e) => {
                tracing::debug!("Metering webhook failed: {}", e);
            }
        }
    }

    tracing::warn!(
        "Metering webhook failed after {} attempts",
        METERING_RETRY_DELAYS.len() + 1
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_delays_are_quick() {
        // Total max wait time should be under 500ms to not block user flow
        let total_delay: u64 = METERING_RETRY_DELAYS.iter().sum();
        assert!(total_delay < 500, "Retry delays should be quick");
        assert_eq!(total_delay, 300); // 100 + 200
    }

    #[test]
    fn test_email_metering_event_serialization() {
        let event = EmailMeteringEvent {
            event: "activation_sent".to_string(),
            org_id: "org_123".to_string(),
            project_id: "proj_456".to_string(),
            license_id: Some("lic_789".to_string()),
            product_id: Some("prod_abc".to_string()),
            delivery_method: "system_key".to_string(),
            timestamp: 1234567890,
            idempotency_key: "code_xyz".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"activation_sent\""));
        assert!(json.contains("\"delivery_method\":\"system_key\""));
        assert!(json.contains("\"org_id\":\"org_123\""));
    }

    #[test]
    fn test_email_metering_event_skips_none_fields() {
        let event = EmailMeteringEvent {
            event: "feedback_sent".to_string(),
            org_id: "org_123".to_string(),
            project_id: "proj_456".to_string(),
            license_id: None,
            product_id: None,
            delivery_method: "webhook".to_string(),
            timestamp: 1234567890,
            idempotency_key: "uuid_xyz".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("license_id"));
        assert!(!json.contains("product_id"));
    }

    #[test]
    fn test_sales_metering_event_serialization() {
        let event = SalesMeteringEvent {
            event: "purchase".to_string(),
            org_id: "org_123".to_string(),
            project_id: "proj_456".to_string(),
            product_id: "prod_abc".to_string(),
            license_id: "lic_789".to_string(),
            transaction_id: "txn_xyz".to_string(),
            payment_provider: "stripe".to_string(),
            amount_cents: 9900,
            currency: "usd".to_string(),
            timestamp: 1234567890,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"purchase\""));
        assert!(json.contains("\"amount_cents\":9900"));
        assert!(json.contains("\"payment_provider\":\"stripe\""));
    }
}
