//! Usage metering webhook support.
//!
//! When configured via `PAYCHECK_METERING_WEBHOOK_URL`, Paycheck emits usage events
//! for billing purposes. This enables the hosted solution to track usage externally
//! while keeping the core lean.
//!
//! **What gets metered:**
//! - Emails: Activation, feedback, and crash emails (with delivery method for billing)
//! - Sales: Purchases, renewals, refunds (all transactions)

use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures::FutureExt;
use reqwest::Client;
use serde::Serialize;

/// Retry delays in milliseconds for metering webhooks.
/// Quick retries (100ms, 200ms) to avoid blocking user flow.
/// Total worst case: 300ms.
const METERING_RETRY_DELAYS: &[u64] = &[100, 200];

/// Generate an idempotency key for email metering events.
///
/// Each email send should have a unique idempotency key. The key is used by the
/// external billing service to deduplicate our retries (same event sent multiple
/// times due to network issues), NOT to deduplicate across different email sends.
///
/// **Important:** Do NOT use license_id or other stable identifiers here.
/// That would cause multiple legitimate email sends to be deduplicated into one
/// billing event, resulting in under-billing.
pub fn generate_email_idempotency_key() -> String {
    uuid::Uuid::new_v4().to_string()
}

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
    /// Idempotency key - must be unique per email send (use `generate_email_idempotency_key()`)
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

/// Spawn a fire-and-forget email metering event.
///
/// If metering is not configured, this is a no-op.
/// The event is sent in a background task and failures don't affect the caller.
/// Panics in the spawned task are logged rather than silently swallowed.
pub fn spawn_email_metering(
    client: Client,
    metering_url: Option<String>,
    event: EmailMeteringEvent,
) {
    if let Some(url) = metering_url {
        let event_type = event.event.clone();
        tokio::spawn(
            AssertUnwindSafe(async move {
                send_metering_event(&client, &url, &event).await;
            })
            .catch_unwind()
            .map(move |result| {
                if let Err(panic) = result {
                    let panic_msg = panic
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".to_string());
                    tracing::error!(
                        "Metering task panicked for event '{}': {}",
                        event_type,
                        panic_msg
                    );
                }
            }),
        );
    }
}

/// Spawn a fire-and-forget sales metering event.
///
/// If metering is not configured, this is a no-op.
/// The event is sent in a background task and failures don't affect the caller.
/// Panics in the spawned task are logged rather than silently swallowed.
pub fn spawn_sales_metering(
    client: Client,
    metering_url: Option<String>,
    event: SalesMeteringEvent,
) {
    if let Some(url) = metering_url {
        let event_type = event.event.clone();
        tokio::spawn(
            AssertUnwindSafe(async move {
                send_metering_event(&client, &url, &event).await;
            })
            .catch_unwind()
            .map(move |result| {
                if let Err(panic) = result {
                    let panic_msg = panic
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".to_string());
                    tracing::error!(
                        "Metering task panicked for event '{}': {}",
                        event_type,
                        panic_msg
                    );
                }
            }),
        );
    }
}

/// Send a metering event to the configured webhook URL.
///
/// Uses quick retries (100ms, 200ms delays) to avoid blocking user flow.
/// This is fire-and-forget - failures are logged but don't affect the main operation.
async fn send_metering_event<T: Serialize>(client: &Client, url: &str, event: &T) {
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

    /// Regression test: Each email send must have a unique idempotency key.
    ///
    /// This test ensures we don't accidentally change the implementation to use
    /// license_id or other stable identifiers, which would cause under-billing
    /// (multiple email sends deduplicated into one billing event).
    #[test]
    fn test_email_idempotency_key_is_unique_per_call() {
        use std::collections::HashSet;

        // Generate 100 keys and verify they're all unique
        let keys: HashSet<String> = (0..100).map(|_| generate_email_idempotency_key()).collect();

        assert_eq!(
            keys.len(),
            100,
            "Each call to generate_email_idempotency_key() must produce a unique key. \
             If this test fails, someone may have changed the implementation to use \
             a stable identifier (like license_id), which would cause under-billing."
        );
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
