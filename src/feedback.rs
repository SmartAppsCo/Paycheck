//! Feedback and crash report delivery service.
//!
//! Handles passthrough delivery of user feedback and crash reports via webhook
//! (primary) or email (fallback). No data is stored by Paycheck - it's immediately
//! forwarded to the configured destination.

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

/// Retry delays in seconds (exponential backoff: 1s, 4s, 16s)
const RETRY_DELAYS: &[u64] = &[1, 4, 16];

/// Delivery target type (feedback or crash)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryTarget {
    Feedback,
    Crash,
}

impl DeliveryTarget {
    pub fn event_name(&self) -> &'static str {
        match self {
            DeliveryTarget::Feedback => "feedback_submitted",
            DeliveryTarget::Crash => "crash_reported",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            DeliveryTarget::Feedback => "Feedback",
            DeliveryTarget::Crash => "Crash Report",
        }
    }
}

/// Configuration for delivering feedback/crash data
#[derive(Debug, Clone)]
pub struct DeliveryConfig {
    pub webhook_url: Option<String>,
    pub email: Option<String>,
}

impl DeliveryConfig {
    /// Check if any delivery method is configured
    pub fn is_configured(&self) -> bool {
        self.webhook_url.is_some() || self.email.is_some()
    }
}

/// Result of delivery attempt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryResult {
    /// Data was POSTed to webhook successfully
    WebhookDelivered,
    /// Data was sent via email
    EmailSent,
}

/// Feedback type classification
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackType {
    Bug,
    Feature,
    Question,
    #[default]
    Other,
}

/// Priority level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Low,
    Medium,
    High,
}

/// Stack frame in a crash report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

/// Breadcrumb for crash context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breadcrumb {
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    pub message: String,
}

/// Feedback request data (submitted by user)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackData {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, rename = "type")]
    pub feedback_type: FeedbackType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Crash request data (submitted by SDK)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashData {
    pub error_type: String,
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<Vec<StackFrame>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breadcrumbs: Option<Vec<Breadcrumb>>,
}

/// Context from JWT claims (auto-attached to payloads)
#[derive(Debug, Clone, Serialize)]
pub struct JwtContext {
    pub license_id: String,
    pub tier: String,
    pub features: Vec<String>,
    pub device_id: String,
    pub device_type: String,
    pub product_id: String,
}

/// Webhook/email payload wrapper
#[derive(Debug, Serialize)]
struct DeliveryPayload<T> {
    event: &'static str,
    timestamp: i64,
    project_id: String,
    project_name: String,
    #[serde(flatten)]
    jwt_context: JwtContext,
    data: T,
}

/// Resend API request body (plain text email)
#[derive(Debug, Serialize)]
struct ResendEmailRequest {
    from: String,
    to: Vec<String>,
    subject: String,
    text: String,
}

/// Delivery service for feedback and crash reports
#[derive(Clone)]
pub struct DeliveryService {
    /// System-level Resend API key (from ENV)
    system_resend_key: Option<String>,
    /// Default "from" email address (from ENV)
    default_from_email: String,
    /// HTTP client for API calls
    http_client: Client,
}

impl DeliveryService {
    /// Create a new delivery service
    pub fn new(system_resend_key: Option<String>, default_from_email: String) -> Self {
        Self {
            system_resend_key,
            default_from_email,
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    /// Deliver feedback data to configured destination.
    ///
    /// Tries webhook first (if configured), then falls back to email.
    /// Returns error if all configured delivery methods fail.
    pub async fn deliver_feedback(
        &self,
        config: &DeliveryConfig,
        project_id: &str,
        project_name: &str,
        jwt_context: JwtContext,
        data: FeedbackData,
        org_resend_key: Option<&str>,
    ) -> Result<DeliveryResult> {
        if !config.is_configured() {
            return Err(AppError::BadRequest(
                "No feedback delivery method configured for this project".into(),
            ));
        }

        let payload = DeliveryPayload {
            event: DeliveryTarget::Feedback.event_name(),
            timestamp: chrono::Utc::now().timestamp(),
            project_id: project_id.to_string(),
            project_name: project_name.to_string(),
            jwt_context,
            data,
        };

        self.deliver(config, DeliveryTarget::Feedback, &payload, project_id, project_name, org_resend_key)
            .await
    }

    /// Deliver crash data to configured destination.
    ///
    /// Tries webhook first (if configured), then falls back to email.
    /// Returns error if all configured delivery methods fail.
    pub async fn deliver_crash(
        &self,
        config: &DeliveryConfig,
        project_id: &str,
        project_name: &str,
        jwt_context: JwtContext,
        data: CrashData,
        org_resend_key: Option<&str>,
    ) -> Result<DeliveryResult> {
        if !config.is_configured() {
            return Err(AppError::BadRequest(
                "No crash reporting destination configured for this project".into(),
            ));
        }

        let payload = DeliveryPayload {
            event: DeliveryTarget::Crash.event_name(),
            timestamp: chrono::Utc::now().timestamp(),
            project_id: project_id.to_string(),
            project_name: project_name.to_string(),
            jwt_context,
            data,
        };

        self.deliver(config, DeliveryTarget::Crash, &payload, project_id, project_name, org_resend_key)
            .await
    }

    /// Internal delivery logic: webhook first, then email fallback
    async fn deliver<T: Serialize>(
        &self,
        config: &DeliveryConfig,
        target: DeliveryTarget,
        payload: &DeliveryPayload<T>,
        project_id: &str,
        project_name: &str,
        org_resend_key: Option<&str>,
    ) -> Result<DeliveryResult> {
        // Try webhook first
        if let Some(ref webhook_url) = config.webhook_url {
            match self
                .deliver_webhook(webhook_url, target, payload, project_id)
                .await
            {
                Ok(()) => return Ok(DeliveryResult::WebhookDelivered),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        project_id = %project_id,
                        target = ?target,
                        "Webhook delivery failed, trying email fallback"
                    );
                    // Fall through to email
                }
            }
        }

        // Try email fallback
        if let Some(ref email) = config.email {
            let api_key = org_resend_key.or(self.system_resend_key.as_deref());
            if let Some(api_key) = api_key {
                return self
                    .deliver_email(api_key, email, target, payload, project_id, project_name)
                    .await;
            } else {
                tracing::warn!(
                    project_id = %project_id,
                    "No Resend API key available for email fallback"
                );
            }
        }

        // All delivery methods failed or not configured
        Err(AppError::Internal(format!(
            "Failed to deliver {} - all methods exhausted",
            target.display_name().to_lowercase()
        )))
    }

    /// Deliver to webhook URL with retry logic
    async fn deliver_webhook<T: Serialize>(
        &self,
        webhook_url: &str,
        target: DeliveryTarget,
        payload: &T,
        project_id: &str,
    ) -> Result<()> {
        let mut last_error: Option<AppError> = None;

        for (attempt, delay_secs) in std::iter::once(&0u64).chain(RETRY_DELAYS).enumerate() {
            // Sleep before retry (skip on first attempt)
            if *delay_secs > 0 {
                tracing::warn!(
                    attempt,
                    delay_secs,
                    webhook_url = %webhook_url,
                    "Retrying {} webhook after transient failure",
                    target.display_name().to_lowercase()
                );
                tokio::time::sleep(Duration::from_secs(*delay_secs)).await;
            }

            match self
                .send_webhook_request(webhook_url, target.event_name(), payload)
                .await
            {
                Ok(()) => {
                    if attempt > 0 {
                        tracing::info!(
                            attempt,
                            webhook_url = %webhook_url,
                            project_id = %project_id,
                            "{} webhook delivered after retry",
                            target.display_name()
                        );
                    } else {
                        tracing::info!(
                            webhook_url = %webhook_url,
                            project_id = %project_id,
                            "{} webhook delivered successfully",
                            target.display_name()
                        );
                    }
                    return Ok(());
                }
                Err((error, is_transient)) => {
                    if is_transient {
                        last_error = Some(error);
                        // Continue to next retry
                    } else {
                        // Non-transient error (4xx), fail immediately
                        return Err(error);
                    }
                }
            }
        }

        // All retries exhausted
        tracing::error!(
            webhook_url = %webhook_url,
            project_id = %project_id,
            attempts = RETRY_DELAYS.len() + 1,
            "{} webhook failed after all retries",
            target.display_name()
        );

        Err(last_error.unwrap_or_else(|| {
            AppError::Internal(format!(
                "{} webhook delivery failed",
                target.display_name()
            ))
        }))
    }

    /// Send a single webhook request
    async fn send_webhook_request<T: Serialize>(
        &self,
        webhook_url: &str,
        event_name: &str,
        payload: &T,
    ) -> std::result::Result<(), (AppError, bool)> {
        let response = self
            .http_client
            .post(webhook_url)
            .header("Content-Type", "application/json")
            .header("X-Paycheck-Event", event_name)
            .json(payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    webhook_url = %webhook_url,
                    "Failed to send webhook request"
                );
                // Network errors are transient
                (
                    AppError::Internal(format!("Webhook request failed: {}", e)),
                    true,
                )
            })?;

        let status = response.status();

        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();

            // Determine if error is transient (should retry)
            let is_transient = status.as_u16() == 429 || status.is_server_error();

            if is_transient {
                tracing::warn!(
                    status = %status,
                    body = %body,
                    webhook_url = %webhook_url,
                    "Webhook returned transient error"
                );
            } else {
                tracing::error!(
                    status = %status,
                    body = %body,
                    webhook_url = %webhook_url,
                    "Webhook returned non-transient error"
                );
            }

            Err((
                AppError::Internal(format!("Webhook error: {} - {}", status, body)),
                is_transient,
            ))
        }
    }

    /// Deliver via email with retry logic
    async fn deliver_email<T: Serialize>(
        &self,
        api_key: &str,
        to_email: &str,
        target: DeliveryTarget,
        payload: &DeliveryPayload<T>,
        project_id: &str,
        project_name: &str,
    ) -> Result<DeliveryResult> {
        let subject = format!("[{}] New {}", project_name, target.display_name());

        // Format payload as readable text
        let body = serde_json::to_string_pretty(payload).unwrap_or_else(|_| {
            format!(
                "New {} received for project {}",
                target.display_name().to_lowercase(),
                project_name
            )
        });

        let text = format!(
            "A new {} has been submitted.\n\n\
             Project: {}\n\
             Timestamp: {}\n\n\
             Details:\n\
             {}",
            target.display_name().to_lowercase(),
            project_name,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            body
        );

        let request = ResendEmailRequest {
            from: self.default_from_email.clone(),
            to: vec![to_email.to_string()],
            subject,
            text,
        };

        self.send_email_with_retry(api_key, &request, to_email, project_id, target)
            .await
    }

    /// Send email with retry logic
    async fn send_email_with_retry(
        &self,
        api_key: &str,
        request: &ResendEmailRequest,
        to_email: &str,
        project_id: &str,
        target: DeliveryTarget,
    ) -> Result<DeliveryResult> {
        let mut last_error: Option<AppError> = None;

        for (attempt, delay_secs) in std::iter::once(&0u64).chain(RETRY_DELAYS).enumerate() {
            if *delay_secs > 0 {
                tracing::warn!(
                    attempt,
                    delay_secs,
                    "Retrying {} email after transient failure",
                    target.display_name().to_lowercase()
                );
                tokio::time::sleep(Duration::from_secs(*delay_secs)).await;
            }

            match self.send_resend_request(api_key, request).await {
                Ok(()) => {
                    if attempt > 0 {
                        tracing::info!(
                            attempt,
                            to = %to_email,
                            project_id = %project_id,
                            "{} email sent after retry",
                            target.display_name()
                        );
                    } else {
                        tracing::info!(
                            to = %to_email,
                            project_id = %project_id,
                            "{} email sent via Resend",
                            target.display_name()
                        );
                    }
                    return Ok(DeliveryResult::EmailSent);
                }
                Err((error, is_transient)) => {
                    if is_transient {
                        last_error = Some(error);
                    } else {
                        return Err(error);
                    }
                }
            }
        }

        tracing::error!(
            to = %to_email,
            project_id = %project_id,
            attempts = RETRY_DELAYS.len() + 1,
            "{} email failed after all retries",
            target.display_name()
        );

        Err(last_error.unwrap_or_else(|| {
            AppError::Internal(format!("{} email delivery failed", target.display_name()))
        }))
    }

    /// Send a single request to Resend API
    async fn send_resend_request(
        &self,
        api_key: &str,
        request: &ResendEmailRequest,
    ) -> std::result::Result<(), (AppError, bool)> {
        let response = self
            .http_client
            .post("https://api.resend.com/emails")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(request)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to send request to Resend API");
                (
                    AppError::Internal(format!("Email service error: {}", e)),
                    true,
                )
            })?;

        let status = response.status();

        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();

            let is_transient = status.as_u16() == 429 || status.is_server_error();

            if is_transient {
                tracing::warn!(
                    status = %status,
                    body = %body,
                    "Resend API returned transient error"
                );
            } else {
                tracing::error!(
                    status = %status,
                    body = %body,
                    "Resend API returned non-transient error"
                );
            }

            Err((
                AppError::Internal(format!("Email service error: {} - {}", status, body)),
                is_transient,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delivery_target_event_names() {
        assert_eq!(DeliveryTarget::Feedback.event_name(), "feedback_submitted");
        assert_eq!(DeliveryTarget::Crash.event_name(), "crash_reported");
    }

    #[test]
    fn test_delivery_target_display_names() {
        assert_eq!(DeliveryTarget::Feedback.display_name(), "Feedback");
        assert_eq!(DeliveryTarget::Crash.display_name(), "Crash Report");
    }

    #[test]
    fn test_delivery_config_is_configured() {
        assert!(!DeliveryConfig {
            webhook_url: None,
            email: None
        }
        .is_configured());

        assert!(DeliveryConfig {
            webhook_url: Some("https://example.com".into()),
            email: None
        }
        .is_configured());

        assert!(DeliveryConfig {
            webhook_url: None,
            email: Some("test@example.com".into())
        }
        .is_configured());

        assert!(DeliveryConfig {
            webhook_url: Some("https://example.com".into()),
            email: Some("test@example.com".into())
        }
        .is_configured());
    }

    #[test]
    fn test_feedback_type_default() {
        let ft: FeedbackType = Default::default();
        assert_eq!(ft, FeedbackType::Other);
    }

    #[test]
    fn test_feedback_type_serialization() {
        assert_eq!(
            serde_json::to_string(&FeedbackType::Bug).unwrap(),
            "\"bug\""
        );
        assert_eq!(
            serde_json::to_string(&FeedbackType::Feature).unwrap(),
            "\"feature\""
        );
        assert_eq!(
            serde_json::to_string(&FeedbackType::Question).unwrap(),
            "\"question\""
        );
        assert_eq!(
            serde_json::to_string(&FeedbackType::Other).unwrap(),
            "\"other\""
        );
    }

    #[test]
    fn test_priority_serialization() {
        assert_eq!(serde_json::to_string(&Priority::Low).unwrap(), "\"low\"");
        assert_eq!(
            serde_json::to_string(&Priority::Medium).unwrap(),
            "\"medium\""
        );
        assert_eq!(serde_json::to_string(&Priority::High).unwrap(), "\"high\"");
    }
}
