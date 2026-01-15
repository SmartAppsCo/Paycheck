//! Email service for sending activation codes.
//!
//! Supports three modes:
//! 1. Send via Resend API (default when API key available)
//! 2. POST to webhook URL (for DIY email delivery)
//! 3. Disabled (no email sent, log only)

use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::models::Project;

/// Retry delays in seconds (exponential backoff: 1s, 4s, 16s)
const RETRY_DELAYS: &[u64] = &[1, 4, 16];

const RESEND_API_URL: &str = "https://api.resend.com/emails";

/// Format a Unix timestamp as a human-readable date (e.g., "Jan 15, 2024")
fn format_date(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%b %d, %Y").to_string())
        .unwrap_or_else(|| "Unknown date".to_string())
}

/// Result of attempting to send an activation code email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailSendResult {
    /// Email was sent successfully via Resend
    Sent,
    /// Data was POSTed to the project's webhook URL
    WebhookCalled,
    /// Email delivery is disabled for this project
    Disabled,
    /// No API key available (system or org level)
    NoApiKey,
}

/// Configuration for sending an activation code email (single license).
pub struct EmailSendConfig<'a> {
    pub to_email: &'a str,
    pub code: &'a str,
    pub expires_in_minutes: i32,
    pub product_name: &'a str,
    pub project_name: &'a str,
    pub project: &'a Project,
    pub license_id: &'a str,
    /// When the license was purchased (Unix timestamp)
    pub purchased_at: i64,
    /// Pre-decrypted org-level Resend API key (if set)
    pub org_resend_key: Option<&'a str>,
    /// What triggered this email
    pub trigger: EmailTrigger,
}

/// Info for a single license's activation code.
#[derive(Debug, Clone)]
pub struct LicenseCodeInfo {
    pub product_name: String,
    pub code: String,
    pub license_id: String,
    /// When the license was purchased (Unix timestamp)
    pub purchased_at: i64,
}

/// Configuration for sending activation codes for multiple licenses.
pub struct MultiLicenseEmailConfig<'a> {
    pub to_email: &'a str,
    pub expires_in_minutes: i32,
    pub project_name: &'a str,
    pub project: &'a Project,
    pub licenses: Vec<LicenseCodeInfo>,
    /// Pre-decrypted org-level Resend API key (if set)
    pub org_resend_key: Option<&'a str>,
    /// What triggered this email
    pub trigger: EmailTrigger,
}

/// What triggered the activation code email.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailTrigger {
    /// Initial purchase (callback/webhook)
    Purchase,
    /// User requested recovery via /activation/request-code
    RecoveryRequest,
    /// Admin generated code via /orgs/.../send-code
    AdminGenerated,
}

/// Webhook payload sent when email_webhook_url is configured (single license).
#[derive(Debug, Serialize)]
pub struct WebhookPayload<'a> {
    pub event: &'static str,
    pub email: &'a str,
    pub code: &'a str,
    pub expires_at: i64,
    pub expires_in_minutes: i32,
    pub product_name: &'a str,
    pub project_id: &'a str,
    pub project_name: &'a str,
    pub license_id: &'a str,
    pub trigger: EmailTrigger,
}

/// License info in multi-license webhook payload.
#[derive(Debug, Serialize)]
pub struct WebhookLicenseInfo {
    pub product_name: String,
    pub code: String,
    pub license_id: String,
    pub purchased_at: i64,
}

/// Webhook payload for multiple licenses.
#[derive(Debug, Serialize)]
pub struct MultiLicenseWebhookPayload<'a> {
    pub event: &'static str,
    pub email: &'a str,
    pub expires_at: i64,
    pub expires_in_minutes: i32,
    pub project_id: &'a str,
    pub project_name: &'a str,
    pub licenses: Vec<WebhookLicenseInfo>,
    pub trigger: EmailTrigger,
}

/// Resend API request body.
#[derive(Debug, Serialize)]
struct ResendEmailRequest<'a> {
    from: &'a str,
    to: Vec<&'a str>,
    subject: String,
    text: String,
    html: String,
}

/// Resend API response.
#[derive(Debug, Deserialize)]
struct ResendEmailResponse {
    #[allow(dead_code)]
    id: String,
}

/// Email service using Resend API.
#[derive(Clone)]
pub struct EmailService {
    /// System-level Resend API key (from ENV)
    system_api_key: Option<String>,
    /// Default "from" email address (from ENV)
    default_from_email: String,
    /// HTTP client for API calls
    http_client: Client,
}

impl EmailService {
    /// Create a new email service with the optional system API key and default from email.
    pub fn new(system_api_key: Option<String>, default_from_email: String) -> Self {
        Self {
            system_api_key,
            default_from_email,
            http_client: Client::new(),
        }
    }

    /// Send an activation code email (or call webhook, or skip if disabled).
    ///
    /// Resolution order:
    /// 1. If email_enabled is false -> return Disabled
    /// 2. If email_webhook_url is set -> POST to webhook
    /// 3. Otherwise send via Resend API (org key -> system key)
    pub async fn send_activation_code(
        &self,
        config: EmailSendConfig<'_>,
    ) -> Result<EmailSendResult> {
        // Check if email is disabled for this project
        if !config.project.email_enabled {
            tracing::debug!(
                project_id = %config.project.id,
                "Email disabled for project, skipping activation code email"
            );
            return Ok(EmailSendResult::Disabled);
        }

        // If webhook URL is configured, POST to it instead of sending email
        if let Some(ref webhook_url) = config.project.email_webhook_url {
            return self.call_webhook(webhook_url, &config).await;
        }

        // Determine API key: org-level overrides system-level
        let api_key = config.org_resend_key.or(self.system_api_key.as_deref());

        let Some(api_key) = api_key else {
            tracing::warn!(
                project_id = %config.project.id,
                "No Resend API key available (system or org level), cannot send email"
            );
            return Ok(EmailSendResult::NoApiKey);
        };

        // Determine from address: project-level or system default
        let from_email = config
            .project
            .email_from
            .as_deref()
            .unwrap_or(&self.default_from_email);

        self.send_via_resend(api_key, from_email, &config).await
    }

    /// Send email via Resend API with retry logic.
    async fn send_via_resend(
        &self,
        api_key: &str,
        from_email: &str,
        config: &EmailSendConfig<'_>,
    ) -> Result<EmailSendResult> {
        let subject = format!(
            "Your {} license for {}",
            config.product_name, config.project_name
        );
        let date = format_date(config.purchased_at);
        let text = format!(
            "Your {} license for {}\n\nYou have a license for {}. Here is your activation code:\n\n{} (purchased {})\nActivation code: {}\n\nThis activation code expires in {} minutes. You can request a new one anytime.\n\nEnter this code in {} to activate your license.\n\nIf you didn't request this, you can ignore this email.",
            config.product_name,
            config.project_name,
            config.project_name,
            config.product_name,
            date,
            config.code,
            config.expires_in_minutes,
            config.project_name
        );
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #333;">Your {} license for {}</h2>
<p>You have a license for <strong>{}</strong>. Here is your activation code:</p>
<div style="margin-bottom: 24px;">
<p style="margin-bottom: 8px;"><strong>{}</strong> <span style="color: #666; font-size: 14px;">(purchased {})</span></p>
<div style="background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center;">
<code style="font-size: 24px; font-weight: bold; letter-spacing: 2px; color: #333;">{}</code>
</div>
</div>
<p style="color: #666;">This activation code expires in {} minutes. You can request a new one anytime.</p>
<p>Enter this code in <strong>{}</strong> to activate your license.</p>
<hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
<p style="color: #999; font-size: 12px;">If you didn't request this, you can ignore this email.</p>
</body>
</html>"#,
            config.product_name,
            config.project_name,
            config.project_name,
            config.product_name,
            date,
            config.code,
            config.expires_in_minutes,
            config.project_name
        );

        let request = ResendEmailRequest {
            from: from_email,
            to: vec![config.to_email],
            subject,
            text,
            html,
        };

        self.send_request_with_retry(api_key, &request, config.to_email, &config.project.id)
            .await
    }

    /// Send a request to Resend API with exponential backoff retry.
    ///
    /// Retries on transient errors (network issues, 5xx, 429 rate limit).
    /// Fails immediately on non-transient errors (4xx except 429).
    async fn send_request_with_retry(
        &self,
        api_key: &str,
        request: &ResendEmailRequest<'_>,
        to_email: &str,
        project_id: &str,
    ) -> Result<EmailSendResult> {
        let mut last_error: Option<AppError> = None;

        for (attempt, delay_secs) in std::iter::once(&0u64).chain(RETRY_DELAYS).enumerate() {
            // Sleep before retry (skip on first attempt)
            if *delay_secs > 0 {
                tracing::warn!(
                    attempt,
                    delay_secs,
                    "Retrying email send after transient failure"
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
                            "Email sent successfully after retry"
                        );
                    } else {
                        tracing::info!(
                            to = %to_email,
                            project_id = %project_id,
                            "Activation code email sent via Resend"
                        );
                    }
                    return Ok(EmailSendResult::Sent);
                }
                Err((error, is_transient)) => {
                    if is_transient {
                        last_error = Some(error);
                        // Continue to next retry
                    } else {
                        // Non-transient error, fail immediately
                        return Err(error);
                    }
                }
            }
        }

        // All retries exhausted
        tracing::error!(
            to = %to_email,
            project_id = %project_id,
            attempts = RETRY_DELAYS.len() + 1,
            "Email send failed after all retries"
        );
        Err(last_error.unwrap_or_else(|| {
            AppError::Internal("Email service error: all retries exhausted".into())
        }))
    }

    /// Send a single request to Resend API.
    ///
    /// Returns Ok(()) on success, or Err((AppError, is_transient)) on failure.
    async fn send_resend_request(
        &self,
        api_key: &str,
        request: &ResendEmailRequest<'_>,
    ) -> std::result::Result<(), (AppError, bool)> {
        let response = self
            .http_client
            .post(RESEND_API_URL)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(request)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to send request to Resend API");
                // Network errors are transient
                (
                    AppError::Internal(format!("Email service error: {}", e)),
                    true,
                )
            })?;

        let status = response.status();

        if status.is_success() {
            let _result: ResendEmailResponse = response.json().await.map_err(|e| {
                tracing::error!(error = %e, "Failed to parse Resend API response");
                // Parse errors after success are weird but not transient
                (AppError::Internal("Email service response error".into()), false)
            })?;
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();

            // Determine if error is transient (should retry)
            let is_transient = status.as_u16() == 429 // Rate limited
                || status.is_server_error(); // 5xx errors

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

    /// POST activation data to the project's webhook URL with retry logic.
    async fn call_webhook(
        &self,
        webhook_url: &str,
        config: &EmailSendConfig<'_>,
    ) -> Result<EmailSendResult> {
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + (config.expires_in_minutes as i64 * 60);

        let payload = WebhookPayload {
            event: "activation_code_created",
            email: config.to_email,
            code: config.code,
            expires_at,
            expires_in_minutes: config.expires_in_minutes,
            product_name: config.product_name,
            project_id: &config.project.id,
            project_name: config.project_name,
            license_id: config.license_id,
            trigger: config.trigger,
        };

        self.call_webhook_with_retry(
            webhook_url,
            "activation_code_created",
            &payload,
            &config.project.id,
        )
        .await
    }

    /// Call a webhook URL with exponential backoff retry.
    ///
    /// Retries on transient errors (network issues, 5xx, 429 rate limit).
    /// After all retries exhausted, returns success anyway (webhook errors
    /// shouldn't block the user flow - the activation code is already created).
    async fn call_webhook_with_retry<T: Serialize>(
        &self,
        webhook_url: &str,
        event_name: &str,
        payload: &T,
        project_id: &str,
    ) -> Result<EmailSendResult> {
        for (attempt, delay_secs) in std::iter::once(&0u64).chain(RETRY_DELAYS).enumerate() {
            // Sleep before retry (skip on first attempt)
            if *delay_secs > 0 {
                tracing::warn!(
                    attempt,
                    delay_secs,
                    webhook_url = %webhook_url,
                    "Retrying webhook call after transient failure"
                );
                tokio::time::sleep(Duration::from_secs(*delay_secs)).await;
            }

            match self
                .send_webhook_request(webhook_url, event_name, payload)
                .await
            {
                Ok(()) => {
                    if attempt > 0 {
                        tracing::info!(
                            attempt,
                            webhook_url = %webhook_url,
                            project_id = %project_id,
                            "Webhook called successfully after retry"
                        );
                    } else {
                        tracing::info!(
                            webhook_url = %webhook_url,
                            project_id = %project_id,
                            "Activation webhook called successfully"
                        );
                    }
                    return Ok(EmailSendResult::WebhookCalled);
                }
                Err(is_transient) => {
                    if !is_transient {
                        // Non-transient error (4xx) - don't retry, but still return success
                        // The dev's webhook rejected it, they can check their logs
                        tracing::warn!(
                            webhook_url = %webhook_url,
                            project_id = %project_id,
                            "Webhook returned non-transient error, not retrying"
                        );
                        return Ok(EmailSendResult::WebhookCalled);
                    }
                    // Transient error - continue to next retry
                }
            }
        }

        // All retries exhausted - still return success, but log prominently
        tracing::error!(
            webhook_url = %webhook_url,
            project_id = %project_id,
            attempts = RETRY_DELAYS.len() + 1,
            "Webhook call failed after all retries - activation code created but webhook not delivered"
        );
        Ok(EmailSendResult::WebhookCalled)
    }

    /// Send a single webhook request.
    ///
    /// Returns Ok(()) on success, or Err(is_transient) on failure.
    async fn send_webhook_request<T: Serialize>(
        &self,
        webhook_url: &str,
        event_name: &str,
        payload: &T,
    ) -> std::result::Result<(), bool> {
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
                true
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

            Err(is_transient)
        }
    }

    /// Send activation codes for multiple licenses in a single email.
    ///
    /// When a user has multiple licenses (bought multiple products), send one email
    /// listing all of them with their activation codes.
    pub async fn send_multi_license_activation_codes(
        &self,
        config: MultiLicenseEmailConfig<'_>,
    ) -> Result<EmailSendResult> {
        // Check if email is disabled for this project
        if !config.project.email_enabled {
            tracing::debug!(
                project_id = %config.project.id,
                "Email disabled for project, skipping activation code email"
            );
            return Ok(EmailSendResult::Disabled);
        }

        // If webhook URL is configured, POST to it instead of sending email
        if let Some(ref webhook_url) = config.project.email_webhook_url {
            return self.call_multi_license_webhook(webhook_url, &config).await;
        }

        // Determine API key: org-level overrides system-level
        let api_key = config.org_resend_key.or(self.system_api_key.as_deref());

        let Some(api_key) = api_key else {
            tracing::warn!(
                project_id = %config.project.id,
                "No Resend API key available (system or org level), cannot send email"
            );
            return Ok(EmailSendResult::NoApiKey);
        };

        // Determine from address: project-level or system default
        let from_email = config
            .project
            .email_from
            .as_deref()
            .unwrap_or(&self.default_from_email);

        self.send_multi_license_via_resend(api_key, from_email, &config)
            .await
    }

    /// Send multi-license email via Resend API.
    async fn send_multi_license_via_resend(
        &self,
        api_key: &str,
        from_email: &str,
        config: &MultiLicenseEmailConfig<'_>,
    ) -> Result<EmailSendResult> {
        let subject = format!("Your licenses for {}", config.project_name);

        // Build text version
        let mut text = format!(
            "Your licenses for {}\n\nYou have multiple licenses for {}. Here are your activation codes:\n\n",
            config.project_name, config.project_name
        );
        for license in &config.licenses {
            let date = format_date(license.purchased_at);
            text.push_str(&format!(
                "{} (purchased {})\nActivation code: {}\n\n",
                license.product_name, date, license.code
            ));
        }
        text.push_str(&format!(
            "These activation codes expire in {} minutes. You can request new ones anytime.\n\nEnter the appropriate code in {} to activate your license.\n\nIf you didn't request this, you can ignore this email.",
            config.expires_in_minutes, config.project_name
        ));

        // Build HTML version
        let mut license_blocks = String::new();
        for license in &config.licenses {
            let date = format_date(license.purchased_at);
            license_blocks.push_str(&format!(
                r#"<div style="margin-bottom: 24px;">
<p style="margin-bottom: 8px;"><strong>{}</strong> <span style="color: #666; font-size: 14px;">(purchased {})</span></p>
<div style="background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center;">
<code style="font-size: 24px; font-weight: bold; letter-spacing: 2px; color: #333;">{}</code>
</div>
</div>"#,
                license.product_name, date, license.code
            ));
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<h2 style="color: #333;">Your licenses for {}</h2>
<p>You have multiple licenses for <strong>{}</strong>. Here are your activation codes:</p>
{}
<p style="color: #666;">These activation codes expire in {} minutes. You can request new ones anytime.</p>
<p>Enter the appropriate code in <strong>{}</strong> to activate your license.</p>
<hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
<p style="color: #999; font-size: 12px;">If you didn't request this, you can ignore this email.</p>
</body>
</html>"#,
            config.project_name,
            config.project_name,
            license_blocks,
            config.expires_in_minutes,
            config.project_name
        );

        let request = ResendEmailRequest {
            from: from_email,
            to: vec![config.to_email],
            subject,
            text,
            html,
        };

        self.send_request_with_retry(api_key, &request, config.to_email, &config.project.id)
            .await
    }

    /// POST multi-license activation data to the project's webhook URL with retry logic.
    async fn call_multi_license_webhook(
        &self,
        webhook_url: &str,
        config: &MultiLicenseEmailConfig<'_>,
    ) -> Result<EmailSendResult> {
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + (config.expires_in_minutes as i64 * 60);

        let payload = MultiLicenseWebhookPayload {
            event: "activation_codes_created",
            email: config.to_email,
            expires_at,
            expires_in_minutes: config.expires_in_minutes,
            project_id: &config.project.id,
            project_name: config.project_name,
            licenses: config
                .licenses
                .iter()
                .map(|l| WebhookLicenseInfo {
                    product_name: l.product_name.clone(),
                    code: l.code.clone(),
                    license_id: l.license_id.clone(),
                    purchased_at: l.purchased_at,
                })
                .collect(),
            trigger: config.trigger,
        };

        self.call_webhook_with_retry(
            webhook_url,
            "activation_codes_created",
            &payload,
            &config.project.id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_trigger_serialization() {
        assert_eq!(
            serde_json::to_string(&EmailTrigger::Purchase).unwrap(),
            "\"purchase\""
        );
        assert_eq!(
            serde_json::to_string(&EmailTrigger::RecoveryRequest).unwrap(),
            "\"recovery_request\""
        );
        assert_eq!(
            serde_json::to_string(&EmailTrigger::AdminGenerated).unwrap(),
            "\"admin_generated\""
        );
    }

    #[test]
    fn test_retry_delays_configuration() {
        // Verify retry configuration is sensible
        assert_eq!(RETRY_DELAYS.len(), 3, "Should have 3 retry attempts");
        assert_eq!(RETRY_DELAYS, &[1, 4, 16], "Exponential backoff: 1s, 4s, 16s");

        // Total max wait time should be reasonable (21 seconds)
        let total_delay: u64 = RETRY_DELAYS.iter().sum();
        assert_eq!(total_delay, 21);
    }
}
