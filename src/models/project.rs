use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result, msg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeConfig {
    pub secret_key: String,
    pub publishable_key: String,
    pub webhook_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LemonSqueezyConfig {
    pub api_key: String,
    pub store_id: String,
    pub webhook_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub license_key_prefix: String,
    /// Encrypted private key (envelope encryption with master key)
    #[serde(skip_serializing)]
    pub private_key: Vec<u8>,
    pub public_key: String,
    /// Post-payment redirect URL (server uses this, not client-specified)
    pub redirect_url: Option<String>,
    /// Email "from" address for activation emails (e.g., "noreply@myapp.com")
    /// Falls back to system default if not set
    pub email_from: Option<String>,
    /// Whether email delivery is enabled for this project
    pub email_enabled: bool,
    /// Webhook URL to POST activation data to (instead of sending email)
    /// If set, Paycheck calls this URL and dev handles email delivery themselves
    pub email_webhook_url: Option<String>,
    /// Payment config override (null = inherit from org)
    pub payment_config_id: Option<String>,
    /// Email config override (null = inherit from org)
    pub email_config_id: Option<String>,
    /// Webhook URL to POST feedback submissions to
    pub feedback_webhook_url: Option<String>,
    /// Email address to send feedback submissions to (fallback if webhook fails or not set)
    pub feedback_email: Option<String>,
    /// Webhook URL to POST crash reports to
    pub crash_webhook_url: Option<String>,
    /// Email address to send crash reports to (fallback if webhook fails or not set)
    pub crash_email: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectPublic {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub license_key_prefix: String,
    pub public_key: String,
    pub redirect_url: Option<String>,
    pub email_from: Option<String>,
    pub email_enabled: bool,
    pub email_webhook_url: Option<String>,
    /// Payment config override (null = inherit from org)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_config_id: Option<String>,
    /// Email config override (null = inherit from org)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_config_id: Option<String>,
    /// Webhook URL to POST feedback submissions to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feedback_webhook_url: Option<String>,
    /// Email address to send feedback submissions to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feedback_email: Option<String>,
    /// Webhook URL to POST crash reports to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_webhook_url: Option<String>,
    /// Email address to send crash reports to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_email: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

impl From<Project> for ProjectPublic {
    fn from(p: Project) -> Self {
        Self {
            id: p.id,
            org_id: p.org_id,
            name: p.name,
            license_key_prefix: p.license_key_prefix,
            public_key: p.public_key,
            redirect_url: p.redirect_url,
            email_from: p.email_from,
            email_enabled: p.email_enabled,
            email_webhook_url: p.email_webhook_url,
            payment_config_id: p.payment_config_id,
            email_config_id: p.email_config_id,
            feedback_webhook_url: p.feedback_webhook_url,
            feedback_email: p.feedback_email,
            crash_webhook_url: p.crash_webhook_url,
            crash_email: p.crash_email,
            created_at: p.created_at,
            updated_at: p.updated_at,
            deleted_at: p.deleted_at,
            deleted_cascade_depth: p.deleted_cascade_depth,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateProject {
    pub name: String,
    #[serde(default = "default_prefix")]
    pub license_key_prefix: String,
    /// Post-payment redirect URL (optional, falls back to Paycheck success page)
    #[serde(default)]
    pub redirect_url: Option<String>,
    /// Email "from" address for activation emails (e.g., "noreply@myapp.com")
    #[serde(default)]
    pub email_from: Option<String>,
    /// Whether email delivery is enabled (default: true)
    #[serde(default = "default_email_enabled")]
    pub email_enabled: bool,
    /// Webhook URL to POST activation data to (instead of sending email)
    #[serde(default)]
    pub email_webhook_url: Option<String>,
    /// Payment config override (null = inherit from org)
    #[serde(default)]
    pub payment_config_id: Option<String>,
    /// Email config override (null = inherit from org)
    #[serde(default)]
    pub email_config_id: Option<String>,
    /// Webhook URL to POST feedback submissions to
    #[serde(default)]
    pub feedback_webhook_url: Option<String>,
    /// Email address to send feedback submissions to
    #[serde(default)]
    pub feedback_email: Option<String>,
    /// Webhook URL to POST crash reports to
    #[serde(default)]
    pub crash_webhook_url: Option<String>,
    /// Email address to send crash reports to
    #[serde(default)]
    pub crash_email: Option<String>,
}

impl CreateProject {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
        validate_prefix(&self.license_key_prefix)?;
        Ok(())
    }
}

/// Validate that a license key prefix contains only alphanumeric characters.
/// This ensures activation codes can be safely normalized (non-alphanumeric chars
/// are treated as separators by the SDK).
fn validate_prefix(prefix: &str) -> Result<()> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest(
            "license_key_prefix cannot be empty".into(),
        ));
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(AppError::BadRequest(
            "license_key_prefix must contain only letters and numbers".into(),
        ));
    }
    Ok(())
}

fn default_prefix() -> String {
    "PC".to_string()
}

fn default_email_enabled() -> bool {
    true
}

/// Masked Stripe config for display (hides sensitive parts of keys)
#[derive(Debug, Clone, Serialize)]
pub struct StripeConfigMasked {
    pub secret_key: String,
    pub publishable_key: String,
    pub webhook_secret: String,
}

impl From<&StripeConfig> for StripeConfigMasked {
    fn from(config: &StripeConfig) -> Self {
        Self {
            secret_key: mask_secret(&config.secret_key),
            publishable_key: config.publishable_key.clone(), // Publishable keys are public
            webhook_secret: mask_secret(&config.webhook_secret),
        }
    }
}

/// Masked LemonSqueezy config for display
#[derive(Debug, Clone, Serialize)]
pub struct LemonSqueezyConfigMasked {
    pub api_key: String,
    pub store_id: String,
    pub webhook_secret: String,
}

impl From<&LemonSqueezyConfig> for LemonSqueezyConfigMasked {
    fn from(config: &LemonSqueezyConfig) -> Self {
        Self {
            api_key: mask_secret(&config.api_key),
            store_id: config.store_id.clone(), // Store ID is not sensitive
            webhook_secret: mask_secret(&config.webhook_secret),
        }
    }
}

/// Mask a secret string, showing first 8 and last 4 characters
/// e.g., "sk_test_abc123xyz789" -> "sk_test_...9789"
fn mask_secret(s: &str) -> String {
    if s.len() <= 12 {
        // Too short to meaningfully mask
        return "*".repeat(s.len().min(8));
    }
    format!("{}...{}", &s[..8], &s[s.len() - 4..])
}

#[derive(Debug, Deserialize)]
pub struct UpdateProject {
    pub name: Option<String>,
    pub license_key_prefix: Option<String>,
    /// Redirect URL (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub redirect_url: Option<Option<String>>,
    /// Email "from" address (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub email_from: Option<Option<String>>,
    /// Whether email delivery is enabled
    pub email_enabled: Option<bool>,
    /// Webhook URL (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub email_webhook_url: Option<Option<String>>,
    /// Payment config override (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub payment_config_id: Option<Option<String>>,
    /// Email config override (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub email_config_id: Option<Option<String>>,
    /// Feedback webhook URL (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub feedback_webhook_url: Option<Option<String>>,
    /// Feedback email (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub feedback_email: Option<Option<String>>,
    /// Crash webhook URL (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub crash_webhook_url: Option<Option<String>>,
    /// Crash email (use Some(None) to clear, None to leave unchanged)
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub crash_email: Option<Option<String>>,
}

impl UpdateProject {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref name) = self.name
            && name.trim().is_empty()
        {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
        if let Some(ref prefix) = self.license_key_prefix {
            validate_prefix(prefix)?;
        }
        Ok(())
    }
}

/// Deserialize a field that can be:
/// - absent (None) - leave unchanged
/// - null (Some(None)) - clear the value
/// - present (Some(Some(value))) - set to value
fn deserialize_optional_field<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_prefix_alphanumeric() {
        // Valid prefixes
        assert!(validate_prefix("MYAPP").is_ok());
        assert!(validate_prefix("MyApp123").is_ok());
        assert!(validate_prefix("PC").is_ok());
        assert!(validate_prefix("A1B2C3").is_ok());
    }

    #[test]
    fn test_validate_prefix_with_whitespace_trim() {
        // Whitespace should be trimmed
        assert!(validate_prefix("  MYAPP  ").is_ok());
        assert!(validate_prefix("\tPC\n").is_ok());
    }

    #[test]
    fn test_validate_prefix_empty() {
        assert!(validate_prefix("").is_err());
        assert!(validate_prefix("   ").is_err());
    }

    #[test]
    fn test_validate_prefix_non_alphanumeric_rejected() {
        // These should all fail - non-alphanumeric chars could break SDK normalization
        assert!(validate_prefix("MY-APP").is_err()); // dash
        assert!(validate_prefix("MY_APP").is_err()); // underscore
        assert!(validate_prefix("MY.APP").is_err()); // dot
        assert!(validate_prefix("MY APP").is_err()); // space (after trim, this is "MY APP")
        assert!(validate_prefix("APP!").is_err()); // special char
        assert!(validate_prefix("`MYAPP`").is_err()); // backticks
    }
}
