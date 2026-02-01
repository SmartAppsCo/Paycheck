use serde::{Deserialize, Serialize};

use crate::crypto::MasterKey;
use crate::error::{AppError, Result};
use crate::models::project::{LemonSqueezyConfig, StripeConfig};

/// Category of external service (for database readability and querying)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceCategory {
    Payment,
    Email,
}

impl ServiceCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Payment => "payment",
            Self::Email => "email",
        }
    }
}

impl std::str::FromStr for ServiceCategory {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "payment" => Ok(Self::Payment),
            "email" => Ok(Self::Email),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for ServiceCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// External service provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProvider {
    // Payment providers
    Stripe,
    LemonSqueezy,
    // Email providers
    Resend,
}

impl ServiceProvider {
    /// Get the category this provider belongs to
    pub fn category(&self) -> ServiceCategory {
        match self {
            Self::Stripe | Self::LemonSqueezy => ServiceCategory::Payment,
            Self::Resend => ServiceCategory::Email,
        }
    }

    /// Check if this is a payment provider
    pub fn is_payment(&self) -> bool {
        self.category() == ServiceCategory::Payment
    }

    /// Check if this is an email provider
    pub fn is_email(&self) -> bool {
        self.category() == ServiceCategory::Email
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stripe => "stripe",
            Self::LemonSqueezy => "lemonsqueezy",
            Self::Resend => "resend",
        }
    }

    /// List all payment providers
    pub fn payment_providers() -> &'static [Self] {
        &[Self::Stripe, Self::LemonSqueezy]
    }

    /// List all email providers
    pub fn email_providers() -> &'static [Self] {
        &[Self::Resend]
    }
}

impl std::str::FromStr for ServiceProvider {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "stripe" => Ok(Self::Stripe),
            "lemonsqueezy" => Ok(Self::LemonSqueezy),
            "resend" => Ok(Self::Resend),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for ServiceProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Named service configuration (encrypted external service credentials).
/// Stored at org level as a reusable pool that can be referenced from org, project, or product.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceConfig {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub category: ServiceCategory,
    pub provider: ServiceProvider,
    #[serde(skip)]
    pub config_encrypted: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ServiceConfig {
    /// Decrypt as Stripe config. Panics if provider is not Stripe.
    pub fn decrypt_stripe_config(&self, master_key: &MasterKey) -> Result<StripeConfig> {
        debug_assert_eq!(self.provider, ServiceProvider::Stripe);
        let decrypted = master_key.decrypt_private_key(&self.org_id, &self.config_encrypted)?;
        let json = String::from_utf8(decrypted)
            .map_err(|_| AppError::Internal("Invalid UTF-8 in Stripe config".into()))?;
        let config: StripeConfig = serde_json::from_str(&json)?;
        Ok(config)
    }

    /// Decrypt as LemonSqueezy config. Panics if provider is not LemonSqueezy.
    pub fn decrypt_ls_config(&self, master_key: &MasterKey) -> Result<LemonSqueezyConfig> {
        debug_assert_eq!(self.provider, ServiceProvider::LemonSqueezy);
        let decrypted = master_key.decrypt_private_key(&self.org_id, &self.config_encrypted)?;
        let json = String::from_utf8(decrypted)
            .map_err(|_| AppError::Internal("Invalid UTF-8 in LemonSqueezy config".into()))?;
        let config: LemonSqueezyConfig = serde_json::from_str(&json)?;
        Ok(config)
    }

    /// Decrypt as Resend API key. Panics if provider is not Resend.
    pub fn decrypt_resend_api_key(&self, master_key: &MasterKey) -> Result<String> {
        debug_assert_eq!(self.provider, ServiceProvider::Resend);
        let decrypted = master_key.decrypt_private_key(&self.org_id, &self.config_encrypted)?;
        let api_key = String::from_utf8(decrypted)
            .map_err(|_| AppError::Internal("Invalid UTF-8 in Resend API key".into()))?;
        Ok(api_key)
    }
}

/// Source of a configuration in hierarchical lookup (for API responses)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigSource {
    /// Configuration from the product level (highest priority)
    Product,
    /// Configuration from the project level
    Project,
    /// Configuration from the organization level (lowest priority/fallback)
    Org,
}
