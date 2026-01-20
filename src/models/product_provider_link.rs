use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result, msg};

/// A link between a product and a payment provider's price/variant.
///
/// This replaces ProductPaymentConfig with a simpler model:
/// - No price passthrough (provider has the real price)
/// - Single `linked_id` column for all providers (Stripe Price ID, LS Variant ID, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductProviderLink {
    pub id: String,
    pub product_id: String,
    /// Payment provider: "stripe", "lemonsqueezy", etc.
    pub provider: String,
    /// The provider's price/variant ID (e.g., "price_xxx" for Stripe, variant ID for LS)
    pub linked_id: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateProviderLink {
    pub provider: String,
    pub linked_id: String,
}

impl CreateProviderLink {
    pub fn validate(&self) -> Result<()> {
        let provider = self.provider.trim().to_lowercase();
        if provider != "stripe" && provider != "lemonsqueezy" {
            return Err(AppError::BadRequest(msg::INVALID_PROVIDER.into()));
        }
        if self.linked_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "linked_id is required".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateProviderLink {
    pub linked_id: Option<String>,
}

impl UpdateProviderLink {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref linked_id) = self.linked_id
            && linked_id.trim().is_empty()
        {
            return Err(AppError::BadRequest("linked_id cannot be empty".into()));
        }
        Ok(())
    }
}
