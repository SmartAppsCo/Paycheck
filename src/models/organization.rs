use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result, msg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    /// Default payment service config for this org (can be overridden at project/product level)
    pub payment_config_id: Option<String>,
    /// Default email service config for this org (can be overridden at project level)
    pub email_config_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganization {
    pub name: String,
    /// User ID to create as owner of this org (must exist in users table)
    #[serde(default)]
    pub owner_user_id: Option<String>,
}

impl CreateOrganization {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganization {
    pub name: Option<String>,
    /// Default payment config ID - use Some(id) to set, Some(None) to clear, None to leave unchanged
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub payment_config_id: Option<Option<String>>,
    /// Default email config ID - use Some(id) to set, Some(None) to clear, None to leave unchanged
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub email_config_id: Option<Option<String>>,
}

impl UpdateOrganization {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref name) = self.name
            && name.trim().is_empty()
        {
            return Err(AppError::BadRequest(msg::NAME_EMPTY.into()));
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

/// Public view of an organization (includes configured services summary)
#[derive(Debug, Clone, Serialize)]
pub struct OrganizationPublic {
    pub id: String,
    pub name: String,
    /// Default payment config ID for this org
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_config_id: Option<String>,
    /// Default email config ID for this org
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_config_id: Option<String>,
    /// Available service configs for this org (id -> name mapping)
    pub service_configs: std::collections::HashMap<String, String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

impl OrganizationPublic {
    /// Create OrganizationPublic with service configs summary
    pub fn from_with_configs(
        org: Organization,
        service_configs: std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            id: org.id,
            name: org.name,
            payment_config_id: org.payment_config_id,
            email_config_id: org.email_config_id,
            service_configs,
            created_at: org.created_at,
            updated_at: org.updated_at,
            deleted_at: org.deleted_at,
            deleted_cascade_depth: org.deleted_cascade_depth,
        }
    }
}
