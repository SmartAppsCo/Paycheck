use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: String,
    /// SHA-256 hash of the purchase email (no PII stored)
    pub email_hash: Option<String>,
    pub project_id: String,
    pub product_id: String,
    /// Developer-managed customer identifier (optional)
    /// Use this to link licenses to your own user/account system
    pub customer_id: Option<String>,
    pub activation_count: i32,
    pub revoked: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub updates_expires_at: Option<i64>,
    /// Soft delete timestamp (None = active, Some = deleted at this time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
    /// Cascade depth (0 = directly deleted, >0 = cascaded from parent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_cascade_depth: Option<i32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseWithProduct {
    #[serde(flatten)]
    pub license: License,
    pub product_name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateLicense {
    /// SHA-256 hash of the purchase email (computed from webhook data)
    #[serde(default)]
    pub email_hash: Option<String>,
    /// Developer-managed customer identifier (optional)
    #[serde(default)]
    pub customer_id: Option<String>,
    pub expires_at: Option<i64>,
    pub updates_expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationCode {
    pub code: String,
    pub license_id: String,
    pub expires_at: i64,
    pub used: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedJti {
    pub jti: String,
    pub license_id: String,
    pub revoked_at: i64,
    pub details: Option<String>,
}
