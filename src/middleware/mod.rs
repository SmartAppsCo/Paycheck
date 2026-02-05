mod operator_auth;
mod org_auth;

pub use operator_auth::*;
pub use org_auth::*;

/// Tracks how a request was authenticated.
/// Used for audit logging.
#[derive(Debug, Clone)]
pub struct AuthMethod {
    /// The API key ID (not the key itself)
    pub key_id: String,
    /// The visible key prefix (e.g., "pc_a1b2...")
    pub key_prefix: String,
}

impl AuthMethod {
    /// Get the auth type as a string for filtering.
    pub fn auth_type(&self) -> &'static str {
        "api_key"
    }

    /// Get the auth credential (key prefix).
    pub fn auth_credential(&self) -> &str {
        &self.key_prefix
    }
}
