mod operator_auth;
mod org_auth;

pub use operator_auth::*;
pub use org_auth::*;

/// Tracks how a request was authenticated.
/// Useful for audit logging to distinguish API key vs JWT auth.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Authenticated via API key
    ApiKey {
        /// The API key ID (not the key itself)
        key_id: String,
        /// The visible key prefix (e.g., "pc_a1b2...")
        key_prefix: String,
    },
    /// Authenticated via JWT from a trusted issuer
    Jwt {
        /// The issuer URL (from JWT `iss` claim)
        issuer: String,
    },
}

impl AuthMethod {
    /// Get the auth type as a string for filtering ("api_key" or "jwt").
    pub fn auth_type(&self) -> &'static str {
        match self {
            AuthMethod::ApiKey { .. } => "api_key",
            AuthMethod::Jwt { .. } => "jwt",
        }
    }

    /// Get the auth credential (key prefix or issuer URL).
    pub fn auth_credential(&self) -> &str {
        match self {
            AuthMethod::ApiKey { key_prefix, .. } => key_prefix,
            AuthMethod::Jwt { issuer } => issuer,
        }
    }
}
