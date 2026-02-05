use serde::{Deserialize, Serialize};

/// Custom claims for Paycheck licenses (non-standard JWT claims)
/// Standard claims (iss, sub, aud, jti, iat, exp) are handled separately
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    // Paycheck-specific claims
    pub license_exp: Option<i64>, // When license access ends (NULL = perpetual)
    pub updates_exp: Option<i64>, // When new version access ends
    pub tier: String,             // Product tier
    pub features: Vec<String>,    // Enabled features

    // Identity
    pub device_id: String,   // Device identifier
    pub device_type: String, // "uuid" or "machine"

    // Metadata
    pub product_id: String, // Product ID
}

impl LicenseClaims {
    pub fn is_license_expired(&self, now: i64) -> bool {
        self.license_exp.is_some_and(|exp| now > exp)
    }

    pub fn covers_version(&self, version_timestamp: i64) -> bool {
        match self.updates_exp {
            Some(exp) => version_timestamp <= exp,
            None => true, // No updates expiration = covers all versions
        }
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

/// Combined claims for signing (includes standard JWT fields)
/// Used internally for jsonwebtoken serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningClaims {
    // Standard claims
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,

    // Custom claims (flattened into top-level)
    #[serde(flatten)]
    pub custom: LicenseClaims,
}

/// Verified claims returned after JWT verification.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    pub custom: LicenseClaims,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub audiences: Option<Vec<String>>,
    pub jwt_id: Option<String>,
    pub issued_at: Option<i64>,
    pub expires_at: Option<i64>,
}

impl From<SigningClaims> for VerifiedClaims {
    fn from(claims: SigningClaims) -> Self {
        Self {
            custom: claims.custom,
            issuer: Some(claims.iss),
            subject: Some(claims.sub),
            audiences: Some(vec![claims.aud]),
            jwt_id: Some(claims.jti),
            issued_at: Some(claims.iat),
            expires_at: Some(claims.exp),
        }
    }
}
