use base64::engine::general_purpose::STANDARD as BASE64;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::rngs::OsRng;
use serde::Deserialize;

use super::{LicenseClaims, SigningClaims, VerifiedClaims};
use crate::error::{msg, AppError, Result};

/// Generate a new Ed25519 key pair
/// Returns (private_key_bytes, public_key_base64)
pub fn generate_keypair() -> (Vec<u8>, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_bytes = signing_key.to_bytes().to_vec();
    let public_b64 = BASE64.encode(verifying_key.to_bytes());

    (private_bytes, public_b64)
}

/// Convert raw 32-byte Ed25519 private key to PKCS8 DER format for jsonwebtoken
fn private_key_to_pkcs8_der(raw_key: &[u8; 32]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::from_bytes(raw_key);
    let der = signing_key
        .to_pkcs8_der()
        .map_err(|e| AppError::Internal(format!("Failed to encode private key as PKCS8: {}", e)))?;
    Ok(der.as_bytes().to_vec())
}

/// Decode base64-encoded Ed25519 public key and validate it
/// Returns raw 32-byte public key (ring expects raw bytes for Ed25519, not SPKI DER)
fn decode_public_key(public_key_b64: &str) -> Result<Vec<u8>> {
    let public_bytes = BASE64
        .decode(public_key_b64)
        .map_err(|e| AppError::Internal(format!("Invalid public key encoding: {}", e)))?;

    if public_bytes.len() != 32 {
        return Err(AppError::Internal(msg::INVALID_PUBLIC_KEY_LENGTH.into()));
    }

    // Validate the key is a valid Ed25519 public key
    let key_bytes: [u8; 32] = public_bytes.clone().try_into().map_err(|e| {
        tracing::error!(
            "Failed to convert public key bytes after length check: {:?}",
            e
        );
        AppError::Internal(msg::FAILED_TO_CONVERT_KEY_BYTES.into())
    })?;

    // This validates the key is on the curve
    let _ = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| AppError::Internal(format!("Invalid public key: {}", e)))?;

    Ok(public_bytes)
}

/// Sign claims with an Ed25519 private key
/// The `audience` parameter is included in the JWT for debugging purposes only
/// (e.g., to identify which project a token belongs to). It is NOT verified.
pub fn sign_claims(
    claims: &LicenseClaims,
    private_key: &[u8],
    subject: &str,
    audience: &str,
    jti: &str,
) -> Result<String> {
    if private_key.len() != 32 {
        return Err(AppError::Internal(msg::INVALID_PRIVATE_KEY_LENGTH.into()));
    }

    let key_bytes: [u8; 32] = private_key.try_into().map_err(|e| {
        tracing::error!(
            "Failed to convert private key bytes after length check: {:?}",
            e
        );
        AppError::Internal(msg::FAILED_TO_CONVERT_KEY_BYTES.into())
    })?;

    let der = private_key_to_pkcs8_der(&key_bytes)?;
    let encoding_key = EncodingKey::from_ed_der(&der);

    let now = chrono::Utc::now().timestamp();
    let signing_claims = SigningClaims {
        iss: "paycheck".to_string(),
        sub: subject.to_string(),
        aud: audience.to_string(),
        jti: jti.to_string(),
        iat: now,
        exp: now + 3600, // 1 hour validity
        custom: claims.clone(),
    };

    let token = encode(&Header::new(Algorithm::EdDSA), &signing_claims, &encoding_key)
        .map_err(|e| AppError::Internal(format!("Failed to sign token: {}", e)))?;

    Ok(token)
}

/// Decode a JWT without verification to extract claims
/// Used to get product_id to look up the signing key
/// MUST be followed by verify_token() before trusting any claims
pub fn decode_unverified(token: &str) -> Result<LicenseClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::BadRequest(msg::INVALID_TOKEN_FORMAT.into()));
    }

    let payload = BASE64_URL.decode(parts[1]).map_err(|e| {
        tracing::debug!("Invalid base64 encoding in token payload: {}", e);
        AppError::BadRequest(msg::INVALID_TOKEN_ENCODING.into())
    })?;

    #[derive(Deserialize)]
    struct TokenPayload {
        #[serde(flatten)]
        claims: LicenseClaims,
    }

    let payload: TokenPayload = serde_json::from_slice(&payload).map_err(|e| {
        tracing::debug!("Invalid JSON in token payload: {}", e);
        AppError::BadRequest(msg::INVALID_TOKEN_PAYLOAD.into())
    })?;

    Ok(payload.claims)
}

/// Verify a JWT and extract claims
/// Validates signature, expiration, and issuer ("paycheck")
/// Note: Audience is NOT verified - signature verification with the project's
/// public key is sufficient to prove the token was issued for that project.
pub fn verify_token(token: &str, public_key_b64: &str) -> Result<VerifiedClaims> {
    verify_token_internal(token, public_key_b64, false)
}

/// Verify a JWT signature but allow expired tokens (for refresh flow)
/// Validates signature and issuer ("paycheck") - but NOT expiration
pub fn verify_token_allow_expired(token: &str, public_key_b64: &str) -> Result<VerifiedClaims> {
    verify_token_internal(token, public_key_b64, true)
}

fn verify_token_internal(
    token: &str,
    public_key_b64: &str,
    allow_expired: bool,
) -> Result<VerifiedClaims> {
    // Note: Despite the name `from_ed_der`, ring/jsonwebtoken expects raw 32-byte Ed25519 public keys
    let raw_bytes = decode_public_key(public_key_b64)?;
    let decoding_key = DecodingKey::from_ed_der(&raw_bytes);

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["paycheck"]);
    // Audience not verified - signature with project's key is sufficient
    validation.validate_aud = false;
    // Required claims
    validation.set_required_spec_claims(&["iss", "sub", "exp", "iat"]);

    if allow_expired {
        validation.validate_exp = false;
    }

    let token_data = decode::<SigningClaims>(token, &decoding_key, &validation)
        .map_err(|e| AppError::BadRequest(format!("Invalid token: {}", e)))?;

    Ok(token_data.claims.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (private_key, public_key) = generate_keypair();

        let claims = LicenseClaims {
            license_exp: Some(chrono::Utc::now().timestamp() + 86400),
            updates_exp: None,
            tier: "pro".to_string(),
            features: vec!["feature1".to_string()],
            device_id: "device-123".to_string(),
            device_type: "uuid".to_string(),
            product_id: "product-123".to_string(),
        };

        let token = sign_claims(&claims, &private_key, "license-id", "project", "jti-123")
            .expect("signing should succeed");

        let verified =
            verify_token(&token, &public_key).expect("verification should succeed");

        assert_eq!(verified.custom.tier, "pro");
        assert_eq!(verified.custom.product_id, "product-123");
        assert_eq!(verified.issuer, Some("paycheck".to_string()));
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let (private_key, _) = generate_keypair();
        let (_, other_public_key) = generate_keypair();

        let claims = LicenseClaims {
            license_exp: None,
            updates_exp: None,
            tier: "pro".to_string(),
            features: vec![],
            device_id: "device-123".to_string(),
            device_type: "uuid".to_string(),
            product_id: "product-123".to_string(),
        };

        let token = sign_claims(&claims, &private_key, "license-id", "project", "jti-123")
            .expect("signing should succeed");

        let result = verify_token(&token, &other_public_key);
        assert!(result.is_err(), "should reject token signed with different key");
    }
}
