//! JWT decoding and verification utilities

use crate::error::{PaycheckError, PaycheckErrorCode, Result};
use crate::types::LicenseClaims;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};

/// Decode a JWT and return the claims.
///
/// Does NOT verify the signature - use `verify_token` for that.
pub fn decode_token(token: &str) -> Result<LicenseClaims> {
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() != 3 {
        return Err(PaycheckError::new(
            PaycheckErrorCode::ValidationError,
            "Invalid JWT format",
        ));
    }

    let payload = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
        PaycheckError::new(
            PaycheckErrorCode::ValidationError,
            "Failed to decode JWT payload",
        )
    })?;

    let claims: LicenseClaims = serde_json::from_slice(&payload).map_err(|_| {
        PaycheckError::new(
            PaycheckErrorCode::ValidationError,
            "Failed to parse JWT claims",
        )
    })?;

    Ok(claims)
}

/// Verify a JWT signature using Ed25519.
///
/// # Arguments
/// * `token` - The JWT token to verify
/// * `public_key` - Base64-encoded Ed25519 public key (32 bytes)
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_token(token: &str, public_key: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Decode public key from base64
    let public_key_bytes = match STANDARD.decode(public_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Convert to VerifyingKey
    let verifying_key: VerifyingKey = match public_key_bytes.try_into() {
        Ok(bytes) => match VerifyingKey::from_bytes(&bytes) {
            Ok(key) => key,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    // Decode signature from base64url
    let signature_bytes = match URL_SAFE_NO_PAD.decode(parts[2]) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // The message is "header.payload"
    let message = format!("{}.{}", parts[0], parts[1]);

    // Verify
    verifying_key.verify(message.as_bytes(), &signature).is_ok()
}

/// Verify a JWT and return the claims if valid.
///
/// # Arguments
/// * `token` - The JWT token to verify
/// * `public_key` - Base64-encoded Ed25519 public key
///
/// # Returns
/// The decoded claims if signature is valid, error otherwise.
pub fn verify_and_decode_token(token: &str, public_key: &str) -> Result<LicenseClaims> {
    if !verify_token(token, public_key) {
        return Err(PaycheckError::new(
            PaycheckErrorCode::ValidationError,
            "Invalid JWT signature",
        ));
    }

    decode_token(token)
}

/// Get the current Unix timestamp
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Check if the JWT's exp claim has passed.
///
/// This is for transport security, not license validity.
pub fn is_jwt_expired(claims: &LicenseClaims) -> bool {
    claims.exp < now()
}

/// Check if the license has expired (license_exp claim).
///
/// This is the actual license validity check.
pub fn is_license_expired(claims: &LicenseClaims) -> bool {
    match claims.license_exp {
        None => false, // Perpetual license
        Some(exp) => exp < now(),
    }
}

/// Check if the license covers a specific version (by its release timestamp).
pub fn covers_version(claims: &LicenseClaims, version_timestamp: i64) -> bool {
    match claims.updates_exp {
        None => true, // All versions covered
        Some(exp) => version_timestamp <= exp,
    }
}

/// Check if the license has a specific feature.
pub fn has_feature(claims: &LicenseClaims, feature: &str) -> bool {
    claims.features.iter().any(|f| f == feature)
}

/// Expected issuer for Paycheck JWTs
pub const EXPECTED_ISSUER: &str = "paycheck";

/// Validate the JWT issuer claim.
///
/// Returns `true` if the issuer is "paycheck", `false` otherwise.
/// This should be called after decoding to ensure the JWT was issued by Paycheck.
pub fn validate_issuer(claims: &LicenseClaims) -> bool {
    claims.iss == EXPECTED_ISSUER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_token() {
        // This is a test token with known claims
        // Header: {"alg":"EdDSA","typ":"JWT"}
        // Payload: {"iss":"paycheck","sub":"license-123","aud":"test.com","jti":"jti-123","iat":1704067200,"exp":1704070800,"license_exp":null,"updates_exp":null,"tier":"pro","features":["export"],"device_id":"device-123","device_type":"uuid","product_id":"product-123"}
        let token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwYXljaGVjayIsInN1YiI6ImxpY2Vuc2UtMTIzIiwiYXVkIjoidGVzdC5jb20iLCJqdGkiOiJqdGktMTIzIiwiaWF0IjoxNzA0MDY3MjAwLCJleHAiOjE3MDQwNzA4MDAsImxpY2Vuc2VfZXhwIjpudWxsLCJ1cGRhdGVzX2V4cCI6bnVsbCwidGllciI6InBybyIsImZlYXR1cmVzIjpbImV4cG9ydCJdLCJkZXZpY2VfaWQiOiJkZXZpY2UtMTIzIiwiZGV2aWNlX3R5cGUiOiJ1dWlkIiwicHJvZHVjdF9pZCI6InByb2R1Y3QtMTIzIn0.signature";

        let claims = decode_token(token).unwrap();
        assert_eq!(claims.iss, "paycheck");
        assert_eq!(claims.tier, "pro");
        assert!(has_feature(&claims, "export"));
        assert!(!has_feature(&claims, "nonexistent"));
    }

    #[test]
    fn test_validate_issuer_rejects_wrong_issuer() {
        // Token with wrong issuer: "wrong-issuer" instead of "paycheck"
        // Header: {"alg":"EdDSA","typ":"JWT"}
        // Payload: {"iss":"wrong-issuer","sub":"license-123","aud":"test.com","jti":"jti-123","iat":1704067200,"exp":1704070800,"license_exp":null,"updates_exp":null,"tier":"pro","features":["export"],"device_id":"device-123","device_type":"uuid","product_id":"product-123"}
        let wrong_issuer_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3cm9uZy1pc3N1ZXIiLCJzdWIiOiJsaWNlbnNlLTEyMyIsImF1ZCI6InRlc3QuY29tIiwianRpIjoianRpLTEyMyIsImlhdCI6MTcwNDA2NzIwMCwiZXhwIjoxNzA0MDcwODAwLCJsaWNlbnNlX2V4cCI6bnVsbCwidXBkYXRlc19leHAiOm51bGwsInRpZXIiOiJwcm8iLCJmZWF0dXJlcyI6WyJleHBvcnQiXSwiZGV2aWNlX2lkIjoiZGV2aWNlLTEyMyIsImRldmljZV90eXBlIjoidXVpZCIsInByb2R1Y3RfaWQiOiJwcm9kdWN0LTEyMyJ9.signature";

        // decode_token should work (it doesn't validate issuer)
        let claims = decode_token(wrong_issuer_token).unwrap();
        assert_eq!(claims.iss, "wrong-issuer");

        // validate_issuer should reject it
        assert!(
            !validate_issuer(&claims),
            "validate_issuer should reject wrong issuer"
        );
    }

    #[test]
    fn test_validate_issuer_accepts_correct_issuer() {
        let token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwYXljaGVjayIsInN1YiI6ImxpY2Vuc2UtMTIzIiwiYXVkIjoidGVzdC5jb20iLCJqdGkiOiJqdGktMTIzIiwiaWF0IjoxNzA0MDY3MjAwLCJleHAiOjE3MDQwNzA4MDAsImxpY2Vuc2VfZXhwIjpudWxsLCJ1cGRhdGVzX2V4cCI6bnVsbCwidGllciI6InBybyIsImZlYXR1cmVzIjpbImV4cG9ydCJdLCJkZXZpY2VfaWQiOiJkZXZpY2UtMTIzIiwiZGV2aWNlX3R5cGUiOiJ1dWlkIiwicHJvZHVjdF9pZCI6InByb2R1Y3QtMTIzIn0.signature";

        let claims = decode_token(token).unwrap();
        assert!(
            validate_issuer(&claims),
            "validate_issuer should accept 'paycheck' issuer"
        );
    }

    // ==================== Helpers for signature tests ====================

    fn make_signed_jwt(claims_json: &str, signing_key: &ed25519_dalek::SigningKey) -> String {
        use ed25519_dalek::Signer;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims_json);
        let message = format!("{}.{}", header, payload);
        let signature = signing_key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{}.{}", message, sig_b64)
    }

    fn make_claims(exp: i64, license_exp: Option<i64>, updates_exp: Option<i64>) -> LicenseClaims {
        let license_exp_str = match license_exp {
            Some(v) => v.to_string(),
            None => "null".to_string(),
        };
        let updates_exp_str = match updates_exp {
            Some(v) => v.to_string(),
            None => "null".to_string(),
        };
        serde_json::from_str(&format!(
            r#"{{"iss":"paycheck","sub":"lic-123","aud":"test","jti":"jti-123","iat":1704067200,"exp":{},"license_exp":{},"updates_exp":{},"tier":"pro","features":[],"device_id":"dev-123","device_type":"uuid","product_id":"prod-123"}}"#,
            exp, license_exp_str, updates_exp_str
        )).unwrap()
    }

    const TEST_CLAIMS_JSON: &str = r#"{"iss":"paycheck","sub":"license-123","aud":"test.com","jti":"jti-123","iat":1704067200,"exp":1704070800,"license_exp":null,"updates_exp":null,"tier":"pro","features":["export"],"device_id":"device-123","device_type":"uuid","product_id":"product-123"}"#;

    // ==================== verify_token tests ====================

    #[test]
    fn test_verify_token_valid_signature() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let public_key_b64 = STANDARD.encode(signing_key.verifying_key().as_bytes());

        let token = make_signed_jwt(TEST_CLAIMS_JSON, &signing_key);
        assert!(verify_token(&token, &public_key_b64));

        // Also verify the decoded claims are correct
        let claims = decode_token(&token).unwrap();
        assert_eq!(claims.iss, "paycheck");
        assert_eq!(claims.tier, "pro");
        assert_eq!(claims.device_id, "device-123");
    }

    #[test]
    fn test_verify_token_invalid_signature() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let public_key_b64 = STANDARD.encode(signing_key.verifying_key().as_bytes());

        let token = make_signed_jwt(TEST_CLAIMS_JSON, &signing_key);

        // Corrupt the signature by flipping a byte
        let parts: Vec<&str> = token.split('.').collect();
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig_bytes[0] ^= 0xFF;
        let corrupted_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let corrupted_token = format!("{}.{}.{}", parts[0], parts[1], corrupted_sig);

        assert!(!verify_token(&corrupted_token, &public_key_b64));
    }

    #[test]
    fn test_verify_token_wrong_key() {
        let key_a = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let key_b = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        let public_key_b_b64 = STANDARD.encode(key_b.verifying_key().as_bytes());

        // Sign with key A, verify with key B
        let token = make_signed_jwt(TEST_CLAIMS_JSON, &key_a);
        assert!(!verify_token(&token, &public_key_b_b64));
    }

    #[test]
    fn test_verify_token_malformed_input() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let pub_key = STANDARD.encode(key.verifying_key().as_bytes());

        // All of these should return false, not panic
        assert!(!verify_token("", &pub_key));
        assert!(!verify_token("not.a.jwt", &pub_key));
        assert!(!verify_token("a.b", &pub_key));
        assert!(!verify_token("a.b.c.d", &pub_key));
    }

    // ==================== Expiration tests ====================

    #[test]
    fn test_is_jwt_expired() {
        let past = now() - 3600;
        let future = now() + 3600;

        let expired_claims = make_claims(past, None, None);
        assert!(is_jwt_expired(&expired_claims), "JWT with past exp should be expired");

        let valid_claims = make_claims(future, None, None);
        assert!(!is_jwt_expired(&valid_claims), "JWT with future exp should not be expired");
    }

    #[test]
    fn test_is_license_expired_perpetual() {
        // license_exp: None = perpetual license, never expires
        let claims = make_claims(now() + 3600, None, None);
        assert!(!is_license_expired(&claims));
    }

    #[test]
    fn test_is_license_expired_past() {
        let claims = make_claims(now() + 3600, Some(now() - 3600), None);
        assert!(is_license_expired(&claims));
    }

    #[test]
    fn test_is_license_expired_future() {
        let claims = make_claims(now() + 3600, Some(now() + 3600), None);
        assert!(!is_license_expired(&claims));
    }

    // ==================== covers_version tests ====================

    #[test]
    fn test_covers_version_no_updates_exp() {
        // updates_exp: None = all versions covered
        let claims = make_claims(now() + 3600, None, None);
        assert!(covers_version(&claims, 999_999_999));
    }

    #[test]
    fn test_covers_version_before_exp() {
        // updates_exp: 1000, timestamp 999 = covered
        let claims = make_claims(now() + 3600, None, Some(1000));
        assert!(covers_version(&claims, 999));
    }

    #[test]
    fn test_covers_version_at_boundary() {
        // Boundary: timestamp == updates_exp (uses <=, so should be covered)
        let claims = make_claims(now() + 3600, None, Some(1000));
        assert!(covers_version(&claims, 1000));
    }

    #[test]
    fn test_covers_version_after_exp() {
        // timestamp > updates_exp = not covered
        let claims = make_claims(now() + 3600, None, Some(1000));
        assert!(!covers_version(&claims, 1001));
    }
}
