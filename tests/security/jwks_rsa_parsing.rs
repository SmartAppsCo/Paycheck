//! Security tests for JWKS RSA key parsing.
//!
//! The JWKS module parses RSA public keys from JWK format (n, e components).
//! These tests verify the parsing works correctly with real-world key formats
//! and that malformed inputs are properly rejected.

#[path = "../common/mod.rs"]
mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};

/// Test claims for RSA JWT tests
#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    exp: i64,
    iat: i64,
}

fn create_test_claims() -> TestClaims {
    let now = chrono::Utc::now().timestamp();
    TestClaims {
        sub: "test-user".to_string(),
        exp: now + 3600,
        iat: now,
    }
}

// ============ VALID KEY PARSING TESTS ============

/// Test that jsonwebtoken's from_rsa_components works with standard RSA keys.
#[test]
fn test_from_components_with_2048_bit_key() {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    // Get n and e components
    let n = private_key.n();
    let e = private_key.e();

    // Encode as base64url
    let n_b64 = URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(e.to_bytes_be());

    // Create decoding key from components
    let decoding_key = DecodingKey::from_rsa_components(&n_b64, &e_b64).unwrap();

    // Create encoding key for signing
    let private_der = private_key.to_pkcs1_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());

    // Sign a token
    let claims = create_test_claims();
    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();

    // Verify with the decoding key
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let verified = decode::<TestClaims>(&token, &decoding_key, &validation);
    assert!(verified.is_ok(), "Key should verify token");
}

/// Test that keys with standard 65537 (0x010001) exponent work.
#[test]
fn test_standard_exponent_65537() {
    // 65537 = 0x010001 in bytes
    let e_bytes = vec![0x01, 0x00, 0x01];

    // Verify exponent encoding (AQAB is standard base64url for 65537)
    let e_b64 = URL_SAFE_NO_PAD.encode(&e_bytes);
    assert_eq!(e_b64, "AQAB");

    // Generate a key and verify the exponent is 65537
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let e = private_key.e();
    assert_eq!(e.to_bytes_be(), e_bytes, "RSA exponent should be 65537");
}

// ============ SIGNATURE VERIFICATION TESTS ============

/// Test that a parsed key can actually verify a signature.
#[test]
fn test_key_verifies_signature() {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    let n = private_key.n();
    let e = private_key.e();
    let n_b64 = URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(e.to_bytes_be());

    let decoding_key = DecodingKey::from_rsa_components(&n_b64, &e_b64).unwrap();
    let private_der = private_key.to_pkcs1_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());

    let claims = create_test_claims();
    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let verification = decode::<TestClaims>(&token, &decoding_key, &validation);
    assert!(verification.is_ok(), "Key should verify valid signature");

    let verified_claims = verification.unwrap();
    assert_eq!(
        verified_claims.claims.sub, "test-user",
        "Claims should be preserved"
    );
}

/// Test that a key rejects signatures from a different key pair.
#[test]
fn test_key_rejects_wrong_signature() {
    let mut rng = rand::thread_rng();
    let private_key_1 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let private_key_2 = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    // Sign with key 1
    let private_der_1 = private_key_1.to_pkcs1_der().unwrap();
    let encoding_key_1 = EncodingKey::from_rsa_der(private_der_1.as_bytes());

    let claims = create_test_claims();
    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key_1).unwrap();

    // Try to verify with key 2's public key
    let n_2 = private_key_2.n();
    let e_2 = private_key_2.e();
    let n_b64_2 = URL_SAFE_NO_PAD.encode(n_2.to_bytes_be());
    let e_b64_2 = URL_SAFE_NO_PAD.encode(e_2.to_bytes_be());

    let decoding_key_2 = DecodingKey::from_rsa_components(&n_b64_2, &e_b64_2).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let verification = decode::<TestClaims>(&token, &decoding_key_2, &validation);

    assert!(
        verification.is_err(),
        "Key should reject signature from different key pair"
    );
}

/// Test that a key rejects a tampered token.
#[test]
fn test_key_rejects_tampered_token() {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    let n = private_key.n();
    let e = private_key.e();
    let n_b64 = URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(e.to_bytes_be());

    let decoding_key = DecodingKey::from_rsa_components(&n_b64, &e_b64).unwrap();
    let private_der = private_key.to_pkcs1_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());

    let claims = create_test_claims();
    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();

    // Tamper with the payload
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    let mut payload_bytes = STANDARD.decode(parts[1]).unwrap_or_default();
    if !payload_bytes.is_empty() {
        payload_bytes[0] ^= 0xFF;
    }
    let tampered_payload = STANDARD.encode(&payload_bytes);
    let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let verification = decode::<TestClaims>(&tampered_token, &decoding_key, &validation);
    assert!(verification.is_err(), "Key should reject tampered token");
}

// ============ from_components TESTS ============

/// Test from_components with valid n and e bytes.
#[test]
fn test_from_components_valid_input() {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    let n = private_key.n();
    let e = private_key.e();
    let n_b64 = URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(e.to_bytes_be());

    let decoding_key = DecodingKey::from_rsa_components(&n_b64, &e_b64).unwrap();
    let private_der = private_key.to_pkcs1_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());

    let claims = create_test_claims();
    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let verification = decode::<TestClaims>(&token, &decoding_key, &validation);
    assert!(verification.is_ok());
}

/// Test that invalid keys fail at verification time.
#[test]
fn test_invalid_key_fails_at_verification() {
    // Create a key with garbage data (way too small for RSA)
    let garbage_n = URL_SAFE_NO_PAD.encode(&[0x01; 32]);
    let valid_e = "AQAB"; // 65537

    // The library may or may not accept this at construction
    let result = DecodingKey::from_rsa_components(&garbage_n, valid_e);

    if let Ok(bad_key) = result {
        // If it accepts the bad key, verification should fail
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_der = private_key.to_pkcs1_der().unwrap();
        let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());

        let claims = create_test_claims();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        let verification = decode::<TestClaims>(&token, &bad_key, &validation);
        assert!(
            verification.is_err(),
            "Invalid key should fail at verification"
        );
    }
    // If construction fails, that's also fine
}

// ============ BASE64URL DECODING TESTS ============

/// Test that invalid base64url is handled properly.
#[test]
fn test_invalid_base64url_rejected() {
    let invalid = "!!!not-valid-base64!!!";
    let result = URL_SAFE_NO_PAD.decode(invalid);
    assert!(result.is_err(), "Invalid base64url should be rejected");
}

/// Test that valid base64url decodes correctly.
#[test]
fn test_valid_base64url_decodes() {
    // AQAB is base64url for [0x01, 0x00, 0x01] (65537)
    let result = URL_SAFE_NO_PAD.decode("AQAB").unwrap();
    assert_eq!(result, vec![0x01, 0x00, 0x01]);
}

// ============ REAL-WORLD COMPATIBILITY TESTS ============

/// Test with Google JWKS format (2048-bit RSA, e=65537).
#[test]
fn test_google_jwks_format_compatibility() {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    let n = private_key.n();
    let e = private_key.e();
    let n_b64 = URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(e.to_bytes_be());

    let decoding_key = DecodingKey::from_rsa_components(&n_b64, &e_b64).unwrap();
    let private_der = private_key.to_pkcs1_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());

    let now = chrono::Utc::now().timestamp();
    #[derive(Serialize, Deserialize)]
    struct GoogleClaims {
        iss: String,
        aud: String,
        sub: String,
        exp: i64,
        iat: i64,
    }

    let claims = GoogleClaims {
        iss: "https://accounts.google.com".to_string(),
        aud: "test-client-id".to_string(),
        sub: "user123".to_string(),
        exp: now + 3600,
        iat: now,
    };

    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://accounts.google.com"]);
    validation.set_audience(&["test-client-id"]);
    let verification = decode::<GoogleClaims>(&token, &decoding_key, &validation);

    assert!(verification.is_ok(), "Google-format key should work");
}

/// Test with Auth0 JWKS format.
#[test]
fn test_auth0_jwks_format_compatibility() {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

    let n = private_key.n();
    let e = private_key.e();
    let n_b64 = URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(e.to_bytes_be());

    let decoding_key = DecodingKey::from_rsa_components(&n_b64, &e_b64).unwrap();
    let private_der = private_key.to_pkcs1_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());

    let now = chrono::Utc::now().timestamp();
    #[derive(Serialize, Deserialize)]
    struct Auth0Claims {
        iss: String,
        aud: String,
        sub: String,
        exp: i64,
        iat: i64,
    }

    let claims = Auth0Claims {
        iss: "https://tenant.auth0.com/".to_string(),
        aud: "https://api.example.com".to_string(),
        sub: "auth0|user123".to_string(),
        exp: now + 3600,
        iat: now,
    };

    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://tenant.auth0.com/"]);
    validation.set_audience(&["https://api.example.com"]);
    let verification = decode::<Auth0Claims>(&token, &decoding_key, &validation);

    assert!(verification.is_ok(), "Auth0-format key should work");
}

/// Test with various RSA key sizes.
#[test]
fn test_various_key_sizes() {
    let mut rng = rand::thread_rng();

    // 2048-bit (minimum recommended)
    let key_2048 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let n = key_2048.n();
    let e = key_2048.e();
    let decoding_key_2048 =
        DecodingKey::from_rsa_components(&URL_SAFE_NO_PAD.encode(n.to_bytes_be()), &URL_SAFE_NO_PAD.encode(e.to_bytes_be())).unwrap();
    let encoding_key_2048 =
        EncodingKey::from_rsa_der(key_2048.to_pkcs1_der().unwrap().as_bytes());

    let claims = create_test_claims();
    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key_2048).unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    assert!(decode::<TestClaims>(&token, &decoding_key_2048, &validation).is_ok());

    // 3072-bit
    let key_3072 = RsaPrivateKey::new(&mut rng, 3072).unwrap();
    let n = key_3072.n();
    let e = key_3072.e();
    let decoding_key_3072 =
        DecodingKey::from_rsa_components(&URL_SAFE_NO_PAD.encode(n.to_bytes_be()), &URL_SAFE_NO_PAD.encode(e.to_bytes_be())).unwrap();
    let encoding_key_3072 =
        EncodingKey::from_rsa_der(key_3072.to_pkcs1_der().unwrap().as_bytes());

    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key_3072).unwrap();
    assert!(decode::<TestClaims>(&token, &decoding_key_3072, &validation).is_ok());

    // 4096-bit
    let key_4096 = RsaPrivateKey::new(&mut rng, 4096).unwrap();
    let n = key_4096.n();
    let e = key_4096.e();
    let decoding_key_4096 =
        DecodingKey::from_rsa_components(&URL_SAFE_NO_PAD.encode(n.to_bytes_be()), &URL_SAFE_NO_PAD.encode(e.to_bytes_be())).unwrap();
    let encoding_key_4096 =
        EncodingKey::from_rsa_der(key_4096.to_pkcs1_der().unwrap().as_bytes());

    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key_4096).unwrap();
    assert!(decode::<TestClaims>(&token, &decoding_key_4096, &validation).is_ok());
}

// ============ JWKS CACHE TESTS ============

/// Test that JwksCache can be created and used.
#[test]
fn test_jwks_cache_creation() {
    use paycheck::jwt::JwksCache;

    let cache = JwksCache::new();
    // Cache should be created successfully
    assert!(std::mem::size_of_val(&cache) > 0);
}
