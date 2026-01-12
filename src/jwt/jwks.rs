//! JWKS (JSON Web Key Set) fetching and caching.
//!
//! This module handles fetching and caching public keys from JWKS endpoints
//! for validating JWTs from trusted issuers.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use jwt_simple::prelude::*;
use serde::Deserialize;

use crate::error::{AppError, Result};

/// Cache duration for JWKS keys (1 hour)
const CACHE_DURATION: Duration = Duration::from_secs(3600);

/// A cached JWKS with its keys and fetch timestamp
struct CachedJwks {
    /// Map from key ID (kid) to public key
    keys: HashMap<String, RS256PublicKey>,
    /// When the JWKS was fetched
    fetched_at: Instant,
}

impl CachedJwks {
    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() > CACHE_DURATION
    }
}

/// Cache for JWKS keys from multiple issuers.
/// Thread-safe with interior mutability via RwLock.
pub struct JwksCache {
    /// Map from JWKS URL to cached keys
    cache: RwLock<HashMap<String, CachedJwks>>,
    /// HTTP client for fetching JWKS
    client: reqwest::Client,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksCache {
    /// Create a new JWKS cache.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Get a public key for a given JWKS URL and key ID.
    /// Fetches and caches the JWKS if not present or stale.
    pub async fn get_key(&self, jwks_url: &str, kid: &str) -> Result<RS256PublicKey> {
        // Try to get from cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(cached) = cache.get(jwks_url)
                && !cached.is_stale()
            {
                if let Some(key) = cached.keys.get(kid) {
                    return Ok(key.clone());
                }
                // Key ID not found in cached JWKS - don't refresh, just error
                return Err(AppError::JwtValidationFailed(format!(
                    "Key ID '{}' not found in JWKS",
                    kid
                )));
            }
        }

        // Cache miss or stale - fetch fresh JWKS
        let keys = self.fetch_jwks(jwks_url).await?;

        // Get the key we need (before moving keys into cache)
        let key = keys
            .get(kid)
            .cloned()
            .ok_or_else(|| AppError::JwtValidationFailed(format!("Key ID '{}' not found in JWKS", kid)))?;

        // Update cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(
                jwks_url.to_string(),
                CachedJwks {
                    keys,
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(key)
    }

    /// Fetch JWKS from a URL and parse the keys.
    async fn fetch_jwks(&self, url: &str) -> Result<HashMap<String, RS256PublicKey>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::JwksFetchFailed(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::JwksFetchFailed(format!(
                "HTTP {} from JWKS endpoint",
                response.status()
            )));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| AppError::JwksFetchFailed(format!("Failed to parse JWKS JSON: {}", e)))?;

        let mut keys = HashMap::new();

        for jwk in jwks.keys {
            // Only process RSA keys with RS256 algorithm (or no algorithm specified)
            if jwk.kty != "RSA" {
                continue;
            }
            if let Some(ref alg) = jwk.alg
                && alg != "RS256"
            {
                continue;
            }

            // Skip keys without a key ID
            let kid = match jwk.kid {
                Some(ref k) => k.clone(),
                None => continue,
            };

            // Parse the RSA public key from n and e components
            match parse_rsa_public_key(&jwk.n, &jwk.e) {
                Ok(public_key) => {
                    keys.insert(kid, public_key);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse JWK with kid '{}': {}", jwk.kid.as_deref().unwrap_or("unknown"), e);
                }
            }
        }

        if keys.is_empty() {
            return Err(AppError::JwksFetchFailed(
                "No valid RS256 keys found in JWKS".to_string(),
            ));
        }

        Ok(keys)
    }
}

/// JWKS response structure (RFC 7517)
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// Individual JWK structure (RFC 7517)
#[derive(Debug, Deserialize)]
struct Jwk {
    /// Key type (e.g., "RSA")
    kty: String,
    /// Key ID
    kid: Option<String>,
    /// Algorithm (e.g., "RS256")
    alg: Option<String>,
    /// RSA modulus (base64url encoded)
    #[serde(default)]
    n: String,
    /// RSA exponent (base64url encoded)
    #[serde(default)]
    e: String,
}

/// Parse an RSA public key from base64url-encoded n and e components.
fn parse_rsa_public_key(n_b64: &str, e_b64: &str) -> Result<RS256PublicKey> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Decode base64url components
    let n_bytes = URL_SAFE_NO_PAD
        .decode(n_b64)
        .map_err(|e| AppError::JwksFetchFailed(format!("Invalid base64url for 'n': {}", e)))?;
    let e_bytes = URL_SAFE_NO_PAD
        .decode(e_b64)
        .map_err(|e| AppError::JwksFetchFailed(format!("Invalid base64url for 'e': {}", e)))?;

    // Build DER-encoded RSA public key
    // RSA public key structure: SEQUENCE { INTEGER n, INTEGER e }
    let der = build_rsa_public_key_der(&n_bytes, &e_bytes);

    RS256PublicKey::from_der(&der)
        .map_err(|e| AppError::JwksFetchFailed(format!("Failed to parse RSA key: {}", e)))
}

/// Build a DER-encoded RSA public key from n and e byte arrays.
/// This creates a PKCS#1 RSAPublicKey structure wrapped in SubjectPublicKeyInfo.
fn build_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    // Helper to encode a DER INTEGER (handling sign bit)
    fn encode_integer(bytes: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        // If high bit is set, prepend 0x00 to indicate positive integer
        let needs_padding = !bytes.is_empty() && (bytes[0] & 0x80) != 0;
        let len = bytes.len() + if needs_padding { 1 } else { 0 };

        result.push(0x02); // INTEGER tag
        encode_length(&mut result, len);
        if needs_padding {
            result.push(0x00);
        }
        result.extend_from_slice(bytes);
        result
    }

    // Helper to encode DER length
    fn encode_length(result: &mut Vec<u8>, len: usize) {
        if len < 128 {
            result.push(len as u8);
        } else if len < 256 {
            result.push(0x81);
            result.push(len as u8);
        } else {
            result.push(0x82);
            result.push((len >> 8) as u8);
            result.push((len & 0xff) as u8);
        }
    }

    // Build RSAPublicKey SEQUENCE
    let n_der = encode_integer(n);
    let e_der = encode_integer(e);

    let mut rsa_key = Vec::new();
    rsa_key.push(0x30); // SEQUENCE tag
    encode_length(&mut rsa_key, n_der.len() + e_der.len());
    rsa_key.extend_from_slice(&n_der);
    rsa_key.extend_from_slice(&e_der);

    // Build SubjectPublicKeyInfo wrapper
    // AlgorithmIdentifier for rsaEncryption: 1.2.840.113549.1.1.1
    let algorithm_id = [
        0x30, 0x0d, // SEQUENCE
        0x06, 0x09, // OID
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // rsaEncryption
        0x05, 0x00, // NULL
    ];

    // BIT STRING containing RSAPublicKey
    let mut bit_string = Vec::new();
    bit_string.push(0x03); // BIT STRING tag
    encode_length(&mut bit_string, rsa_key.len() + 1);
    bit_string.push(0x00); // unused bits
    bit_string.extend_from_slice(&rsa_key);

    // Final SubjectPublicKeyInfo SEQUENCE
    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE tag
    encode_length(&mut result, algorithm_id.len() + bit_string.len());
    result.extend_from_slice(&algorithm_id);
    result.extend_from_slice(&bit_string);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_stale_detection() {
        // This test just verifies the stale detection logic works
        let cached = CachedJwks {
            keys: HashMap::new(),
            fetched_at: Instant::now(),
        };
        assert!(!cached.is_stale());
    }
}
