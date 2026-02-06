//! Crypto module tests (envelope encryption, secret hashing)

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use paycheck::crypto::{MasterKey, hash_secret};

/// Master key size in bytes (256 bits for AES-256)
const MASTER_KEY_SIZE: usize = 32;

/// SHA-256 hash output length in hex characters
const SHA256_HEX_LENGTH: usize = 64;

/// Short key size for invalid length test (half of required size)
const SHORT_KEY_SIZE: usize = 16;

#[test]
fn test_generate_master_key() {
    let key = MasterKey::generate();
    assert!(!key.is_empty(), "generated master key should not be empty");

    // Should be valid base64 that decodes to 32 bytes
    let decoded = BASE64.decode(&key).unwrap();
    assert_eq!(
        decoded.len(),
        MASTER_KEY_SIZE,
        "decoded master key should be {MASTER_KEY_SIZE} bytes for AES-256"
    );
}

#[test]
fn test_from_base64_valid() {
    let key_b64 = MasterKey::generate();
    let result = MasterKey::from_base64(&key_b64);
    assert!(
        result.is_ok(),
        "valid base64-encoded master key should parse successfully"
    );
}

#[test]
fn test_from_base64_invalid_length() {
    let short_key = BASE64.encode([0u8; SHORT_KEY_SIZE]);
    let result = MasterKey::from_base64(&short_key);
    assert!(
        result.is_err(),
        "master key with only {SHORT_KEY_SIZE} bytes should be rejected"
    );
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-123";
    let private_key = [42u8; MASTER_KEY_SIZE]; // Simulated Ed25519 private key

    let encrypted = master_key
        .encrypt_private_key(project_id, &private_key)
        .unwrap();

    let decrypted = master_key
        .decrypt_private_key(project_id, &encrypted)
        .unwrap();

    assert_eq!(
        decrypted, private_key,
        "decrypted private key should match original plaintext"
    );
}

#[test]
fn test_different_projects_different_ciphertext() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let private_key = [42u8; MASTER_KEY_SIZE];

    let encrypted1 = master_key
        .encrypt_private_key("project-1", &private_key)
        .unwrap();
    let encrypted2 = master_key
        .encrypt_private_key("project-2", &private_key)
        .unwrap();

    // Same plaintext, different project IDs -> different ciphertext
    // (Also different due to random nonce, but DEK derivation also differs)
    assert_ne!(
        encrypted1, encrypted2,
        "same plaintext encrypted for different projects should produce different ciphertext"
    );
}

#[test]
fn test_wrong_project_id_fails() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let private_key = [42u8; MASTER_KEY_SIZE];

    let encrypted = master_key
        .encrypt_private_key("project-1", &private_key)
        .unwrap();

    // Try to decrypt with wrong project ID
    let result = master_key.decrypt_private_key("project-2", &encrypted);
    assert!(
        result.is_err(),
        "decryption with wrong project ID should fail due to different DEK"
    );
}

#[test]
fn test_hash_secret_produces_deterministic_hex_output() {
    let key = "PC-ABCD-1234-WXYZ-5678";
    let hash = hash_secret(key);

    // Should be 64 hex chars (256 bits)
    assert_eq!(
        hash.len(),
        SHA256_HEX_LENGTH,
        "SHA-256 hash should be {SHA256_HEX_LENGTH} hex characters"
    );
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "hash should contain only hexadecimal characters"
    );

    // Same input should produce same hash
    assert_eq!(
        hash,
        hash_secret(key),
        "hashing the same input twice should produce identical output"
    );

    // Different input should produce different hash
    assert_ne!(
        hash,
        hash_secret("PC-DIFFERENT-KEY"),
        "different inputs should produce different hashes"
    );
}

// ============ AES-256-GCM Authentication / Tamper Detection Tests ============

/// Encrypted format: ENC1 (4 bytes) || nonce (12 bytes) || ciphertext
const MAGIC_LEN: usize = 4;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC_LEN + NONCE_LEN; // 16 bytes before ciphertext

#[test]
fn test_tampered_ciphertext_detected() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-tamper-ct";
    let plaintext = b"secret private key data for tamper test";

    let mut encrypted = master_key
        .encrypt_private_key(project_id, plaintext)
        .expect("encrypt should succeed");

    assert!(encrypted.len() > HEADER_LEN + 1, "ciphertext should exist after header");

    // Flip a byte in the ciphertext portion (after magic + nonce)
    let ct_index = HEADER_LEN + 1;
    encrypted[ct_index] ^= 0xFF;

    let result = master_key.decrypt_private_key(project_id, &encrypted);
    assert!(
        result.is_err(),
        "tampered ciphertext should be rejected by AES-256-GCM authentication"
    );
}

#[test]
fn test_tampered_nonce_detected() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-tamper-nonce";
    let plaintext = b"secret private key data for nonce tamper test";

    let mut encrypted = master_key
        .encrypt_private_key(project_id, plaintext)
        .expect("encrypt should succeed");

    // Flip a byte in the nonce region (bytes 4..16)
    let nonce_index = MAGIC_LEN + 3; // byte 7, within the nonce
    encrypted[nonce_index] ^= 0xFF;

    let result = master_key.decrypt_private_key(project_id, &encrypted);
    assert!(
        result.is_err(),
        "tampered nonce should cause decryption to fail (wrong nonce = wrong keystream)"
    );
}

#[test]
fn test_tampered_magic_bytes_detected() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-tamper-magic";
    let plaintext = b"secret data";

    let mut encrypted = master_key
        .encrypt_private_key(project_id, plaintext)
        .expect("encrypt should succeed");

    // Verify the magic bytes are "ENC1"
    assert_eq!(&encrypted[..4], b"ENC1", "should start with ENC1 magic");

    // Change magic from "ENC1" to "ENC2"
    encrypted[3] = b'2';

    let result = master_key.decrypt_private_key(project_id, &encrypted);
    assert!(
        result.is_err(),
        "tampered magic bytes should be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("magic bytes"),
        "error should mention magic bytes, got: {}",
        err_msg
    );
}

#[test]
fn test_wrong_master_key_fails_decrypt() {
    let key_a = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let key_b = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-wrong-key";
    let plaintext = b"secret data encrypted with key A";

    let encrypted = key_a
        .encrypt_private_key(project_id, plaintext)
        .expect("encrypt should succeed");

    // Attempt to decrypt with a different master key (same project_id)
    let result = key_b.decrypt_private_key(project_id, &encrypted);
    assert!(
        result.is_err(),
        "decryption with wrong master key should fail (different DEK derived)"
    );
}

#[test]
fn test_same_plaintext_different_ciphertext() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-nonce-uniqueness";
    let plaintext = b"identical plaintext for both encryptions";

    let encrypted1 = master_key
        .encrypt_private_key(project_id, plaintext)
        .expect("first encrypt should succeed");
    let encrypted2 = master_key
        .encrypt_private_key(project_id, plaintext)
        .expect("second encrypt should succeed");

    // Same key + same project + same plaintext, but random nonce should differ
    assert_ne!(
        encrypted1, encrypted2,
        "encrypting the same plaintext twice should produce different ciphertext (random nonce)"
    );

    // Verify the nonces themselves are different
    let nonce1 = &encrypted1[MAGIC_LEN..HEADER_LEN];
    let nonce2 = &encrypted2[MAGIC_LEN..HEADER_LEN];
    assert_ne!(
        nonce1, nonce2,
        "random nonces should differ between encryptions"
    );

    // Both should decrypt to the same plaintext
    let decrypted1 = master_key
        .decrypt_private_key(project_id, &encrypted1)
        .expect("decrypt 1 should succeed");
    let decrypted2 = master_key
        .decrypt_private_key(project_id, &encrypted2)
        .expect("decrypt 2 should succeed");
    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
}

#[test]
fn test_truncated_ciphertext_rejected() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-truncated";

    // Test various truncated lengths that should all fail:
    // Minimum valid: MAGIC(4) + NONCE(12) + at least 1 byte ciphertext = 17
    let test_lengths = [0, 4, 12, 16];

    for len in test_lengths {
        // Build data with valid magic prefix where possible
        let mut data = vec![0u8; len];
        if len >= 4 {
            data[..4].copy_from_slice(b"ENC1");
        }

        let result = master_key.decrypt_private_key(project_id, &data);
        assert!(
            result.is_err(),
            "truncated data of length {} should be rejected (minimum is {})",
            len,
            HEADER_LEN + 1
        );
    }

    // Length 17 passes the length check but has garbage ciphertext -- should still fail
    let mut data_17 = vec![0u8; 17];
    data_17[..4].copy_from_slice(b"ENC1");
    let result = master_key.decrypt_private_key(project_id, &data_17);
    assert!(
        result.is_err(),
        "17 bytes with garbage ciphertext should fail AES-GCM authentication"
    );
}

#[test]
fn test_encrypt_decrypt_empty_plaintext() {
    let master_key = MasterKey::from_base64(&MasterKey::generate()).unwrap();
    let project_id = "project-empty";

    let encrypted = master_key
        .encrypt_private_key(project_id, &[])
        .expect("encrypting empty plaintext should succeed");

    // Should still have magic + nonce + AES-GCM auth tag (16 bytes)
    assert!(
        encrypted.len() > HEADER_LEN,
        "encrypted empty plaintext should have header + auth tag"
    );

    let decrypted = master_key
        .decrypt_private_key(project_id, &encrypted)
        .expect("decrypting empty plaintext should succeed");
    assert!(
        decrypted.is_empty(),
        "decrypted empty plaintext should be empty"
    );
}
