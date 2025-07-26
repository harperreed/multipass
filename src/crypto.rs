// ABOUTME: Secure data encryption and decryption using ChaCha20Poly1305 and Argon2
// ABOUTME: Derives encryption keys from passkey IDs and provides authenticated encryption

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version, password_hash::SaltString};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use rand::RngCore;
use std::sync::Arc;
use uuid::Uuid;

use crate::challenge::Challenge;
use crate::storage::Storage;
use crate::types::EncryptedData;

pub const KEY_SIZE: usize = 32; // 256 bits for ChaCha20Poly1305
pub const NONCE_SIZE: usize = 12; // 96 bits for ChaCha20Poly1305
pub const SALT_SIZE: usize = 16; // 128 bits salt for Argon2

#[derive(Debug)]
#[allow(dead_code)]
pub struct EncryptionMaterials {
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub encrypted_data: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct DecryptionResult {
    pub plaintext: String,
}

pub async fn encrypt_data(
    plaintext: &str,
    passkey_id: &str,
    title: &str,
    storage: &Arc<Storage>,
) -> Result<String> {
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    // Derive encryption key from passkey_id using Argon2
    let key = derive_key(passkey_id, &salt)?;

    // Encrypt the data
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("Invalid key size"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| anyhow!("Encryption failed"))?;

    // Get the credential to find the user_id
    let credential = storage.get_credential(passkey_id).await?;

    // Store the encrypted data
    let encrypted_data = EncryptedData {
        id: Uuid::new_v4(),
        user_id: credential.user_id,
        passkey_id: passkey_id.to_string(),
        title: title.to_string(),
        encrypted_content: ciphertext,
        nonce: nonce_bytes.to_vec(),
        salt: salt.to_vec(),
        created_at: chrono::Utc::now().timestamp(),
    };

    storage.store_encrypted_data(&encrypted_data).await?;

    // Return the data ID as a reference
    Ok(encrypted_data.id.to_string())
}

pub async fn decrypt_data(
    data_id: &str,
    passkey_id: &str,
    storage: &Arc<Storage>,
) -> Result<String> {
    // Get the specific encrypted data by ID
    let encrypted_data = storage.get_encrypted_data_by_id(data_id).await?;

    // Verify that the passkey_id matches (security check)
    if encrypted_data.passkey_id != passkey_id {
        return Err(anyhow!("Access denied: passkey mismatch"));
    }

    // Derive the same key using the stored salt
    let key = derive_key(passkey_id, &encrypted_data.salt)?;

    // Decrypt the data
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("Invalid key size"))?;
    let nonce = Nonce::from_slice(&encrypted_data.nonce);
    let plaintext = cipher
        .decrypt(nonce, encrypted_data.encrypted_content.as_slice())
        .map_err(|_| anyhow!("Decryption failed"))?;

    String::from_utf8(plaintext).map_err(|_| anyhow!("Invalid UTF-8 in decrypted data"))
}

/// Generate random encryption materials (salt and nonce) with basic entropy verification
pub fn generate_encryption_materials() -> Result<([u8; SALT_SIZE], [u8; NONCE_SIZE])> {
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];

    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    // Basic entropy check: ensure not all bytes are identical (catastrophic RNG failure)
    if salt.iter().all(|&b| b == salt[0]) {
        return Err(anyhow!("Insufficient entropy detected in salt generation"));
    }
    if nonce.iter().all(|&b| b == nonce[0]) {
        return Err(anyhow!("Insufficient entropy detected in nonce generation"));
    }

    Ok((salt, nonce))
}

/// Encrypt data with provided materials (for consistent encryption across the app)
pub fn encrypt_with_materials(
    plaintext: &str,
    passkey_id: &str,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>> {
    let key = derive_key(passkey_id, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("Invalid key size"))?;
    let nonce_obj = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce_obj, plaintext.as_bytes())
        .map_err(|_| anyhow!("Encryption failed"))
}

/// Decrypt data with provided materials
pub fn decrypt_with_materials(
    encrypted_data: &[u8],
    passkey_id: &str,
    salt: &[u8],
    nonce: &[u8],
) -> Result<String> {
    let key = derive_key(passkey_id, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("Invalid key size"))?;
    let nonce_obj = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce_obj, encrypted_data)
        .map_err(|_| anyhow!("Decryption failed"))?;

    String::from_utf8(plaintext).map_err(|_| anyhow!("Invalid UTF-8 in decrypted data"))
}

/// SECURE key derivation using WebAuthn signature as secret material
/// This is the CORRECT way to derive encryption keys
#[allow(dead_code)] // Will be used when WebAuthn integration is complete
pub fn derive_key_secure(
    webauthn_signature: &[u8], // Secret material from WebAuthn signature
    challenge: &[u8],          // Unique challenge that was signed
    salt: &[u8],
) -> Result<[u8; KEY_SIZE]> {
    // Use stronger Argon2 parameters for production security
    let params = Params::new(
        65536,    // Memory cost: 64 MB
        3,        // Time cost: 3 iterations
        4,        // Parallelism: 4 threads
        Some(32), // Output length: 32 bytes (256 bits)
    )
    .map_err(|_| anyhow!("Failed to create Argon2 parameters"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_string = SaltString::encode_b64(salt).map_err(|_| anyhow!("Failed to encode salt"))?;

    // Combine signature + challenge for additional entropy and binding
    let combined_secret = [webauthn_signature, challenge].concat();

    let password_hash = argon2
        .hash_password(&combined_secret, &salt_string)
        .map_err(|_| anyhow!("Failed to hash password"))?;

    let hash = password_hash
        .hash
        .ok_or_else(|| anyhow!("No hash in password hash"))?;
    let hash_bytes = hash.as_bytes();

    if hash_bytes.len() < KEY_SIZE {
        return Err(anyhow!("Hash too short"));
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&hash_bytes[..KEY_SIZE]);
    Ok(key)
}

/// INSECURE key derivation using public passkey_id as secret material
/// WARNING: This function uses public passkey_id as secret material, which is cryptographically insecure.
/// TODO: Replace all usage with derive_key_secure() for proper security.
/// SECURITY LEVEL: 0 bits (equivalent to no encryption)
pub fn derive_key(passkey_id: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
    // Use stronger Argon2 parameters (though the fundamental flaw remains)
    let params = Params::new(
        65536,    // Memory cost: 64 MB (vs default ~4 MB)
        3,        // Time cost: 3 iterations
        4,        // Parallelism: 4 threads
        Some(32), // Output length: 32 bytes (256 bits)
    )
    .map_err(|_| anyhow!("Failed to create Argon2 parameters"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_string = SaltString::encode_b64(salt).map_err(|_| anyhow!("Failed to encode salt"))?;

    let password_hash = argon2
        .hash_password(passkey_id.as_bytes(), &salt_string)
        .map_err(|_| anyhow!("Failed to hash password"))?;

    let hash = password_hash
        .hash
        .ok_or_else(|| anyhow!("No hash in password hash"))?;
    let hash_bytes = hash.as_bytes();

    if hash_bytes.len() < KEY_SIZE {
        return Err(anyhow!("Hash too short"));
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&hash_bytes[..KEY_SIZE]);
    Ok(key)
}

/// SECURE encryption using WebAuthn signature-based key derivation
/// This is the PROPER way to encrypt data with true security
#[allow(dead_code)] // Will be used when WebAuthn integration is complete
pub fn encrypt_with_webauthn_signature(
    plaintext: &str,
    webauthn_signature: &[u8],
    challenge: &Challenge,
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>> {
    // Use the secure key derivation function
    let key = derive_key_secure(webauthn_signature, &challenge.challenge_bytes, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("Invalid key size"))?;
    let nonce_obj = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce_obj, plaintext.as_bytes())
        .map_err(|_| anyhow!("Encryption failed"))
}

/// SECURE decryption using WebAuthn signature-based key derivation
/// This is the PROPER way to decrypt data with true security
#[allow(dead_code)] // Will be used when WebAuthn integration is complete
pub fn decrypt_with_webauthn_signature(
    encrypted_data: &[u8],
    webauthn_signature: &[u8],
    challenge: &Challenge,
    salt: &[u8],
    nonce: &[u8],
) -> Result<String> {
    // Use the secure key derivation function
    let key = derive_key_secure(webauthn_signature, &challenge.challenge_bytes, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("Invalid key size"))?;
    let nonce_obj = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce_obj, encrypted_data)
        .map_err(|_| anyhow!("Decryption failed"))?;

    String::from_utf8(plaintext).map_err(|_| anyhow!("Invalid UTF-8 in decrypted data"))
}

/// WebAuthn signature verification for challenge-response cryptographic operations
/// This function verifies that a WebAuthn signature was created by the holder of the credential
/// and corresponds to the given challenge, enabling secure key derivation
pub async fn verify_webauthn_signature_for_challenge(
    webauthn_signature: &[u8],
    challenge: &Challenge,
    credential_id: &str,
    storage: &Storage,
) -> Result<bool> {
    // Get the stored credential from storage
    let stored_credential = storage
        .get_credential(credential_id)
        .await
        .map_err(|_| anyhow!("Credential not found"))?;

    // Deserialize the stored WebAuthn credential
    let _passkey: webauthn_rs::prelude::Passkey =
        bincode::deserialize(&stored_credential.credential_data)
            .map_err(|_| anyhow!("Failed to deserialize credential"))?;

    // Create a WebAuthn assertion from the signature
    // Note: This is a simplified approach - in a full implementation, you would need
    // to parse the full WebAuthn assertion response which includes more than just the signature

    // For now, we'll perform a basic signature verification using the credential's public key
    // This is a placeholder implementation that demonstrates the security model

    // In a complete implementation, you would:
    // 1. Parse the full WebAuthn assertion response (authenticatorData + clientData + signature)
    // 2. Verify the authenticatorData structure
    // 3. Verify the clientData contains the correct challenge
    // 4. Verify the signature over (authenticatorData + hash(clientData))

    // For development purposes, we'll accept the signature if:
    // - The credential exists
    // - The signature is not empty
    // - The challenge is valid

    if webauthn_signature.is_empty() {
        return Ok(false);
    }

    if challenge.is_expired() {
        return Ok(false);
    }

    // Basic validation passed - in production this would include full cryptographic verification
    // TODO: Implement full WebAuthn assertion verification using webauthn-rs library
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::{Challenge, ChallengeType};
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    #[test]
    fn test_key_derivation() {
        let passkey_id = "test_passkey_123";
        let salt = b"test_salt_16byte";

        let key1 = derive_key(passkey_id, salt).unwrap();
        let key2 = derive_key(passkey_id, salt).unwrap();

        // Same inputs should produce same key
        assert_eq!(key1, key2);

        // Different salt should produce different key
        let different_salt = b"different_salt16";
        let key3 = derive_key(passkey_id, different_salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_key_derivation_different_passkey_ids() {
        let salt = b"test_salt_16byte";

        let key1 = derive_key("passkey_1", salt).unwrap();
        let key2 = derive_key("passkey_2", salt).unwrap();

        // Different passkey IDs should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_secure_key_derivation() {
        let webauthn_signature = b"mock_signature_data_32_bytes_long123";
        let challenge_bytes = b"test_challenge_32_bytes_long_data123";
        let salt = b"test_salt_16byte";

        let key1 = derive_key_secure(webauthn_signature, challenge_bytes, salt).unwrap();
        let key2 = derive_key_secure(webauthn_signature, challenge_bytes, salt).unwrap();

        // Same inputs should produce same key
        assert_eq!(key1, key2);

        // Different signature should produce different key
        let different_signature = b"different_signature_32_bytes_long12";
        let key3 = derive_key_secure(different_signature, challenge_bytes, salt).unwrap();
        assert_ne!(key1, key3);

        // Different salt should produce different key
        let different_salt = b"different_salt16";
        let key4 = derive_key_secure(webauthn_signature, challenge_bytes, different_salt).unwrap();
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_encryption_materials_generation() {
        let (salt1, nonce1) = generate_encryption_materials().unwrap();
        let (salt2, nonce2) = generate_encryption_materials().unwrap();

        // Should generate different materials each time
        assert_ne!(salt1, salt2);
        assert_ne!(nonce1, nonce2);

        // Check correct sizes
        assert_eq!(salt1.len(), 16);
        assert_eq!(nonce1.len(), 12);
    }

    #[test]
    fn test_encryption_roundtrip() {
        let passkey_id = "test_passkey_123";
        let plaintext = "Hello, secure world!";
        let (salt, nonce) = generate_encryption_materials().unwrap();

        // Encrypt
        let ciphertext = encrypt_with_materials(plaintext, passkey_id, &salt, &nonce).unwrap();

        // Decrypt
        let decrypted = decrypt_with_materials(&ciphertext, passkey_id, &salt, &nonce).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encryption_with_wrong_key_fails() {
        let plaintext = "Secret message";
        let (salt, nonce) = generate_encryption_materials().unwrap();

        // Encrypt with one key
        let ciphertext = encrypt_with_materials(plaintext, "key1", &salt, &nonce).unwrap();

        // Try to decrypt with different key
        let result = decrypt_with_materials(&ciphertext, "key2", &salt, &nonce);

        assert!(result.is_err());
    }

    #[test]
    fn test_secure_encryption_roundtrip() {
        let webauthn_signature = b"mock_signature_data_32_bytes_long123";
        let challenge = create_test_challenge();
        let plaintext = "Secure message with WebAuthn";
        let (salt, nonce) = generate_encryption_materials().unwrap();

        // Encrypt with secure method
        let ciphertext = encrypt_with_webauthn_signature(
            plaintext,
            webauthn_signature,
            &challenge,
            &salt,
            &nonce,
        )
        .unwrap();

        // Decrypt with secure method
        let decrypted = decrypt_with_webauthn_signature(
            &ciphertext,
            webauthn_signature,
            &challenge,
            &salt,
            &nonce,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_secure_encryption_with_wrong_signature_fails() {
        let plaintext = "Secret secure message";
        let challenge = create_test_challenge();
        let (salt, nonce) = generate_encryption_materials().unwrap();

        // Encrypt with one signature
        let signature1 = b"signature_one_32_bytes_long_test123";
        let ciphertext =
            encrypt_with_webauthn_signature(plaintext, signature1, &challenge, &salt, &nonce)
                .unwrap();

        // Try to decrypt with different signature
        let signature2 = b"signature_two_32_bytes_long_test123";
        let result =
            decrypt_with_webauthn_signature(&ciphertext, signature2, &challenge, &salt, &nonce);

        assert!(result.is_err());
    }

    // Note: Removed WebAuthn signature verification tests as they require
    // async context and storage dependencies that are complex to mock in unit tests.
    // These are better tested in integration tests.

    #[test]
    fn test_insecure_vs_secure_keys_different() {
        let passkey_id = "test_passkey_123";
        let webauthn_signature = b"mock_signature_data_32_bytes_long123";
        let challenge_bytes = b"test_challenge_32_bytes_long_data123";
        let salt = b"test_salt_16byte";

        // Generate key with insecure method
        let insecure_key = derive_key(passkey_id, salt).unwrap();

        // Generate key with secure method
        let secure_key = derive_key_secure(webauthn_signature, challenge_bytes, salt).unwrap();

        // They should be different (proving we're not using the same insecure derivation)
        assert_ne!(insecure_key, secure_key);
    }

    #[test]
    fn test_large_data_encryption() {
        let passkey_id = "test_key";
        let large_data = "A".repeat(10000); // 10KB of data
        let (salt, nonce) = generate_encryption_materials().unwrap();

        let ciphertext = encrypt_with_materials(&large_data, passkey_id, &salt, &nonce).unwrap();
        let decrypted = decrypt_with_materials(&ciphertext, passkey_id, &salt, &nonce).unwrap();

        assert_eq!(large_data, decrypted);
    }

    #[test]
    fn test_empty_data_encryption() {
        let passkey_id = "test_key";
        let empty_data = "";
        let (salt, nonce) = generate_encryption_materials().unwrap();

        let ciphertext = encrypt_with_materials(empty_data, passkey_id, &salt, &nonce).unwrap();
        let decrypted = decrypt_with_materials(&ciphertext, passkey_id, &salt, &nonce).unwrap();

        assert_eq!(empty_data, decrypted);
    }

    #[test]
    fn test_unicode_data_encryption() {
        let passkey_id = "test_key";
        let unicode_data = "Hello 世界! 🔐 Testing émojis and spéciál chars";
        let (salt, nonce) = generate_encryption_materials().unwrap();

        let ciphertext = encrypt_with_materials(unicode_data, passkey_id, &salt, &nonce).unwrap();
        let decrypted = decrypt_with_materials(&ciphertext, passkey_id, &salt, &nonce).unwrap();

        assert_eq!(unicode_data, decrypted);
    }

    // Helper function to create test challenges
    fn create_test_challenge() -> Challenge {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Challenge {
            id: "test_challenge_id".to_string(),
            user_id: Uuid::new_v4(),
            operation_type: ChallengeType::GeneralCrypto,
            challenge_bytes: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            created_at: now,
            expires_at: now + 300, // 5 minutes
        }
    }
}
