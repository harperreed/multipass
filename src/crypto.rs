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

#[cfg(test)]
mod tests {
    use super::*;

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
}
