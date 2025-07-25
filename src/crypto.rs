// ABOUTME: Secure data encryption and decryption using ChaCha20Poly1305 and Argon2
// ABOUTME: Derives encryption keys from passkey IDs and provides authenticated encryption

use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use std::sync::Arc;
use uuid::Uuid;

use crate::storage::Storage;
use crate::types::EncryptedData;

const KEY_SIZE: usize = 32; // 256 bits for ChaCha20Poly1305
const NONCE_SIZE: usize = 12; // 96 bits for ChaCha20Poly1305
const SALT_SIZE: usize = 16; // 128 bits salt for Argon2

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
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("Invalid key size"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
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
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("Invalid key size"))?;
    let nonce = Nonce::from_slice(&encrypted_data.nonce);
    let plaintext = cipher.decrypt(nonce, encrypted_data.encrypted_content.as_slice())
        .map_err(|_| anyhow!("Decryption failed"))?;

    String::from_utf8(plaintext).map_err(|_| anyhow!("Invalid UTF-8 in decrypted data"))
}

fn derive_key(passkey_id: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|_| anyhow!("Failed to encode salt"))?;
    
    let password_hash = argon2.hash_password(passkey_id.as_bytes(), &salt_string)
        .map_err(|_| anyhow!("Failed to hash password"))?;
    
    let hash = password_hash.hash
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