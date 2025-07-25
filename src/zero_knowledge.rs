// ABOUTME: Zero-knowledge server endpoints that only store encrypted blobs
// ABOUTME: Server never sees plaintext data or has ability to decrypt

use axum::{extract::{Path, State}, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreEncryptedRequest {
    pub passkey_id: String,
    pub encrypted_blob: EncryptedBlob,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreEncryptedResponse {
    pub data_id: String,
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetEncryptedResponse {
    pub encrypted_blob: EncryptedBlob,
}

// Store encrypted blob (server never sees plaintext)
pub async fn store_encrypted(
    State(state): State<AppState>,
    Json(req): Json<StoreEncryptedRequest>,
) -> Result<Json<StoreEncryptedResponse>, StatusCode> {
    let data_id = Uuid::new_v4();
    
    // Get the credential to find the user_id (for access control)
    let credential = state.storage.get_credential(&req.passkey_id).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Store the encrypted blob directly (no server-side decryption possible)
    sqlx::query(
        r#"
        INSERT INTO zero_knowledge_data (id, user_id, passkey_id, ciphertext, salt, iv, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(data_id.to_string())
    .bind(credential.user_id.to_string())
    .bind(&req.passkey_id)
    .bind(&req.encrypted_blob.ciphertext)
    .bind(&req.encrypted_blob.salt)
    .bind(&req.encrypted_blob.iv)
    .bind(chrono::Utc::now().timestamp())
    .execute(&state.storage.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(StoreEncryptedResponse {
        data_id: data_id.to_string(),
        success: true,
    }))
}

// Retrieve encrypted blob (server cannot decrypt it)
pub async fn get_encrypted(
    Path(data_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<GetEncryptedResponse>, StatusCode> {
    let row = sqlx::query(
        "SELECT ciphertext, salt, iv FROM zero_knowledge_data WHERE id = ?"
    )
    .bind(&data_id)
    .fetch_one(&state.storage.pool)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;
    
    Ok(Json(GetEncryptedResponse {
        encrypted_blob: EncryptedBlob {
            ciphertext: row.get("ciphertext"),
            salt: row.get("salt"),
            iv: row.get("iv"),
        },
    }))
}

// Add this to storage.rs initialize_schema function:
pub async fn add_zero_knowledge_table(pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS zero_knowledge_data (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            passkey_id TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            salt BLOB NOT NULL,
            iv BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (passkey_id) REFERENCES credentials (id)
        )
        "#,
    )
    .execute(pool)
    .await?;
    
    Ok(())
}