// ABOUTME: Zero-knowledge server endpoints that only store encrypted blobs
// ABOUTME: Server never sees plaintext data or has ability to decrypt

use crate::entities::zero_knowledge_data;
use crate::{AppState, error};
use axum::{
    extract::{Path, State},
    response::Json,
};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
) -> error::Result<Json<StoreEncryptedResponse>> {
    let data_id = Uuid::new_v4();

    // Get the credential to find the user_id (for access control)
    let credential = state
        .storage
        .get_credential(&req.passkey_id)
        .await
        .map_err(|_| error::AppError::Unauthorized("Invalid passkey ID".to_string()))?;

    // Store the encrypted blob directly (no server-side decryption possible)
    let zero_knowledge_data = zero_knowledge_data::ActiveModel {
        id: Set(data_id.to_string()),
        user_id: Set(credential.user_id),
        passkey_id: Set(req.passkey_id.clone()),
        ciphertext: Set(req.encrypted_blob.ciphertext.clone()),
        salt: Set(req.encrypted_blob.salt.clone()),
        iv: Set(req.encrypted_blob.iv.clone()),
        created_at: Set(chrono::Utc::now().timestamp()),
    };

    zero_knowledge_data.insert(&state.storage.db).await?;

    Ok(Json(StoreEncryptedResponse {
        data_id: data_id.to_string(),
        success: true,
    }))
}

// Retrieve encrypted blob (server cannot decrypt it)
pub async fn get_encrypted(
    Path(data_id): Path<String>,
    State(state): State<AppState>,
) -> error::Result<Json<GetEncryptedResponse>> {
    let zero_knowledge_model = zero_knowledge_data::Entity::find_by_id(&data_id)
        .one(&state.storage.db)
        .await?
        .ok_or_else(|| {
            error::AppError::NotFound(format!("Encrypted data {} not found", data_id))
        })?;

    Ok(Json(GetEncryptedResponse {
        encrypted_blob: EncryptedBlob {
            ciphertext: zero_knowledge_model.ciphertext,
            salt: zero_knowledge_model.salt,
            iv: zero_knowledge_model.iv,
        },
    }))
}
