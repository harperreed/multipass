// ABOUTME: Type definitions for API requests, responses, and internal data structures
// ABOUTME: Includes WebAuthn types, encryption payloads, and storage models

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::{
    prelude::{CreationChallengeResponse, RequestChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential},
};

// WebAuthn related types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    pub user_id: Uuid,
    pub creation_options: CreationChallengeResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFinishRequest {
    pub user_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFinishResponse {
    pub success: bool,
    pub passkey_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticateStartRequest {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticateStartResponse {
    pub request_options: RequestChallengeResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticateFinishRequest {
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticateFinishResponse {
    pub success: bool,
    pub passkey_id: String,
    pub user_id: Uuid,
}

// Encryption related types
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub title: Option<String>,
    pub data: String,
    pub passkey_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub encrypted_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub encrypted_data: String,
    pub passkey_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub data: String,
}

// New types for secret management
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretSummary {
    pub id: String,
    pub title: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListSecretsResponse {
    pub secrets: Vec<SecretSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifyRequest {
    pub credential_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifyResponse {
    pub passkey_id: String,
    pub user_id: Uuid,
}

// Internal storage types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub id: String,
    pub user_id: Uuid,
    pub credential_data: Vec<u8>,
    pub counter: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub id: Uuid,
    pub user_id: Uuid,
    pub passkey_id: String,
    pub title: String,
    pub encrypted_content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
    pub created_at: i64,
}