// ABOUTME: Type definitions for API requests, responses, and internal data structures
// ABOUTME: Includes WebAuthn types, encryption payloads, and storage models

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
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
    pub vault_name: Option<String>,
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

// Legacy type - keeping for migration compatibility
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

// New file browser types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    pub id: Uuid,
    pub user_id: Uuid,
    pub passkey_id: String,
    pub filename: String,
    pub tags: String, // Stored as slash-separated string like "docs/home"
    pub current_version_id: Option<Uuid>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileVersion {
    pub id: Uuid,
    pub file_id: Uuid,
    pub user_id: Uuid,
    pub version_number: i32,
    pub encrypted_content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
    pub content_hash: String, // Hash of decrypted content for change detection
    pub change_summary: Option<String>, // Optional description of changes
    pub created_at: i64,
}

// File browser API types
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateFileRequest {
    pub filename: String,
    pub tags: String,
    pub content: String,
    // passkey_id now comes from session, not from request
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateFileResponse {
    pub file_id: Uuid,
    pub version_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveVersionRequest {
    pub content: String,
    pub change_summary: Option<String>,
    // file_id now comes from URL path, not from request body
    // passkey_id now comes from session, not from request
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveVersionResponse {
    pub version_id: Uuid,
    pub version_number: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileInfo {
    pub id: Uuid,
    pub filename: String,
    pub tags: String,
    pub version_count: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileBrowserResponse {
    pub files: Vec<FileInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionInfo {
    pub id: Uuid,
    pub version_number: i32,
    pub change_summary: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileVersionsResponse {
    pub versions: Vec<VersionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetFileContentRequest {
    pub version_id: Option<Uuid>, // If None, get latest version
                                  // file_id now comes from URL path, not from request body
                                  // passkey_id now comes from session, not from request
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetFileContentResponse {
    pub content: String,
    pub version_id: Uuid,
    pub version_number: i32,
}
