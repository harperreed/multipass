// ABOUTME: Main entry point for the multipass webapp with passkey auth and data encryption
// ABOUTME: Sets up the web server, routes, and initialization logic

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use base64::Engine;

mod auth;
mod crypto;
mod storage;
mod types;
mod entities;
mod migration;

use auth::AuthState;
use storage::Storage;

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthState,
    pub storage: Arc<Storage>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize storage
    let storage = Arc::new(Storage::new().await?);
    
    // Initialize WebAuthn
    let auth = AuthState::new()?;
    
    let app_state = AppState { auth, storage };

    // Build our application with routes
    let app = Router::new()
        .route("/", get(index))
        .route("/register", post(auth::register_start))
        .route("/register/finish", post(auth::register_finish))
        .route("/authenticate", post(auth::authenticate_start))
        .route("/authenticate/finish", post(auth::authenticate_finish))
        .route("/encrypt", post(encrypt_data))
        .route("/decrypt", post(decrypt_data))
        .route("/list_secrets/:passkey_id", get(list_secrets))
        .route("/delete_secret/:data_id", delete(delete_secret))
        .route("/identify", post(identify_user))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("🚀 Server running on http://localhost:3000");
    
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn encrypt_data(
    State(state): State<AppState>,
    Json(payload): Json<types::EncryptRequest>,
) -> Result<Json<types::EncryptResponse>, StatusCode> {
    let title = payload.title.unwrap_or_else(|| "Untitled Secret".to_string());
    let encrypted = crypto::encrypt_data(&payload.data, &payload.passkey_id, &title, &state.storage)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(types::EncryptResponse { encrypted_data: encrypted }))
}

async fn decrypt_data(
    State(state): State<AppState>,
    Json(payload): Json<types::DecryptRequest>,
) -> Result<Json<types::DecryptResponse>, StatusCode> {
    let decrypted = crypto::decrypt_data(&payload.encrypted_data, &payload.passkey_id, &state.storage)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(types::DecryptResponse { data: decrypted }))
}

async fn list_secrets(
    Path(passkey_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<types::ListSecretsResponse>, StatusCode> {
    // URL decode the passkey ID to handle special characters
    let decoded_passkey_id = urlencoding::decode(&passkey_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let encrypted_data = state.storage.get_encrypted_data(&decoded_passkey_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let secrets: Vec<types::SecretSummary> = encrypted_data
        .into_iter()
        .map(|data| types::SecretSummary {
            id: data.id.to_string(),
            title: data.title,
            created_at: data.created_at,
        })
        .collect();
    
    Ok(Json(types::ListSecretsResponse { secrets }))
}

async fn delete_secret(
    Path(data_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    state.storage.delete_encrypted_data(&data_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(serde_json::json!({"success": true})))
}

async fn identify_user(
    State(state): State<AppState>,
    Json(req): Json<types::IdentifyRequest>,
) -> Result<Json<types::IdentifyResponse>, StatusCode> {
    println!("Attempting to identify credential ID: {}", req.credential_id);
    
    // The credential ID from the frontend uses base64url encoding (with - and _)
    // Convert from base64url to standard base64 (with + and /)
    let standard_base64 = req.credential_id
        .replace('-', "+")
        .replace('_', "/");
    
    // Add padding if needed
    let padded_base64 = match standard_base64.len() % 4 {
        0 => standard_base64,
        n => format!("{}{}", standard_base64, "=".repeat(4 - n)),
    };
    
    println!("Converted to standard base64: {}", padded_base64);
    
    // Try to find it with the converted format
    if let Ok(stored_cred) = state.storage.get_credential(&padded_base64).await {
        println!("Found credential with converted format: {}", padded_base64);
        return Ok(Json(types::IdentifyResponse {
            passkey_id: padded_base64,
            user_id: stored_cred.user_id,
        }));
    }
    
    // Fallback: try the original format in case it's already correct
    if let Ok(stored_cred) = state.storage.get_credential(&req.credential_id).await {
        println!("Found credential directly: {}", req.credential_id);
        return Ok(Json(types::IdentifyResponse {
            passkey_id: req.credential_id,
            user_id: stored_cred.user_id,
        }));
    }
    
    // Debug: List all stored credentials to see what's actually there
    println!("Debugging: Let's see what credentials are stored...");
    use crate::entities::credential;
    use sea_orm::EntityTrait;
    if let Ok(credentials) = credential::Entity::find().all(&state.storage.db).await {
        for cred in credentials {
            println!("Stored credential ID: {}", cred.id);
        }
    }
    
    println!("Credential not found with either method");
    Err(StatusCode::NOT_FOUND)
}
