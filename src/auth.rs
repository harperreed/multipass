// ABOUTME: WebAuthn passkey authentication implementation using webauthn-rs
// ABOUTME: Handles registration and authentication flows for secure passkey-based auth

use axum::{extract::State, http::StatusCode, response::Json};
use serde_json::json;
use base64::Engine;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::{
    prelude::{PasskeyAuthentication, PasskeyRegistration, Passkey},
    Webauthn, WebauthnBuilder,
};

use crate::types::*;
use crate::AppState;

#[derive(Clone)]
pub struct AuthState {
    pub webauthn: Webauthn,
    pub registration_sessions: std::sync::Arc<Mutex<HashMap<Uuid, PasskeyRegistration>>>,
    pub authentication_sessions: std::sync::Arc<Mutex<HashMap<String, PasskeyAuthentication>>>,
}

impl AuthState {
    pub fn new() -> anyhow::Result<Self> {
        let rp_id = "localhost";
        let rp_origin = url::Url::parse("http://localhost:3000")?;
        
        let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;
        let webauthn = builder.build()?;

        Ok(Self {
            webauthn,
            registration_sessions: std::sync::Arc::new(Mutex::new(HashMap::new())),
            authentication_sessions: std::sync::Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

pub async fn register_start(
    State(state): State<AppState>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, Json<serde_json::Value>)> {
    let user_id = Uuid::new_v4();
    let user = User {
        id: user_id,
        username: req.username.clone(),
        display_name: req.display_name.clone(),
    };

    // Check if user already exists (using UUID as unique identifier)
    if state.storage.get_user_by_username(&req.username).await.is_ok() {
        return Err((StatusCode::CONFLICT, Json(json!({
            "error": "Vault already exists",
            "message": "This vault already exists. Please try accessing it instead."
        }))));
    }

    // Store user in database
    state.storage.store_user(&user).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Database error",
            "message": "Failed to store user in database"
        }))))?;

    // Start passkey registration - use display_name as the identifier shown to user
    let (ccr, passkey_registration) = state.auth.webauthn
        .start_passkey_registration(
            user_id,
            &user.display_name,  // This is what shows in the passkey dialog
            &user.display_name,
            None,
        )
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "WebAuthn error",
            "message": "Failed to start passkey registration"
        }))))?;

    // Store registration session
    state.auth.registration_sessions
        .lock()
        .unwrap()
        .insert(user_id, passkey_registration);

    Ok(Json(RegisterStartResponse {
        user_id,
        creation_options: ccr,
    }))
}

pub async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<RegisterFinishResponse>, StatusCode> {
    // Retrieve registration session
    let registration_session = state.auth.registration_sessions
        .lock()
        .unwrap()
        .remove(&req.user_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Finish registration
    let passkey = state.auth.webauthn
        .finish_passkey_registration(&req.credential, &registration_session)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store the credential
    let credential_id = base64::engine::general_purpose::STANDARD.encode(passkey.cred_id());
    state.storage.store_credential(&credential_id, req.user_id, &passkey).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(RegisterFinishResponse {
        success: true,
        passkey_id: credential_id,
    }))
}

pub async fn authenticate_start(
    State(state): State<AppState>,
    Json(req): Json<AuthenticateStartRequest>,
) -> Result<Json<AuthenticateStartResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get user
    let user = state.storage.get_user_by_username(&req.username).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(json!({
            "error": "Vault not found",
            "message": format!("No vault found with ID: {}", req.username)
        }))))?;

    // Get user's credentials
    let credentials = state.storage.get_user_credentials(user.id).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Database error",
            "message": "Failed to retrieve credentials"
        }))))?;

    if credentials.is_empty() {
        return Err((StatusCode::NOT_FOUND, Json(json!({
            "error": "No credentials found",
            "message": "This vault has no registered passkeys"
        }))));
    }

    let passkeys: Vec<Passkey> = credentials.into_iter()
        .filter_map(|cred| bincode::deserialize(&cred.credential_data).ok())
        .collect();

    // Start authentication
    let (rcr, passkey_authentication) = state.auth.webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "WebAuthn error",
            "message": "Failed to start authentication"
        }))))?;

    // Store authentication session
    let session_id = Uuid::new_v4().to_string();
    state.auth.authentication_sessions
        .lock()
        .unwrap()
        .insert(session_id, passkey_authentication);

    Ok(Json(AuthenticateStartResponse {
        request_options: rcr,
    }))
}

#[axum::debug_handler]
pub async fn authenticate_finish(
    State(state): State<AppState>,
    Json(req): Json<AuthenticateFinishRequest>,
) -> Result<Json<AuthenticateFinishResponse>, StatusCode> {
    // Find the right authentication session
    let (auth_success, _session_to_remove) = {
        let mut sessions = state.auth.authentication_sessions.lock().unwrap();
        let mut auth_result = None;
        let mut session_to_remove = None;
        
        for (session_id, auth_session) in sessions.iter() {
            if let Ok(auth_success) = state.auth.webauthn.finish_passkey_authentication(&req.credential, auth_session) {
                auth_result = Some(auth_success);
                session_to_remove = Some(session_id.clone());
                break;
            }
        }
        
        if let Some(session_id) = &session_to_remove {
            sessions.remove(session_id);
        }
        
        (auth_result, session_to_remove)
    };

    let auth_success = auth_success.ok_or(StatusCode::UNAUTHORIZED)?;
    
    // Get credential and user info
    let credential_id = base64::engine::general_purpose::STANDARD.encode(auth_success.cred_id());
    let stored_cred = state.storage.get_credential(&credential_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update counter
    state.storage.update_credential_counter(&credential_id, auth_success.counter()).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(AuthenticateFinishResponse {
        success: true,
        passkey_id: credential_id,
        user_id: stored_cred.user_id,
    }))
}