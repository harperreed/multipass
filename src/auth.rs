// ABOUTME: WebAuthn passkey authentication implementation using webauthn-rs
// ABOUTME: Handles registration and authentication flows for secure passkey-based auth

use axum::{extract::State, http::StatusCode, response::Json};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration},
};

use crate::types::*;
use crate::{AppState, session};

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

    pub fn new_with_config(host: &str, port: u16, use_https: bool) -> anyhow::Result<Self> {
        let rp_id = if host == "127.0.0.1" || host == "0.0.0.0" {
            "localhost"
        } else {
            host
        };

        let protocol = if use_https { "https" } else { "http" };
        let rp_origin = if (use_https && port == 443) || (!use_https && port == 80) {
            url::Url::parse(&format!("{}://{}", protocol, rp_id))?
        } else {
            url::Url::parse(&format!("{}://{}:{}", protocol, rp_id, port))?
        };

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
    if state
        .storage
        .get_user_by_username(&req.username)
        .await
        .is_ok()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Vault already exists",
                "message": "This vault already exists. Please try accessing it instead."
            })),
        ));
    }

    // Store user in database
    state.storage.store_user(&user).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Database error",
                "message": "Failed to store user in database"
            })),
        )
    })?;

    // Start passkey registration - use display_name as the identifier shown to user
    let (ccr, passkey_registration) = state
        .auth
        .webauthn
        .start_passkey_registration(
            user_id,
            &user.display_name, // This is what shows in the passkey dialog
            &user.display_name,
            None,
        )
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "WebAuthn error",
                    "message": "Failed to start passkey registration"
                })),
            )
        })?;

    // Store registration session
    state
        .auth
        .registration_sessions
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
    jar: CookieJar,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<(CookieJar, Json<RegisterFinishResponse>), StatusCode> {
    // Retrieve registration session
    let registration_session = state
        .auth
        .registration_sessions
        .lock()
        .unwrap()
        .remove(&req.user_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Finish registration
    let passkey = state
        .auth
        .webauthn
        .finish_passkey_registration(&req.credential, &registration_session)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store the credential
    let credential_id = base64::engine::general_purpose::STANDARD.encode(passkey.cred_id());
    state
        .storage
        .store_credential(&credential_id, req.user_id, &passkey)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create session and set cookie
    let session_id =
        state
            .sessions
            .create_session(req.user_id, credential_id.clone(), req.vault_name.clone());

    // Determine if we should use secure cookies (HTTPS)
    let is_secure = false; // TODO: detect from request or config
    let session_cookie = session::create_session_cookie(session_id, is_secure);
    let jar = jar.add(session_cookie);

    Ok((
        jar,
        Json(RegisterFinishResponse {
            success: true,
            passkey_id: credential_id,
        }),
    ))
}

pub async fn authenticate_start(
    State(state): State<AppState>,
    Json(req): Json<AuthenticateStartRequest>,
) -> Result<Json<AuthenticateStartResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get user
    let user = state
        .storage
        .get_user_by_username(&req.username)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "Vault not found",
                    "message": format!("No vault found with ID: {}", req.username)
                })),
            )
        })?;

    // Get user's credentials
    let credentials = state
        .storage
        .get_user_credentials(user.id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Database error",
                    "message": "Failed to retrieve credentials"
                })),
            )
        })?;

    if credentials.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "No credentials found",
                "message": "This vault has no registered passkeys"
            })),
        ));
    }

    let passkeys: Vec<Passkey> = credentials
        .into_iter()
        .filter_map(|cred| bincode::deserialize(&cred.credential_data).ok())
        .collect();

    // Start authentication
    let (rcr, passkey_authentication) = state
        .auth
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "WebAuthn error",
                    "message": "Failed to start authentication"
                })),
            )
        })?;

    // Store authentication session
    let session_id = Uuid::new_v4().to_string();
    state
        .auth
        .authentication_sessions
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
    jar: CookieJar,
    Json(req): Json<AuthenticateFinishRequest>,
) -> Result<(CookieJar, Json<AuthenticateFinishResponse>), StatusCode> {
    // Find the right authentication session
    let (auth_success, _session_to_remove) = {
        let mut sessions = state.auth.authentication_sessions.lock().unwrap();
        let mut auth_result = None;
        let mut session_to_remove = None;

        for (session_id, auth_session) in sessions.iter() {
            if let Ok(auth_success) = state
                .auth
                .webauthn
                .finish_passkey_authentication(&req.credential, auth_session)
            {
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
    let stored_cred = state
        .storage
        .get_credential(&credential_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update counter
    state
        .storage
        .update_credential_counter(&credential_id, auth_success.counter())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create session and set cookie
    let session_id = state.sessions.create_session(
        stored_cred.user_id,
        credential_id.clone(),
        None, // vault name not available at login
    );

    // Determine if we should use secure cookies (HTTPS)
    let is_secure = false; // TODO: detect from request or config
    let session_cookie = session::create_session_cookie(session_id, is_secure);
    let jar = jar.add(session_cookie);

    Ok((
        jar,
        Json(AuthenticateFinishResponse {
            success: true,
            passkey_id: credential_id,
            user_id: stored_cred.user_id,
        }),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<serde_json::Value>), StatusCode> {
    // Extract session from cookie and remove it
    if let Ok(_session_data) = session::extract_session_from_jar(&jar, &state.sessions) {
        // Find the session ID from the cookie
        if let Some(session_cookie) = jar.get("multipass_session") {
            state.sessions.remove_session(session_cookie.value());
        }
    }

    // Create a logout cookie that expires immediately
    let logout_cookie = session::create_logout_cookie();
    let jar = jar.add(logout_cookie);

    Ok((jar, Json(serde_json::json!({"success": true}))))
}
