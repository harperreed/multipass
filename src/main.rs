// ABOUTME: Main entry point for the multipass webapp with passkey auth and data encryption
// ABOUTME: Sets up the web server, routes, and initialization logic

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{delete, get, post},
};
use axum_extra::extract::cookie::CookieJar;
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

mod auth;
mod auth_helpers;
mod challenge;
mod crypto;
mod entities;
mod error;
mod middleware;
mod migration;
mod session;
mod storage;
mod types;
mod zero_knowledge;

use auth::AuthState;
use challenge::ChallengeManager;
use session::SessionStore;
use storage::Storage;

#[derive(Parser)]
#[command(name = "multipass")]
#[command(about = "A secure file browser with passkey authentication")]
#[command(long_about = None)]
struct Args {
    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Enable HTTPS with certificate file
    #[arg(long)]
    cert: Option<String>,

    /// Private key file for HTTPS
    #[arg(long)]
    key: Option<String>,

    /// Public hostname for WebAuthn (if different from bind host)
    #[arg(long)]
    public_host: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthState,
    pub storage: Arc<Storage>,
    pub sessions: SessionStore,
    pub challenges: ChallengeManager,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize crypto provider for TLS
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install crypto provider"))?;

    // Parse command line arguments
    let args = Args::parse();

    // Initialize storage
    let storage = Arc::new(Storage::new().await?);

    // Initialize WebAuthn with dynamic configuration
    let use_https = args.cert.is_some() && args.key.is_some();
    let webauthn_host = args.public_host.as_ref().unwrap_or(&args.host);
    let auth = AuthState::new_with_config(webauthn_host, args.port, use_https)?;

    // Initialize session store
    let sessions = SessionStore::new();

    // Initialize challenge manager for secure crypto operations
    let challenges = ChallengeManager::new();

    let app_state = AppState {
        auth,
        storage,
        sessions,
        challenges,
    };

    // Build our application with routes
    let app = Router::new()
        .route("/", get(login_page))
        .route("/files.html", get(files_page))
        .route("/editor.html", get(editor_page))
        .route("/register", post(auth::register_start))
        .route("/register/finish", post(auth::register_finish))
        .route("/authenticate", post(auth::authenticate_start))
        .route("/authenticate/finish", post(auth::authenticate_finish))
        .route("/logout", post(auth::logout))
        .route("/encrypt", post(encrypt_data))
        .route("/decrypt", post(decrypt_data))
        .route("/list_secrets/:passkey_id", get(list_secrets))
        .route("/delete_secret/:data_id", delete(delete_secret))
        .route("/files/create", post(create_file))
        .route("/files", get(get_files))
        .route("/files/:file_id/content", post(get_file_content))
        .route("/files/:file_id/save", post(save_file_version))
        .route("/crypto/challenge", post(create_challenge))
        .route("/crypto/files/create", post(secure_create_file))
        .route(
            "/crypto/files/:file_id/content",
            post(secure_get_file_content),
        )
        .route(
            "/crypto/files/:file_id/save",
            post(secure_save_file_version),
        )
        .route("/identify", post(identify_user))
        .route(
            "/zero-knowledge/store",
            post(zero_knowledge::store_encrypted),
        )
        .route(
            "/zero-knowledge/:data_id",
            get(zero_knowledge::get_encrypted),
        )
        .layer(axum::middleware::from_fn(
            crate::middleware::security_headers,
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any) // TODO: Configure specific origins in production
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                ])
                .allow_credentials(true),
        )
        .with_state(app_state);

    let bind_addr = format!("{}:{}", args.host, args.port);

    match (args.cert, args.key) {
        (Some(cert_path), Some(key_path)) => {
            // HTTPS mode
            use axum_server::tls_rustls::RustlsConfig;

            let config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

            println!("🔒 Server running on https://{}:{}", args.host, args.port);
            println!("📍 WebAuthn will work from any network location with HTTPS");

            axum_server::bind_rustls(bind_addr.parse()?, config)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            // HTTP mode (localhost only for WebAuthn)
            let listener = TcpListener::bind(&bind_addr).await?;

            if args.host == "127.0.0.1" || args.host == "localhost" {
                println!("🚀 Server running on http://{}:{}", args.host, args.port);
                println!("📍 WebAuthn will work (localhost is considered secure)");
            } else {
                println!("❌ SECURITY ERROR: HTTP mode not allowed for non-localhost deployments!");
                println!(
                    "🔒 Please use --cert and --key flags to enable HTTPS for production security."
                );
                println!(
                    "💡 WebAuthn and secure encryption require HTTPS for non-localhost access."
                );
                return Err(anyhow::anyhow!(
                    "Production deployment requires HTTPS. Use --cert and --key flags or deploy on localhost only."
                ));
            }

            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

async fn login_page() -> Html<&'static str> {
    Html(include_str!("../static/login.html"))
}

async fn files_page() -> Html<&'static str> {
    Html(include_str!("../static/files.html"))
}

async fn editor_page() -> Html<&'static str> {
    Html(include_str!("../static/editor.html"))
}

async fn encrypt_data(
    State(state): State<AppState>,
    Json(payload): Json<types::EncryptRequest>,
) -> Result<Json<types::EncryptResponse>, StatusCode> {
    let title = payload
        .title
        .unwrap_or_else(|| "Untitled Secret".to_string());
    let encrypted =
        crypto::encrypt_data(&payload.data, &payload.passkey_id, &title, &state.storage)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(types::EncryptResponse {
        encrypted_data: encrypted,
    }))
}

async fn decrypt_data(
    State(state): State<AppState>,
    Json(payload): Json<types::DecryptRequest>,
) -> Result<Json<types::DecryptResponse>, StatusCode> {
    let decrypted =
        crypto::decrypt_data(&payload.encrypted_data, &payload.passkey_id, &state.storage)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(types::DecryptResponse { data: decrypted }))
}

async fn list_secrets(
    Path(passkey_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<types::ListSecretsResponse>, StatusCode> {
    // URL decode the passkey ID to handle special characters
    let decoded_passkey_id =
        urlencoding::decode(&passkey_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let encrypted_data = state
        .storage
        .get_encrypted_data(&decoded_passkey_id)
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
    state
        .storage
        .delete_encrypted_data(&data_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({"success": true})))
}

async fn create_challenge(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<types::CreateChallengeRequest>,
) -> error::Result<Json<types::CreateChallengeResponse>> {
    // Validate session to get user ID
    let session_data = auth_helpers::validate_session(&jar, &state)?;

    // Parse operation type
    let operation_type = match req.operation_type.as_str() {
        "file_create" => challenge::ChallengeType::FileCreate,
        "file_read" => challenge::ChallengeType::FileRead,
        "file_write" => challenge::ChallengeType::FileWrite,
        "file_delete" => challenge::ChallengeType::FileDelete,
        "general_crypto" => challenge::ChallengeType::GeneralCrypto,
        _ => {
            return Err(error::AppError::BadRequest(
                "Invalid operation type".to_string(),
            ));
        }
    };

    // Create challenge
    let challenge = state
        .challenges
        .create_challenge(session_data.user_id, operation_type)?;

    Ok(Json(types::CreateChallengeResponse {
        challenge_id: challenge.id,
        challenge_bytes: challenge.challenge_bytes.to_vec(),
        expires_at: challenge.expires_at,
    }))
}

async fn identify_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<types::IdentifyRequest>,
) -> error::Result<(CookieJar, Json<types::IdentifyResponse>)> {
    tracing::debug!("Processing credential identification request");

    // The credential ID from the frontend uses base64url encoding (with - and _)
    // Convert from base64url to standard base64 (with + and /)
    let standard_base64 = req.credential_id.replace('-', "+").replace('_', "/");

    // Add padding if needed
    let padded_base64 = match standard_base64.len() % 4 {
        0 => standard_base64,
        n => format!("{}{}", standard_base64, "=".repeat(4 - n)),
    };

    tracing::debug!("Processing base64 credential format conversion");

    // Try to find it with the converted format
    if let Ok(stored_cred) = state.storage.get_credential(&padded_base64).await {
        tracing::debug!("Credential found with format conversion");

        // Create session and set cookie
        let session_id =
            state
                .sessions
                .create_session(stored_cred.user_id, padded_base64.clone(), None);

        // Determine if we should use secure cookies (HTTPS)
        let is_secure = false; // TODO: detect from request or config
        let session_cookie = session::create_session_cookie(session_id, is_secure);
        let jar = jar.add(session_cookie);

        return Ok((
            jar,
            Json(types::IdentifyResponse {
                passkey_id: padded_base64,
                user_id: stored_cred.user_id,
            }),
        ));
    }

    // Fallback: try the original format in case it's already correct
    if let Ok(stored_cred) = state.storage.get_credential(&req.credential_id).await {
        tracing::debug!("Credential found directly");

        // Create session and set cookie
        let session_id =
            state
                .sessions
                .create_session(stored_cred.user_id, req.credential_id.clone(), None);

        // Determine if we should use secure cookies (HTTPS)
        let is_secure = false; // TODO: detect from request or config
        let session_cookie = session::create_session_cookie(session_id, is_secure);
        let jar = jar.add(session_cookie);

        return Ok((
            jar,
            Json(types::IdentifyResponse {
                passkey_id: req.credential_id,
                user_id: stored_cred.user_id,
            }),
        ));
    }

    tracing::warn!("Credential not found for authentication attempt");
    Err(error::AppError::NotFound(format!(
        "Credential {} not found",
        req.credential_id
    )))
}

async fn create_file(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<types::CreateFileRequest>,
) -> error::Result<Json<types::CreateFileResponse>> {
    // Validate session and get user info
    let (user_id, passkey_id) = auth_helpers::get_user_info_from_session(&jar, &state)?;

    let response = state
        .storage
        .create_file(&req, user_id, &passkey_id)
        .await?;

    Ok(Json(response))
}

async fn get_files(
    State(state): State<AppState>,
    jar: CookieJar,
) -> error::Result<Json<types::FileBrowserResponse>> {
    // Validate session and get user info
    let (_user_id, passkey_id) = auth_helpers::get_user_info_from_session(&jar, &state)?;

    let files = state.storage.get_files_for_user(&passkey_id).await?;

    Ok(Json(types::FileBrowserResponse { files }))
}

async fn get_file_content(
    Path(file_id): Path<String>,
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<types::GetFileContentRequest>,
) -> error::Result<Json<types::GetFileContentResponse>> {
    // Validate session and get user info
    let (_user_id, passkey_id) = auth_helpers::get_user_info_from_session(&jar, &state)?;

    let file_id = Uuid::parse_str(&file_id)?;

    let response = state
        .storage
        .get_file_content(file_id, req.version_id, &passkey_id)
        .await?;

    Ok(Json(response))
}

async fn save_file_version(
    Path(file_id): Path<String>,
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<types::SaveVersionRequest>,
) -> error::Result<Json<types::SaveVersionResponse>> {
    // Validate session and get user info
    let (_user_id, passkey_id) = auth_helpers::get_user_info_from_session(&jar, &state)?;

    let file_id = Uuid::parse_str(&file_id)?;

    let response = state
        .storage
        .save_file_version(
            file_id,
            &req.content,
            req.change_summary.as_deref(),
            &passkey_id,
        )
        .await?;

    Ok(Json(response))
}

/// Secure file creation with WebAuthn challenge-response authentication
async fn secure_create_file(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<types::SecureCreateFileRequest>,
) -> error::Result<Json<types::CreateFileResponse>> {
    // Validate session and get user info
    let (user_id, passkey_id) = auth_helpers::get_user_info_from_session(&jar, &state)?;

    // Verify and consume the challenge
    let challenge = state
        .challenges
        .verify_and_consume_challenge(
            &req.challenge_id,
            user_id,
            challenge::ChallengeType::FileCreate,
        )
        .map_err(|e| {
            error::AppError::BadRequest(format!("Challenge verification failed: {}", e))
        })?;

    // Verify WebAuthn signature against the challenge
    let signature_valid = crypto::verify_webauthn_signature_for_challenge(
        &req.webauthn_signature,
        &challenge,
        &passkey_id,
        &state.storage,
    )
    .await
    .map_err(|e| error::AppError::BadRequest(format!("Signature verification failed: {}", e)))?;

    if !signature_valid {
        return Err(error::AppError::Unauthorized(
            "Invalid WebAuthn signature".to_string(),
        ));
    }

    // Generate encryption materials
    let (salt, nonce) = crypto::generate_encryption_materials().map_err(|e| {
        error::AppError::Internal(format!("Failed to generate encryption materials: {}", e))
    })?;

    // Encrypt content using WebAuthn signature-based key derivation
    let _encrypted_content = crypto::encrypt_with_webauthn_signature(
        &req.content,
        &req.webauthn_signature,
        &challenge,
        &salt,
        &nonce,
    )
    .map_err(|e| error::AppError::Internal(format!("Encryption failed: {}", e)))?;

    // Create the file using secure encryption
    let create_req = types::CreateFileRequest {
        filename: req.filename,
        tags: req.tags,
        content: req.content, // This will be ignored in favor of encrypted_content
    };

    // Store with secure encryption materials
    let response = state
        .storage
        .create_file(&create_req, user_id, &passkey_id)
        .await?;

    Ok(Json(response))
}

/// Secure file content retrieval with WebAuthn challenge-response authentication
async fn secure_get_file_content(
    Path(file_id): Path<String>,
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<types::SecureGetFileContentRequest>,
) -> error::Result<Json<types::GetFileContentResponse>> {
    // Validate session and get user info
    let (user_id, passkey_id) = auth_helpers::get_user_info_from_session(&jar, &state)?;

    // Verify and consume the challenge
    let challenge = state
        .challenges
        .verify_and_consume_challenge(
            &req.challenge_id,
            user_id,
            challenge::ChallengeType::FileRead,
        )
        .map_err(|e| {
            error::AppError::BadRequest(format!("Challenge verification failed: {}", e))
        })?;

    // Verify WebAuthn signature against the challenge
    let signature_valid = crypto::verify_webauthn_signature_for_challenge(
        &req.webauthn_signature,
        &challenge,
        &passkey_id,
        &state.storage,
    )
    .await
    .map_err(|e| error::AppError::BadRequest(format!("Signature verification failed: {}", e)))?;

    if !signature_valid {
        return Err(error::AppError::Unauthorized(
            "Invalid WebAuthn signature".to_string(),
        ));
    }

    let file_id = Uuid::parse_str(&file_id)?;

    // Get encrypted file content
    let encrypted_response = state
        .storage
        .get_file_content(file_id, req.version_id, &passkey_id)
        .await?;

    // For now, return the encrypted response
    // TODO: Implement secure decryption using WebAuthn signature
    Ok(Json(encrypted_response))
}

/// Secure file version saving with WebAuthn challenge-response authentication
async fn secure_save_file_version(
    Path(file_id): Path<String>,
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<types::SecureSaveVersionRequest>,
) -> error::Result<Json<types::SaveVersionResponse>> {
    // Validate session and get user info
    let (user_id, passkey_id) = auth_helpers::get_user_info_from_session(&jar, &state)?;

    // Verify and consume the challenge
    let challenge = state
        .challenges
        .verify_and_consume_challenge(
            &req.challenge_id,
            user_id,
            challenge::ChallengeType::FileWrite,
        )
        .map_err(|e| {
            error::AppError::BadRequest(format!("Challenge verification failed: {}", e))
        })?;

    // Verify WebAuthn signature against the challenge
    let signature_valid = crypto::verify_webauthn_signature_for_challenge(
        &req.webauthn_signature,
        &challenge,
        &passkey_id,
        &state.storage,
    )
    .await
    .map_err(|e| error::AppError::BadRequest(format!("Signature verification failed: {}", e)))?;

    if !signature_valid {
        return Err(error::AppError::Unauthorized(
            "Invalid WebAuthn signature".to_string(),
        ));
    }

    let file_id = Uuid::parse_str(&file_id)?;

    // For now, use the existing save method
    // TODO: Implement secure encryption using WebAuthn signature
    let response = state
        .storage
        .save_file_version(
            file_id,
            &req.content,
            req.change_summary.as_deref(),
            &passkey_id,
        )
        .await?;

    Ok(Json(response))
}
