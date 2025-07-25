// ABOUTME: Main entry point for the multipass webapp with passkey auth and data encryption
// ABOUTME: Sets up the web server, routes, and initialization logic

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{delete, get, post},
};
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

mod auth;
mod crypto;
mod entities;
mod migration;
mod storage;
mod types;

use auth::AuthState;
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
        .route("/files/create", post(create_file))
        .route("/files/:passkey_id", get(get_files))
        .route("/files/:file_id/content", post(get_file_content))
        .route("/files/:file_id/save", post(save_file_version))
        .route("/identify", post(identify_user))
        .layer(CorsLayer::permissive())
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
                println!("🚀 Server running on http://{}:{}", args.host, args.port);
                println!("⚠️  WebAuthn requires HTTPS for non-localhost access!");
                println!("💡 Use --cert and --key flags for HTTPS, or access via localhost");
            }

            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
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

async fn identify_user(
    State(state): State<AppState>,
    Json(req): Json<types::IdentifyRequest>,
) -> Result<Json<types::IdentifyResponse>, StatusCode> {
    println!(
        "Attempting to identify credential ID: {}",
        req.credential_id
    );

    // The credential ID from the frontend uses base64url encoding (with - and _)
    // Convert from base64url to standard base64 (with + and /)
    let standard_base64 = req.credential_id.replace('-', "+").replace('_', "/");

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

async fn create_file(
    State(state): State<AppState>,
    Json(req): Json<types::CreateFileRequest>,
) -> Result<Json<types::CreateFileResponse>, StatusCode> {
    // Get the user ID from the credential
    let credential = state
        .storage
        .get_credential(&req.passkey_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let response = state
        .storage
        .create_file(&req, credential.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(response))
}

async fn get_files(
    Path(passkey_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<types::FileBrowserResponse>, StatusCode> {
    // URL decode the passkey ID to handle special characters
    let decoded_passkey_id =
        urlencoding::decode(&passkey_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let files = state
        .storage
        .get_files_for_user(&decoded_passkey_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(types::FileBrowserResponse { files }))
}

async fn get_file_content(
    Path(file_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<types::GetFileContentRequest>,
) -> Result<Json<types::GetFileContentResponse>, StatusCode> {
    let file_id = Uuid::parse_str(&file_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let response = state
        .storage
        .get_file_content(file_id, req.version_id, &req.passkey_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(response))
}

async fn save_file_version(
    Path(file_id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<types::SaveVersionRequest>,
) -> Result<Json<types::SaveVersionResponse>, StatusCode> {
    let file_id = Uuid::parse_str(&file_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let response = state
        .storage
        .save_file_version(
            file_id,
            &req.content,
            req.change_summary.as_deref(),
            &req.passkey_id,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(response))
}
