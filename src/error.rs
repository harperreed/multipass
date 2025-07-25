// ABOUTME: Centralized error handling system with detailed context and logging
// ABOUTME: Provides structured errors without exposing sensitive details to clients

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Database(sea_orm::DbErr),
    Unauthorized(String),
    NotFound(String),
    BadRequest(String),
    #[allow(dead_code)]
    Crypto(String),
    Serialization(String),
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Database(err) => write!(f, "Database error: {}", err),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Crypto(msg) => write!(f, "Cryptography error: {}", msg),
            AppError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Database(_) => {
                tracing::error!("Database error: {}", self);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database operation failed",
                )
            }
            AppError::Unauthorized(msg) => {
                tracing::warn!("Unauthorized access: {}", msg);
                (StatusCode::UNAUTHORIZED, "Authentication required")
            }
            AppError::NotFound(msg) => {
                tracing::info!("Resource not found: {}", msg);
                (StatusCode::NOT_FOUND, "Resource not found")
            }
            AppError::BadRequest(msg) => {
                tracing::warn!("Bad request: {}", msg);
                (StatusCode::BAD_REQUEST, msg.as_str())
            }
            AppError::Crypto(_) => {
                tracing::error!("Cryptography error: {}", self);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Cryptography operation failed",
                )
            }
            AppError::Serialization(_) => {
                tracing::error!("Serialization error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Data processing failed")
            }
            AppError::Internal(_) => {
                tracing::error!("Internal error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}

// Conversion implementations
impl From<sea_orm::DbErr> for AppError {
    fn from(err: sea_orm::DbErr) -> Self {
        AppError::Database(err)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}

impl From<bincode::Error> for AppError {
    fn from(err: bincode::Error) -> Self {
        AppError::Serialization(err.to_string())
    }
}

impl From<uuid::Error> for AppError {
    fn from(err: uuid::Error) -> Self {
        AppError::BadRequest(format!("Invalid UUID: {}", err))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
