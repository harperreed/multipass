// ABOUTME: Session management with HttpOnly cookies for secure authentication token storage
// ABOUTME: Replaces localStorage tokens to prevent XSS-based token theft

use crate::error::{AppError, Result};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: Uuid,
    pub passkey_id: String,
    pub vault_name: Option<String>,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn create_session(
        &self,
        user_id: Uuid,
        passkey_id: String,
        vault_name: Option<String>,
    ) -> String {
        let session_id = Uuid::new_v4().to_string();
        let session_data = SessionData {
            user_id,
            passkey_id,
            vault_name,
            created_at: chrono::Utc::now().timestamp(),
        };

        if let Ok(mut sessions) = self.sessions.write() {
            sessions.insert(session_id.clone(), session_data);
        }

        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionData> {
        if let Ok(sessions) = self.sessions.read() {
            sessions.get(session_id).cloned()
        } else {
            None
        }
    }

    pub fn remove_session(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.remove(session_id);
        }
    }

    pub fn cleanup_expired_sessions(&self, max_age_seconds: i64) {
        let cutoff = chrono::Utc::now().timestamp() - max_age_seconds;

        if let Ok(mut sessions) = self.sessions.write() {
            sessions.retain(|_, session| session.created_at > cutoff);
        }
    }
}

const SESSION_COOKIE_NAME: &str = "multipass_session";
const SESSION_MAX_AGE: i64 = 24 * 60 * 60; // 24 hours

pub fn create_session_cookie(session_id: String, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, session_id))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(SESSION_MAX_AGE))
        .path("/")
        .build()
}

pub fn create_logout_cookie() -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, ""))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(0))
        .path("/")
        .build()
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct AuthenticatedSession {
    pub session_data: SessionData,
}

pub fn extract_session_from_jar(
    jar: &CookieJar,
    session_store: &SessionStore,
) -> Result<SessionData> {
    let session_cookie = jar
        .get(SESSION_COOKIE_NAME)
        .ok_or_else(|| AppError::Unauthorized("No session cookie found".to_string()))?;

    let session_data = session_store
        .get_session(session_cookie.value())
        .ok_or_else(|| AppError::Unauthorized("Invalid session".to_string()))?;

    Ok(session_data)
}
