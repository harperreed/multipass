// ABOUTME: Authentication helper functions for session validation in endpoints
// ABOUTME: Provides utilities to extract and validate session data from cookies

use crate::{AppState, error, session};
use axum_extra::extract::cookie::CookieJar;

pub fn validate_session(jar: &CookieJar, state: &AppState) -> error::Result<session::SessionData> {
    session::extract_session_from_jar(jar, &state.sessions)
}

pub fn get_user_info_from_session(
    jar: &CookieJar,
    state: &AppState,
) -> error::Result<(uuid::Uuid, String)> {
    let session_data = validate_session(jar, state)?;
    Ok((session_data.user_id, session_data.passkey_id))
}
