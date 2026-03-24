use anyhow::Result;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::warn;

use crate::db::DynDatabase;

pub mod token;

/// Store connection type in request extensions
#[derive(Clone)]
pub enum ConnectionType {
    UnixSocket,
    Tcp,
}

/// Middleware to check API authentication
pub async fn auth_middleware(
    State(db): State<DynDatabase>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Check if this is a Unix socket connection (already set by router)
    if let Some(conn_type) = request.extensions().get::<ConnectionType>() {
        if matches!(conn_type, ConnectionType::UnixSocket) {
            return Ok(next.run(request).await);
        }
    }

    // Check for Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    // Extract Bearer token
    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid Authorization header format. Expected: Bearer <token>",
        )
    })?;

    // Verify token against database
    let valid = verify_token_in_db(&db, token).await.map_err(|e| {
        warn!("Token verification error: {}", e);
        (StatusCode::UNAUTHORIZED, "Invalid token")
    })?;

    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid or disabled token"));
    }

    Ok(next.run(request).await)
}

/// Verify a token exists in the database and is enabled
async fn verify_token_in_db(db: &DynDatabase, token: &str) -> Result<bool> {
    let tokens = db.list_tokens().await?;

    for (token_hash, enabled) in tokens {
        if token::verify(token, &token_hash)? {
            let _ = db.update_token_last_used(&token_hash).await;
            return Ok(enabled == 1);
        }
    }

    Ok(false)
}
