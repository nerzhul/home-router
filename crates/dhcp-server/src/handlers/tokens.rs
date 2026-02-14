use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use tracing::error;

use crate::{
    auth::{generate_token, hash_token},
    db::Database,
    models::{ApiToken, CreateTokenRequest, CreateTokenResponse},
};

/// List all API tokens
#[utoipa::path(
    get,
    path = "/api/tokens",
    responses(
        (status = 200, description = "List of API tokens", body = Vec<ApiToken>),
        (status = 500, description = "Internal server error")
    ),
    tag = "tokens"
)]
pub async fn list_tokens(
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<ApiToken>>, impl IntoResponse> {
    match sqlx::query_as::<_, (i64, String, i64, Option<i64>, bool)>(
        "SELECT id, name, created_at, last_used_at, enabled FROM api_tokens ORDER BY created_at DESC"
    )
    .fetch_all(db.pool())
    .await
    {
        Ok(records) => {
            let tokens: Vec<ApiToken> = records
                .into_iter()
                .map(|(id, name, created_at, last_used_at, enabled)| ApiToken {
                    id: Some(id),
                    name,
                    token_hash: None,
                    salt: None,
                    created_at: Some(created_at),
                    last_used_at,
                    enabled,
                    token: None,
                })
                .collect();
            Ok(Json(tokens))
        }
        Err(e) => {
            error!("Failed to list tokens: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to list tokens"))
        }
    }
}

/// Create a new API token
#[utoipa::path(
    post,
    path = "/api/tokens",
    request_body = CreateTokenRequest,
    responses(
        (status = 201, description = "Token created successfully", body = CreateTokenResponse),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tokens"
)]
pub async fn create_token(
    State(db): State<Arc<Database>>,
    Json(request): Json<CreateTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), impl IntoResponse> {
    // Generate token
    let token = generate_token();

    // Hash token
    let (token_hash, salt) = hash_token(&token).map_err(|e| {
        error!("Failed to hash token: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash token")
    })?;

    // Insert into database
    match sqlx::query("INSERT INTO api_tokens (name, token_hash, salt) VALUES (?, ?, ?)")
        .bind(&request.name)
        .bind(&token_hash)
        .bind(&salt)
        .execute(db.pool())
        .await
    {
        Ok(result) => {
            let response = CreateTokenResponse {
                id: result.last_insert_rowid(),
                name: request.name,
                token,
            };
            Ok((StatusCode::CREATED, Json(response)))
        }
        Err(e) => {
            error!("Failed to create token: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to create token"))
        }
    }
}

/// Delete an API token
#[utoipa::path(
    delete,
    path = "/api/tokens/{id}",
    params(
        ("id" = i64, Path, description = "Token ID")
    ),
    responses(
        (status = 204, description = "Token deleted successfully"),
        (status = 404, description = "Token not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tokens"
)]
pub async fn delete_token(
    State(db): State<Arc<Database>>,
    Path(id): Path<i64>,
) -> Result<StatusCode, impl IntoResponse> {
    match sqlx::query("DELETE FROM api_tokens WHERE id = ?")
        .bind(id)
        .execute(db.pool())
        .await
    {
        Ok(result) => {
            if result.rows_affected() == 0 {
                Err((StatusCode::NOT_FOUND, "Token not found"))
            } else {
                Ok(StatusCode::NO_CONTENT)
            }
        }
        Err(e) => {
            error!("Failed to delete token: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete token"))
        }
    }
}

/// Enable/disable an API token
#[utoipa::path(
    patch,
    path = "/api/tokens/{id}/toggle",
    params(
        ("id" = i64, Path, description = "Token ID")
    ),
    responses(
        (status = 200, description = "Token toggled successfully"),
        (status = 404, description = "Token not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tokens"
)]
pub async fn toggle_token(
    State(db): State<Arc<Database>>,
    Path(id): Path<i64>,
) -> Result<StatusCode, impl IntoResponse> {
    match sqlx::query(
        "UPDATE api_tokens SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?",
    )
    .bind(id)
    .execute(db.pool())
    .await
    {
        Ok(result) => {
            if result.rows_affected() == 0 {
                Err((StatusCode::NOT_FOUND, "Token not found"))
            } else {
                Ok(StatusCode::OK)
            }
        }
        Err(e) => {
            error!("Failed to toggle token: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to toggle token"))
        }
    }
}
