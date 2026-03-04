use crate::{models::DynamicRange, AppState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RangeQuery {
    subnet_id: Option<i64>,
}

/// List all dynamic ranges
#[utoipa::path(
    get,
    path = "/api/ranges",
    tag = "ranges",
    params(
        ("subnet_id" = Option<i64>, Query, description = "Filter by subnet ID")
    ),
    responses(
        (status = 200, description = "List of dynamic ranges", body = Vec<DynamicRange>),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_ranges(
    State(state): State<AppState>,
    Query(query): Query<RangeQuery>,
) -> Result<Json<Vec<DynamicRange>>, StatusCode> {
    state
        .db
        .list_ranges(query.subnet_id)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Create a new dynamic range
#[utoipa::path(
    post,
    path = "/api/ranges",
    tag = "ranges",
    request_body = DynamicRange,
    responses(
        (status = 201, description = "Range created", body = i64),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn create_range(
    State(state): State<AppState>,
    Json(range): Json<DynamicRange>,
) -> Result<(StatusCode, Json<i64>), StatusCode> {
    state
        .db
        .create_range(&range)
        .await
        .map(|id| (StatusCode::CREATED, Json(id)))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Delete a dynamic range
#[utoipa::path(
    delete,
    path = "/api/ranges/{id}",
    tag = "ranges",
    params(
        ("id" = i64, Path, description = "Range ID")
    ),
    responses(
        (status = 204, description = "Range deleted"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn delete_range(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    state
        .db
        .delete_range(id)
        .await
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
