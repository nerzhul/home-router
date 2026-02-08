use crate::{db::Database, models::Lease};
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

/// List all active leases
#[utoipa::path(
    get,
    path = "/api/leases",
    tag = "leases",
    responses(
        (status = 200, description = "List of active leases", body = Vec<Lease>),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_leases(State(db): State<Arc<Database>>) -> Result<Json<Vec<Lease>>, StatusCode> {
    db.list_active_leases()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
