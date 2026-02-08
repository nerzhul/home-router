pub mod config;
pub mod models;
pub mod db;
pub mod dhcp;
pub mod handlers;
pub mod routes;

pub use config::Config;
pub use models::{Subnet, DynamicRange, StaticIP};

use axum::{
    Router,
    routing::{get, post, put, delete},
};
use std::sync::Arc;
use db::Database;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::subnets::list_subnets,
        handlers::subnets::create_subnet,
        handlers::subnets::get_subnet,
        handlers::subnets::update_subnet,
        handlers::subnets::delete_subnet,
        handlers::ranges::list_ranges,
        handlers::ranges::create_range,
        handlers::ranges::delete_range,
        handlers::static_ips::list_static_ips,
        handlers::static_ips::create_static_ip,
        handlers::static_ips::delete_static_ip,
        handlers::leases::list_leases,
    ),
    components(
        schemas(
            models::Subnet,
            models::DynamicRange,
            models::StaticIP,
            models::Lease,
        )
    ),
    tags(
        (name = "subnets", description = "Subnet management endpoints"),
        (name = "ranges", description = "Dynamic range management endpoints"),
        (name = "static-ips", description = "Static IP management endpoints"),
        (name = "leases", description = "Lease information endpoints"),
    )
)]
pub struct ApiDoc;

pub fn create_router(db: Arc<Database>) -> Router {
    let app = Router::new()
        // Subnet routes
        .route("/api/subnets", get(handlers::subnets::list_subnets))
        .route("/api/subnets", post(handlers::subnets::create_subnet))
        .route("/api/subnets/:id", get(handlers::subnets::get_subnet))
        .route("/api/subnets/:id", put(handlers::subnets::update_subnet))
        .route("/api/subnets/:id", delete(handlers::subnets::delete_subnet))
        // Dynamic range routes
        .route("/api/ranges", get(handlers::ranges::list_ranges))
        .route("/api/ranges", post(handlers::ranges::create_range))
        .route("/api/ranges/:id", delete(handlers::ranges::delete_range))
        // Static IP routes
        .route("/api/static-ips", get(handlers::static_ips::list_static_ips))
        .route("/api/static-ips", post(handlers::static_ips::create_static_ip))
        .route("/api/static-ips/:id", delete(handlers::static_ips::delete_static_ip))
        // Lease routes
        .route("/api/leases", get(handlers::leases::list_leases))
        // Health check
        .route("/health", get(handlers::health::health_check))
        .with_state(db);
    
    // Merge with Swagger UI
    let app = app.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()));
    
    app
}
