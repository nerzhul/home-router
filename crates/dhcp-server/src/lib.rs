pub mod auth;
pub mod config;
pub mod db;
pub mod dhcp;
pub mod handlers;
pub mod models;
pub mod routes;

pub use config::Config;
pub use models::{DynamicRange, StaticIP, Subnet};

use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};
use db::Database;
use std::sync::Arc;
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
        handlers::tokens::list_tokens,
        handlers::tokens::create_token,
        handlers::tokens::delete_token,
        handlers::tokens::toggle_token,
    ),
    components(
        schemas(
            models::Subnet,
            models::DynamicRange,
            models::StaticIP,
            models::Lease,
            models::ApiToken,
            models::CreateTokenRequest,
            models::CreateTokenResponse,
        )
    ),
    tags(
        (name = "subnets", description = "Subnet management endpoints"),
        (name = "ranges", description = "Dynamic range management endpoints"),
        (name = "static-ips", description = "Static IP management endpoints"),
        (name = "leases", description = "Lease information endpoints"),
        (name = "tokens", description = "API token management endpoints"),
    )
)]
pub struct ApiDoc;

pub fn create_router(db: Arc<Database>) -> Router {
    create_router_with_auth(db, false)
}

pub fn create_router_with_auth(db: Arc<Database>, require_auth: bool) -> Router {
    let protected_routes = Router::new()
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
        .route(
            "/api/static-ips",
            get(handlers::static_ips::list_static_ips),
        )
        .route(
            "/api/static-ips",
            post(handlers::static_ips::create_static_ip),
        )
        .route(
            "/api/static-ips/:id",
            delete(handlers::static_ips::delete_static_ip),
        )
        // Lease routes
        .route("/api/leases", get(handlers::leases::list_leases))
        // Token management routes
        .route("/api/tokens", get(handlers::tokens::list_tokens))
        .route("/api/tokens", post(handlers::tokens::create_token))
        .route("/api/tokens/:id", delete(handlers::tokens::delete_token))
        .route(
            "/api/tokens/:id/toggle",
            patch(handlers::tokens::toggle_token),
        );

    // Apply authentication middleware only if required
    let protected_routes = if require_auth {
        protected_routes.layer(middleware::from_fn_with_state(
            db.clone(),
            auth::auth_middleware,
        ))
    } else {
        protected_routes
    };

    let app = Router::new()
        .merge(protected_routes)
        // Health check - always public
        .route("/health", get(handlers::health::health_check))
        .with_state(db);

    // Merge with Swagger UI
    let app =
        app.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()));

    app
}
