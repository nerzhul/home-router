pub mod auth;
pub mod config;
pub mod db;
pub mod dhcp;
pub mod handlers;
pub mod models;
pub mod ra;
pub mod utils;

pub use config::{Config, RaConfig};
pub use db::{create_database, Database, DynDatabase, InMemoryDatabase, SqliteDatabase};
pub use models::{DynamicRange, IAPrefix, StaticIP, Subnet};
pub use ra::RaServer;

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
        handlers::static_ips::update_static_ip_hostname,
        handlers::leases::list_leases,
        handlers::tokens::list_tokens,
        handlers::tokens::create_token,
        handlers::tokens::delete_token,
        handlers::tokens::toggle_token,
        handlers::ia_prefixes::list_ia_prefixes,
        handlers::ia_prefixes::create_ia_prefix,
        handlers::ia_prefixes::get_ia_prefix,
        handlers::ia_prefixes::update_ia_prefix,
        handlers::ia_prefixes::delete_ia_prefix,
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
            models::IAPrefix,
            handlers::static_ips::UpdateHostnameRequest,
        )
    ),
    tags(
        (name = "subnets", description = "Subnet management endpoints"),
        (name = "ranges", description = "Dynamic range management endpoints"),
        (name = "static-ips", description = "Static IP management endpoints"),
        (name = "leases", description = "Lease information endpoints"),
        (name = "tokens", description = "API token management endpoints"),
        (name = "ia-prefixes", description = "IPv6 prefix (IA Prefix) management for Router Advertisement"),
    )
)]
pub struct ApiDoc;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: DynDatabase,
    pub ra_config: Arc<RaConfig>,
}

impl AppState {
    pub fn new(db: DynDatabase, ra_config: Arc<RaConfig>) -> Self {
        Self { db, ra_config }
    }
}

pub fn create_router(db: DynDatabase, ra_config: Arc<RaConfig>) -> axum::Router {
    handlers::create_router(db, ra_config)
}

pub fn create_router_with_auth(
    db: DynDatabase,
    ra_config: Arc<RaConfig>,
    require_auth: bool,
) -> axum::Router {
    let app = handlers::create_router_with_auth(db, ra_config, require_auth);
    // Merge with Swagger UI
    app.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
}
