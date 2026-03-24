pub mod health;
pub mod ia_prefixes;
pub mod leases;
pub mod ranges;
pub mod static_ips;
pub mod subnets;
pub mod tokens;

use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::{
    auth,
    db::DynDatabase,
    config::RaConfig,
    AppState,
};

pub fn create_router(db: DynDatabase, ra_config: Arc<RaConfig>) -> Router {
    create_router_with_auth(db, ra_config, false)
}

pub fn create_router_with_auth(
    db: DynDatabase,
    ra_config: Arc<RaConfig>,
    require_auth: bool,
) -> Router {
    let state = AppState::new(db.clone(), ra_config);

    let protected_routes = Router::new()
        // Subnet routes
        .route("/api/subnets", get(subnets::list_subnets))
        .route("/api/subnets", post(subnets::create_subnet))
        .route("/api/subnets/{id}", get(subnets::get_subnet))
        .route("/api/subnets/{id}", put(subnets::update_subnet))
        .route("/api/subnets/{id}", delete(subnets::delete_subnet))
        // Dynamic range routes
        .route("/api/ranges", get(ranges::list_ranges))
        .route("/api/ranges", post(ranges::create_range))
        .route("/api/ranges/{id}", delete(ranges::delete_range))
        // Static IP routes
        .route("/api/static-ips", get(static_ips::list_static_ips))
        .route("/api/static-ips", post(static_ips::create_static_ip))
        .route("/api/static-ips/{ip}", delete(static_ips::delete_static_ip))
        .route(
            "/api/static-ips/{ip}/hostname",
            patch(static_ips::update_static_ip_hostname),
        )
        // Lease routes
        .route("/api/leases", get(leases::list_leases))
        // Token management routes
        .route("/api/tokens", get(tokens::list_tokens))
        .route("/api/tokens", post(tokens::create_token))
        .route("/api/tokens/{id}", delete(tokens::delete_token))
        .route("/api/tokens/{id}/toggle", patch(tokens::toggle_token))
        // IA Prefix routes (IPv6 for Router Advertisement)
        .route("/api/ia-prefixes", get(ia_prefixes::list_ia_prefixes))
        .route("/api/ia-prefixes", post(ia_prefixes::create_ia_prefix))
        .route("/api/ia-prefixes/{id}", get(ia_prefixes::get_ia_prefix))
        .route("/api/ia-prefixes/{id}", put(ia_prefixes::update_ia_prefix))
        .route(
            "/api/ia-prefixes/{id}",
            delete(ia_prefixes::delete_ia_prefix),
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

    Router::new()
        .merge(protected_routes)
        // Health check - always public
        .route("/health", get(health::health_check))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use crate::db::InMemoryDatabase;
    use tower::ServiceExt;

    fn make_db() -> DynDatabase {
        Arc::new(InMemoryDatabase::new())
    }

    fn make_ra_config() -> Arc<RaConfig> {
        Arc::new(RaConfig::default())
    }

    async fn send(router: Router, method: Method, uri: &str) -> StatusCode {
        router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn test_router_creation_no_auth() {
        // Ensure the router can be built without panicking (e.g. invalid path syntax)
        let _router = create_router(make_db(), make_ra_config());
    }

    #[tokio::test]
    async fn test_router_creation_with_auth_disabled() {
        let _router = create_router_with_auth(make_db(), make_ra_config(), false);
    }

    #[tokio::test]
    async fn test_router_creation_with_auth_enabled() {
        let _router = create_router_with_auth(make_db(), make_ra_config(), true);
    }

    #[tokio::test]
    async fn test_health_check() {
        let router = create_router(make_db(), make_ra_config());
        let status = send(router, Method::GET, "/health").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_routes_reachable_without_auth() {
        let routes = [
            (Method::GET, "/api/subnets"),
            (Method::GET, "/api/ranges"),
            (Method::GET, "/api/static-ips"),
            (Method::GET, "/api/leases"),
            (Method::GET, "/api/tokens"),
            (Method::GET, "/api/ia-prefixes"),
        ];
        for (method, path) in routes {
            let router = create_router_with_auth(make_db(), make_ra_config(), false);
            let status = send(router, method, path).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "Route {} {} should exist",
                path,
                path
            );
        }
    }

    #[tokio::test]
    async fn test_routes_require_auth_when_enabled() {
        let routes = [
            (Method::GET, "/api/subnets"),
            (Method::GET, "/api/ranges"),
            (Method::GET, "/api/static-ips"),
            (Method::GET, "/api/leases"),
            (Method::GET, "/api/tokens"),
            (Method::GET, "/api/ia-prefixes"),
        ];
        for (method, path) in routes {
            let router = create_router_with_auth(make_db(), make_ra_config(), true);
            let status = send(router, method, path).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "Route {} should return 401 when auth is required",
                path
            );
        }
    }
}
