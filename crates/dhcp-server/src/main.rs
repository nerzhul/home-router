use anyhow::Result;
use dhcp_server::{create_router, db::Database, dhcp::DhcpServer, Config};
use std::sync::Arc;
use tower::ServiceExt;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dhcp_server=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting DHCP Server");

    // Load configuration
    let config_path =
        std::env::var("DHCP_CONFIG").unwrap_or_else(|_| "/etc/dhcp-server/config.yaml".to_string());

    let config = match Config::from_file(&config_path) {
        Ok(cfg) => {
            info!("Loaded configuration from {}", config_path);
            Arc::new(cfg)
        }
        Err(e) => {
            error!("Failed to load configuration from {}: {}", config_path, e);
            info!("Using default configuration");
            Arc::new(Config::default())
        }
    };

    // Initialize database
    let db_url = format!("sqlite:{}", config.database_path);
    let db = match Database::new(&db_url).await {
        Ok(database) => {
            info!("Database initialized at {}", config.database_path);
            Arc::new(database)
        }
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Err(e);
        }
    };

    // Start API server
    let api_addr = format!("{}:{}", config.api.listen_address, config.api.port);
    let unix_socket_path = config.api.unix_socket.clone();

    // Start Unix socket listener if configured
    if let Some(socket_path) = unix_socket_path {
        let api_db_unix = Arc::clone(&db);
        tokio::spawn(async move {
            // Remove existing socket file if it exists
            let _ = std::fs::remove_file(&socket_path);

            let app = create_router(api_db_unix);

            match tokio::net::UnixListener::bind(&socket_path) {
                Ok(listener) => {
                    info!("API server listening on Unix socket: {}", socket_path);

                    loop {
                        match listener.accept().await {
                            Ok((stream, _)) => {
                                let app = app.clone();
                                tokio::spawn(async move {
                                    let stream = hyper_util::rt::TokioIo::new(stream);
                                    let hyper_service = hyper::service::service_fn(
                                        move |request: hyper::Request<hyper::body::Incoming>| {
                                            app.clone().oneshot(request)
                                        },
                                    );

                                    if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                                        hyper_util::rt::TokioExecutor::new(),
                                    )
                                    .serve_connection(stream, hyper_service)
                                    .await
                                    {
                                        error!("Error serving Unix socket connection: {}", err);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Error accepting Unix socket connection: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind Unix socket at {}: {}", socket_path, e);
                }
            }
        });
    }

    // Start TCP API server
    let api_db = Arc::clone(&db);
    tokio::spawn(async move {
        let app = create_router(api_db);
        let listener = match tokio::net::TcpListener::bind(&api_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind API server to {}: {}", api_addr, e);
                return;
            }
        };

        info!("API server listening on {}", api_addr);
        info!("Swagger UI available at http://{}/swagger-ui", api_addr);

        if let Err(e) = axum::serve(listener, app).await {
            error!("API server error: {}", e);
        }
    });

    // Start DHCP server
    let dhcp_server = DhcpServer::new(Arc::clone(&config), Arc::clone(&db));

    info!(
        "DHCP server starting on addresses: {:?}",
        config.listen_addresses
    );

    // Run DHCP server (blocks)
    if let Err(e) = dhcp_server.run().await {
        error!("DHCP server error: {}", e);
        return Err(e);
    }

    Ok(())
}
