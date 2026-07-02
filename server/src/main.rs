mod auth;
mod blob;
mod config;
mod db;
mod error;
mod models;
mod routes;
mod state;
mod util;

use std::net::SocketAddr;
use std::str::FromStr;

use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,shardx_team_server=debug")),
        )
        .init();

    let cfg = Config::from_env();
    let pool = db::init_pool(&cfg).await?;
    db::bootstrap_admin(&pool, &cfg).await?;

    let state = AppState {
        db: pool,
        cfg: cfg.clone(),
    };
    let app = routes::router(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from_str(&cfg.bind)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("ShardX Team Server listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
