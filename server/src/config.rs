use std::sync::Arc;

/// Server configuration, sourced entirely from environment variables so the
/// same binary runs identically in Docker and on a dev box.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub data_dir: String,
    pub db_path: String,
    pub blob_dir: String,
    pub token_secret: String,
    pub token_ttl_secs: i64,
    pub admin_user: String,
    pub admin_pass: String,
    /// Checkout-lock lease lifetime; the client renews within this window.
    pub lease_ttl_secs: i64,
    /// How many recent snapshots to retain per environment (older ones GC'd).
    pub snapshot_keep: i64,
    /// Max accepted snapshot upload size, bytes.
    pub max_snapshot_bytes: usize,
}

impl Config {
    pub fn from_env() -> Arc<Config> {
        let bind = env_or("SHARDX_BIND", "0.0.0.0:8080");
        let data_dir = env_or("SHARDX_DATA_DIR", "./data");
        let trimmed = data_dir.trim_end_matches('/').to_string();
        let db_path = format!("{trimmed}/shardx.db");
        let blob_dir = format!("{trimmed}/blobs");

        let token_secret = std::env::var("SHARDX_TOKEN_SECRET").unwrap_or_else(|_| {
            tracing::warn!(
                "SHARDX_TOKEN_SECRET not set; using an ephemeral random secret — \
                 every issued token becomes invalid when the server restarts"
            );
            uuid::Uuid::new_v4().to_string()
        });
        let token_ttl_secs = std::env::var("SHARDX_TOKEN_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7 * 24 * 3600);

        let admin_user = env_or("SHARDX_ADMIN_USER", "admin");
        let admin_pass = env_or("SHARDX_ADMIN_PASS", "admin");

        let lease_ttl_secs = parse_env("SHARDX_LEASE_TTL_SECS", 90);
        let snapshot_keep = parse_env("SHARDX_SNAPSHOT_KEEP", 5);
        let max_snapshot_bytes = parse_env::<usize>("SHARDX_MAX_SNAPSHOT_BYTES", 512 * 1024 * 1024);

        Arc::new(Config {
            bind,
            data_dir,
            db_path,
            blob_dir,
            token_secret,
            token_ttl_secs,
            admin_user,
            admin_pass,
            lease_ttl_secs,
            snapshot_keep,
            max_snapshot_bytes,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
