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
    /// Trust `X-Forwarded-For` / `X-Real-IP` for the client IP (login throttle).
    /// Only enable behind a reverse proxy that sets it — otherwise a client
    /// could spoof the header to dodge the per-IP limit.
    pub trust_proxy: bool,
}

impl Config {
    pub fn from_env() -> Arc<Config> {
        // Default to loopback: bare-metal/dev is reachable only from the host,
        // so a fresh install isn't exposed by accident. Exposing it is a
        // deliberate `SHARDX_BIND=0.0.0.0` (the Docker image sets that), which
        // then trips the default-admin-password guard in `bootstrap_admin`.
        let bind = env_or("SHARDX_BIND", "127.0.0.1:8080");
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

        // Floor the lease TTL: clients renew at ~TTL/3, so too small a TTL (or a
        // non-positive one, which would mint an already-expired lease) leaves a
        // window where the lock lapses between renewals and a peer can steal it.
        let lease_ttl_secs = {
            const MIN_LEASE_TTL_SECS: i64 = 15;
            let configured = parse_env("SHARDX_LEASE_TTL_SECS", 90);
            if configured < MIN_LEASE_TTL_SECS {
                tracing::warn!(
                    "SHARDX_LEASE_TTL_SECS={configured} is below the {MIN_LEASE_TTL_SECS}s \
                     minimum; clamping to {MIN_LEASE_TTL_SECS}s so clients can renew in time"
                );
                MIN_LEASE_TTL_SECS
            } else {
                configured
            }
        };
        let snapshot_keep = parse_env("SHARDX_SNAPSHOT_KEEP", 5);
        let max_snapshot_bytes = parse_env::<usize>("SHARDX_MAX_SNAPSHOT_BYTES", 512 * 1024 * 1024);
        let trust_proxy = env_or("SHARDX_TRUST_PROXY", "0") == "1";

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
            trust_proxy,
        })
    }

    /// True if `bind` is a loopback address (reachable only from this host).
    /// Non-loopback (or an unparseable host) is treated as network-facing.
    pub fn bind_is_loopback(&self) -> bool {
        self.bind
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false)
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_bind(bind: &str) -> Config {
        Config {
            bind: bind.to_string(),
            data_dir: String::new(),
            db_path: String::new(),
            blob_dir: String::new(),
            token_secret: String::new(),
            token_ttl_secs: 0,
            admin_user: String::new(),
            admin_pass: String::new(),
            lease_ttl_secs: 0,
            snapshot_keep: 0,
            max_snapshot_bytes: 0,
            trust_proxy: false,
        }
    }

    #[test]
    fn loopback_detection() {
        assert!(cfg_with_bind("127.0.0.1:8080").bind_is_loopback());
        assert!(cfg_with_bind("[::1]:8080").bind_is_loopback());
        // Network-facing (or unparseable) binds are treated as exposed.
        assert!(!cfg_with_bind("0.0.0.0:8080").bind_is_loopback());
        assert!(!cfg_with_bind("192.168.1.10:8080").bind_is_loopback());
        assert!(!cfg_with_bind("localhost:8080").bind_is_loopback()); // not an IP literal
    }
}
