use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

use crate::config::Config;
use crate::models::User;
use crate::{auth, util};

/// Open (creating if needed) the SQLite DB and run migrations.
pub async fn init_pool(cfg: &Config) -> anyhow::Result<SqlitePool> {
    tokio::fs::create_dir_all(&cfg.data_dir).await?;
    tokio::fs::create_dir_all(&cfg.blob_dir).await?;

    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", cfg.db_path))?
        .create_if_missing(true)
        .foreign_keys(true)
        // Writers queue instead of failing fast when a checkin transaction
        // briefly holds the write lock.
        .busy_timeout(std::time::Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// On an empty DB, create the initial admin from config.
pub async fn bootstrap_admin(pool: &SqlitePool, cfg: &Config) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    // On a network-facing bind, a weak/default admin password is remote-takeover
    // by default. Loopback only exposes it locally (a warning suffices) and an
    // explicit opt-out covers exposed-dev setups.
    let guard_exposed = !cfg.bind_is_loopback()
        && !std::env::var("SHARDX_ALLOW_INSECURE_ADMIN").is_ok_and(|v| v == "1");

    if count == 0 {
        // Creating the first admin: we have the plaintext, so reject empty /
        // too-short / placeholder passwords up front.
        if guard_exposed && is_weak_password(&cfg.admin_pass) {
            anyhow::bail!(
                "refusing to bootstrap the admin account with a weak/default password on a \
                 non-loopback bind ({}). Set SHARDX_ADMIN_PASS to a strong secret \
                 (recommended), bind 127.0.0.1, or set SHARDX_ALLOW_INSECURE_ADMIN=1 to \
                 override.",
                cfg.bind
            );
        }
        let hash = auth::hash_password(&cfg.admin_pass).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        sqlx::query(
            "INSERT INTO users (id, username, pw_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
        )
        .bind(util::new_id())
        .bind(&cfg.admin_user)
        .bind(hash)
        .bind(util::now_rfc3339())
        .execute(pool)
        .await?;
        tracing::warn!(
            "bootstrapped admin user '{}' — set SHARDX_ADMIN_USER/SHARDX_ADMIN_PASS to override, \
             then change the password",
            cfg.admin_user
        );
    }

    // Also catch an already-seeded weak admin (e.g. a DB first bootstrapped with
    // admin/admin, or set up on loopback then later exposed). Only placeholder
    // passwords are testable from a stored hash — length-only-weak ones set on an
    // existing install aren't caught here, nor are case variants of a placeholder
    // (the hash pins the exact bytes; we only test the canonical spellings); the
    // bootstrap check above covers new installs case-insensitively. An admin whose
    // password was changed to a strong one passes.
    if guard_exposed {
        let hashes: Vec<String> =
            sqlx::query_scalar("SELECT pw_hash FROM users WHERE role = 'admin'")
                .fetch_all(pool)
                .await?;
        let weak = hashes
            .iter()
            .any(|h| WEAK_PASSWORDS.iter().any(|w| auth::verify_password(w, h).is_ok()));
        if weak {
            anyhow::bail!(
                "an admin account still uses a weak/default password while binding a \
                 non-loopback address ({}). Change it (POST /me/password or an admin \
                 reset), bind 127.0.0.1, or set SHARDX_ALLOW_INSECURE_ADMIN=1 to override.",
                cfg.bind
            );
        }
    }
    Ok(())
}

/// Well-known placeholder passwords we refuse to expose. Also used to detect an
/// already-bootstrapped weak admin from its stored hash.
const WEAK_PASSWORDS: &[&str] = &[
    "admin",
    "admin123",
    "password",
    "password123",
    "secret",
    "change-me",
    "changeme",
    "changeme123",
    "changethis",
    "root",
    "test",
    "letmein",
    "qwerty",
    "123456",
];

/// A password too weak to expose on a public bind: empty, too short, or a known
/// placeholder.
fn is_weak_password(pw: &str) -> bool {
    pw.len() < 8 || WEAK_PASSWORDS.iter().any(|w| pw.eq_ignore_ascii_case(w))
}

pub async fn find_user(pool: &SqlitePool, id: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn find_user_by_name(pool: &SqlitePool, name: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(name)
        .fetch_optional(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_password_detection() {
        // Placeholders (case-insensitive) and too-short/empty are weak.
        for w in ["admin", "ADMIN", "secret", "change-me", "changethis", "123456", "", "short7"] {
            assert!(is_weak_password(w), "{w:?} should be weak");
        }
        // A long, non-placeholder secret is fine.
        for ok in ["a-strong-unique-pass", "Xk9$2mQ!vz7Lp", "correct horse battery staple"] {
            assert!(!is_weak_password(ok), "{ok:?} should be accepted");
        }
    }

    fn cfg(bind: &str) -> Config {
        Config {
            bind: bind.into(),
            data_dir: String::new(),
            db_path: String::new(),
            blob_dir: String::new(),
            token_secret: "t".into(),
            token_ttl_secs: 3600,
            admin_user: "admin".into(),
            admin_pass: "unused-here".into(),
            lease_ttl_secs: 90,
            snapshot_keep: 5,
            max_snapshot_bytes: 1024,
            trust_proxy: false,
        }
    }

    async fn mem_pool() -> SqlitePool {
        // max_connections(1) so every query hits the same in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    async fn seed_admin(pool: &SqlitePool, password: &str) {
        let hash = auth::hash_password(password).unwrap();
        sqlx::query("INSERT INTO users (id, username, pw_hash, role, created_at) VALUES ('a1','admin',?,'admin','2020-01-01T00:00:00+00:00')")
            .bind(hash)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn exposed_bind_rejects_existing_weak_admin() {
        let pool = mem_pool().await;
        seed_admin(&pool, "admin").await; // the classic default
        // Network-facing bind + an admin still on a default password → refuse.
        assert!(bootstrap_admin(&pool, &cfg("0.0.0.0:8080")).await.is_err());
        // Same DB on a loopback bind is tolerated (local-only exposure).
        assert!(bootstrap_admin(&pool, &cfg("127.0.0.1:8080")).await.is_ok());
    }

    #[tokio::test]
    async fn exposed_bind_accepts_strong_admin() {
        let pool = mem_pool().await;
        seed_admin(&pool, "a-strong-unique-password").await;
        // A changed-to-strong admin passes even on an exposed bind.
        assert!(bootstrap_admin(&pool, &cfg("0.0.0.0:8080")).await.is_ok());
    }
}
