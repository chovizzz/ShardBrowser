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
    if count > 0 {
        return Ok(());
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
    Ok(())
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
