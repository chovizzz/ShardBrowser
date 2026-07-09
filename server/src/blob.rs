//! Opaque snapshot blob storage on the local filesystem.
//!
//! The server is content-agnostic: the launcher packs the environment's
//! user-data-dir into a `tar.zst` (excluding cache) and uploads the bytes;
//! the server just persists them, records sha256 + size, and serves them back.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::config::Config;

fn env_dir(cfg: &Config, env_id: &str) -> PathBuf {
    PathBuf::from(&cfg.blob_dir).join(env_id)
}

/// Startup sweep of blob storage: delete `<version>.blob` files no snapshot row
/// references, plus any leftover `incoming-*.tmp` staging files. These orphans
/// accumulate when a checkin crashes between promote and DB commit, or is
/// cancelled mid-upload. Best-effort (logs a count); safe at startup because no
/// checkin is in flight yet.
pub async fn gc_orphans(cfg: &Config, db: &sqlx::SqlitePool) {
    // Referenced (env_id, version) pairs — compared by identity, not by path
    // string, so a changed `SHARDX_DATA_DIR` spelling / symlink can't make a live
    // blob look orphaned. FAIL CLOSED: if the DB read fails, skip blob GC rather
    // than treat every blob as an orphan and delete it.
    let referenced: HashSet<(String, i64)> =
        match sqlx::query_as::<_, (String, i64)>("SELECT env_id, version FROM snapshots")
            .fetch_all(db)
            .await
        {
            Ok(rows) => rows.into_iter().collect(),
            Err(e) => {
                tracing::warn!("blob GC skipped (cannot read snapshots: {e})");
                return;
            }
        };

    let mut env_dirs = match tokio::fs::read_dir(Path::new(&cfg.blob_dir)).await {
        Ok(d) => d,
        Err(_) => return, // no blob dir yet
    };
    let (mut temps, mut orphans) = (0u64, 0u64);
    while let Ok(Some(env)) = env_dirs.next_entry().await {
        let env_path = env.path();
        if !env_path.is_dir() {
            continue;
        }
        let env_id = env.file_name().to_string_lossy().into_owned();
        let Ok(mut files) = tokio::fs::read_dir(&env_path).await else { continue };
        while let Ok(Some(f)) = files.next_entry().await {
            let name = f.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("incoming-") && name.ends_with(".tmp") {
                if tokio::fs::remove_file(f.path()).await.is_ok() {
                    temps += 1;
                }
            } else if let Some(ver) = name.strip_suffix(".blob").and_then(|s| s.parse::<i64>().ok()) {
                // Only a well-formed `<version>.blob` with no referencing row is
                // an orphan; anything else is left untouched.
                if !referenced.contains(&(env_id.clone(), ver))
                    && tokio::fs::remove_file(f.path()).await.is_ok()
                {
                    orphans += 1;
                }
            }
        }
    }
    if temps + orphans > 0 {
        tracing::info!("blob GC: removed {temps} stale temp + {orphans} orphan blob file(s)");
    }
}

/// Create the env's blob dir and return a fresh unique temp path to stream an
/// incoming snapshot into. The caller streams bytes to it (hashing + enforcing
/// the size cap as it goes), then [`promote`]s it once the version is settled —
/// so two concurrent checkins never overwrite each other's bytes — or
/// [`remove`]s it on failure.
pub async fn new_temp(cfg: &Config, env_id: &str) -> anyhow::Result<PathBuf> {
    let dir = env_dir(cfg, env_id);
    tokio::fs::create_dir_all(&dir).await?;
    Ok(dir.join(format!("incoming-{}.tmp", uuid::Uuid::new_v4())))
}

/// Move a temp blob to its final versioned path; returns the final path.
/// Any orphan at the target (a prior checkin that failed after promote but
/// before commit) is removed first — `rename` onto an existing file errors on
/// Windows.
pub async fn promote(cfg: &Config, env_id: &str, version: i64, temp_path: &str) -> anyhow::Result<String> {
    let path = env_dir(cfg, env_id).join(format!("{version}.blob"));
    let _ = tokio::fs::remove_file(&path).await;
    tokio::fs::rename(temp_path, &path).await?;
    Ok(path.to_string_lossy().into_owned())
}

/// Open a blob for streaming (download path). The caller streams it to the
/// response body rather than buffering the whole snapshot in memory.
pub async fn open(path: &str) -> anyhow::Result<tokio::fs::File> {
    Ok(tokio::fs::File::open(path).await?)
}

pub async fn remove(path: &str) {
    let _ = tokio::fs::remove_file(path).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(blob_dir: &str) -> Config {
        Config {
            bind: String::new(),
            data_dir: String::new(),
            db_path: String::new(),
            blob_dir: blob_dir.to_string(),
            token_secret: String::new(),
            token_ttl_secs: 0,
            admin_user: String::new(),
            admin_pass: String::new(),
            lease_ttl_secs: 90,
            snapshot_keep: 5,
            max_snapshot_bytes: 1024,
            trust_proxy: false,
        }
    }

    #[tokio::test]
    async fn gc_removes_orphans_and_temps_keeps_referenced() {
        let base = std::env::temp_dir().join(format!("shardx-blobgc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let blob_dir = base.join("blobs");
        let env = blob_dir.join("env1");
        std::fs::create_dir_all(&env).unwrap();
        let referenced = env.join("1.blob");
        let orphan = env.join("2.blob");
        let temp = env.join("incoming-abc.tmp");
        std::fs::write(&referenced, b"a").unwrap();
        std::fs::write(&orphan, b"b").unwrap();
        std::fs::write(&temp, b"c").unwrap();

        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(false); // isolate GC from env/user FK setup
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO snapshots (env_id, version, blob_path, sha256, size, created_by, created_at) \
             VALUES ('env1', 1, ?, 'x', 1, 'u', 'now')",
        )
        .bind(referenced.to_string_lossy().as_ref())
        .execute(&pool)
        .await
        .unwrap();

        gc_orphans(&cfg(blob_dir.to_string_lossy().as_ref()), &pool).await;

        assert!(referenced.exists(), "referenced blob kept");
        assert!(!orphan.exists(), "orphan blob removed");
        assert!(!temp.exists(), "stale temp removed");
    }

    #[tokio::test]
    async fn gc_fails_closed_on_db_error() {
        let base = std::env::temp_dir().join(format!("shardx-blobgc-fc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let env = base.join("blobs").join("env1");
        std::fs::create_dir_all(&env).unwrap();
        let blob = env.join("2.blob");
        std::fs::write(&blob, b"keep-me").unwrap();

        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(false);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        // Make the referenced-set query fail.
        sqlx::query("DROP TABLE snapshots").execute(&pool).await.unwrap();

        gc_orphans(&cfg(base.join("blobs").to_string_lossy().as_ref()), &pool).await;
        assert!(blob.exists(), "GC must fail closed on DB error, not delete blobs");
    }
}
