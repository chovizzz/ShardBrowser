//! Opaque snapshot blob storage on the local filesystem.
//!
//! The server is content-agnostic: the launcher packs the environment's
//! user-data-dir into a `tar.zst` (excluding cache) and uploads the bytes;
//! the server just persists them, records sha256 + size, and serves them back.

use std::path::PathBuf;

use crate::config::Config;

fn env_dir(cfg: &Config, env_id: &str) -> PathBuf {
    PathBuf::from(&cfg.blob_dir).join(env_id)
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

pub async fn read(path: &str) -> anyhow::Result<Vec<u8>> {
    Ok(tokio::fs::read(path).await?)
}

pub async fn remove(path: &str) {
    let _ = tokio::fs::remove_file(path).await;
}
