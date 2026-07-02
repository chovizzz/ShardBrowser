//! Exclusive checkout locks + snapshot upload/download (Phase 2).
//!
//! Flow: `checkout` acquires a leased lock and returns the latest snapshot to
//! pull; the client renews with `lease` while the browser runs; `checkin`
//! uploads the new snapshot and releases the lock; `release` discards and
//! unlocks. `force-unlock` (admin) clears a stuck lock.

use axum::extract::{Multipart, Path, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{ClientReq, Lock, Snapshot};
use crate::routes::envs::load_accessible;
use crate::state::AppState;
use crate::{blob, util};

fn client_id(body: Option<Json<ClientReq>>) -> String {
    body.and_then(|b| b.0.client_id)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "default".to_string())
}

async fn load_lock(app: &AppState, env_id: &str) -> Result<Option<Lock>, AppError> {
    Ok(
        sqlx::query_as::<_, Lock>("SELECT * FROM locks WHERE env_id = ?")
            .bind(env_id)
            .fetch_optional(&app.db)
            .await?,
    )
}

fn snapshot_url(env_id: &str, version: i64) -> Option<String> {
    (version > 0).then(|| format!("/envs/{env_id}/snapshot/{version}"))
}

/// Acquire (or reclaim an expired) lock and report the snapshot to pull.
pub async fn checkout(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ClientReq>>,
) -> Result<Json<Value>, AppError> {
    let client = client_id(body);
    let env = load_accessible(&app, &user, &id).await?;

    let mut tx = app.db.begin().await?;
    let existing = sqlx::query_as::<_, Lock>("SELECT * FROM locks WHERE env_id = ?")
        .bind(&id)
        .fetch_optional(&mut *tx)
        .await?;

    if let Some(l) = &existing {
        let mine = l.owner_user_id == user.id && l.owner_client_id == client;
        if !mine && !util::is_past(&l.lease_expires_at) {
            tx.rollback().await?;
            let owner = sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = ?")
                .bind(&l.owner_user_id)
                .fetch_optional(&app.db)
                .await?
                .unwrap_or_else(|| "another user".into());
            return Err(AppError::Conflict(format!(
                "environment is in use by {owner} (lease until {})",
                l.lease_expires_at
            )));
        }
    }

    let now = util::now_rfc3339();
    let expires = util::rfc3339_in(app.cfg.lease_ttl_secs);
    sqlx::query(
        "INSERT INTO locks (env_id, owner_user_id, owner_client_id, acquired_at, lease_expires_at) \
         VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(env_id) DO UPDATE SET owner_user_id=excluded.owner_user_id, \
           owner_client_id=excluded.owner_client_id, acquired_at=excluded.acquired_at, \
           lease_expires_at=excluded.lease_expires_at",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&client)
    .bind(&now)
    .bind(&expires)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    audit(&app, &user.id, "checkout", &id, &client).await;
    Ok(Json(json!({
        "env_id": id,
        "client_id": client,
        "lease_expires_at": expires,
        "version": env.current_version,
        "snapshot_url": snapshot_url(&id, env.current_version),
    })))
}

/// Renew the lease. Must be the current owner (same user + client).
pub async fn lease(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ClientReq>>,
) -> Result<Json<Value>, AppError> {
    let client = client_id(body);
    let lock = load_lock(&app, &id).await?.ok_or(AppError::NotFound)?;
    if lock.owner_user_id != user.id || lock.owner_client_id != client {
        return Err(AppError::Conflict("you do not hold this lock".into()));
    }
    let expires = util::rfc3339_in(app.cfg.lease_ttl_secs);
    sqlx::query("UPDATE locks SET lease_expires_at = ? WHERE env_id = ?")
        .bind(&expires)
        .bind(&id)
        .execute(&app.db)
        .await?;
    Ok(Json(json!({ "env_id": id, "lease_expires_at": expires })))
}

/// Upload a new snapshot (multipart field `snapshot`) and release the lock.
pub async fn checkin(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    // Field order: optional `client_id` text part, then the `snapshot` file.
    let mut client = "default".to_string();
    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        match field.name() {
            Some("client_id") => {
                if let Ok(v) = field.text().await {
                    if !v.trim().is_empty() {
                        client = v;
                    }
                }
            }
            Some("snapshot") | None => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("read snapshot: {e}")))?;
                if data.len() > app.cfg.max_snapshot_bytes {
                    return Err(AppError::BadRequest("snapshot exceeds size limit".into()));
                }
                bytes = Some(data.to_vec());
            }
            _ => {}
        }
    }
    let bytes = bytes.ok_or_else(|| AppError::BadRequest("missing `snapshot` field".into()))?;

    // Must currently hold the lock (admins may check in regardless, to recover).
    let lock = load_lock(&app, &id).await?.ok_or(AppError::Conflict(
        "no active checkout for this environment".into(),
    ))?;
    let mine = lock.owner_user_id == user.id && lock.owner_client_id == client;
    if !mine && !user.is_admin() {
        return Err(AppError::Conflict("you do not hold this lock".into()));
    }

    let env = sqlx::query_as::<_, crate::models::Environment>(
        "SELECT * FROM environments WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&app.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let version = env.current_version + 1;
    let (path, size, sha) = blob::store(&app.cfg, &id, version, &bytes).await?;
    let now = util::now_rfc3339();

    let mut tx = app.db.begin().await?;
    sqlx::query(
        "INSERT INTO snapshots (env_id, version, blob_path, sha256, size, created_by, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(version)
    .bind(&path)
    .bind(&sha)
    .bind(size)
    .bind(&user.id)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE environments SET current_version = ?, updated_by = ?, updated_at = ? WHERE id = ?")
        .bind(version)
        .bind(&user.id)
        .bind(&now)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM locks WHERE env_id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    gc_snapshots(&app, &id, version).await;
    audit(&app, &user.id, "checkin", &id, &format!("v{version}")).await;
    Ok(Json(json!({
        "env_id": id,
        "version": version,
        "size": size,
        "sha256": sha,
    })))
}

/// Release the lock without uploading (discard local changes).
pub async fn release(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ClientReq>>,
) -> Result<Json<Value>, AppError> {
    let client = client_id(body);
    let lock = load_lock(&app, &id).await?.ok_or(AppError::NotFound)?;
    let mine = lock.owner_user_id == user.id && lock.owner_client_id == client;
    if !mine && !user.is_admin() {
        return Err(AppError::Conflict("you do not hold this lock".into()));
    }
    sqlx::query("DELETE FROM locks WHERE env_id = ?")
        .bind(&id)
        .execute(&app.db)
        .await?;
    audit(&app, &user.id, "release", &id, &client).await;
    Ok(Json(json!({ "released": true, "env_id": id })))
}

/// Admin: clear a stuck lock regardless of owner.
pub async fn force_unlock(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    let res = sqlx::query("DELETE FROM locks WHERE env_id = ?")
        .bind(&id)
        .execute(&app.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit(&app, &user.id, "force_unlock", &id, "").await;
    Ok(Json(json!({ "unlocked": true, "env_id": id })))
}

/// Current lock status (who holds it, whether the lease is stale).
pub async fn status(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let _ = load_accessible(&app, &user, &id).await?;
    match load_lock(&app, &id).await? {
        None => Ok(Json(json!({ "locked": false }))),
        Some(l) => {
            let owner = sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = ?")
                .bind(&l.owner_user_id)
                .fetch_optional(&app.db)
                .await?;
            Ok(Json(json!({
                "locked": true,
                "owner_user_id": l.owner_user_id,
                "owner_username": owner,
                "owner_client_id": l.owner_client_id,
                "acquired_at": l.acquired_at,
                "lease_expires_at": l.lease_expires_at,
                "expired": util::is_past(&l.lease_expires_at),
                "held_by_me": l.owner_user_id == user.id,
            })))
        }
    }
}

/// Download a snapshot blob (raw bytes).
pub async fn download(
    State(app): State<AppState>,
    user: AuthUser,
    Path((id, version)): Path<(String, i64)>,
) -> Result<impl IntoResponse, AppError> {
    let _ = load_accessible(&app, &user, &id).await?;
    let snap = sqlx::query_as::<_, Snapshot>(
        "SELECT * FROM snapshots WHERE env_id = ? AND version = ?",
    )
    .bind(&id)
    .bind(version)
    .fetch_optional(&app.db)
    .await?
    .ok_or(AppError::NotFound)?;
    let bytes = blob::read(&snap.blob_path).await.map_err(AppError::from)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{id}-v{version}.tar.zst\""),
            ),
            ("x-snapshot-sha256".parse().unwrap(), snap.sha256),
        ],
        bytes,
    ))
}

/// Drop snapshots older than the retention window, blobs and rows alike.
async fn gc_snapshots(app: &AppState, env_id: &str, current: i64) {
    let cutoff = current - app.cfg.snapshot_keep;
    if cutoff < 1 {
        return;
    }
    let stale = sqlx::query_as::<_, Snapshot>(
        "SELECT * FROM snapshots WHERE env_id = ? AND version <= ?",
    )
    .bind(env_id)
    .bind(cutoff)
    .fetch_all(&app.db)
    .await
    .unwrap_or_default();
    for s in &stale {
        blob::remove(&s.blob_path).await;
    }
    let _ = sqlx::query("DELETE FROM snapshots WHERE env_id = ? AND version <= ?")
        .bind(env_id)
        .bind(cutoff)
        .execute(&app.db)
        .await;
}

async fn audit(app: &AppState, actor: &str, action: &str, env_id: &str, detail: &str) {
    let _ = sqlx::query(
        "INSERT INTO audit_log (actor, action, env_id, detail, at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(actor)
    .bind(action)
    .bind(env_id)
    .bind(detail)
    .bind(util::now_rfc3339())
    .execute(&app.db)
    .await;
}
