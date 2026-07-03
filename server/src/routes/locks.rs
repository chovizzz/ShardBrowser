//! Exclusive checkout locks + snapshot upload/download (Phase 2).
//!
//! Flow: `checkout` acquires a leased lock and returns a per-session
//! `lock_token` plus the latest snapshot to pull; the client renews with
//! `lease` while the browser runs; `checkin` uploads the new snapshot and
//! releases the lock; `release` discards and unlocks. Every lock operation
//! must present the token, so a stale session (crash, expired lease, lock
//! reclaimed by someone else) can no longer touch the environment.
//! `force-unlock` (admin) clears a stuck lock.

use axum::extract::{Multipart, Path, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use crate::audit;
use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{ClientReq, Lock, Snapshot};
use crate::routes::envs::{load_accessible, Perm};
use crate::state::AppState;
use crate::{blob, util};

fn client_id(body: &Option<Json<ClientReq>>) -> String {
    body.as_ref()
        .and_then(|b| b.0.client_id.clone())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "default".to_string())
}

fn lock_token(body: &Option<Json<ClientReq>>) -> String {
    body.as_ref()
        .and_then(|b| b.0.lock_token.clone())
        .unwrap_or_default()
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
///
/// The grab is a single conditional upsert — atomic on its own, no read-then-
/// write window: it only succeeds when the slot is free, already ours (same
/// user+client, token rotates), or the existing lease has expired.
pub async fn checkout(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ClientReq>>,
) -> Result<Json<Value>, AppError> {
    let client = client_id(&body);
    let env = load_accessible(&app, &user, &id, Perm::Use).await?;

    // Snapshot of the previous holder, only for the 409 message / takeover
    // flag; the upsert condition below is the actual arbiter.
    let prev = load_lock(&app, &id).await?;

    let now = util::now_rfc3339();
    let expires = util::rfc3339_in(app.cfg.lease_ttl_secs);
    let token = util::new_id();
    let res = sqlx::query(
        "INSERT INTO locks (env_id, owner_user_id, owner_client_id, lock_token, acquired_at, lease_expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(env_id) DO UPDATE SET owner_user_id=excluded.owner_user_id, \
           owner_client_id=excluded.owner_client_id, lock_token=excluded.lock_token, \
           acquired_at=excluded.acquired_at, lease_expires_at=excluded.lease_expires_at \
         WHERE (locks.owner_user_id = excluded.owner_user_id AND locks.owner_client_id = excluded.owner_client_id) \
            OR locks.lease_expires_at <= ?5",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&client)
    .bind(&token)
    .bind(&now)
    .bind(&expires)
    .execute(&app.db)
    .await?;

    if res.rows_affected() == 0 {
        let owner = match &prev {
            Some(l) => sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = ?")
                .bind(&l.owner_user_id)
                .fetch_optional(&app.db)
                .await?
                .unwrap_or_else(|| "another user".into()),
            None => "another user".into(),
        };
        let until = prev.as_ref().map(|l| l.lease_expires_at.clone()).unwrap_or_default();
        return Err(AppError::Conflict(format!(
            "environment is in use by {owner} (lease until {until})"
        )));
    }

    // We won the slot. If someone else's expired lease was sitting there, the
    // previous session may hold un-pushed local changes — surface that to the
    // caller and the audit trail instead of silently swallowing it.
    let stale_takeover = prev
        .as_ref()
        .map(|l| l.owner_user_id != user.id || l.owner_client_id != client)
        .unwrap_or(false);
    if stale_takeover {
        let prev_owner = prev.as_ref().map(|l| l.owner_user_id.clone()).unwrap_or_default();
        audit::log(
            &app.db,
            Some(&user.id),
            "checkout_stale_takeover",
            Some(&id),
            &format!("previous owner {prev_owner} (lease expired)"),
        )
        .await;
    } else {
        audit::log(&app.db, Some(&user.id), "checkout", Some(&id), &client).await;
    }

    let mut resp = json!({
        "env_id": id,
        "client_id": client,
        "lock_token": token,
        "lease_expires_at": expires,
        "version": env.current_version,
        "snapshot_url": snapshot_url(&id, env.current_version),
        "stale_takeover": stale_takeover,
    });
    if stale_takeover {
        if let Some(l) = &prev {
            let prev_owner =
                sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = ?")
                    .bind(&l.owner_user_id)
                    .fetch_optional(&app.db)
                    .await?;
            resp["previous_owner"] = json!(prev_owner);
        }
    }
    Ok(Json(resp))
}

/// Renew the lease. Must present the current session's lock_token.
pub async fn lease(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ClientReq>>,
) -> Result<Json<Value>, AppError> {
    let client = client_id(&body);
    let token = lock_token(&body);
    let _ = load_accessible(&app, &user, &id, Perm::Use).await?; // ACL revocation ends the session
    let expires = util::rfc3339_in(app.cfg.lease_ttl_secs);
    let res = sqlx::query(
        "UPDATE locks SET lease_expires_at = ? \
         WHERE env_id = ? AND owner_user_id = ? AND owner_client_id = ? AND lock_token = ?",
    )
    .bind(&expires)
    .bind(&id)
    .bind(&user.id)
    .bind(&client)
    .bind(&token)
    .execute(&app.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "you no longer hold this lock (expired, taken over, or bad token)".into(),
        ));
    }
    Ok(Json(json!({ "env_id": id, "lease_expires_at": expires })))
}

/// Upload a new snapshot (multipart: optional `client_id` + `lock_token`
/// text parts, then the `snapshot` file) and release the lock. Requires the
/// checkout session's lock_token — there is no admin bypass; recovery is
/// force-unlock + a fresh checkout.
pub async fn checkin(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let mut client = "default".to_string();
    let mut token = String::new();
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
            Some("lock_token") => {
                if let Ok(v) = field.text().await {
                    token = v;
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

    let _ = load_accessible(&app, &user, &id, Perm::Use).await?;

    // Stage the bytes under a unique temp name first; the final versioned
    // path exists only after the transaction below has settled the version.
    let (temp_path, size, sha) = blob::store_temp(&app.cfg, &id, &bytes).await?;

    let result: Result<(i64, String), AppError> = async {
        let mut tx = app.db.begin().await?;
        // The conditional DELETE is the atomic owner check: it removes the
        // lock only if this session still holds it. A reclaimed or replaced
        // lock (different token) makes this a no-op → conflict.
        let del = sqlx::query(
            "DELETE FROM locks WHERE env_id = ? AND owner_user_id = ? AND owner_client_id = ? AND lock_token = ?",
        )
        .bind(&id)
        .bind(&user.id)
        .bind(&client)
        .bind(&token)
        .execute(&mut *tx)
        .await?;
        if del.rows_affected() != 1 {
            tx.rollback().await?;
            return Err(AppError::Conflict(
                "you no longer hold this lock (expired, taken over, or bad token)".into(),
            ));
        }
        let cur: i64 =
            sqlx::query_scalar("SELECT current_version FROM environments WHERE id = ?")
                .bind(&id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(AppError::NotFound)?;
        let version = cur + 1;
        let final_path = blob::promote(&app.cfg, &id, version, &temp_path)
            .await
            .map_err(AppError::from)?;
        let now = util::now_rfc3339();
        sqlx::query(
            "INSERT INTO snapshots (env_id, version, blob_path, sha256, size, created_by, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(version)
        .bind(&final_path)
        .bind(&sha)
        .bind(size)
        .bind(&user.id)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE environments SET current_version = ?, updated_by = ?, updated_at = ? WHERE id = ?",
        )
        .bind(version)
        .bind(&user.id)
        .bind(&now)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((version, final_path))
    }
    .await;

    let (version, _final_path) = match result {
        Ok(v) => v,
        Err(e) => {
            // Remove the staged temp file. If the failure hit after the
            // rename, the orphaned `<version>.blob` is harmless: the version
            // was never committed, so the next successful checkin computes
            // the same number and the rename overwrites it.
            blob::remove(&temp_path).await;
            return Err(e);
        }
    };

    gc_snapshots(&app, &id, version).await;
    audit::log(&app.db, Some(&user.id), "checkin", Some(&id), &format!("v{version}")).await;
    Ok(Json(json!({
        "env_id": id,
        "version": version,
        "size": size,
        "sha256": sha,
    })))
}

/// Release the lock without uploading (discard local changes). Requires the
/// session's lock_token; admins use force-unlock instead.
pub async fn release(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    body: Option<Json<ClientReq>>,
) -> Result<Json<Value>, AppError> {
    let client = client_id(&body);
    let token = lock_token(&body);
    let res = sqlx::query(
        "DELETE FROM locks WHERE env_id = ? AND owner_user_id = ? AND owner_client_id = ? AND lock_token = ?",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&client)
    .bind(&token)
    .execute(&app.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "you no longer hold this lock (expired, taken over, or bad token)".into(),
        ));
    }
    audit::log(&app.db, Some(&user.id), "release", Some(&id), &client).await;
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
    audit::log(&app.db, Some(&user.id), "force_unlock", Some(&id), "").await;
    Ok(Json(json!({ "unlocked": true, "env_id": id })))
}

/// Current lock status (who holds it, whether the lease is stale).
pub async fn status(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let _ = load_accessible(&app, &user, &id, Perm::Use).await?;
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

/// Download a snapshot blob (raw bytes). Snapshots carry the environment's
/// full login state (portable plaintext cookies), so downloads are limited to
/// the session that currently holds the checkout lock — or an admin.
pub async fn download(
    State(app): State<AppState>,
    user: AuthUser,
    Path((id, version)): Path<(String, i64)>,
) -> Result<impl IntoResponse, AppError> {
    let _ = load_accessible(&app, &user, &id, Perm::Use).await?;
    if !user.is_admin() {
        let holds = load_lock(&app, &id)
            .await?
            .map(|l| l.owner_user_id == user.id)
            .unwrap_or(false);
        if !holds {
            return Err(AppError::Conflict(
                "snapshot download requires holding the checkout lock".into(),
            ));
        }
    }
    let snap = sqlx::query_as::<_, Snapshot>(
        "SELECT * FROM snapshots WHERE env_id = ? AND version = ?",
    )
    .bind(&id)
    .bind(version)
    .fetch_optional(&app.db)
    .await?
    .ok_or(AppError::NotFound)?;
    let bytes = blob::read(&snap.blob_path).await.map_err(AppError::from)?;
    audit::log(&app.db, Some(&user.id), "snapshot_download", Some(&id), &format!("v{version}")).await;
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
