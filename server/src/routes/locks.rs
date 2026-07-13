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
use sha2::{Digest, Sha256};

use crate::audit;
use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{ClientReq, Lock, Snapshot};
use crate::routes::envs::{load_accessible, Perm};
use crate::state::AppState;
use crate::{blob, util};

fn client_id(body: &Option<ClientReq>) -> String {
    body.as_ref()
        .and_then(|b| b.client_id.clone())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "default".to_string())
}

fn lock_token(body: &Option<ClientReq>) -> String {
    body.as_ref()
        .and_then(|b| b.lock_token.clone())
        .unwrap_or_default()
}

/// Read a request header as an owned string (empty when absent / non-ASCII).
/// Used by GET routes that can't carry a JSON body (snapshot download).
fn header_str(headers: &axum::http::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn load_lock(app: &AppState, env_id: &str) -> Result<Option<Lock>, AppError> {
    Ok(
        sqlx::query_as::<_, Lock>("SELECT * FROM locks WHERE env_id = ?")
            .bind(env_id)
            .fetch_optional(&app.db)
            .await?,
    )
}

/// Non-atomic check that this exact session (user + client + non-empty token)
/// currently owns the lock. Used to reject a request before reading an upload
/// body; the operation's own conditional SQL remains the atomic authority.
async fn session_holds_lock(
    app: &AppState,
    env_id: &str,
    user_id: &str,
    client_id: &str,
    token: &str,
) -> Result<bool, AppError> {
    if token.is_empty() {
        return Ok(false);
    }
    let hit: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM locks WHERE env_id = ? AND owner_user_id = ? \
         AND owner_client_id = ? AND lock_token = ?",
    )
    .bind(env_id)
    .bind(user_id)
    .bind(client_id)
    .bind(token)
    .fetch_optional(&app.db)
    .await?;
    Ok(hit.is_some())
}

/// Stream the multipart `snapshot` field to `temp`, hashing and enforcing the
/// size cap incrementally so the whole upload is never buffered in memory.
/// Returns (size bytes, sha256 hex). Non-`snapshot` fields are ignored — the
/// session identity travels in headers now.
async fn stream_snapshot(
    multipart: &mut Multipart,
    temp: &std::path::Path,
    max: usize,
) -> Result<(i64, String), AppError> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(temp)
        .await
        .map_err(|e| AppError::Internal(format!("open temp: {e}")))?;
    let mut hasher = Sha256::new();
    let mut size: usize = 0;
    let mut got = false;
    // Idle timeout per read: a stalled connection must not pin its upload slot
    // until the socket dies (which would let a few stalls block all checkins).
    const IDLE: std::time::Duration = std::time::Duration::from_secs(30);
    let stalled = || AppError::BadRequest("upload stalled".into());
    while let Some(mut field) = tokio::time::timeout(IDLE, multipart.next_field())
        .await
        .map_err(|_| stalled())?
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        // The multipart body now carries exactly the `snapshot` part (identity
        // moved to headers); ignore anything else rather than guessing.
        if field.name() != Some("snapshot") {
            continue;
        }
        while let Some(chunk) = tokio::time::timeout(IDLE, field.chunk())
            .await
            .map_err(|_| stalled())?
            .map_err(|e| AppError::BadRequest(format!("read snapshot: {e}")))?
        {
            size += chunk.len();
            if size > max {
                return Err(AppError::BadRequest("snapshot exceeds size limit".into()));
            }
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|e| AppError::Internal(format!("write snapshot: {e}")))?;
        }
        got = true;
    }
    file.flush()
        .await
        .map_err(|e| AppError::Internal(format!("flush snapshot: {e}")))?;
    if !got {
        return Err(AppError::BadRequest("missing `snapshot` field".into()));
    }
    Ok((size as i64, format!("{:x}", hasher.finalize())))
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
    crate::extract::AppJsonOpt(body): crate::extract::AppJsonOpt<ClientReq>,
) -> Result<Json<Value>, AppError> {
    let client = client_id(&body);
    let presented = lock_token(&body);
    // Enforce access; the version is re-read after the lock is acquired below.
    load_accessible(&app, &user, &id, Perm::Use).await?;

    // Snapshot of the previous holder, only for the 409 message / takeover
    // flag; the upsert condition below is the actual arbiter.
    let prev = load_lock(&app, &id).await?;

    let now = util::now_rfc3339();
    let expires = util::rfc3339_in(app.cfg.lease_ttl_secs);
    let token = util::new_id();
    // Reclaim a LIVE lock only if the caller proves possession of its current
    // token — otherwise a second JWT for the same user could learn the (exposed)
    // client_id, re-checkout, mint a fresh token, and both steal the lock and
    // bypass the download check. A free slot (INSERT) or an expired lease still
    // needs no token. `?7 <> ''` also rejects empty/legacy-migrated tokens.
    let res = sqlx::query(
        "INSERT INTO locks (env_id, owner_user_id, owner_client_id, lock_token, acquired_at, lease_expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(env_id) DO UPDATE SET owner_user_id=excluded.owner_user_id, \
           owner_client_id=excluded.owner_client_id, lock_token=excluded.lock_token, \
           acquired_at=excluded.acquired_at, lease_expires_at=excluded.lease_expires_at \
         WHERE (locks.owner_user_id = excluded.owner_user_id \
                AND locks.owner_client_id = excluded.owner_client_id \
                AND locks.lock_token = ?7 AND ?7 <> '') \
            OR locks.lease_expires_at <= ?5",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&client)
    .bind(&token)
    .bind(&now)
    .bind(&expires)
    .bind(&presented)
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

    // Re-read the version now that the lock is OURS — no concurrent checkin can
    // move it anymore. A checkin that committed between `load_accessible` above
    // and this upsert would otherwise hand us a stale version + snapshot_url, and
    // our own next checkin would clobber that work.
    let current_version: i64 =
        sqlx::query_scalar("SELECT current_version FROM environments WHERE id = ?")
            .bind(&id)
            .fetch_one(&app.db)
            .await?;

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
        "lease_ttl_secs": app.cfg.lease_ttl_secs,
        "version": current_version,
        "snapshot_url": snapshot_url(&id, current_version),
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
    crate::extract::AppJsonOpt(body): crate::extract::AppJsonOpt<ClientReq>,
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
    Ok(Json(json!({
        "env_id": id,
        "lease_expires_at": expires,
        "lease_ttl_secs": app.cfg.lease_ttl_secs,
    })))
}

/// Upload a new snapshot and release the lock. The session identity
/// (`x-client-id` + `x-lock-token` headers) is checked BEFORE the body is read,
/// and the `snapshot` multipart part is streamed to disk — an authenticated
/// non-holder can't make us buffer a large upload. Requires the checkout
/// session's lock_token; there is no admin bypass (recovery is force-unlock +
/// a fresh checkout).
pub async fn checkin(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    // Identity comes from headers, not multipart body parts, so we can authorize
    // BEFORE touching the (up to max_snapshot_bytes) upload — an authenticated
    // non-holder must never make us buffer or stream a large snapshot.
    let client = {
        let c = header_str(&headers, "x-client-id");
        if c.trim().is_empty() { "default".to_string() } else { c }
    };
    let token = header_str(&headers, "x-lock-token");

    let _ = load_accessible(&app, &user, &id, Perm::Use).await?;

    // Fast-fail lock pre-check (the atomic conditional DELETE below is still the
    // authority). An empty token can never match.
    if token.is_empty() || !session_holds_lock(&app, &id, &user.id, &client, &token).await? {
        return Err(AppError::Conflict(
            "you no longer hold this lock (expired, taken over, or bad token)".into(),
        ));
    }

    // Bound concurrent uploads so a burst of lock holders can't saturate disk /
    // bandwidth. The slot covers only receiving+writing the body; it's released
    // before the (cheap) commit (a rename + DB writes). The client retries on 429
    // (its exit-checkin degrades to a recoverable pending push).
    let upload = app
        .upload_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::TooManyRequests(2))?;

    // Stream the snapshot straight to a temp file — hashing and enforcing the
    // size cap incrementally, never buffering the whole thing in memory. The
    // final versioned path exists only after the transaction settles the version.
    let temp = blob::new_temp(&app.cfg, &id).await?;
    let temp_path = temp.to_string_lossy().into_owned();
    let (size, sha) = match stream_snapshot(&mut multipart, &temp, app.cfg.max_snapshot_bytes).await
    {
        Ok(v) => v,
        Err(e) => {
            blob::remove(&temp_path).await;
            return Err(e);
        }
    };
    drop(upload); // upload received; free the slot before the DB transaction

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
    crate::extract::AppJsonOpt(body): crate::extract::AppJsonOpt<ClientReq>,
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
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let _ = load_accessible(&app, &user, &id, Perm::Use).await?;
    if !user.is_admin() {
        // Require the exact current checkout session — the owner's `client_id`
        // AND `lock_token`, presented as headers — not merely the same user. A
        // second/stale token of the owner must not be able to pull the snapshot
        // (which carries plaintext cookies + payment secrets) out from under the
        // live session, or after the lock has moved on.
        let client_id = header_str(&headers, "x-client-id");
        let lock_token = header_str(&headers, "x-lock-token");
        if !session_holds_lock(&app, &id, &user.id, &client_id, &lock_token).await? {
            return Err(AppError::Conflict(
                "snapshot download requires the current checkout's client_id + lock_token".into(),
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
    // Bound concurrent downloads (each streams a full snapshot: disk reads +
    // bandwidth) the same way checkin bounds uploads. The permit is moved into
    // the response body below, so it's held for the whole transfer and released
    // when the stream is exhausted or the client disconnects.
    let permit = app
        .download_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::TooManyRequests(2))?;
    // Stream straight from disk instead of buffering the whole blob in memory.
    let file = blob::open(&snap.blob_path).await.map_err(AppError::from)?;
    // Defense-in-depth: the advertised Content-Length is the size recorded at
    // checkin. If the on-disk blob no longer matches (corruption, external
    // tampering), a mismatched length would hang or truncate the client — fail
    // loudly instead of streaming a body that contradicts its header.
    let actual = file
        .metadata()
        .await
        .map_err(|e| AppError::from(anyhow::Error::new(e)))?
        .len();
    if actual != snap.size as u64 {
        return Err(AppError::Internal(format!(
            "snapshot blob size mismatch for env {id} v{version}: recorded {}, on disk {actual}",
            snap.size
        )));
    }
    let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(GuardedReader {
        inner: file,
        _permit: permit,
    }));
    // Distinguish an admin break-glass download (bypasses the lock check) from a
    // normal lock-holder pull, and record who currently holds the lock.
    let detail = if user.is_admin() {
        let holder = load_lock(&app, &id)
            .await
            .ok()
            .flatten()
            .map(|l| format!("{}/{}", l.owner_user_id, l.owner_client_id))
            .unwrap_or_else(|| "none".into());
        format!("v{version} admin_bypass=true lock_holder={holder}")
    } else {
        format!("v{version}")
    };
    audit::log(&app.db, Some(&user.id), "snapshot_download", Some(&id), &detail).await;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, snap.size.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{id}-v{version}.tar.zst\""),
            ),
            ("x-snapshot-sha256".parse().unwrap(), snap.sha256),
        ],
        body,
    ))
}

/// A blob reader that owns a download slot for the whole streamed response, so
/// the concurrency bound covers the entire transfer — not just the handler call.
/// Reads delegate to the inner file; the permit drops with the reader when the
/// stream ends or the client disconnects.
struct GuardedReader {
    inner: tokio::fs::File,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl tokio::io::AsyncRead for GuardedReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
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
    // Delete the ROWS first, then the blob files. A crash between the two leaves
    // orphan blobs (no row), which the orphan GC reclaims — recoverable. The
    // reverse order would leave rows pointing at missing blobs, which download
    // can't heal and would surface as a hard error. If the row delete fails we
    // skip the blob removal entirely rather than orphan a row's data.
    if sqlx::query("DELETE FROM snapshots WHERE env_id = ? AND version <= ?")
        .bind(env_id)
        .bind(cutoff)
        .execute(&app.db)
        .await
        .is_err()
    {
        return;
    }
    for s in &stale {
        blob::remove(&s.blob_path).await;
    }
}
