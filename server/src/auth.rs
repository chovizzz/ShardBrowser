use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::{async_trait, Json};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::extract::AppJson;
use crate::db;
use crate::error::AppError;
use crate::models::LoginReq;
use crate::state::AppState;

// ---- password hashing (argon2) ----

pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(format!("hash: {e}")))
}

pub fn verify_password(password: &str, hash: &str) -> Result<(), AppError> {
    let parsed = PasswordHash::new(hash).map_err(|_| AppError::Internal("bad hash".into()))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AppError::Unauthorized)
}

/// Argon2 is CPU-heavy by design; run every hash/verify under the shared login
/// throttle (bounds concurrency → 429 when saturated) and on the blocking pool
/// (so it never ties up an async worker). Every password-touching route MUST go
/// through these, not the sync `hash_password`/`verify_password` directly.
pub async fn verify_slot(app: &AppState, password: String, hash: String) -> Result<bool, AppError> {
    let _slot = app.login_throttle.try_verify_slot().ok_or(AppError::TooManyRequests(1))?;
    tokio::task::spawn_blocking(move || verify_password(&password, &hash).is_ok())
        .await
        .map_err(|e| AppError::Internal(format!("verify task: {e}")))
}

pub async fn hash_slot(app: &AppState, password: String) -> Result<String, AppError> {
    let _slot = app.login_throttle.try_verify_slot().ok_or(AppError::TooManyRequests(1))?;
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| AppError::Internal(format!("hash task: {e}")))?
}

// ---- JWT (HS256) ----

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: i64,
    /// users.token_version at issue time; a password change bumps the column
    /// so every previously-issued token stops verifying.
    #[serde(default)]
    pub ver: i64,
}

pub fn issue(
    secret: &str,
    user_id: &str,
    role: &str,
    token_version: i64,
    ttl_secs: i64,
) -> Result<String, AppError> {
    let exp = chrono::Utc::now().timestamp() + ttl_secs;
    let claims = Claims { sub: user_id.into(), role: role.into(), exp, ver: token_version };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("jwt: {e}")))
}

pub fn verify(secret: &str, token: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|d| d.claims)
    .map_err(|_| AppError::Unauthorized)
}

// ---- authenticated-user extractor ----

/// Pulled from the `Authorization: Bearer <jwt>` header. The role is re-read
/// from the DB on every request (not trusted from the token) so a demotion or
/// deletion takes effect immediately rather than at token expiry.
pub struct AuthUser {
    pub id: String,
    pub username: String,
    pub role: String,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
    pub fn require_admin(&self) -> Result<(), AppError> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or(AppError::Unauthorized)?;
        let token = header.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)?;
        let claims = verify(&app.cfg.token_secret, token)?;
        let user = db::find_user(&app.db, &claims.sub)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if claims.ver != user.token_version {
            return Err(AppError::Unauthorized); // password changed since issue
        }
        Ok(AuthUser {
            id: user.id,
            username: user.username,
            role: user.role,
        })
    }
}

// ---- handlers ----

/// Resolve the client IP for throttling. Trusts `X-Forwarded-For` / `X-Real-IP`
/// only when `SHARDX_TRUST_PROXY=1` (i.e. behind an edge proxy that OVERWRITES
/// the inbound header) — otherwise a client could spoof it to dodge the per-IP
/// limit. The header value must parse as an IP or it's ignored.
fn client_ip(app: &AppState, headers: &HeaderMap, peer: SocketAddr) -> String {
    if app.cfg.trust_proxy {
        for header in ["x-forwarded-for", "x-real-ip"] {
            if let Some(raw) = headers.get(header).and_then(|v| v.to_str().ok()) {
                let first = raw.split(',').next().unwrap_or("").trim();
                // Return the parsed IP's canonical form so the same address in
                // different text spellings maps to one throttle key.
                if let Ok(addr) = first.parse::<std::net::IpAddr>() {
                    return addr.to_string();
                }
            }
        }
    }
    peer.ip().to_string()
}

pub async fn login(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AppJson(req): AppJson<LoginReq>,
) -> Result<Json<Value>, AppError> {
    let ip = client_ip(&app, &headers, peer);
    // Raw username: accounts are case-sensitive, so a case variant targets a
    // different (usually nonexistent) account, not this one.
    let user_key = req.username.clone();

    // Throttle BEFORE any DB lookup or Argon2, so a locked-out source can't
    // drive brute force. `locked_for` returns the longer of the IP/user waits.
    if let Some(retry) = app.login_throttle.locked_for(&ip, &user_key) {
        return Err(AppError::TooManyRequests(retry));
    }

    let user = match db::find_user_by_name(&app.db, &req.username).await? {
        Some(u) => u,
        None => {
            app.login_throttle.record_failure(&ip, &user_key);
            let detail = format!("{} from {ip}", req.username);
            crate::audit::log(&app.db, None, "login_failed", None, &detail).await;
            return Err(AppError::Unauthorized);
        }
    };

    // Throttled + off-runtime Argon2 (see `verify_slot`): bounds a concurrent
    // first wave that all passed `locked_for` before any was recorded.
    let verified = verify_slot(&app, req.password.clone(), user.pw_hash.clone()).await?;
    if !verified {
        app.login_throttle.record_failure(&ip, &user_key);
        let detail = format!("{} from {ip}", user.username);
        crate::audit::log(&app.db, Some(&user.id), "login_failed", None, &detail).await;
        return Err(AppError::Unauthorized);
    }
    // Success clears the failure history for this IP + account.
    app.login_throttle.record_success(&ip, &user_key);
    let token = issue(
        &app.cfg.token_secret,
        &user.id,
        &user.role,
        user.token_version,
        app.cfg.token_ttl_secs,
    )?;
    Ok(Json(
        json!({ "token": token, "role": user.role, "user_id": user.id }),
    ))
}

pub async fn me(user: AuthUser) -> Json<Value> {
    Json(json!({ "id": user.id, "username": user.username, "role": user.role }))
}

/// Self-service password change; requires the current password. Bumps
/// token_version (invalidating every outstanding token) and returns a fresh
/// token so the caller stays logged in.
pub async fn change_password(
    State(app): State<AppState>,
    user: AuthUser,
    AppJson(req): AppJson<crate::models::ChangePasswordReq>,
) -> Result<Json<Value>, AppError> {
    if req.new_password.is_empty() {
        return Err(AppError::BadRequest("new password required".into()));
    }
    let row = db::find_user(&app.db, &user.id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !verify_slot(&app, req.old_password, row.pw_hash.clone()).await? {
        return Err(AppError::Unauthorized);
    }
    let hash = hash_slot(&app, req.new_password).await?;
    sqlx::query("UPDATE users SET pw_hash = ?, token_version = token_version + 1 WHERE id = ?")
        .bind(&hash)
        .bind(&user.id)
        .execute(&app.db)
        .await?;
    crate::audit::log(&app.db, Some(&user.id), "password_change", None, &user.username).await;
    let token = issue(
        &app.cfg.token_secret,
        &user.id,
        &user.role,
        row.token_version + 1,
        app.cfg.token_ttl_secs,
    )?;
    Ok(Json(json!({ "changed": true, "token": token })))
}
