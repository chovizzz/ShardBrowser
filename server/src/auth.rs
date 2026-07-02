use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::{async_trait, Json};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

// ---- JWT (HS256) ----

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: i64,
}

pub fn issue(secret: &str, user_id: &str, role: &str, ttl_secs: i64) -> Result<String, AppError> {
    let exp = chrono::Utc::now().timestamp() + ttl_secs;
    let claims = Claims { sub: user_id.into(), role: role.into(), exp };
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
        Ok(AuthUser {
            id: user.id,
            username: user.username,
            role: user.role,
        })
    }
}

// ---- handlers ----

pub async fn login(
    State(app): State<AppState>,
    Json(req): Json<LoginReq>,
) -> Result<Json<Value>, AppError> {
    let user = db::find_user_by_name(&app.db, &req.username)
        .await?
        .ok_or(AppError::Unauthorized)?;
    verify_password(&req.password, &user.pw_hash)?;
    let token = issue(&app.cfg.token_secret, &user.id, &user.role, app.cfg.token_ttl_secs)?;
    Ok(Json(
        json!({ "token": token, "role": user.role, "user_id": user.id }),
    ))
}

pub async fn me(user: AuthUser) -> Json<Value> {
    Json(json!({ "id": user.id, "username": user.username, "role": user.role }))
}
