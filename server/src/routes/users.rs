use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use crate::auth::{self, AuthUser};
use crate::audit;
use crate::error::AppError;
use crate::models::{CreateUserReq, ResetPasswordReq, SetRoleReq, User};
use crate::state::AppState;
use crate::util;

pub async fn list(
    State(app): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<User>>, AppError> {
    user.require_admin()?;
    let rows = sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at")
        .fetch_all(&app.db)
        .await?;
    Ok(Json(rows))
}

pub async fn create(
    State(app): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateUserReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    let role = match req.role.as_deref() {
        None | Some("member") => "member",
        Some("admin") => "admin",
        Some(other) => return Err(AppError::BadRequest(format!("invalid role: {other}"))),
    };
    if req.username.trim().is_empty() || req.password.is_empty() {
        return Err(AppError::BadRequest("username and password required".into()));
    }
    let hash = auth::hash_password(&req.password)?;
    let id = util::new_id();
    let res = sqlx::query(
        "INSERT INTO users (id, username, pw_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.username)
    .bind(hash)
    .bind(role)
    .bind(util::now_rfc3339())
    .execute(&app.db)
    .await;
    match res {
        Ok(_) => {
            audit::log(&app.db, Some(&user.id), "user_create", None, &format!("{} ({role})", req.username)).await;
            Ok(Json(json!({ "id": id, "username": req.username, "role": role })))
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            Err(AppError::Conflict("username already exists".into()))
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn delete(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    if id == user.id {
        return Err(AppError::BadRequest("cannot delete yourself".into()));
    }
    let res = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&id)
        .execute(&app.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit::log(&app.db, Some(&user.id), "user_delete", None, &id).await;
    Ok(Json(json!({ "deleted": id })))
}

/// Admin: set a user's password without knowing the old one. Bumps
/// token_version so every token the user still holds stops working.
pub async fn reset_password(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ResetPasswordReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    if req.password.is_empty() {
        return Err(AppError::BadRequest("password required".into()));
    }
    let hash = auth::hash_password(&req.password)?;
    let res = sqlx::query(
        "UPDATE users SET pw_hash = ?, token_version = token_version + 1 WHERE id = ?",
    )
    .bind(&hash)
    .bind(&id)
    .execute(&app.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit::log(&app.db, Some(&user.id), "password_reset", None, &id).await;
    Ok(Json(json!({ "reset": true, "id": id })))
}

pub async fn set_role(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<SetRoleReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    if req.role != "admin" && req.role != "member" {
        return Err(AppError::BadRequest("role must be admin|member".into()));
    }
    if id == user.id && req.role != "admin" {
        return Err(AppError::BadRequest("cannot demote yourself".into()));
    }
    let res = sqlx::query("UPDATE users SET role = ? WHERE id = ?")
        .bind(&req.role)
        .bind(&id)
        .execute(&app.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit::log(&app.db, Some(&user.id), "user_set_role", None, &format!("{id} -> {}", req.role)).await;
    Ok(Json(json!({ "id": id, "role": req.role })))
}
