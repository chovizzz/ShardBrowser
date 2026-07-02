use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{CreateEnvReq, Environment, UpdateEnvReq};
use crate::state::AppState;
use crate::util;

/// Member access = direct env grant OR a grant on the env's folder. Admins see all.
pub(crate) async fn can_access(
    app: &AppState,
    user: &AuthUser,
    env: &Environment,
) -> Result<bool, AppError> {
    if user.is_admin() {
        return Ok(true);
    }
    let direct: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM acl WHERE user_id = ? AND object_kind = 'env' AND object_id = ?",
    )
    .bind(&user.id)
    .bind(&env.id)
    .fetch_one(&app.db)
    .await?;
    if direct > 0 {
        return Ok(true);
    }
    if let Some(folder) = &env.folder_id {
        let via_folder: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM acl WHERE user_id = ? AND object_kind = 'folder' AND object_id = ?",
        )
        .bind(&user.id)
        .bind(folder)
        .fetch_one(&app.db)
        .await?;
        if via_folder > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn list(
    State(app): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<Value>>, AppError> {
    let rows = if user.is_admin() {
        sqlx::query_as::<_, Environment>("SELECT * FROM environments ORDER BY updated_at DESC")
            .fetch_all(&app.db)
            .await?
    } else {
        sqlx::query_as::<_, Environment>(
            "SELECT * FROM environments e WHERE \
             EXISTS (SELECT 1 FROM acl a WHERE a.user_id = ? AND a.object_kind = 'env' AND a.object_id = e.id) \
             OR EXISTS (SELECT 1 FROM acl a WHERE a.user_id = ? AND a.object_kind = 'folder' AND a.object_id = e.folder_id) \
             ORDER BY updated_at DESC",
        )
        .bind(&user.id)
        .bind(&user.id)
        .fetch_all(&app.db)
        .await?
    };
    Ok(Json(rows.iter().map(|e| e.to_json()).collect()))
}

pub async fn get(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let env = load_accessible(&app, &user, &id).await?;
    Ok(Json(env.to_json()))
}

/// Load an environment, enforcing access; 404 if missing, 403 if not allowed.
pub(crate) async fn load_accessible(
    app: &AppState,
    user: &AuthUser,
    id: &str,
) -> Result<Environment, AppError> {
    let env = sqlx::query_as::<_, Environment>("SELECT * FROM environments WHERE id = ?")
        .bind(id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(AppError::NotFound)?;
    if !can_access(app, user, &env).await? {
        return Err(AppError::Forbidden);
    }
    Ok(env)
}

pub async fn create(
    State(app): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateEnvReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest("name required".into()));
    }
    let id = util::new_id();
    let now = util::now_rfc3339();
    let config_json = req.config.unwrap_or_else(|| json!({})).to_string();
    let notes = req.notes.unwrap_or_default();
    sqlx::query(
        "INSERT INTO environments \
         (id, name, folder_id, config_json, proxy_id, host_os, current_version, notes, created_by, updated_by, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.folder_id)
    .bind(&config_json)
    .bind(&req.proxy_id)
    .bind(&req.host_os)
    .bind(&notes)
    .bind(&user.id)
    .bind(&user.id)
    .bind(&now)
    .bind(&now)
    .execute(&app.db)
    .await?;
    let env = sqlx::query_as::<_, Environment>("SELECT * FROM environments WHERE id = ?")
        .bind(&id)
        .fetch_one(&app.db)
        .await?;
    Ok(Json(env.to_json()))
}

pub async fn update(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateEnvReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    let mut env = sqlx::query_as::<_, Environment>("SELECT * FROM environments WHERE id = ?")
        .bind(&id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if let Some(v) = req.name {
        env.name = v;
    }
    if let Some(v) = req.folder_id {
        env.folder_id = Some(v);
    }
    if let Some(v) = req.proxy_id {
        env.proxy_id = Some(v);
    }
    if let Some(v) = req.host_os {
        env.host_os = Some(v);
    }
    if let Some(v) = req.notes {
        env.notes = v;
    }
    if let Some(v) = req.config {
        env.config_json = v.to_string();
    }
    let now = util::now_rfc3339();
    sqlx::query(
        "UPDATE environments SET name=?, folder_id=?, config_json=?, proxy_id=?, host_os=?, notes=?, updated_by=?, updated_at=? WHERE id=?",
    )
    .bind(&env.name)
    .bind(&env.folder_id)
    .bind(&env.config_json)
    .bind(&env.proxy_id)
    .bind(&env.host_os)
    .bind(&env.notes)
    .bind(&user.id)
    .bind(&now)
    .bind(&id)
    .execute(&app.db)
    .await?;
    env.updated_at = now;
    Ok(Json(env.to_json()))
}

pub async fn delete(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    let res = sqlx::query("DELETE FROM environments WHERE id = ?")
        .bind(&id)
        .execute(&app.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(json!({ "deleted": id })))
}
