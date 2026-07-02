use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use crate::audit;
use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{CreateEnvReq, Environment, Proxy, UpdateEnvReq};
use crate::state::AppState;
use crate::util;

/// Minimum permission for an operation. `Use` = launch (checkout/lease/
/// checkin/download); `Edit` additionally allows changing the env itself.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Perm {
    Use,
    Edit,
}

/// Member access = direct env grant OR a grant on the env's folder or any of
/// its ancestor folders. `Edit` requires perm='edit' on the matching grant
/// ('edit' implies 'use'). Admins can do everything.
pub(crate) async fn can_access(
    app: &AppState,
    user: &AuthUser,
    env: &Environment,
    need: Perm,
) -> Result<bool, AppError> {
    if user.is_admin() {
        return Ok(true);
    }
    let perm_ok = |p: &str| need == Perm::Use || p == "edit";
    let direct: Option<String> = sqlx::query_scalar(
        "SELECT perm FROM acl WHERE user_id = ? AND object_kind = 'env' AND object_id = ?",
    )
    .bind(&user.id)
    .bind(&env.id)
    .fetch_optional(&app.db)
    .await?;
    if direct.as_deref().map(perm_ok).unwrap_or(false) {
        return Ok(true);
    }
    if let Some(folder) = &env.folder_id {
        // Walk the folder's ancestor chain; a grant anywhere above counts.
        // UNION (not UNION ALL) dedups, so a parent_id cycle terminates.
        let folder_perms: Vec<String> = sqlx::query_scalar(
            "WITH RECURSIVE anc(id) AS ( \
                 SELECT ?1 \
                 UNION \
                 SELECT f.parent_id FROM folders f JOIN anc a ON f.id = a.id \
                 WHERE f.parent_id IS NOT NULL \
             ) \
             SELECT perm FROM acl \
             WHERE user_id = ?2 AND object_kind = 'folder' AND object_id IN (SELECT id FROM anc)",
        )
        .bind(folder)
        .bind(&user.id)
        .fetch_all(&app.db)
        .await?;
        if folder_perms.iter().any(|p| perm_ok(p)) {
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
        // Folder grants cover every descendant folder (recursive CTE).
        sqlx::query_as::<_, Environment>(
            "WITH RECURSIVE af(id) AS ( \
                 SELECT object_id FROM acl WHERE user_id = ?1 AND object_kind = 'folder' \
                 UNION \
                 SELECT f.id FROM folders f JOIN af ON f.parent_id = af.id \
             ) \
             SELECT * FROM environments e WHERE \
             EXISTS (SELECT 1 FROM acl a WHERE a.user_id = ?1 AND a.object_kind = 'env' AND a.object_id = e.id) \
             OR e.folder_id IN (SELECT id FROM af) \
             ORDER BY updated_at DESC",
        )
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
    let env = load_accessible(&app, &user, &id, Perm::Use).await?;
    let mut v = env.to_json();
    // Resolve the bound proxy inline: the launcher needs host/credentials to
    // start the browser, and this (env-scoped, ACL-gated) is the only place a
    // member can see them.
    if let Some(pid) = &env.proxy_id {
        let proxy = sqlx::query_as::<_, Proxy>("SELECT * FROM proxies WHERE id = ?")
            .bind(pid)
            .fetch_optional(&app.db)
            .await?;
        if let Some(p) = proxy {
            v["proxy"] = serde_json::to_value(&p).unwrap_or(Value::Null);
        }
    }
    Ok(Json(v))
}

/// Load an environment, enforcing access; 404 if missing, 403 if not allowed.
pub(crate) async fn load_accessible(
    app: &AppState,
    user: &AuthUser,
    id: &str,
    need: Perm,
) -> Result<Environment, AppError> {
    let env = sqlx::query_as::<_, Environment>("SELECT * FROM environments WHERE id = ?")
        .bind(id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(AppError::NotFound)?;
    if !can_access(app, user, &env, need).await? {
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
    audit::log(&app.db, Some(&user.id), "env_create", Some(&id), &req.name).await;
    Ok(Json(env.to_json()))
}

pub async fn update(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateEnvReq>,
) -> Result<Json<Value>, AppError> {
    // Members holding an 'edit' grant may change content fields; moving the
    // env (folder = who can see it) or rebinding infrastructure (proxy =
    // credential access, host_os) stays admin-only.
    let mut env = load_accessible(&app, &user, &id, Perm::Edit).await?;
    if !user.is_admin()
        && (req.folder_id.is_some() || req.proxy_id.is_some() || req.host_os.is_some())
    {
        return Err(AppError::Forbidden);
    }

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
    audit::log(&app.db, Some(&user.id), "env_update", Some(&id), &env.name).await;
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
    // ACL rows have no FK on object_id; drop grants pointing at the env.
    let _ = sqlx::query("DELETE FROM acl WHERE object_kind = 'env' AND object_id = ?")
        .bind(&id)
        .execute(&app.db)
        .await;
    audit::log(&app.db, Some(&user.id), "env_delete", Some(&id), "").await;
    Ok(Json(json!({ "deleted": id })))
}
