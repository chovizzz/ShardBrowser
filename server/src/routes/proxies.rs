use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use crate::audit;
use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{CreateProxyReq, Proxy};
use crate::state::AppState;
use crate::util;

/// Admins get full entries. Members get a sanitized list (id/name/kind) —
/// proxy endpoints and credentials reach a member only through
/// `GET /envs/{id}` for an env they can access.
pub async fn list(
    State(app): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<Value>>, AppError> {
    let rows = sqlx::query_as::<_, Proxy>("SELECT * FROM proxies ORDER BY name")
        .fetch_all(&app.db)
        .await?;
    let out = if user.is_admin() {
        rows.iter()
            .map(|p| serde_json::to_value(p).unwrap_or(Value::Null))
            .collect()
    } else {
        rows.iter().map(|p| p.sanitized()).collect()
    };
    Ok(Json(out))
}

pub async fn create(
    State(app): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateProxyReq>,
) -> Result<Json<Proxy>, AppError> {
    user.require_admin()?;
    let id = util::new_id();
    let now = util::now_rfc3339();
    sqlx::query(
        "INSERT INTO proxies (id, name, kind, host, port, username, password, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.kind)
    .bind(&req.host)
    .bind(req.port)
    .bind(&req.username)
    .bind(&req.password)
    .bind(&now)
    .execute(&app.db)
    .await?;
    audit::log(&app.db, Some(&user.id), "proxy_create", None, &req.name).await;
    Ok(Json(Proxy {
        id,
        name: req.name,
        kind: req.kind,
        host: req.host,
        port: req.port,
        username: req.username,
        password: req.password,
        created_at: now,
    }))
}

pub async fn delete(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    let res = sqlx::query("DELETE FROM proxies WHERE id = ?")
        .bind(&id)
        .execute(&app.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit::log(&app.db, Some(&user.id), "proxy_delete", None, &id).await;
    Ok(Json(json!({ "deleted": id })))
}
