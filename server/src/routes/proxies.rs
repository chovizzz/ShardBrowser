use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{CreateProxyReq, Proxy};
use crate::state::AppState;
use crate::util;

pub async fn list(
    State(app): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<Proxy>>, AppError> {
    let rows = sqlx::query_as::<_, Proxy>("SELECT * FROM proxies ORDER BY name")
        .fetch_all(&app.db)
        .await?;
    Ok(Json(rows))
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
    Ok(Json(json!({ "deleted": id })))
}
