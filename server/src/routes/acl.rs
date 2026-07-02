use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{GrantReq, RevokeReq};
use crate::state::AppState;

fn valid_kind(k: &str) -> bool {
    k == "env" || k == "folder"
}

pub async fn grant(
    State(app): State<AppState>,
    user: AuthUser,
    Json(req): Json<GrantReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    if !valid_kind(&req.object_kind) {
        return Err(AppError::BadRequest("object_kind must be env|folder".into()));
    }
    let perm = match req.perm.as_deref() {
        None | Some("use") => "use",
        Some("edit") => "edit",
        Some(o) => return Err(AppError::BadRequest(format!("invalid perm: {o}"))),
    };
    sqlx::query(
        "INSERT INTO acl (user_id, object_id, object_kind, perm) VALUES (?, ?, ?, ?) \
         ON CONFLICT(user_id, object_id, object_kind) DO UPDATE SET perm = excluded.perm",
    )
    .bind(&req.user_id)
    .bind(&req.object_id)
    .bind(&req.object_kind)
    .bind(perm)
    .execute(&app.db)
    .await?;
    Ok(Json(json!({
        "granted": true,
        "user_id": req.user_id,
        "object_id": req.object_id,
        "object_kind": req.object_kind,
        "perm": perm,
    })))
}

pub async fn revoke(
    State(app): State<AppState>,
    user: AuthUser,
    Json(req): Json<RevokeReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    let res = sqlx::query("DELETE FROM acl WHERE user_id = ? AND object_id = ? AND object_kind = ?")
        .bind(&req.user_id)
        .bind(&req.object_id)
        .bind(&req.object_kind)
        .execute(&app.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(json!({ "revoked": true })))
}
