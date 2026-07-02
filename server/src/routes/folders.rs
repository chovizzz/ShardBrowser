use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{CreateFolderReq, Folder, UpdateFolderReq};
use crate::state::AppState;
use crate::util;

pub async fn list(
    State(app): State<AppState>,
    _user: AuthUser,
) -> Result<Json<Vec<Folder>>, AppError> {
    let rows = sqlx::query_as::<_, Folder>("SELECT * FROM folders ORDER BY name")
        .fetch_all(&app.db)
        .await?;
    Ok(Json(rows))
}

pub async fn create(
    State(app): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateFolderReq>,
) -> Result<Json<Folder>, AppError> {
    user.require_admin()?;
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest("name required".into()));
    }
    let id = util::new_id();
    let now = util::now_rfc3339();
    sqlx::query("INSERT INTO folders (id, name, parent_id, created_at) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(&req.name)
        .bind(&req.parent_id)
        .bind(&now)
        .execute(&app.db)
        .await?;
    Ok(Json(Folder {
        id,
        name: req.name,
        parent_id: req.parent_id,
        created_at: now,
    }))
}

pub async fn update(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateFolderReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    if let Some(name) = &req.name {
        sqlx::query("UPDATE folders SET name = ? WHERE id = ?")
            .bind(name)
            .bind(&id)
            .execute(&app.db)
            .await?;
    }
    if let Some(parent) = &req.parent_id {
        sqlx::query("UPDATE folders SET parent_id = ? WHERE id = ?")
            .bind(parent)
            .bind(&id)
            .execute(&app.db)
            .await?;
    }
    Ok(Json(json!({ "id": id })))
}

pub async fn delete(
    State(app): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    let res = sqlx::query("DELETE FROM folders WHERE id = ?")
        .bind(&id)
        .execute(&app.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(json!({ "deleted": id })))
}
