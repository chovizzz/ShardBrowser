use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

use crate::audit;
use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{CreateFolderReq, Folder, UpdateFolderReq};
use crate::state::AppState;
use crate::util;

/// Admins see the whole tree. Members see folders they were granted (plus
/// every descendant, mirroring env access) and the folders that directly
/// contain envs granted to them (so the env list can show its location).
pub async fn list(
    State(app): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<Folder>>, AppError> {
    let rows = if user.is_admin() {
        sqlx::query_as::<_, Folder>("SELECT * FROM folders ORDER BY name")
            .fetch_all(&app.db)
            .await?
    } else {
        sqlx::query_as::<_, Folder>(
            "WITH RECURSIVE af(id) AS ( \
                 SELECT object_id FROM acl WHERE user_id = ?1 AND object_kind = 'folder' \
                 UNION \
                 SELECT f.id FROM folders f JOIN af ON f.parent_id = af.id \
             ) \
             SELECT * FROM folders WHERE id IN (SELECT id FROM af) \
             OR id IN ( \
                 SELECT e.folder_id FROM environments e \
                 JOIN acl a ON a.object_kind = 'env' AND a.object_id = e.id \
                 WHERE a.user_id = ?1 AND e.folder_id IS NOT NULL \
             ) \
             ORDER BY name",
        )
        .bind(&user.id)
        .fetch_all(&app.db)
        .await?
    };
    Ok(Json(rows))
}

/// True if `candidate` is `folder_id` itself or one of its descendants —
/// making it an illegal parent for `folder_id` (would create a cycle).
async fn creates_cycle(app: &AppState, folder_id: &str, candidate: &str) -> Result<bool, AppError> {
    if folder_id == candidate {
        return Ok(true);
    }
    let hit: i64 = sqlx::query_scalar(
        "WITH RECURSIVE desc_(id) AS ( \
             SELECT ?1 \
             UNION \
             SELECT f.id FROM folders f JOIN desc_ d ON f.parent_id = d.id \
         ) \
         SELECT COUNT(*) FROM desc_ WHERE id = ?2",
    )
    .bind(folder_id)
    .bind(candidate)
    .fetch_one(&app.db)
    .await?;
    Ok(hit > 0)
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
    if let Some(parent) = &req.parent_id {
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM folders WHERE id = ?")
            .bind(parent)
            .fetch_one(&app.db)
            .await?;
        if exists == 0 {
            return Err(AppError::BadRequest("parent folder does not exist".into()));
        }
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
    audit::log(&app.db, Some(&user.id), "folder_create", None, &req.name).await;
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
    // Validate the parent move BEFORE mutating anything, so a rejected parent
    // doesn't leave a half-applied rename behind.
    if let Some(parent) = &req.parent_id {
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM folders WHERE id = ?")
            .bind(parent)
            .fetch_one(&app.db)
            .await?;
        if exists == 0 {
            return Err(AppError::BadRequest("parent folder does not exist".into()));
        }
        if creates_cycle(&app, &id, parent).await? {
            return Err(AppError::BadRequest(
                "cannot move a folder under itself or its descendant".into(),
            ));
        }
    }
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
    audit::log(&app.db, Some(&user.id), "folder_update", None, &id).await;
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
    // ACL rows have no FK on object_id; drop grants pointing at the folder.
    let _ = sqlx::query("DELETE FROM acl WHERE object_kind = 'folder' AND object_id = ?")
        .bind(&id)
        .execute(&app.db)
        .await;
    audit::log(&app.db, Some(&user.id), "folder_delete", None, &id).await;
    Ok(Json(json!({ "deleted": id })))
}
