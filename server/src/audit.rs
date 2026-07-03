//! Best-effort audit trail. Every security-relevant mutation (auth, user/ACL
//! management, env/folder/proxy CRUD, lock lifecycle, snapshot access) lands
//! here; failures are swallowed so auditing never breaks the operation itself.

use axum::extract::{Query, State};
use axum::Json;
use sqlx::SqlitePool;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{AuditEntry, AuditQuery};
use crate::state::AppState;
use crate::util;

pub async fn log(db: &SqlitePool, actor: Option<&str>, action: &str, env_id: Option<&str>, detail: &str) {
    let _ = sqlx::query(
        "INSERT INTO audit_log (actor, action, env_id, detail, at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(actor)
    .bind(action)
    .bind(env_id)
    .bind(detail)
    .bind(util::now_rfc3339())
    .execute(db)
    .await;
}

/// Admin: newest-first audit entries, optionally filtered by env/action.
pub async fn list(
    State(app): State<AppState>,
    user: AuthUser,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, AppError> {
    user.require_admin()?;
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let rows = sqlx::query_as::<_, AuditEntry>(
        "SELECT * FROM audit_log \
         WHERE (?1 IS NULL OR env_id = ?1) AND (?2 IS NULL OR action = ?2) \
         ORDER BY id DESC LIMIT ?3",
    )
    .bind(&q.env_id)
    .bind(&q.action)
    .bind(limit)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(rows))
}
