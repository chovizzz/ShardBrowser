use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::extract::AppJson;
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
    AppJson(req): AppJson<GrantReq>,
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
    // Refuse a grant against a target (or user) that doesn't exist — otherwise
    // the ACL row is a ghost that never applies and just lingers. Do it as one
    // atomic statement (existence gated by `EXISTS` in the same INSERT) so a
    // concurrent target delete can't slip a ghost row in between a check and the
    // write. ids/perm are bound.
    //
    // The two statements are spelled out in full rather than interpolating a
    // table name: the only part that varies is which table `EXISTS` probes, and
    // an exhaustive `match` over the validated kinds keeps every byte of SQL a
    // `&'static str`. That is also what sqlx 0.9's `SqlSafeStr` requires, so a
    // future kind cannot be added without either writing its statement here or
    // failing to compile — which is the point.
    macro_rules! grant_sql {
        ($target:literal) => {
            concat!(
                "INSERT INTO acl (user_id, object_id, object_kind, perm) \
                 SELECT ?1, ?2, ?3, ?4 \
                 WHERE EXISTS (SELECT 1 FROM ",
                $target,
                " WHERE id = ?2) \
                   AND EXISTS (SELECT 1 FROM users WHERE id = ?1) \
                 ON CONFLICT(user_id, object_id, object_kind) DO UPDATE SET perm = excluded.perm",
            )
        };
    }
    let sql: &'static str = match req.object_kind.as_str() {
        "env" => grant_sql!("environments"),
        "folder" => grant_sql!("folders"),
        // Unreachable: `valid_kind` above admits exactly these two.
        other => return Err(AppError::BadRequest(format!("invalid object_kind: {other}"))),
    };
    let res = sqlx::query(sql)
    .bind(&req.user_id)
    .bind(&req.object_id)
    .bind(&req.object_kind)
    .bind(perm)
    .execute(&app.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    crate::audit::log(
        &app.db,
        Some(&user.id),
        "acl_grant",
        (req.object_kind == "env").then_some(req.object_id.as_str()),
        &format!("{} {}:{} perm={}", req.user_id, req.object_kind, req.object_id, perm),
    )
    .await;
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
    AppJson(req): AppJson<RevokeReq>,
) -> Result<Json<Value>, AppError> {
    user.require_admin()?;
    // Same gate as `grant` — one rule for what an ACL kind may be, so a value
    // the grant path would have refused can never be used to probe/delete here.
    if !valid_kind(&req.object_kind) {
        return Err(AppError::BadRequest("object_kind must be env|folder".into()));
    }
    let res = sqlx::query("DELETE FROM acl WHERE user_id = ? AND object_id = ? AND object_kind = ?")
        .bind(&req.user_id)
        .bind(&req.object_id)
        .bind(&req.object_kind)
        .execute(&app.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    crate::audit::log(
        &app.db,
        Some(&user.id),
        "acl_revoke",
        (req.object_kind == "env").then_some(req.object_id.as_str()),
        &format!("{} {}:{}", req.user_id, req.object_kind, req.object_id),
    )
    .await;
    Ok(Json(json!({ "revoked": true })))
}
