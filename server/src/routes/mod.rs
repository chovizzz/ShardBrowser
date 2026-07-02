pub mod acl;
pub mod envs;
pub mod folders;
pub mod locks;
pub mod proxies;
pub mod users;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::auth;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth::login))
        .route("/me", get(auth::me))
        .route("/me/password", post(auth::change_password))
        // users (admin)
        .route("/users", get(users::list).post(users::create))
        .route("/users/:id", delete(users::delete))
        .route("/users/:id/role", patch(users::set_role))
        .route("/users/:id/password", patch(users::reset_password))
        // audit trail (admin)
        .route("/audit", get(crate::audit::list))
        // folders
        .route("/folders", get(folders::list).post(folders::create))
        .route("/folders/:id", patch(folders::update).delete(folders::delete))
        // environments
        .route("/envs", get(envs::list).post(envs::create))
        .route(
            "/envs/:id",
            get(envs::get).patch(envs::update).delete(envs::delete),
        )
        // checkout locks + snapshots
        .route("/envs/:id/checkout", post(locks::checkout))
        .route("/envs/:id/lease", post(locks::lease))
        .route("/envs/:id/release", post(locks::release))
        .route("/envs/:id/force-unlock", post(locks::force_unlock))
        .route("/envs/:id/lock", get(locks::status))
        .route(
            "/envs/:id/checkin",
            post(locks::checkin).layer(DefaultBodyLimit::max(state.cfg.max_snapshot_bytes)),
        )
        .route("/envs/:id/snapshot/:version", get(locks::download))
        // access control (admin)
        .route("/acl", post(acl::grant).delete(acl::revoke))
        // proxies
        .route("/proxies", get(proxies::list).post(proxies::create))
        .route("/proxies/:id", delete(proxies::delete))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}
