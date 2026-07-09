//! `AppJson<T>`: a JSON request-body extractor whose rejections render as the
//! app's uniform `{ "error": ... }` shape. axum's built-in `Json` rejection is
//! plain text, which breaks the documented error contract; this wraps it.

use axum::async_trait;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::Json;

use crate::error::AppError;

pub struct AppJson<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for AppJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(AppJson(v)),
            // `body_text()` is the same client-facing parse message axum would
            // return, now delivered as JSON. It describes the caller's own bad
            // body, not server internals.
            Err(rej) => Err(AppError::BadRequest(rej.body_text())),
        }
    }
}

/// Optional JSON body: an absent body (no `application/json` content-type) is
/// `None`, but a PRESENT-yet-malformed body is a `400` — unlike `Option<Json<T>>`,
/// which silently swallows a parse error into `None`.
pub struct AppJsonOpt<T>(pub Option<T>);

#[async_trait]
impl<T, S> FromRequest<S> for AppJsonOpt<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Media types are case-insensitive and may carry params (`; charset=`);
        // accept `application/json` and any `application/*+json`, matching what
        // axum's `Json` will actually parse.
        let is_json = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
            .is_some_and(|m| m == "application/json" || (m.starts_with("application/") && m.ends_with("+json")));
        if !is_json {
            return Ok(AppJsonOpt(None)); // treat "no JSON body" as absent
        }
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(AppJsonOpt(Some(v))),
            Err(rej) => Err(AppError::BadRequest(rej.body_text())),
        }
    }
}
