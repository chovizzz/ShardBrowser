use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Uniform error type for handlers; renders to `{ "error": "..." }`.
#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict(String),
    BadRequest(String),
    Internal(String),
    /// Rate-limited; the value is the Retry-After hint in seconds.
    TooManyRequests(u64),
}

impl AppError {
    fn parts(&self) -> (StatusCode, String) {
        match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
            AppError::TooManyRequests(_) => {
                (StatusCode::TOO_MANY_REQUESTS, "too many attempts; try again later".into())
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, msg) = self.parts();
        // A 5xx detail stays in the server log; the client only ever sees a
        // generic message, so we never leak SQL text, file paths, or constraint
        // names. 4xx messages are deliberate and safe to return.
        let client_msg = if code.is_server_error() {
            tracing::error!("internal error: {msg}");
            "internal server error".to_string()
        } else {
            msg
        };
        let mut resp = (code, Json(json!({ "error": client_msg }))).into_response();
        if let AppError::TooManyRequests(secs) = self {
            if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(axum::http::header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        // Map predictable, client-caused DB errors to 4xx instead of 500; the
        // rest are genuine internal failures (detail logged, not returned).
        match &e {
            sqlx::Error::RowNotFound => AppError::NotFound,
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AppError::Conflict("resource already exists".into())
            }
            sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                AppError::BadRequest("references a resource that does not exist".into())
            }
            _ => AppError::Internal(format!("db: {e}")),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}
