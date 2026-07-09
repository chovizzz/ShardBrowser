use std::sync::Arc;

use crate::config::Config;
use crate::ratelimit::LoginThrottle;

/// Shared application state handed to every handler. Cheap to clone:
/// the pool is an `Arc` internally and `cfg`/`login_throttle` are `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub cfg: Arc<Config>,
    pub login_throttle: Arc<LoginThrottle>,
}
