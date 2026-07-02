use std::sync::Arc;

use crate::config::Config;

/// Shared application state handed to every handler. Cheap to clone:
/// the pool is an `Arc` internally and `cfg` is wrapped in `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub cfg: Arc<Config>,
}
