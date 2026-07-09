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
    /// Bounds concurrent checkin snapshot uploads (disk/bandwidth DoS guard).
    pub upload_slots: Arc<tokio::sync::Semaphore>,
    /// Bounds concurrent snapshot downloads — same disk/bandwidth guard on the
    /// read path, held for the whole streamed transfer.
    pub download_slots: Arc<tokio::sync::Semaphore>,
}
