/// RFC3339 UTC timestamp — the on-disk format for every `*_at` column.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Fresh UUID v4 string — used for every primary key.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// RFC3339 timestamp `secs` from now (used for lock lease expiry).
pub fn rfc3339_in(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
}

/// True if an RFC3339 timestamp is in the past (or unparseable → treat as expired).
pub fn is_past(ts: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| t.with_timezone(&chrono::Utc) < chrono::Utc::now())
        .unwrap_or(true)
}
