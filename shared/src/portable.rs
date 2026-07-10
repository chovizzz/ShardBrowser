use serde::{Deserialize, Serialize};

/// Decrypted, machine-independent cookie — the form stored inside a snapshot so
/// it can be re-encrypted with the target machine's key on restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableCookie {
    pub domain: String,
    pub name: String,
    pub value: String,
    #[serde(default = "default_path")]
    pub path: String,
    /// Unix seconds; None = session cookie.
    #[serde(default)]
    pub expires: Option<f64>,
    #[serde(default)]
    pub secure: bool,
    #[serde(default, alias = "httpOnly")]
    pub http_only: bool,
    /// "Strict" | "Lax" | "None" | "unspecified" (case-insensitive).
    #[serde(default, alias = "sameSite")]
    pub same_site: Option<String>,
    /// CHIPS partition key — the top-level site a partitioned cookie is scoped
    /// to (empty for an unpartitioned cookie). It's part of the Chromium cookie
    /// row's UNIQUE index, so it must round-trip or a partitioned cookie would
    /// collide with (or widen into) the unpartitioned scope on restore.
    #[serde(default)]
    pub top_frame_site_key: String,
    /// Unique-index component — 1 unless the cookie was set in a cross-site
    /// context. `None` on legacy snapshots → written as 1 (the old default).
    #[serde(default)]
    pub has_cross_site_ancestor: Option<i64>,
    /// Unique-index components. `None` on legacy snapshots → derived from
    /// `secure` on write, matching the old rebuild behavior.
    #[serde(default)]
    pub source_scheme: Option<i64>,
    #[serde(default)]
    pub source_port: Option<i64>,
}

fn default_path() -> String {
    "/".to_string()
}

// Hand-written (not derived) so `path` defaults to "/" like the serde default,
// rather than an empty string — this type is public and an empty path would be
// an invalid cookie.
impl Default for PortableCookie {
    fn default() -> Self {
        Self {
            domain: String::new(),
            name: String::new(),
            value: String::new(),
            path: default_path(),
            expires: None,
            secure: false,
            http_only: false,
            same_site: None,
            top_frame_site_key: String::new(),
            has_cross_site_ancestor: None,
            source_scheme: None,
            source_port: None,
        }
    }
}

/// A decrypted saved password (Chromium `Login Data` → `logins`), carried in a
/// snapshot so it can be re-sealed with the destination machine's os_crypt key
/// on restore. The raw DB travels with the snapshot; only the `password_value`
/// column is rekeyed in place, located by the row's stable SQLite `rowid` (the
/// file travels unchanged, so rowids match between pack and unpack). The value
/// is the raw decrypted bytes — not a `String`, so an arbitrary-byte password
/// survives the round-trip intact.
#[derive(Clone, Serialize, Deserialize)]
pub struct PortableLogin {
    pub rowid: i64,
    pub password_value: Vec<u8>,
}

// Hand-written so a decrypted password never lands in a log line.
impl std::fmt::Debug for PortableLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortableLogin")
            .field("rowid", &self.rowid)
            .field("password_value", &format_args!("<{} bytes redacted>", self.password_value.len()))
            .finish()
    }
}

/// A decrypted `Web Data` secret (a credit-card number, CVC, or IBAN), carried
/// in a snapshot so it can be re-sealed with the destination machine's os_crypt
/// key on restore. `table` + `key` (the row's `guid`) locate the exact row to
/// rewrite; `value` is the raw decrypted bytes.
#[derive(Clone, Serialize, Deserialize)]
pub struct PortableSecret {
    pub table: String,
    pub key: String,
    pub value: Vec<u8>,
}

// Hand-written so a decrypted card number / CVC never lands in a log line.
impl std::fmt::Debug for PortableSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortableSecret")
            .field("table", &self.table)
            .field("key", &self.key)
            .field("value", &format_args!("<{} bytes redacted>", self.value.len()))
            .finish()
    }
}

/// The plaintext, portable slice of a profile's state embedded in a snapshot
/// (everything that is machine-bound-encrypted on disk).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortableState {
    #[serde(default)]
    pub cookies: Vec<PortableCookie>,
    #[serde(default)]
    pub logins: Vec<PortableLogin>,
    /// `Web Data` os_crypt secrets, re-sealed in place on restore (the raw DB
    /// travels with the snapshot; only its encrypted columns need rekeying).
    #[serde(default)]
    pub web_secrets: Vec<PortableSecret>,
}

/// Filename of the portable state blob inside a snapshot archive.
pub const PORTABLE_FILE: &str = "shardx-portable.json";
