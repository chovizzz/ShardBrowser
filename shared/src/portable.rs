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
}

fn default_path() -> String {
    "/".to_string()
}

/// Decrypted saved login (Chromium `Login Data` → `logins`). Reserved for a
/// later phase; snapshots currently normalize cookies only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableLogin {
    pub origin_url: String,
    pub username_value: String,
    pub password_value: String,
    #[serde(default)]
    pub signon_realm: String,
}

/// A decrypted `Web Data` secret (a credit-card number, CVC, or IBAN), carried
/// in a snapshot so it can be re-sealed with the destination machine's os_crypt
/// key on restore. `table` + `key` (the row's `guid`) locate the exact row to
/// rewrite; `value` is the raw decrypted bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableSecret {
    pub table: String,
    pub key: String,
    pub value: Vec<u8>,
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
