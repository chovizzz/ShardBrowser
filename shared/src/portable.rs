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

/// The plaintext, portable slice of a profile's state embedded in a snapshot
/// (everything that is machine-bound-encrypted on disk).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortableState {
    #[serde(default)]
    pub cookies: Vec<PortableCookie>,
    #[serde(default)]
    pub logins: Vec<PortableLogin>,
}

/// Filename of the portable state blob inside a snapshot archive.
pub const PORTABLE_FILE: &str = "shardx-portable.json";
