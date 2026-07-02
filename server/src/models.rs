use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::FromRow;

// ---- DB row types ----

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub pw_hash: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct Environment {
    pub id: String,
    pub name: String,
    pub folder_id: Option<String>,
    pub config_json: String,
    pub proxy_id: Option<String>,
    pub host_os: Option<String>,
    pub current_version: i64,
    pub notes: String,
    pub created_by: Option<String>,
    pub updated_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Environment {
    /// API shape: `config_json` is parsed back into real JSON so clients get
    /// a `config` object rather than an escaped string.
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "folder_id": self.folder_id,
            "proxy_id": self.proxy_id,
            "host_os": self.host_os,
            "current_version": self.current_version,
            "notes": self.notes,
            "config": serde_json::from_str::<Value>(&self.config_json).unwrap_or(Value::Null),
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Lock {
    pub env_id: String,
    pub owner_user_id: String,
    pub owner_client_id: String,
    pub acquired_at: String,
    pub lease_expires_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Snapshot {
    pub env_id: String,
    pub version: i64,
    #[serde(skip_serializing)]
    pub blob_path: String,
    pub sha256: String,
    pub size: i64,
    pub created_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Proxy {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub host: String,
    pub port: i64,
    pub username: Option<String>,
    pub password: Option<String>,
    pub created_at: String,
}

// ---- request DTOs ----

#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateUserReq {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Deserialize)]
pub struct SetRoleReq {
    pub role: String,
}

#[derive(Deserialize)]
pub struct CreateFolderReq {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateFolderReq {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub parent_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateEnvReq {
    pub name: String,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub proxy_id: Option<String>,
    #[serde(default)]
    pub host_os: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub config: Option<Value>,
}

#[derive(Deserialize)]
pub struct UpdateEnvReq {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub proxy_id: Option<String>,
    #[serde(default)]
    pub host_os: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub config: Option<Value>,
}

#[derive(Deserialize)]
pub struct GrantReq {
    pub user_id: String,
    pub object_id: String,
    pub object_kind: String,
    #[serde(default)]
    pub perm: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokeReq {
    pub user_id: String,
    pub object_id: String,
    pub object_kind: String,
}

/// Identifies the holding session so two sessions of the same user don't
/// silently share a lock. Optional; defaults to "default" server-side.
#[derive(Deserialize, Default)]
pub struct ClientReq {
    #[serde(default)]
    pub client_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateProxyReq {
    pub name: String,
    pub kind: String,
    pub host: String,
    pub port: i64,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}
