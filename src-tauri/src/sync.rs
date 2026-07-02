//! Team-server sync client (Phase 4).
//!
//! Talks to the self-hosted ShardX Team Server to check a shared environment
//! out (acquire the lock + pull the latest snapshot into the local profile's
//! user-data-dir) and back in (pack the user-data-dir + upload + release).
//! Cross-machine cookie portability is handled by `shardx_core::snapshot`.

use crate::{profile, settings};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

/// Resolved (base_url, token, client_id) from settings.
fn config() -> Result<(String, String, String)> {
    let s = settings::load()?;
    let server = s
        .remote_server
        .filter(|x| !x.trim().is_empty())
        .ok_or_else(|| anyhow!("team server URL not configured"))?;
    let token = s.remote_token.unwrap_or_default();
    let client_id = s.remote_client_id.unwrap_or_else(|| "default".to_string());
    Ok((server.trim_end_matches('/').to_string(), token, client_id))
}

/// True when a server URL + token are both configured.
pub fn is_configured() -> bool {
    settings::load()
        .ok()
        .map(|s| {
            s.remote_server.as_deref().map(|x| !x.trim().is_empty()).unwrap_or(false)
                && s.remote_token.as_deref().map(|t| !t.is_empty()).unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Renew the checkout lease every 30s until the profile is no longer running.
pub fn spawn_lease_renewer(profile_id: String, env_id: String) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let still_running = crate::process::Tracker::shared()
                .running()
                .iter()
                .any(|r| r.profile_id == profile_id);
            if !still_running {
                break;
            }
            if let Err(e) = lease(&env_id).await {
                eprintln!("[launcher] lease renew failed for env {env_id}: {e}");
            }
        }
    });
}

fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?)
}

fn err_msg(v: &Value, fallback: &str) -> String {
    v.get("error")
        .and_then(|e| e.as_str())
        .unwrap_or(fallback)
        .to_string()
}

/// Authenticate against a team server; returns the bearer token.
pub async fn login(server: &str, username: &str, password: &str) -> Result<String> {
    let server = server.trim_end_matches('/');
    let resp = http()?
        .post(format!("{server}/auth/login"))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .context("login request failed")?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(anyhow!("login failed: {}", err_msg(&v, "unknown")));
    }
    v.get("token")
        .and_then(|t| t.as_str())
        .map(String::from)
        .ok_or_else(|| anyhow!("no token in login response"))
}

/// Authenticated JSON request against the configured server.
async fn req(method: &str, path: &str, body: Option<Value>) -> Result<Value> {
    let (server, token, _) = config()?;
    let url = format!("{server}{path}");
    let cli = http()?;
    let mut r = match method {
        "GET" => cli.get(&url),
        "POST" => cli.post(&url),
        "DELETE" => cli.delete(&url),
        "PATCH" => cli.patch(&url),
        m => return Err(anyhow!("unsupported method {m}")),
    };
    r = r.bearer_auth(&token);
    if let Some(b) = body {
        r = r.json(&b);
    }
    let resp = r.send().await.context("team server request failed")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(anyhow!(
            "{} {}: {}",
            status.as_u16(),
            path,
            err_msg(&v, &text)
        ));
    }
    Ok(v)
}

pub async fn me() -> Result<Value> {
    req("GET", "/me", None).await
}

pub async fn force_unlock(env_id: &str) -> Result<Value> {
    req("POST", &format!("/envs/{env_id}/force-unlock"), None).await
}

pub async fn list_envs() -> Result<Value> {
    req("GET", "/envs", None).await
}

pub async fn get_env(env_id: &str) -> Result<Value> {
    req("GET", &format!("/envs/{env_id}"), None).await
}

pub async fn lock_status(env_id: &str) -> Result<Value> {
    req("GET", &format!("/envs/{env_id}/lock"), None).await
}

async fn checkout_meta(env_id: &str) -> Result<Value> {
    let (_, _, client_id) = config()?;
    req(
        "POST",
        &format!("/envs/{env_id}/checkout"),
        Some(json!({ "client_id": client_id })),
    )
    .await
}

/// Renew the checkout lease (called periodically while the browser runs).
pub async fn lease(env_id: &str) -> Result<Value> {
    let (_, _, client_id) = config()?;
    req(
        "POST",
        &format!("/envs/{env_id}/lease"),
        Some(json!({ "client_id": client_id })),
    )
    .await
}

/// Release the lock without uploading (discard local changes).
pub async fn release(env_id: &str) -> Result<Value> {
    let (_, _, client_id) = config()?;
    req(
        "POST",
        &format!("/envs/{env_id}/release"),
        Some(json!({ "client_id": client_id })),
    )
    .await
}

async fn download(url_path: &str) -> Result<Vec<u8>> {
    let (server, token, _) = config()?;
    let resp = http()?
        .get(format!("{server}{url_path}"))
        .bearer_auth(&token)
        .send()
        .await
        .context("snapshot download failed")?;
    if !resp.status().is_success() {
        return Err(anyhow!("download {url_path} failed: {}", resp.status()));
    }
    Ok(resp.bytes().await?.to_vec())
}

async fn upload(env_id: &str, bytes: Vec<u8>) -> Result<Value> {
    let (server, token, client_id) = config()?;
    let form = reqwest::multipart::Form::new().text("client_id", client_id).part(
        "snapshot",
        reqwest::multipart::Part::bytes(bytes).file_name("snapshot.tgz"),
    );
    let resp = http()?
        .post(format!("{server}/envs/{env_id}/checkin"))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .await
        .context("checkin upload failed")?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(anyhow!("checkin failed: {} {}", status.as_u16(), err_msg(&v, "")));
    }
    Ok(v)
}

/// Checkout: acquire the lock and pull the latest snapshot into the local
/// profile's user-data-dir (re-encrypting cookies for this machine). Returns
/// the checkout metadata (lease expiry, version).
pub async fn pull(profile_id: &str, env_id: &str) -> Result<Value> {
    let meta = checkout_meta(env_id).await?;
    if let Some(url) = meta.get("snapshot_url").and_then(|u| u.as_str()) {
        let bytes = download(url).await?;
        let udd = profile::user_data_dir(profile_id)?;
        // pack/unpack do blocking fs + sqlite work; keep off the async runtime.
        tokio::task::spawn_blocking(move || shardx_core::snapshot::unpack(&bytes, &udd))
            .await
            .map_err(|e| anyhow!("unpack task: {e}"))?
            .map_err(|e| anyhow!("unpack snapshot: {e}"))?;
    }
    Ok(meta)
}

/// Checkin: pack the local profile's user-data-dir, upload it as a new snapshot,
/// and release the lock.
pub async fn push(profile_id: &str, env_id: &str) -> Result<Value> {
    let udd = profile::user_data_dir(profile_id)?;
    let bytes = tokio::task::spawn_blocking(move || shardx_core::snapshot::pack(&udd))
        .await
        .map_err(|e| anyhow!("pack task: {e}"))?
        .map_err(|e| anyhow!("pack snapshot: {e}"))?;
    upload(env_id, bytes).await
}
