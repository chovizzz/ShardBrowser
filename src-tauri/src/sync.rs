//! Team-server sync client (Phase 4).
//!
//! Talks to the self-hosted ShardX Team Server to check a shared environment
//! out (acquire the lock + pull the latest snapshot into the local profile's
//! user-data-dir) and back in (pack the user-data-dir + upload + release).
//! Cross-machine cookie portability is handled by `shardx_core::snapshot`.
//!
//! The checkout session is identified by a per-checkout `lock_token` returned
//! by the server and persisted in the profile meta; lease/checkin/release all
//! present it, so a crashed or reclaimed session can no longer mutate the env.

use crate::{profile, settings};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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

/// Warn when a server URL sends credentials in cleartext: `http://` to a
/// non-loopback host means the login password, bearer token, proxy credentials
/// and snapshot plaintext all travel unencrypted. Returns `None` for `https://`
/// or a loopback address (dev/self-hosted on the same box). The URL is only
/// inspected, never contacted.
pub fn insecure_transport_warning(server: &str) -> Option<String> {
    let url = reqwest::Url::parse(server.trim()).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    // Typed host so IPv6 is compared as an address, not a bracketed string.
    let is_loopback = match url.host()? {
        url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    if is_loopback {
        return None;
    }
    let host = url.host_str().unwrap_or("");
    Some(format!(
        "Connecting to {host} over plain HTTP — your password, token, proxy \
         credentials and environment data will be sent unencrypted. Put the \
         server behind HTTPS (a reverse proxy) before using it over a network."
    ))
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

/// Read the persisted lock_token for a profile's active checkout.
fn stored_lock_token(profile_id: &str) -> Option<String> {
    profile::load_raw(profile_id).ok().and_then(|p| p.meta.remote_lock_token)
}

/// Persist the checkout session (lock_token + base version) on the profile.
fn set_checkout_state(profile_id: &str, lock_token: Option<String>, base_version: Option<i64>) {
    if let Ok(mut p) = profile::load_raw(profile_id) {
        p.meta.remote_lock_token = lock_token;
        p.meta.remote_base_version = base_version;
        let _ = profile::save_raw(&mut p);
    }
}

/// Flag/clear the "browser exited but checkin failed" state.
fn set_pending_push(profile_id: &str, pending: bool) {
    if let Ok(mut p) = profile::load_raw(profile_id) {
        p.meta.remote_pending_push = pending;
        let _ = profile::save_raw(&mut p);
    }
}

/// True if a profile has un-pushed local changes from a failed checkin.
pub fn has_pending_push(profile_id: &str) -> bool {
    profile::load_raw(profile_id).map(|p| p.meta.remote_pending_push).unwrap_or(false)
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
            if let Err(e) = lease(&profile_id, &env_id).await {
                eprintln!("[launcher] lease renew failed for env {env_id}: {e}");
            }
        }
    });
}

/// Keep a checkout lease alive for the duration of a (possibly slow) push.
/// The process Tracker's renewer stops when the child exits, so a large
/// snapshot pack+upload could otherwise outlive the lease. Dropped on return.
struct LeaseGuard {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl LeaseGuard {
    fn start(profile_id: &str, env_id: &str) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (pid, eid, flag) = (profile_id.to_string(), env_id.to_string(), stop.clone());
        tokio::spawn(async move {
            // Renew immediately (the browser's own renewer already stopped),
            // then every 15s — short enough to survive a small server TTL
            // while a large snapshot packs and uploads.
            let _ = lease(&pid, &eid).await;
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let _ = lease(&pid, &eid).await;
            }
        });
        Self { stop }
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
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
        return Err(anyhow!("{} {}: {}", status.as_u16(), path, err_msg(&v, &text)));
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

/// Acquire the lock. Returns the checkout metadata (lock_token, version,
/// snapshot_url, stale_takeover).
async fn checkout_meta(env_id: &str) -> Result<Value> {
    let (_, _, client_id) = config()?;
    req(
        "POST",
        &format!("/envs/{env_id}/checkout"),
        Some(json!({ "client_id": client_id })),
    )
    .await
}

/// Renew the checkout lease (presents the persisted lock_token).
pub async fn lease(profile_id: &str, env_id: &str) -> Result<Value> {
    let (_, _, client_id) = config()?;
    let token = stored_lock_token(profile_id).unwrap_or_default();
    req(
        "POST",
        &format!("/envs/{env_id}/lease"),
        Some(json!({ "client_id": client_id, "lock_token": token })),
    )
    .await
}

/// Release the lock without uploading (discard local changes).
pub async fn release(profile_id: &str, env_id: &str) -> Result<Value> {
    let (_, _, client_id) = config()?;
    let token = stored_lock_token(profile_id).unwrap_or_default();
    let out = req(
        "POST",
        &format!("/envs/{env_id}/release"),
        Some(json!({ "client_id": client_id, "lock_token": token })),
    )
    .await;
    // Only forget the session if the server actually released it; on a network
    // blip the lock may still be held, and we need the token to retry.
    if out.is_ok() {
        set_checkout_state(profile_id, None, None);
    }
    out
}

/// Download a snapshot and verify its bytes against the server's advertised
/// sha256 (`x-snapshot-sha256`) before handing them to unpack.
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
    let expected = resp
        .headers()
        .get("x-snapshot-sha256")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.bytes().await?.to_vec();
    if let Some(expected) = expected {
        let got = format!("{:x}", Sha256::digest(&bytes));
        if !got.eq_ignore_ascii_case(&expected) {
            return Err(anyhow!(
                "snapshot integrity check failed: expected {expected}, got {got}"
            ));
        }
    }
    Ok(bytes)
}

/// Multipart checkin upload; carries the lock_token so the server can confirm
/// this session still owns the lock.
async fn upload(profile_id: &str, env_id: &str, bytes: Vec<u8>) -> Result<Value> {
    let (server, token, client_id) = config()?;
    let lock_token = stored_lock_token(profile_id).unwrap_or_default();
    let form = reqwest::multipart::Form::new()
        .text("client_id", client_id)
        .text("lock_token", lock_token)
        .part(
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
/// the checkout metadata. If anything after the lock is acquired fails, the
/// lock is released so the environment doesn't stay stuck until lease expiry.
pub async fn pull(profile_id: &str, env_id: &str) -> Result<Value> {
    let meta = checkout_meta(env_id).await?;
    let lock_token = meta.get("lock_token").and_then(|t| t.as_str()).map(String::from);
    let version = meta.get("version").and_then(|v| v.as_i64());
    set_checkout_state(profile_id, lock_token, version);

    let result: Result<()> = async {
        if let Some(url) = meta.get("snapshot_url").and_then(|u| u.as_str()) {
            let bytes = download(url).await?;
            let udd = profile::user_data_dir(profile_id)?;
            // pack/unpack do blocking fs + sqlite work; keep off the async runtime.
            tokio::task::spawn_blocking(move || shardx_core::snapshot::unpack(&bytes, &udd))
                .await
                .map_err(|e| anyhow!("unpack task: {e}"))?
                .map_err(|e| anyhow!("unpack snapshot: {e}"))?;
        }
        Ok(())
    }
    .await;

    if let Err(e) = result {
        // We hold the lock but failed to materialize the snapshot — release it
        // (best effort) so we don't strand the environment.
        if let Err(re) = release(profile_id, env_id).await {
            eprintln!("[launcher] release after failed pull also failed for {env_id}: {re}");
        }
        return Err(e).context("pull shared environment");
    }
    Ok(meta)
}

/// Checkin: pack the local profile's user-data-dir, upload it as a new
/// snapshot, and release the lock. A lease guard keeps the checkout alive
/// while a large snapshot packs and uploads.
pub async fn push(profile_id: &str, env_id: &str) -> Result<Value> {
    let _guard = LeaseGuard::start(profile_id, env_id);
    let udd = profile::user_data_dir(profile_id)?;
    let bytes = tokio::task::spawn_blocking(move || shardx_core::snapshot::pack(&udd))
        .await
        .map_err(|e| anyhow!("pack task: {e}"))?
        .map_err(|e| anyhow!("pack snapshot: {e}"))?;
    let out = upload(profile_id, env_id, bytes).await?;
    // Checked in cleanly — clear the session + any pending flag.
    set_checkout_state(profile_id, None, None);
    set_pending_push(profile_id, false);
    Ok(out)
}

/// Called by the process Tracker on browser exit. Wraps `push`; on failure it
/// marks the profile pending so the user can retry rather than silently losing
/// the session's changes.
pub async fn checkin_on_exit(profile_id: &str, env_id: &str) {
    match push(profile_id, env_id).await {
        Ok(_) => eprintln!("[launcher] checked in shared environment {env_id}"),
        Err(e) => {
            eprintln!("[launcher] checkin failed for env {env_id}: {e} — marked pending");
            set_pending_push(profile_id, true);
        }
    }
}

/// Discard un-pushed local changes: clear the pending flag and forget the
/// checkout session (accepting the loss). Best-effort releases the server lock
/// if we still hold its token. The next launch will pull the server's copy.
pub async fn discard_pending(profile_id: &str, env_id: &str) -> Result<()> {
    if stored_lock_token(profile_id).is_some() {
        let _ = release(profile_id, env_id).await;
    }
    set_checkout_state(profile_id, None, None);
    set_pending_push(profile_id, false);
    Ok(())
}

/// Retry a checkin that failed on exit. Re-acquires the lock, but refuses to
/// overwrite if someone else has checked in since (server version moved past
/// the base this checkout was taken from) — that would clobber their work.
pub async fn retry_push(profile_id: &str, env_id: &str) -> Result<Value> {
    if !has_pending_push(profile_id) {
        return Err(anyhow!("no pending changes to push for this environment"));
    }
    let base_version = profile::load_raw(profile_id).ok().and_then(|p| p.meta.remote_base_version);

    // Re-acquire the lock (do NOT pull — that would overwrite local changes).
    let meta = checkout_meta(env_id).await?;
    let lock_token = meta.get("lock_token").and_then(|t| t.as_str()).map(String::from);
    let server_version = meta.get("version").and_then(|v| v.as_i64());
    // Keep the same base so a subsequent retry still compares correctly.
    set_checkout_state(profile_id, lock_token, base_version);

    if let (Some(base), Some(server)) = (base_version, server_version) {
        if server != base {
            // Someone else advanced the environment; don't clobber it.
            if let Err(re) = release(profile_id, env_id).await {
                eprintln!("[launcher] release after retry conflict failed for {env_id}: {re}");
            }
            set_checkout_state(profile_id, None, base_version);
            return Err(anyhow!(
                "cannot push: the shared environment was updated by someone else \
                 (server v{server}, your changes are based on v{base}). Your local \
                 changes were kept; discard them or contact an admin."
            ));
        }
    }

    push(profile_id, env_id).await
}

#[cfg(test)]
mod tests {
    use super::insecure_transport_warning as warn;

    #[test]
    fn https_and_loopback_are_silent() {
        assert!(warn("https://team.example.com:8080").is_none());
        assert!(warn("http://localhost:8080").is_none());
        assert!(warn("http://127.0.0.1:8080").is_none());
        assert!(warn("http://[::1]:8080").is_none());
    }

    #[test]
    fn plain_http_to_remote_host_warns() {
        assert!(warn("http://team.example.com:8080").is_some());
        assert!(warn("http://10.0.0.5:8080").is_some());
    }
}
