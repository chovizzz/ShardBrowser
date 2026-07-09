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

/// Renewal cadence derived from the server's lease TTL: renew at ~1/3 of the
/// TTL so a single failed renewal still leaves two more attempts before the
/// lease lapses. Clamped to [5s, 300s]. Falls back to 30s when the server
/// doesn't report a TTL (older server predating the `lease_ttl_secs` field).
fn renew_interval(ttl_secs: Option<i64>) -> std::time::Duration {
    let secs = match ttl_secs {
        Some(ttl) if ttl > 0 => (ttl / 3).clamp(5, 300),
        _ => 30,
    };
    std::time::Duration::from_secs(secs as u64)
}

/// Pull the server's advertised lease TTL out of a checkout/lease response.
fn lease_ttl_secs(v: &Value) -> Option<i64> {
    v.get("lease_ttl_secs").and_then(|t| t.as_i64())
}

/// Interval until the next renewal, given the outcome of the last one. On
/// success, track the server TTL (renew at ~TTL/3). On failure, back off to a
/// short fixed retry rather than the TTL-derived cadence: a failed renewal must
/// be retried quickly (a lost network blip shouldn't let a small TTL lapse),
/// and we can't trust the (absent) response to tell us how long we may wait.
fn interval_after(result: &Result<Value>) -> std::time::Duration {
    match result {
        Ok(v) => renew_interval(lease_ttl_secs(v)),
        Err(_) => std::time::Duration::from_secs(5),
    }
}

/// Renew the checkout lease until the profile is no longer running.
///
/// The cadence tracks the server's lease TTL (renew at ~TTL/3) rather than a
/// fixed interval, so a short server-side `SHARDX_LEASE_TTL_SECS` can't let the
/// lease lapse between renewals. An immediate renewal on spawn learns the TTL
/// (checkout already set the lease, so this just refreshes it and reads the TTL
/// back), and every subsequent renewal re-reads it in case the server was
/// reconfigured mid-session. The launch path also holds a `LeaseGuard` across
/// pre-spawn preflight, so the lease is already fresh when this takes over.
pub fn spawn_lease_renewer(profile_id: String, env_id: String) {
    tokio::spawn(async move {
        // Immediate renew learns the TTL and sets the first interval.
        let res = lease(&profile_id, &env_id).await;
        if let Err(e) = &res {
            eprintln!("[launcher] initial lease renew failed for env {env_id}: {e}");
            if lease_error_is_terminal(e) {
                return; // lock lost / access revoked — nothing left to renew
            }
        }
        let mut interval = interval_after(&res);
        loop {
            tokio::time::sleep(interval).await;
            let still_running = crate::process::Tracker::shared()
                .running()
                .iter()
                .any(|r| r.profile_id == profile_id);
            if !still_running {
                break;
            }
            let res = lease(&profile_id, &env_id).await;
            if let Err(e) = &res {
                eprintln!("[launcher] lease renew failed for env {env_id}: {e}");
                if lease_error_is_terminal(e) {
                    eprintln!("[launcher] lease for env {env_id} is gone; stopping renewer");
                    break;
                }
            }
            interval = interval_after(&res);
        }
    });
}

/// Keep a checkout lease alive across a window where the browser's own renewer
/// isn't running: launch preflight (proxy probe / geo resolve before spawn),
/// the pull download+unpack, and a (possibly slow) push pack+upload. Renews
/// immediately on start, then tracks the server TTL. Dropped to stop.
pub struct LeaseGuard {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl LeaseGuard {
    pub fn start(profile_id: &str, env_id: &str) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (pid, eid, flag) = (profile_id.to_string(), env_id.to_string(), stop.clone());
        tokio::spawn(async move {
            // Renew immediately, learning the server TTL so the cadence tracks
            // it (renew at ~TTL/3); a failed renew backs off to a short retry,
            // but a terminal failure (lock lost / access revoked) stops it.
            let res = lease(&pid, &eid).await;
            if let Some(e) = res.as_ref().err().filter(|e| lease_error_is_terminal(e)) {
                eprintln!("[launcher] lease guard for env {eid} stopped: {e}");
                return;
            }
            let mut interval = interval_after(&res);
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(interval).await;
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let res = lease(&pid, &eid).await;
                if let Some(e) = res.as_ref().err().filter(|e| lease_error_is_terminal(e)) {
                    eprintln!("[launcher] lease guard for env {eid} stopped: {e}");
                    break;
                }
                interval = interval_after(&res);
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

/// A non-2xx response from the team server, carrying the HTTP status so callers
/// can distinguish terminal failures (lock lost, access revoked) from transient
/// ones (network blip, 5xx) instead of parsing the error string.
#[derive(Debug)]
struct HttpError {
    status: u16,
    path: String,
    msg: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.path, self.msg)
    }
}

impl std::error::Error for HttpError {}

/// True if a failed lease/renew can never succeed on retry — the lock is gone,
/// access was revoked, or the session is otherwise dead, so the renewer should
/// stop rather than hammer the server. Network errors and 5xx are NOT terminal
/// (they may recover), so this returns false for them.
fn lease_error_is_terminal(err: &anyhow::Error) -> bool {
    err.downcast_ref::<HttpError>()
        .is_some_and(|e| matches!(e.status, 400 | 401 | 403 | 404 | 409))
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
        return Err(anyhow::Error::new(HttpError {
            status: status.as_u16(),
            path: path.to_string(),
            msg: err_msg(&v, &text),
        }));
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
/// snapshot_url, stale_takeover). Presents any persisted lock_token so the
/// server lets this same client re-acquire its own still-live lock (e.g. a
/// relaunch after a crash) — a first/free checkout just sends an empty one.
async fn checkout_meta(profile_id: &str, env_id: &str) -> Result<Value> {
    let (_, _, client_id) = config()?;
    let lock_token = stored_lock_token(profile_id).unwrap_or_default();
    req(
        "POST",
        &format!("/envs/{env_id}/checkout"),
        Some(json!({ "client_id": client_id, "lock_token": lock_token })),
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
async fn download(profile_id: &str, url_path: &str) -> Result<Vec<u8>> {
    let (server, token, client_id) = config()?;
    // Present this checkout session's client_id + lock_token: the server limits
    // snapshot download (plaintext cookies + payment secrets) to the exact
    // session holding the lock, not just any token of the same user.
    let lock_token = stored_lock_token(profile_id).unwrap_or_default();
    // The server caps concurrent downloads (disk/bandwidth guard) and returns
    // 429 + Retry-After when saturated. That's transient — back off and retry a
    // few times before surfacing an error that would abort the launch, mirroring
    // the checkin side's degrade-and-recover behavior.
    const MAX_ATTEMPTS: u32 = 5;
    let mut attempt = 0u32;
    let resp = loop {
        let resp = http()?
            .get(format!("{server}{url_path}"))
            .bearer_auth(&token)
            .header("x-client-id", client_id.clone())
            .header("x-lock-token", lock_token.clone())
            .send()
            .await
            .context("snapshot download failed")?;
        if resp.status().as_u16() == 429 {
            // Bounded by MAX_ATTEMPTS so a stuck 429 can't loop forever; cap the
            // honored Retry-After so a hostile hint can't wedge the launch.
            let wait = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(2)
                .clamp(1, 10);
            attempt += 1;
            if attempt >= MAX_ATTEMPTS {
                return Err(anyhow!(
                    "download {url_path} rate-limited: still 429 after {MAX_ATTEMPTS} attempts"
                ));
            }
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            continue;
        }
        break resp;
    };
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

/// Multipart checkin upload. The session identity (client_id + lock_token) goes
/// in headers, not body parts, so the server can authorize before reading the
/// snapshot; the multipart body carries only the snapshot file itself.
async fn upload(profile_id: &str, env_id: &str, bytes: Vec<u8>) -> Result<Value> {
    let (server, token, client_id) = config()?;
    let lock_token = stored_lock_token(profile_id).unwrap_or_default();
    let form = reqwest::multipart::Form::new().part(
        "snapshot",
        reqwest::multipart::Part::bytes(bytes).file_name("snapshot.tgz"),
    );
    let resp = http()?
        .post(format!("{server}/envs/{env_id}/checkin"))
        .bearer_auth(&token)
        .header("x-client-id", client_id)
        .header("x-lock-token", lock_token)
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
    let meta = checkout_meta(profile_id, env_id).await?;
    let lock_token = meta.get("lock_token").and_then(|t| t.as_str()).map(String::from);
    let version = meta.get("version").and_then(|v| v.as_i64());
    set_checkout_state(profile_id, lock_token, version);

    let result: Result<()> = async {
        if let Some(url) = meta.get("snapshot_url").and_then(|u| u.as_str()) {
            // Renew the lease across the download+unpack: the browser-side
            // renewer only starts once the engine spawns, so a slow pull of a
            // large snapshot could otherwise outlive the lease we just acquired.
            let _guard = LeaseGuard::start(profile_id, env_id);
            let bytes = download(profile_id, url).await?;
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
    let meta = checkout_meta(profile_id, env_id).await?;
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

    #[test]
    fn renew_interval_tracks_ttl() {
        use super::{lease_ttl_secs, renew_interval};
        use serde_json::json;
        // ~TTL/3, so a short server TTL renews before it lapses.
        assert_eq!(renew_interval(Some(90)).as_secs(), 30); // default TTL
        assert_eq!(renew_interval(Some(20)).as_secs(), 6); // small TTL renews often
        // At the server-enforced minimum TTL (15s) the interval still beats it.
        assert_eq!(renew_interval(Some(15)).as_secs(), 5);
        assert!(renew_interval(Some(15)).as_secs() < 15);
        // Clamped: never hammer, never drift too far.
        assert_eq!(renew_interval(Some(6)).as_secs(), 5); // floor
        assert_eq!(renew_interval(Some(3600)).as_secs(), 300); // ceiling
        // Missing / bogus TTL falls back to a safe fixed cadence.
        assert_eq!(renew_interval(None).as_secs(), 30);
        assert_eq!(renew_interval(Some(0)).as_secs(), 30);
        assert_eq!(renew_interval(Some(-5)).as_secs(), 30);
        // Parses the field the server actually sends.
        assert_eq!(lease_ttl_secs(&json!({ "lease_ttl_secs": 90 })), Some(90));
        assert_eq!(lease_ttl_secs(&json!({ "env_id": "x" })), None);
    }

    #[test]
    fn terminal_vs_transient_lease_errors() {
        use super::{lease_error_is_terminal, HttpError};
        let http = |status| {
            anyhow::Error::new(HttpError { status, path: "/lease".into(), msg: "m".into() })
        };
        // Terminal: bad request / auth / access revoked / gone / lock lost.
        for s in [400, 401, 403, 404, 409] {
            assert!(lease_error_is_terminal(&http(s)), "{s} should be terminal");
        }
        // Transient: server hiccup or rate limit — keep retrying.
        for s in [408, 429, 500, 502, 503] {
            assert!(!lease_error_is_terminal(&http(s)), "{s} should be transient");
        }
        // A non-HTTP error (e.g. a network failure) is never terminal.
        assert!(!lease_error_is_terminal(&anyhow::anyhow!("connection refused")));
        // Still detected through a context wrapper.
        assert!(lease_error_is_terminal(&http(409).context("renew lease")));
    }

    #[test]
    fn interval_after_backs_off_on_failure() {
        use super::interval_after;
        use serde_json::json;
        // Success tracks the TTL...
        assert_eq!(interval_after(&Ok(json!({ "lease_ttl_secs": 90 }))).as_secs(), 30);
        // ...a success without the field falls back to the legacy 30s cadence...
        assert_eq!(interval_after(&Ok(json!({ "env_id": "x" }))).as_secs(), 30);
        // ...but a FAILED renewal retries quickly, never a wide fixed gap that a
        // short TTL could outlast.
        assert_eq!(interval_after(&Err(anyhow::anyhow!("network down"))).as_secs(), 5);
    }
}
