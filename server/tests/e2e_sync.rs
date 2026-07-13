//! End-to-end tests against the real server binary.
//!
//! The first test mirrors what the launcher's `sync.rs` does — checkout,
//! multipart snapshot upload (checkin), checkout again, snapshot download —
//! paired with `shardx_core` pack/unpack to prove a snapshot restores across
//! user-data-dirs. The rest cover the hardening added on top: lock-token
//! enforcement, ACL perm/folder semantics, proxy credential scoping, stale-
//! lock takeover, and password-change token invalidation.

use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{json, Value};

fn base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

async fn wait_health(c: &reqwest::Client, port: u16) {
    for _ in 0..60 {
        if let Ok(r) = c.get(format!("{}/health", base(port))).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server did not become healthy on port {port}");
}

/// Spawn a server on a fresh data dir. The stale-takeover test ages the lease
/// row directly (the server floors the TTL at 15s), so this uses a normal TTL.
fn spawn_server(data: &std::path::Path, port: u16) -> ServerGuard {
    let _ = std::fs::remove_dir_all(data);
    let bin = env!("CARGO_BIN_EXE_shardx-team-server");
    let child = Command::new(bin)
        .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", data)
        .env("SHARDX_TOKEN_SECRET", "e2e-secret")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "secret")
        .env("SHARDX_SNAPSHOT_KEEP", "3")
        .env("SHARDX_LEASE_TTL_SECS", "20")
        .spawn()
        .expect("spawn server binary");
    ServerGuard(child)
}

async fn login(c: &reqwest::Client, port: u16, user: &str, pass: &str) -> Value {
    c.post(format!("{}/auth/login", base(port)))
        .json(&json!({ "username": user, "password": pass }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn token(c: &reqwest::Client, port: u16, user: &str, pass: &str) -> String {
    login(c, port, user, pass).await["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn checkout_checkin_snapshot_roundtrip() {
    let port = 38080u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;

    let admin = token(&c, port, "admin", "secret").await;

    // create a shared environment
    let v: Value = c
        .post(format!("{}/envs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "name": "e2e", "host_os": "Windows" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let env_id = v["id"].as_str().unwrap().to_string();

    // build a source user-data-dir with one encrypted cookie + a cache file
    let src = data.join("src_udd");
    std::fs::create_dir_all(src.join("Default/Network")).unwrap();
    std::fs::create_dir_all(src.join("Default/Cache")).unwrap();
    std::fs::write(src.join("Default/Cache/blob"), vec![0u8; 2048]).unwrap();
    let crypt = shardx_core::LocalCrypt::open(&src).unwrap();
    shardx_core::cookies::write(
        &src.join("Default/Network/Cookies"),
        &crypt,
        &[shardx_core::PortableCookie {
            domain: ".acme.test".into(),
            name: "sid".into(),
            value: "E2E-TOKEN".into(),
            path: "/".into(),
            expires: Some(4_102_444_800.0),
            secure: true,
            http_only: true,
            same_site: Some("Lax".into()),
            ..Default::default()
        }],
    )
    .unwrap();
    let snapshot = shardx_core::snapshot::pack(&src).unwrap();

    // checkout (v0) → capture the lock_token the rest of the session needs
    let v: Value = c
        .post(format!("{}/envs/{env_id}/checkout", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "client_id": "tester" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["version"].as_i64(), Some(0));
    assert!(v["snapshot_url"].is_null());
    let lock_token = v["lock_token"].as_str().expect("lock_token").to_string();

    // checkin with a WRONG token is rejected (stale-session protection)
    let bad = reqwest::multipart::Form::new()
        .part("snapshot", reqwest::multipart::Part::bytes(snapshot.clone()).file_name("s.tgz"));
    let resp = c
        .post(format!("{}/envs/{env_id}/checkin", base(port)))
        .bearer_auth(&admin)
        .header("x-client-id", "tester")
        .header("x-lock-token", "not-the-token")
        .multipart(bad)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409, "wrong lock_token must be rejected");

    // checkin with the RIGHT token, exactly as sync.rs::upload builds it
    let form = reqwest::multipart::Form::new()
        .part("snapshot", reqwest::multipart::Part::bytes(snapshot).file_name("snapshot.tgz"));
    let resp = c
        .post(format!("{}/envs/{env_id}/checkin", base(port)))
        .bearer_auth(&admin)
        .header("x-client-id", "tester")
        .header("x-lock-token", lock_token)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "checkin failed: {}", resp.status());
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["version"].as_i64(), Some(1));

    // checkout again → now there's a snapshot to pull, and a sha256 header
    let v: Value = c
        .post(format!("{}/envs/{env_id}/checkout", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "client_id": "tester" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["version"].as_i64(), Some(1));
    let url = v["snapshot_url"].as_str().unwrap().to_string();
    let dl_token = v["lock_token"].as_str().unwrap().to_string();

    let resp = c
        .get(format!("{}{}", base(port), url))
        .bearer_auth(&admin)
        .header("x-client-id", "tester")
        .header("x-lock-token", &dl_token)
        .send()
        .await
        .unwrap();
    let sha = resp
        .headers()
        .get("x-snapshot-sha256")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .expect("sha256 header");
    let bytes = resp.bytes().await.unwrap().to_vec();
    use sha2::{Digest, Sha256};
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), sha, "download sha256 matches");

    let dst = data.join("dst_udd");
    shardx_core::snapshot::unpack(&bytes, &dst).unwrap();
    assert!(!dst.join("Default/Cache/blob").exists(), "cache must not be synced");
    let dcrypt = shardx_core::LocalCrypt::open(&dst).unwrap();
    let cookies =
        shardx_core::cookies::read(&shardx_core::cookies::cookies_db_path(&dst), &dcrypt).unwrap();
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].value, "E2E-TOKEN");
}

#[tokio::test]
async fn acl_perm_and_folder_recursion_and_proxy_scoping() {
    let port = 38081u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-acl-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    // helper closures
    let post = |path: String, tok: String, body: Value| {
        let c = c.clone();
        async move {
            c.post(format!("{}{}", base(port), path))
                .bearer_auth(tok)
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // a member
    let m: Value = post("/users".into(), admin.clone(), json!({ "username": "mem", "password": "pw1" }))
        .await
        .json()
        .await
        .unwrap();
    let mem_id = m["id"].as_str().unwrap().to_string();

    // a proxy with credentials
    let px: Value = post(
        "/proxies".into(),
        admin.clone(),
        json!({ "name": "px", "kind": "socks5", "host": "1.2.3.4", "port": 1080, "username": "u", "password": "p" }),
    )
    .await
    .json()
    .await
    .unwrap();
    let proxy_id = px["id"].as_str().unwrap().to_string();

    // folder tree: parent → child; env lives in child
    let parent: Value = post("/folders".into(), admin.clone(), json!({ "name": "parent" })).await.json().await.unwrap();
    let parent_id = parent["id"].as_str().unwrap().to_string();
    let child: Value = post("/folders".into(), admin.clone(), json!({ "name": "child", "parent_id": parent_id }))
        .await
        .json()
        .await
        .unwrap();
    let child_id = child["id"].as_str().unwrap().to_string();

    let env: Value = post(
        "/envs".into(),
        admin.clone(),
        json!({ "name": "shared", "folder_id": child_id, "proxy_id": proxy_id }),
    )
    .await
    .json()
    .await
    .unwrap();
    let env_id = env["id"].as_str().unwrap().to_string();

    let mem = token(&c, port, "mem", "pw1").await;

    // before any grant: member can't see the env
    let list: Value = c.get(format!("{}/envs", base(port))).bearer_auth(&mem).send().await.unwrap().json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 0, "no access before grant");

    // grant 'use' on the PARENT folder → recursion reaches the child's env
    post(
        "/acl".into(),
        admin.clone(),
        json!({ "user_id": mem_id, "object_id": parent_id, "object_kind": "folder", "perm": "use" }),
    )
    .await;
    let list: Value = c.get(format!("{}/envs", base(port))).bearer_auth(&mem).send().await.unwrap().json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1, "parent-folder grant reaches child env");

    // member GET env → proxy is inlined WITH credentials (needed to launch)
    let got: Value = c.get(format!("{}/envs/{env_id}", base(port))).bearer_auth(&mem).send().await.unwrap().json().await.unwrap();
    assert_eq!(got["proxy"]["password"].as_str(), Some("p"), "env proxy carries credentials");

    // but GET /proxies is sanitized for members (no host/credentials)
    let plist: Value = c.get(format!("{}/proxies", base(port))).bearer_auth(&mem).send().await.unwrap().json().await.unwrap();
    let p0 = &plist.as_array().unwrap()[0];
    assert!(p0.get("password").is_none(), "member proxy list must not expose password");
    assert!(p0.get("host").is_none(), "member proxy list must not expose host");

    // 'use' perm cannot edit the env
    let resp = c
        .patch(format!("{}/envs/{env_id}", base(port)))
        .bearer_auth(&mem)
        .json(&json!({ "name": "hacked" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "'use' perm cannot PATCH");

    // upgrade to 'edit' → name/notes editable, but not proxy rebind
    post(
        "/acl".into(),
        admin.clone(),
        json!({ "user_id": mem_id, "object_id": parent_id, "object_kind": "folder", "perm": "edit" }),
    )
    .await;
    let resp = c
        .patch(format!("{}/envs/{env_id}", base(port)))
        .bearer_auth(&mem)
        .json(&json!({ "name": "renamed" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "'edit' perm can rename");

    let resp = c
        .patch(format!("{}/envs/{env_id}", base(port)))
        .bearer_auth(&mem)
        .json(&json!({ "proxy_id": "some-other" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "member cannot rebind proxy even with edit");
}

#[tokio::test]
async fn stale_lock_takeover_and_password_invalidation() {
    let port = 38082u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-lock-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    // two members
    for u in ["alice", "bob"] {
        c.post(format!("{}/users", base(port)))
            .bearer_auth(&admin)
            .json(&json!({ "username": u, "password": "pw" }))
            .send()
            .await
            .unwrap();
    }
    let env: Value = c
        .post(format!("{}/envs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "name": "contended" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let env_id = env["id"].as_str().unwrap().to_string();
    // grant both
    for who in ["alice", "bob"] {
        let uid: Value = c
            .get(format!("{}/users", base(port)))
            .bearer_auth(&admin)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = uid.as_array().unwrap().iter().find(|u| u["username"] == who).unwrap()["id"].as_str().unwrap().to_string();
        c.post(format!("{}/acl", base(port)))
            .bearer_auth(&admin)
            .json(&json!({ "user_id": id, "object_id": env_id, "object_kind": "env", "perm": "use" }))
            .send()
            .await
            .unwrap();
    }

    let alice = token(&c, port, "alice", "pw").await;
    let bob = token(&c, port, "bob", "pw").await;

    // alice checks out
    let a: Value = c
        .post(format!("{}/envs/{env_id}/checkout", base(port)))
        .bearer_auth(&alice)
        .json(&json!({ "client_id": "a" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alice_token = a["lock_token"].as_str().unwrap().to_string();

    // bob is refused while alice's lease is live
    let resp = c
        .post(format!("{}/envs/{env_id}/checkout", base(port)))
        .bearer_auth(&bob)
        .json(&json!({ "client_id": "b" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409, "live lease blocks others");

    // Expire alice's lease by aging the row directly — the server floors the
    // TTL at 15s, too long to wait out in a test — then bob takes over.
    {
        use std::str::FromStr;
        let db = data.join("shardx.db");
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite://{}", db.display()))
            .unwrap()
            .busy_timeout(Duration::from_secs(5));
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        let n = sqlx::query("UPDATE locks SET lease_expires_at = '2000-01-01T00:00:00+00:00'")
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(n, 1, "aged exactly alice's lease");
        pool.close().await;
    }
    let b: Value = c
        .post(format!("{}/envs/{env_id}/checkout", base(port)))
        .bearer_auth(&bob)
        .json(&json!({ "client_id": "b" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(b["stale_takeover"].as_bool(), Some(true), "expired lease → takeover flagged");

    // alice's late checkin with her old token must NOT clobber bob's lock
    let form = reqwest::multipart::Form::new()
        .part("snapshot", reqwest::multipart::Part::bytes(vec![1u8, 2, 3]).file_name("s.tgz"));
    let resp = c
        .post(format!("{}/envs/{env_id}/checkin", base(port)))
        .bearer_auth(&alice)
        .header("x-client-id", "a")
        .header("x-lock-token", alice_token)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409, "stale owner cannot check in over a new lock");

    // password change invalidates alice's existing token
    let resp = c
        .post(format!("{}/me/password", base(port)))
        .bearer_auth(&alice)
        .json(&json!({ "old_password": "pw", "new_password": "pw2" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "password change ok");
    let resp = c.get(format!("{}/me", base(port))).bearer_auth(&alice).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 401, "old token rejected after password change");
    // new password works
    let _ = token(&c, port, "alice", "pw2").await;
}

/// Snapshot download must present the current checkout's client_id + lock_token,
/// not merely be the same user — a second/stale token can't pull the (plaintext)
/// snapshot out from under the live session.
#[tokio::test]
async fn snapshot_download_requires_lock_token() {
    let port = 38083u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-dl-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    // A member with `use` on an env.
    c.post(format!("{}/users", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "username": "alice", "password": "pw" }))
        .send()
        .await
        .unwrap();
    let env: Value = c
        .post(format!("{}/envs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "name": "dl" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let env_id = env["id"].as_str().unwrap().to_string();
    let users: Value = c
        .get(format!("{}/users", base(port)))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alice_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "alice")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    c.post(format!("{}/acl", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "user_id": alice_id, "object_id": env_id, "object_kind": "env", "perm": "use" }))
        .send()
        .await
        .unwrap();
    let alice = token(&c, port, "alice", "pw").await;

    // checkout(client a) → checkin (creates v1, releases lock).
    let srcdir = data.join("dlsrc");
    std::fs::create_dir_all(&srcdir).unwrap();
    let snap = shardx_core::snapshot::pack(&srcdir).unwrap();
    let v0: Value = c
        .post(format!("{}/envs/{env_id}/checkout", base(port)))
        .bearer_auth(&alice)
        .json(&json!({ "client_id": "a" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tok0 = v0["lock_token"].as_str().unwrap().to_string();
    let form = reqwest::multipart::Form::new()
        .part("snapshot", reqwest::multipart::Part::bytes(snap).file_name("s.tgz"));
    let r = c
        .post(format!("{}/envs/{env_id}/checkin", base(port)))
        .bearer_auth(&alice)
        .header("x-client-id", "a")
        .header("x-lock-token", tok0)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "checkin creates v1");

    // checkout(client a) again → alice holds the lock and v1 exists.
    let v1: Value = c
        .post(format!("{}/envs/{env_id}/checkout", base(port)))
        .bearer_auth(&alice)
        .json(&json!({ "client_id": "a" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let url = v1["snapshot_url"].as_str().expect("v1 snapshot").to_string();
    let tok1 = v1["lock_token"].as_str().unwrap().to_string();

    let get = |client_id: &str, lock_token: &str| {
        c.get(format!("{}{}", base(port), url))
            .bearer_auth(&alice)
            .header("x-client-id", client_id.to_string())
            .header("x-lock-token", lock_token.to_string())
            .send()
    };
    // Correct session → 200.
    assert_eq!(get("a", &tok1).await.unwrap().status().as_u16(), 200, "lock holder downloads");
    // Same user, wrong client / wrong token / no headers → refused.
    assert_eq!(get("b", &tok1).await.unwrap().status().as_u16(), 409, "other client refused");
    assert_eq!(get("a", "wrong").await.unwrap().status().as_u16(), 409, "wrong token refused");
    let none = c.get(format!("{}{}", base(port), url)).bearer_auth(&alice).send().await.unwrap();
    assert_eq!(none.status().as_u16(), 409, "missing session headers refused");
}

/// A LIVE lock can only be re-acquired by presenting its current lock_token, so
/// a second JWT for the same user can't learn the client_id, re-checkout, mint a
/// fresh token, and steal the lock (which would also bypass the download check).
#[tokio::test]
async fn reacquiring_live_lock_requires_token() {
    let port = 38084u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-remint-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    let env: Value = c
        .post(format!("{}/envs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "name": "remint" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let env_id = env["id"].as_str().unwrap().to_string();

    let checkout = |tok: Option<&str>| {
        let mut body = json!({ "client_id": "a" });
        if let Some(t) = tok {
            body["lock_token"] = json!(t);
        }
        c.post(format!("{}/envs/{env_id}/checkout", base(port)))
            .bearer_auth(&admin)
            .json(&body)
            .send()
    };

    // First checkout on a free slot needs no token.
    let v0: Value = checkout(None).await.unwrap().json().await.unwrap();
    let tok = v0["lock_token"].as_str().unwrap().to_string();

    // Re-acquiring the now-LIVE lock without / with a wrong token is refused.
    assert_eq!(checkout(None).await.unwrap().status().as_u16(), 409, "no token can't reclaim live lock");
    assert_eq!(checkout(Some("wrong")).await.unwrap().status().as_u16(), 409, "wrong token refused");
    // With the real token it succeeds and rotates the token.
    let v1: Value = checkout(Some(&tok)).await.unwrap().json().await.unwrap();
    let tok2 = v1["lock_token"].as_str().unwrap().to_string();
    assert_ne!(tok, tok2, "token rotates on re-acquire");
    // The old token no longer works.
    assert_eq!(checkout(Some(&tok)).await.unwrap().status().as_u16(), 409, "old token invalid after rotate");
}

/// Repeated failed logins from one source get throttled (429 with Retry-After)
/// before any password verify — brute-force / Argon2 CPU-exhaustion guard.
#[tokio::test]
async fn login_throttles_after_repeated_failures() {
    let port = 38085u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-throttle-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;

    let attempt = |password: &str| {
        c.post(format!("{}/auth/login", base(port)))
            .json(&json!({ "username": "admin", "password": password }))
            .send()
    };

    // Five wrong-password attempts are plain 401s.
    for _ in 0..5 {
        assert_eq!(attempt("wrong").await.unwrap().status().as_u16(), 401);
    }
    // Now the source is locked: even the CORRECT password is refused with 429.
    let r = attempt("secret").await.unwrap();
    assert_eq!(r.status().as_u16(), 429, "locked out after repeated failures");
    assert!(r.headers().get("retry-after").is_some(), "429 carries Retry-After");
}

/// A predictable client error (a foreign-key violation from a bogus folder_id)
/// maps to 400, not a 500 leaking SQL / constraint text.
#[tokio::test]
async fn bad_foreign_key_is_client_error_not_500() {
    let port = 38086u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-fk-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    let r = c
        .post(format!("{}/envs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "name": "x", "folder_id": "does-not-exist" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400, "FK violation → 400, not 500");
    let body: Value = r.json().await.unwrap();
    let err = body["error"].as_str().unwrap_or_default().to_lowercase();
    assert!(
        !err.contains("foreign key") && !err.contains("sql") && !err.contains("constraint"),
        "error message must not leak DB internals: {err}"
    );
}

/// ACL grants against a nonexistent target or user are refused (no ghost rows).
#[tokio::test]
async fn acl_grant_rejects_ghost_target_or_user() {
    let port = 38087u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-ghost-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    c.post(format!("{}/users", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "username": "alice", "password": "pw" }))
        .send()
        .await
        .unwrap();
    let users: Value = c
        .get(format!("{}/users", base(port)))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alice_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "alice")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let grant = |user_id: &str, object_id: &str| {
        c.post(format!("{}/acl", base(port)))
            .bearer_auth(&admin)
            .json(&json!({ "user_id": user_id, "object_id": object_id, "object_kind": "env", "perm": "use" }))
            .send()
    };
    // Nonexistent env → 404.
    assert_eq!(grant(&alice_id, "ghost-env").await.unwrap().status().as_u16(), 404);

    let env: Value = c
        .post(format!("{}/envs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "name": "e" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let env_id = env["id"].as_str().unwrap().to_string();
    // Nonexistent user → 404; a valid grant → success.
    assert_eq!(grant("ghost-user", &env_id).await.unwrap().status().as_u16(), 404);
    assert!(grant(&alice_id, &env_id).await.unwrap().status().is_success());
}

/// env update can clear folder_id to null, and rejects a nonexistent folder
/// with 404 (not a 500/leaky FK error).
#[tokio::test]
async fn env_update_clears_folder_and_rejects_bad_folder() {
    let port = 38088u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-envupd-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    let folder: Value = c
        .post(format!("{}/folders", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "name": "F" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let folder_id = folder["id"].as_str().unwrap().to_string();
    let env: Value = c
        .post(format!("{}/envs", base(port)))
        .bearer_auth(&admin)
        .json(&json!({ "name": "e", "folder_id": folder_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let env_id = env["id"].as_str().unwrap().to_string();
    assert_eq!(env["folder_id"].as_str(), Some(folder_id.as_str()));

    let patch = |body: Value| {
        c.patch(format!("{}/envs/{env_id}", base(port))).bearer_auth(&admin).json(&body).send()
    };
    // A nonexistent folder → 404.
    assert_eq!(patch(json!({ "folder_id": "no-such" })).await.unwrap().status().as_u16(), 404);
    // Clearing to null succeeds and the env is unfoldered.
    let r = patch(json!({ "folder_id": Value::Null })).await.unwrap();
    assert!(r.status().is_success(), "clear folder: {}", r.status());
    let updated: Value = r.json().await.unwrap();
    assert!(updated["folder_id"].is_null(), "folder_id cleared to null");
}

/// A malformed JSON body is rejected as the uniform { "error": ... } shape,
/// not axum's default plain-text rejection.
#[tokio::test]
async fn malformed_json_body_returns_json_error() {
    let port = 38089u16;
    let data = std::env::temp_dir().join(format!("shardx-e2e-badjson-{}", std::process::id()));
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    let r = c
        .post(format!("{}/users", base(port)))
        .bearer_auth(&admin)
        .header("content-type", "application/json")
        .body("{ this is not json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400, "malformed body → 400");
    let body: Value = r.json().await.expect("response is JSON");
    assert!(body.get("error").and_then(|e| e.as_str()).is_some(), "has an error field: {body}");
}
