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

/// Spawn a server on a fresh data dir. Lease TTL is 1s so the stale-takeover
/// test doesn't have to wait the default 90s.
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
        .env("SHARDX_LEASE_TTL_SECS", "1")
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
        .text("client_id", "tester")
        .text("lock_token", "not-the-token")
        .part("snapshot", reqwest::multipart::Part::bytes(snapshot.clone()).file_name("s.tgz"));
    let resp = c
        .post(format!("{}/envs/{env_id}/checkin", base(port)))
        .bearer_auth(&admin)
        .multipart(bad)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409, "wrong lock_token must be rejected");

    // checkin with the RIGHT token, exactly as sync.rs::upload builds it
    let form = reqwest::multipart::Form::new()
        .text("client_id", "tester")
        .text("lock_token", lock_token)
        .part("snapshot", reqwest::multipart::Part::bytes(snapshot).file_name("snapshot.tgz"));
    let resp = c
        .post(format!("{}/envs/{env_id}/checkin", base(port)))
        .bearer_auth(&admin)
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

    let resp = c.get(format!("{}{}", base(port), url)).bearer_auth(&admin).send().await.unwrap();
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

    // lease TTL is 1s; wait it out, then bob takes over
    tokio::time::sleep(Duration::from_millis(1300)).await;
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
        .text("client_id", "a")
        .text("lock_token", alice_token)
        .part("snapshot", reqwest::multipart::Part::bytes(vec![1u8, 2, 3]).file_name("s.tgz"));
    let resp = c
        .post(format!("{}/envs/{env_id}/checkin", base(port)))
        .bearer_auth(&alice)
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
