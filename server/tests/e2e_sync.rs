//! End-to-end test of the team-sync pipeline against the real server binary.
//!
//! Mirrors exactly what the launcher's `sync.rs` does — checkout, multipart
//! snapshot upload (checkin), checkout again, snapshot download — and pairs it
//! with `shardx_core` pack/unpack to prove a snapshot taken from one
//! user-data-dir restores (cookies readable) into another via the server.

use std::process::{Child, Command};
use std::time::Duration;

const PORT: u16 = 38080;

fn base() -> String {
    format!("http://127.0.0.1:{PORT}")
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Bypass any ambient HTTP proxy so 127.0.0.1 is reached directly.
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

async fn wait_health(c: &reqwest::Client) {
    for _ in 0..60 {
        if let Ok(r) = c.get(format!("{}/health", base())).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server did not become healthy on port {PORT}");
}

#[tokio::test]
async fn checkout_checkin_snapshot_roundtrip() {
    let data = std::env::temp_dir().join(format!("shardx-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);

    let bin = env!("CARGO_BIN_EXE_shardx-team-server");
    let child = Command::new(bin)
        .env("SHARDX_BIND", format!("127.0.0.1:{PORT}"))
        .env("SHARDX_DATA_DIR", &data)
        .env("SHARDX_TOKEN_SECRET", "e2e-secret")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "secret")
        .env("SHARDX_SNAPSHOT_KEEP", "3")
        .spawn()
        .expect("spawn server binary");
    let _guard = ServerGuard(child);

    let c = client();
    wait_health(&c).await;

    // ---- login ----
    let v: serde_json::Value = c
        .post(format!("{}/auth/login", base()))
        .json(&serde_json::json!({ "username": "admin", "password": "secret" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = v["token"].as_str().expect("token").to_string();

    // ---- create a shared environment ----
    let v: serde_json::Value = c
        .post(format!("{}/envs", base()))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "e2e", "host_os": "Windows" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let env_id = v["id"].as_str().expect("env id").to_string();

    // ---- build a source user-data-dir with one encrypted cookie + a cache file ----
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

    // ---- checkout (v0, nothing to pull yet) ----
    let v: serde_json::Value = c
        .post(format!("{}/envs/{env_id}/checkout", base()))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "client_id": "tester" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["version"].as_i64(), Some(0));
    assert!(v["snapshot_url"].is_null());

    // ---- checkin: multipart upload, EXACTLY as sync.rs::upload builds it ----
    let form = reqwest::multipart::Form::new().text("client_id", "tester").part(
        "snapshot",
        reqwest::multipart::Part::bytes(snapshot).file_name("snapshot.tgz"),
    );
    let resp = c
        .post(format!("{}/envs/{env_id}/checkin", base()))
        .bearer_auth(&token)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "checkin failed: {}", resp.status());
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["version"].as_i64(), Some(1));

    // ---- checkout again → now there's a snapshot to pull ----
    let v: serde_json::Value = c
        .post(format!("{}/envs/{env_id}/checkout", base()))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "client_id": "tester" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["version"].as_i64(), Some(1));
    let url = v["snapshot_url"].as_str().expect("snapshot_url").to_string();

    // ---- download + unpack into a fresh udd, verify the cookie survives ----
    let bytes = c
        .get(format!("{}{}", base(), url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec();

    let dst = data.join("dst_udd");
    shardx_core::snapshot::unpack(&bytes, &dst).unwrap();

    // Cache excluded, cookie restored + readable with the destination key.
    assert!(!dst.join("Default/Cache/blob").exists(), "cache must not be synced");
    let dcrypt = shardx_core::LocalCrypt::open(&dst).unwrap();
    let cookies =
        shardx_core::cookies::read(&shardx_core::cookies::cookies_db_path(&dst), &dcrypt).unwrap();
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].value, "E2E-TOKEN");
    assert_eq!(cookies[0].domain, ".acme.test");
}
