//! End-to-end regression tests for `DELETE /acl` object_kind validation.
//!
//! `grant` has always rejected an `object_kind` outside `env|folder`, but
//! `revoke` used to bind whatever the client sent straight into the DELETE.
//! These tests pin the fixed behaviour: the same rule, the same message, and
//! authorization still ahead of it — plus proof that a rejected revoke touches
//! neither the acl table nor the audit trail.
//!
//! Ports 38100–38109 are reserved for this file (e2e_sync.rs owns 38080–38089).

use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{json, Value};

const BAD_KIND_MSG: &str = "object_kind must be env|folder";

/// Values that must all be refused — no trimming, no case folding, no empty.
const BAD_KINDS: [&str; 4] = ["device", "", "ENV", " env"];

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
    reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(30)).build().unwrap()
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

/// One server per test, on its own data dir (name carries the test + pid so the
/// tests in this binary can run in parallel without deleting each other's dir).
fn spawn_server(data: &std::path::Path, port: u16) -> ServerGuard {
    let _ = std::fs::remove_dir_all(data);
    let bin = env!("CARGO_BIN_EXE_shardx-team-server");
    let child = Command::new(bin)
        .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", data)
        .env("SHARDX_TOKEN_SECRET", "e2e-acl-secret")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "secret")
        .spawn()
        .expect("spawn server binary");
    ServerGuard(child)
}

fn data_dir(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("shardx-e2e-acl-{name}-{}", std::process::id()))
}

async fn token(c: &reqwest::Client, port: u16, user: &str, pass: &str) -> String {
    let v: Value = c
        .post(format!("{}/auth/login", base(port)))
        .json(&json!({ "username": user, "password": pass }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["token"].as_str().expect("login token").to_string()
}

/// POST a JSON body as `tok`, asserting 2xx, and return the decoded body.
async fn post_ok(c: &reqwest::Client, port: u16, path: &str, tok: &str, body: Value) -> Value {
    let r = c
        .post(format!("{}{}", base(port), path))
        .bearer_auth(tok)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "POST {path} failed: {}", r.status());
    r.json().await.unwrap()
}

/// DELETE /acl with an optional bearer token; returns (status, body).
async fn revoke(
    c: &reqwest::Client,
    port: u16,
    tok: Option<&str>,
    user_id: &str,
    object_id: &str,
    object_kind: &str,
) -> (u16, Value) {
    let mut req = c.delete(format!("{}/acl", base(port)));
    if let Some(t) = tok {
        req = req.bearer_auth(t);
    }
    let r = req
        .json(&json!({ "user_id": user_id, "object_id": object_id, "object_kind": object_kind }))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

/// Create a member and return its id.
async fn make_member(c: &reqwest::Client, port: u16, admin: &str, name: &str) -> String {
    let v = post_ok(c, port, "/users", admin, json!({ "username": name, "password": "pw1" })).await;
    v["id"].as_str().expect("user id").to_string()
}

/// A pool onto the server's SQLite file, configured like the server's own.
async fn open_db(data: &std::path::Path) -> sqlx::SqlitePool {
    use std::str::FromStr;
    let db = data.join("shardx.db");
    let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&format!("sqlite://{}", db.display()))
        .unwrap()
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    sqlx::SqlitePool::connect_with(opts).await.unwrap()
}

/// Every rejected `object_kind` is a 400 carrying the exact grant-side message.
#[tokio::test]
async fn revoke_rejects_invalid_kind() {
    let port = 38100u16;
    let data = data_dir("badkind");
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    let mem_id = make_member(&c, port, &admin, "mem").await;
    let env = post_ok(&c, port, "/envs", &admin, json!({ "name": "e" })).await;
    let env_id = env["id"].as_str().unwrap().to_string();

    for kind in BAD_KINDS {
        let (status, body) = revoke(&c, port, Some(&admin), &mem_id, &env_id, kind).await;
        assert_eq!(status, 400, "kind {kind:?} must be a 400");
        assert_eq!(body, json!({ "error": BAD_KIND_MSG }), "kind {kind:?} body");
    }
}

/// Authorization runs before the kind check: a member sending a well-formed but
/// invalid kind still gets 403 (and no token at all is 401) — the kind-validation
/// 400 is only reachable by an admin, so it can't be used to probe as a member.
#[tokio::test]
async fn revoke_kind_validation_runs_after_admin_check() {
    let port = 38101u16;
    let data = data_dir("authfirst");
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    let mem_id = make_member(&c, port, &admin, "mem").await;
    let mem = token(&c, port, "mem", "pw1").await;

    for kind in BAD_KINDS {
        let (status, body) = revoke(&c, port, Some(&mem), &mem_id, "whatever", kind).await;
        assert_eq!(status, 403, "member + kind {kind:?} must stay 403");
        assert_eq!(body, json!({ "error": "forbidden" }), "member + kind {kind:?} body");

        let (status, _) = revoke(&c, port, None, &mem_id, "whatever", kind).await;
        assert_eq!(status, 401, "anonymous + kind {kind:?} must stay 401");
    }
}

/// The legal path is unchanged: env and folder grants revoke once with
/// `{ revoked: true }`, and a repeat revoke of the same row is a 404.
#[tokio::test]
async fn revoke_env_and_folder_roundtrip() {
    let port = 38102u16;
    let data = data_dir("roundtrip");
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    let mem_id = make_member(&c, port, &admin, "mem").await;
    let folder = post_ok(&c, port, "/folders", &admin, json!({ "name": "F" })).await;
    let folder_id = folder["id"].as_str().unwrap().to_string();
    let env = post_ok(&c, port, "/envs", &admin, json!({ "name": "e" })).await;
    let env_id = env["id"].as_str().unwrap().to_string();

    for (object_id, kind) in [(&env_id, "env"), (&folder_id, "folder")] {
        post_ok(
            &c,
            port,
            "/acl",
            &admin,
            json!({ "user_id": mem_id, "object_id": object_id, "object_kind": kind, "perm": "use" }),
        )
        .await;
    }

    // env: first revoke succeeds, the second finds nothing left.
    let (status, body) = revoke(&c, port, Some(&admin), &mem_id, &env_id, "env").await;
    assert_eq!(status, 200, "env revoke succeeds");
    assert_eq!(body, json!({ "revoked": true }));
    let (status, body) = revoke(&c, port, Some(&admin), &mem_id, &env_id, "env").await;
    assert_eq!(status, 404, "second env revoke is a 404, not a 400");
    assert_eq!(body, json!({ "error": "not found" }));

    // folder grants revoke the same way.
    let (status, body) = revoke(&c, port, Some(&admin), &mem_id, &folder_id, "folder").await;
    assert_eq!(status, 200, "folder revoke succeeds");
    assert_eq!(body, json!({ "revoked": true }));
}

/// The check must happen *before* the DELETE: seed a row whose kind the API
/// would never accept (the table has no CHECK, so pre-fix data can look like
/// this), then try to revoke it. The request is refused, the row survives, and
/// nothing is written to the audit trail.
#[tokio::test]
async fn invalid_kind_revoke_leaves_db_and_audit_untouched() {
    use sqlx::Row;

    let port = 38103u16;
    let data = data_dir("dbuntouched");
    let _guard = spawn_server(&data, port);
    let c = client();
    wait_health(&c, port).await;
    let admin = token(&c, port, "admin", "secret").await;

    let mem_id = make_member(&c, port, &admin, "mem").await;

    // Seed the illegal row directly, then drop the connection before issuing
    // any request so the server never contends with this pool.
    {
        let pool = open_db(&data).await;
        sqlx::query("INSERT INTO acl (user_id, object_id, object_kind, perm) VALUES (?, ?, ?, ?)")
            .bind(&mem_id)
            .bind("legacy-object")
            .bind("device")
            .bind("edit")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    let (status, body) = revoke(&c, port, Some(&admin), &mem_id, "legacy-object", "device").await;
    assert_eq!(status, 400, "illegal kind is refused before the DELETE");
    assert_eq!(body, json!({ "error": BAD_KIND_MSG }));

    // The seeded row is still there, untouched.
    {
        let pool = open_db(&data).await;
        let row = sqlx::query(
            "SELECT perm FROM acl WHERE user_id = ? AND object_id = ? AND object_kind = ?",
        )
        .bind(&mem_id)
        .bind("legacy-object")
        .bind("device")
        .fetch_optional(&pool)
        .await
        .unwrap();
        let perm: Option<String> = row.map(|r| r.get::<String, _>("perm"));
        assert_eq!(perm.as_deref(), Some("edit"), "rejected revoke must not delete the row");
        pool.close().await;
    }

    // ...and the refusal left no acl_revoke audit entry.
    let audit: Value = c
        .get(format!("{}/audit?action=acl_revoke", base(port)))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(audit, json!([]), "a refused revoke must not be audited");
}
