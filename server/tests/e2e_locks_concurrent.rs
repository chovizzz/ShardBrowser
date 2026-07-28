//! Concurrency tests for the checkout-lock path.
//!
//! `e2e_sync.rs` drives the lock endpoints strictly one request at a time, so
//! the conditional upsert (`checkout`), the conditional UPDATE (`lease`), the
//! in-transaction conditional DELETE (`checkin`) and `force-unlock` had never
//! been raced against each other. These tests fire two genuinely concurrent
//! requests — two independent `reqwest::Client`s on two `tokio::spawn`ed tasks
//! released together by a three-party barrier — at the real server binary, and
//! assert the *set of allowed outcomes* plus the resulting state-machine
//! invariants. Each race is repeated on a fresh environment; a round is not
//! required to produce both orderings (that would be scheduler-dependent and
//! flaky), only to land inside the allowed set.
//!
//! This is a stress harness, not a deterministic rendezvous: the barrier makes
//! the two requests start together, it cannot prove the server interleaved them
//! at a chosen instruction. What it does prove is that neither observed
//! ordering can reach an illegal state. Where one side is inherently much
//! slower (a checkin uploads a snapshot; its opponent is a single statement)
//! the opponent's start is additionally swept across the checkin's in-flight
//! window, to sample both orderings rather than only the one the faster
//! request always wins — see [`opponent_delay`].
//!
//! Note the deliberate SOFT-LEASE semantics being pinned here: `lease`,
//! `checkin` and `release` do not check `lease_expires_at`, so an expired
//! holder that nobody has preempted can still operate. That is intentional
//! (see `soft_lease_lets_expired_holder_lease_release_and_checkin`), not a bug
//! to be "fixed" — only a competing `checkout` takes the lock away.
//!
//! The DB is opened directly only to age a lease past its expiry (the server
//! floors the TTL at 15s, too long to wait out) and to read final state. The
//! operations under test are always exercised through HTTP.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

/// How many times each race is repeated (on a fresh env every time).
/// A multiple of `opponent_delay`'s 8-step sweep, so every offset gets equal
/// weight rather than the low end being sampled twice as often.
const ROUNDS: usize = 16;

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

fn spawn_server(data: &Path, port: u16) -> ServerGuard {
    let _ = std::fs::remove_dir_all(data);
    let bin = env!("CARGO_BIN_EXE_shardx-team-server");
    let child = Command::new(bin)
        .env("SHARDX_BIND", format!("127.0.0.1:{port}"))
        .env("SHARDX_DATA_DIR", data)
        .env("SHARDX_TOKEN_SECRET", "locks-concurrent-secret")
        .env("SHARDX_ADMIN_USER", "admin")
        .env("SHARDX_ADMIN_PASS", "secret")
        .env("SHARDX_SNAPSHOT_KEEP", "3")
        .env("SHARDX_LEASE_TTL_SECS", "20")
        .spawn()
        .expect("spawn server binary");
    ServerGuard(child)
}

/// Wait for `/health`, but surface an early exit (e.g. the port was busy)
/// immediately instead of burning the whole timeout on a dead process.
async fn wait_health(c: &reqwest::Client, guard: &mut ServerGuard, port: u16) {
    for _ in 0..60 {
        if let Ok(Some(st)) = guard.0.try_wait() {
            panic!("server on port {port} exited before becoming healthy: {st}");
        }
        if let Ok(r) = c.get(format!("{}/health", base(port))).send().await {
            if r.status().is_success() {
                // The port answering does not prove OUR child is the one
                // answering — a leftover server from an aborted run would too.
                if let Ok(Some(st)) = guard.0.try_wait() {
                    panic!("port {port} is healthy but our server exited: {st} \
                            (stale server still bound to the port?)");
                }
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server did not become healthy on port {port}");
}

/// Open a connection and run one trivial request, so the connect/TLS-less
/// handshake cost is paid before a race rather than inside it.
async fn warm(c: &reqwest::Client, port: u16) {
    let r = c.get(format!("{}/health", base(port))).send().await.unwrap();
    assert!(r.status().is_success(), "warmup health: {}", r.status());
    let _ = r.bytes().await.unwrap();
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

// ---------------------------------------------------------------- requests --

#[derive(Debug)]
struct Resp {
    status: u16,
    body: Value,
}

impl Resp {
    fn s(&self, key: &str) -> String {
        self.body[key].as_str().unwrap_or_default().to_string()
    }
}

/// Drive a request to completion (status + parsed body). Built as a plain
/// future so it can be handed to [`race`] without borrowing anything.
async fn send(rb: reqwest::RequestBuilder) -> Resp {
    let r = rb.send().await.expect("request completes");
    let status = r.status().as_u16();
    // Every route here answers JSON. Falling back to Null on a parse failure
    // would let a corrupt or non-JSON body slide through the branches that only
    // check a status code, and would throw away the text needed to debug it.
    let text = r.text().await.expect("response body readable");
    let body = serde_json::from_str::<Value>(&text)
        .unwrap_or_else(|e| panic!("HTTP {status} body is not JSON ({e}): {text:?}"));
    Resp { status, body }
}

fn checkout_req(
    c: &reqwest::Client,
    port: u16,
    jwt: &str,
    env: &str,
    client_id: &str,
    tok: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut body = json!({ "client_id": client_id });
    if let Some(t) = tok {
        body["lock_token"] = json!(t);
    }
    c.post(format!("{}/envs/{env}/checkout", base(port))).bearer_auth(jwt).json(&body)
}

fn lease_req(
    c: &reqwest::Client,
    port: u16,
    jwt: &str,
    env: &str,
    client_id: &str,
    tok: &str,
) -> reqwest::RequestBuilder {
    c.post(format!("{}/envs/{env}/lease", base(port)))
        .bearer_auth(jwt)
        .json(&json!({ "client_id": client_id, "lock_token": tok }))
}

fn release_req(
    c: &reqwest::Client,
    port: u16,
    jwt: &str,
    env: &str,
    client_id: &str,
    tok: &str,
) -> reqwest::RequestBuilder {
    c.post(format!("{}/envs/{env}/release", base(port)))
        .bearer_auth(jwt)
        .json(&json!({ "client_id": client_id, "lock_token": tok }))
}

fn checkin_req(
    c: &reqwest::Client,
    port: u16,
    jwt: &str,
    env: &str,
    client_id: &str,
    tok: &str,
    bytes: Vec<u8>,
) -> reqwest::RequestBuilder {
    let form = reqwest::multipart::Form::new()
        .part("snapshot", reqwest::multipart::Part::bytes(bytes).file_name("s.tgz"));
    c.post(format!("{}/envs/{env}/checkin", base(port)))
        .bearer_auth(jwt)
        .header("x-client-id", client_id.to_string())
        .header("x-lock-token", tok.to_string())
        .multipart(form)
}

fn force_unlock_req(
    c: &reqwest::Client,
    port: u16,
    jwt: &str,
    env: &str,
) -> reqwest::RequestBuilder {
    c.post(format!("{}/envs/{env}/force-unlock", base(port))).bearer_auth(jwt)
}

/// The snapshot body used by every checkin here. Big enough (256 KiB) that the
/// upload is not a single instantaneous write — which widens the window between
/// checkin's pre-check and its transaction, the interleaving these tests hunt.
fn payload() -> Vec<u8> {
    (0..256 * 1024usize).map(|i| (i % 251) as u8).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Run two requests concurrently: each task parks on the barrier, and the test
/// task itself is the third party that releases them. `delay` holds the SECOND
/// request back by that much — see [`opponent_delay`] for why that is not a
/// retreat from concurrency.
async fn race<FA, FB, RA, RB>(fa: FA, fb: FB, delay: Duration) -> (RA, RB)
where
    FA: Future<Output = RA> + Send + 'static,
    FB: Future<Output = RB> + Send + 'static,
    RA: Send + 'static,
    RB: Send + 'static,
{
    let gate = Arc::new(tokio::sync::Barrier::new(3));
    let (ga, gb) = (gate.clone(), gate.clone());
    let ha = tokio::spawn(async move {
        ga.wait().await;
        fa.await
    });
    let hb = tokio::spawn(async move {
        gb.wait().await;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        fb.await
    });
    gate.wait().await;
    (ha.await.expect("task a"), hb.await.expect("task b"))
}

/// Number of delay offsets in the sweep; `ROUNDS` is a multiple of it so every
/// offset is sampled equally.
const SWEEP_STEPS: usize = 8;

/// A best-effort delay applied to the *faster* of two racing requests, swept
/// across rounds from a dead heat to just past a checkin's own duration.
///
/// A checkin uploads 256 KiB and then runs a transaction; `checkout` /
/// `force-unlock` are a single statement. From a dead-heat start the opponent
/// therefore won every one of 60 measured rounds and the "checkin committed
/// first" ordering was never sampled — those assertions were dead code. The
/// checkin only wins when its opponent fires near or after the checkin's commit
/// point, so the sweep has to *reach past* that duration; overshooting far
/// enough (~5x) just serialises the two and proves nothing either.
///
/// `unit` is therefore measured at runtime rather than hardcoded: a fixed
/// millisecond ladder calibrated on one machine silently stops reaching the
/// window on a slower or busier one. Observed directly while developing this —
/// the same ladder that produced 3-5 checkin wins per 16 rounds on an idle
/// laptop produced 0 on the same laptop under load, with every assertion still
/// passing. `Coverage` is what makes that visible; this is what makes it rare.
///
/// Coverage is still not guaranteed: no assertion requires a particular
/// ordering, every round merely has to land in its allowed outcome set.
/// Demanding both orderings would reintroduce exactly the scheduler-dependent
/// flakiness this design avoids.
fn opponent_delay(round: usize, unit: Duration) -> Duration {
    // 0, u/6, 2u/6 ... 7u/6 — a dead heat at one end, ~17% past the measured
    // checkin duration at the other.
    unit.mul_f64((round % SWEEP_STEPS) as f64 / 6.0)
}

/// Time one real checkin, so [`opponent_delay`] can scale its sweep to whatever
/// this machine actually costs. Uses a throwaway env, and leaves it checked in
/// (the caller races on fresh envs).
async fn calibrate_checkin(ctx: &Ctx, body: Vec<u8>) -> Duration {
    let env = ctx.new_env("calibrate").await;
    let tok = ctx.alice_holds(&env).await;
    let t0 = std::time::Instant::now();
    let r = send(checkin_req(&ctx.ca, ctx.port, &ctx.alice, &env, "a", &tok, body)).await;
    let dt = t0.elapsed();
    assert_eq!(r.status, 200, "calibration checkin should succeed: {r:?}");
    // A pathologically fast or slow measurement would make the sweep useless in
    // one direction or stall the suite in the other; clamp to a sane band.
    let dt = dt.clamp(Duration::from_millis(4), Duration::from_millis(120));
    println!("[calibration] checkin round-trip {dt:?} — sweeping opponent start over 0..{:?}", dt.mul_f64(7.0 / 6.0));
    dt
}

/// Tally of which interleaving each round actually produced.
///
/// The races below assert only that whatever ordering occurred left the state
/// machine intact — deliberately, since demanding both orderings every run
/// would be flaky on a loaded machine. The cost is that coverage can silently
/// collapse to one branch (a slow CI where checkin never outruns the delay
/// window), leaving the other branch's assertions as dead code while the test
/// still passes. So report the split: a `0` is not a failure, but it is the
/// signal that this test stopped proving half of what it claims.
///
/// Reporting happens in `Drop`, not at the end of the loop, so the split is
/// still printed when a round panics — that is precisely when you want to know
/// which interleavings had been reached.
struct Coverage {
    scenario: &'static str,
    labels: (&'static str, &'static str),
    counts: (usize, usize),
}

impl Coverage {
    fn new(scenario: &'static str, when_true: &'static str, when_false: &'static str) -> Self {
        Self { scenario, labels: (when_true, when_false), counts: (0, 0) }
    }

    fn record(&mut self, first_branch: bool) {
        if first_branch {
            self.counts.0 += 1;
        } else {
            self.counts.1 += 1;
        }
    }
}

impl Drop for Coverage {
    /// `cargo test -- --nocapture` surfaces this; on a failing round the
    /// harness prints the captured output anyway.
    fn drop(&mut self) {
        let (scenario, (a, b)) = (self.scenario, self.counts);
        let done = a + b;
        println!(
            "[coverage] {scenario}: {}={a}, {}={b} ({done}/{ROUNDS} rounds)",
            self.labels.0, self.labels.1
        );
        // Don't cry "no coverage" when the run simply aborted early — a panic
        // mid-loop is its own, louder signal.
        if done == ROUNDS && (a == 0 || b == 0) {
            println!(
                "[coverage] WARNING: {scenario} only exercised one interleaving this run — \
                 the other branch's assertions did not execute. Timing-dependent, not a failure."
            );
        }
    }
}

// --------------------------------------------------------------- DB probes --

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockRow {
    owner_user_id: String,
    owner_client_id: String,
    lock_token: String,
    acquired_at: String,
    lease_expires_at: String,
}

async fn lock_row(pool: &SqlitePool, env: &str) -> Option<LockRow> {
    sqlx::query_as::<_, (String, String, String, String, String)>(
        "SELECT owner_user_id, owner_client_id, lock_token, acquired_at, lease_expires_at \
         FROM locks WHERE env_id = ?",
    )
    .bind(env)
    .fetch_optional(pool)
    .await
    .unwrap()
    .map(|(u, c, t, a, e)| LockRow {
        owner_user_id: u,
        owner_client_id: c,
        lock_token: t,
        acquired_at: a,
        lease_expires_at: e,
    })
}

async fn lock_count(pool: &SqlitePool, env: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM locks WHERE env_id = ?")
        .bind(env)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn env_version(pool: &SqlitePool, env: &str) -> i64 {
    sqlx::query_scalar("SELECT current_version FROM environments WHERE id = ?")
        .bind(env)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// (version, blob_path, sha256, size, created_by) for every snapshot of an env.
async fn snapshot_rows(
    pool: &SqlitePool,
    env: &str,
) -> Vec<(i64, String, String, i64, Option<String>)> {
    sqlx::query_as("SELECT version, blob_path, sha256, size, created_by FROM snapshots \
                    WHERE env_id = ? ORDER BY version")
        .bind(env)
        .fetch_all(pool)
        .await
        .unwrap()
}

/// Force a lease into the past. The server floors the lease TTL at 15s, so the
/// only practical way to test expiry is to age the row.
async fn age_lease(pool: &SqlitePool, env: &str) {
    let n = sqlx::query("UPDATE locks SET lease_expires_at = '2000-01-01T00:00:00+00:00' \
                         WHERE env_id = ?")
        .bind(env)
        .execute(pool)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(n, 1, "aged exactly one lease for env {env}");
}

fn parse_ts(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap_or_else(|e| panic!("timestamp {s:?} is not RFC3339: {e}"))
        .with_timezone(&chrono::Utc)
}

fn env_blob_dir(data: &Path, env: &str) -> PathBuf {
    data.join("blobs").join(env)
}

/// Names of leftover `incoming-*.tmp` staging files — a failed checkin must not
/// leave any behind.
fn staging_temps(dir: &Path) -> Vec<String> {
    // A missing dir genuinely means "no staging files". Any other error (perms,
    // I/O) must not be read as a clean result — that would pass the assertion
    // for the wrong reason.
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => panic!("read_dir({}) failed: {e}", dir.display()),
    };
    rd.filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("incoming-") && n.ends_with(".tmp"))
        .collect()
}

// -------------------------------------------------------------- test setup --

/// One server + two independent clients + alice/bob (both granted `use` on a
/// shared folder, so each round only has to create an env inside it).
struct Ctx {
    _guard: ServerGuard,
    port: u16,
    data: PathBuf,
    pool: SqlitePool,
    ca: reqwest::Client,
    cb: reqwest::Client,
    admin: String,
    alice: String,
    bob: String,
    alice_id: String,
    bob_id: String,
    folder_id: String,
}

impl Ctx {
    async fn new(name: &str, port: u16) -> Ctx {
        let data =
            std::env::temp_dir().join(format!("shardx-e2e-lockrace-{name}-{}", std::process::id()));
        let mut guard = spawn_server(&data, port);
        let ca = client();
        let cb = client();
        wait_health(&ca, &mut guard, port).await;
        let admin = token(&ca, port, "admin", "secret").await;

        for u in ["alice", "bob"] {
            let r = ca
                .post(format!("{}/users", base(port)))
                .bearer_auth(&admin)
                .json(&json!({ "username": u, "password": "pw" }))
                .send()
                .await
                .unwrap();
            assert!(r.status().is_success(), "create {u}: {}", r.status());
        }
        let users: Value = ca
            .get(format!("{}/users", base(port)))
            .bearer_auth(&admin)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let uid = |who: &str| {
            users
                .as_array()
                .unwrap()
                .iter()
                .find(|u| u["username"] == who)
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let (alice_id, bob_id) = (uid("alice"), uid("bob"));

        let folder: Value = ca
            .post(format!("{}/folders", base(port)))
            .bearer_auth(&admin)
            .json(&json!({ "name": "race" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let folder_id = folder["id"].as_str().unwrap().to_string();
        // One folder-level grant each; every env created below inherits it.
        for id in [&alice_id, &bob_id] {
            let r = ca
                .post(format!("{}/acl", base(port)))
                .bearer_auth(&admin)
                .json(&json!({
                    "user_id": id, "object_id": folder_id,
                    "object_kind": "folder", "perm": "use",
                }))
                .send()
                .await
                .unwrap();
            assert!(r.status().is_success(), "grant: {}", r.status());
        }

        let alice = token(&ca, port, "alice", "pw").await;
        let bob = token(&cb, port, "bob", "pw").await;

        let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&format!(
            "sqlite://{}",
            data.join("shardx.db").display()
        ))
        .unwrap()
        .busy_timeout(Duration::from_secs(5));
        // A single observer connection: this pool only ages leases and reads
        // final state between races, it must not add write contention.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();

        Ctx {
            _guard: guard,
            port,
            data,
            pool,
            ca,
            cb,
            admin,
            alice,
            bob,
            alice_id,
            bob_id,
            folder_id,
        }
    }

    async fn new_env(&self, name: &str) -> String {
        let v: Value = self
            .ca
            .post(format!("{}/envs", base(self.port)))
            .bearer_auth(&self.admin)
            .json(&json!({ "name": name, "folder_id": self.folder_id }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["id"].as_str().expect("env id").to_string()
    }

    /// Pay the connection cost on both clients before the barrier drops.
    async fn warm_both(&self) {
        tokio::join!(warm(&self.ca, self.port), warm(&self.cb, self.port));
    }

    /// Alice takes the lock with client id `a`; returns her lock_token.
    async fn alice_holds(&self, env: &str) -> String {
        let r = send(checkout_req(&self.ca, self.port, &self.alice, env, "a", None)).await;
        assert_eq!(r.status, 200, "alice initial checkout: {:?}", r.body);
        r.s("lock_token")
    }
}

// ------------------------------------------------------------- scenario 1 ---

/// Two clients grab a free lock at the same instant. Exactly one wins; the
/// loser gets 409 and holds nothing it can act with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_checkouts_on_free_lock_elect_one_winner() {
    let ctx = Ctx::new("free", 38200).await;

    for round in 0..ROUNDS {
        let env = ctx.new_env(&format!("free-{round}")).await;
        ctx.warm_both().await;

        let (ra, rb) = race(
            send(checkout_req(&ctx.ca, ctx.port, &ctx.alice, &env, "a", None)),
            send(checkout_req(&ctx.cb, ctx.port, &ctx.bob, &env, "b", None)),
            Duration::ZERO,
        )
        .await;

        // The only legal outcome pair — in particular never 200/200 (two
        // holders) and never a 500 from a lost write race.
        let mut codes = [ra.status, rb.status];
        codes.sort_unstable();
        assert_eq!(codes, [200, 409], "round {round}: alice={ra:?} bob={rb:?}");

        let alice_won = ra.status == 200;
        let (win, lose) = if alice_won { (&ra, &rb) } else { (&rb, &ra) };
        let (win_user, win_client) = if alice_won {
            (&ctx.alice_id, "a")
        } else {
            (&ctx.bob_id, "b")
        };
        let (lose_jwt, lose_client) = if alice_won {
            (&ctx.bob, "b")
        } else {
            (&ctx.alice, "a")
        };

        // Winner's view of a never-checked-in env.
        assert_eq!(win.body["version"].as_i64(), Some(0), "round {round}");
        assert!(win.body["snapshot_url"].is_null(), "round {round}: no snapshot yet");
        assert_eq!(win.body["stale_takeover"].as_bool(), Some(false), "round {round}");
        assert_eq!(win.s("client_id"), win_client, "round {round}");
        let win_token = win.s("lock_token");
        assert!(!win_token.is_empty(), "round {round}: winner got a token");
        assert!(lose.body["lock_token"].is_null(), "round {round}: loser got no token");

        // Exactly one lock row, and it is the winner's.
        assert_eq!(lock_count(&ctx.pool, &env).await, 1, "round {round}");
        let row = lock_row(&ctx.pool, &env).await.expect("lock row");
        assert_eq!(&row.owner_user_id, win_user, "round {round}");
        assert_eq!(row.owner_client_id, win_client, "round {round}");
        assert_eq!(row.lock_token, win_token, "round {round}: DB token == response token");
        assert_eq!(row.lease_expires_at, win.s("lease_expires_at"), "round {round}");
        assert!(parse_ts(&row.lease_expires_at) > parse_ts(&row.acquired_at), "round {round}");

        // The loser cannot act on the lock with its own client id, whether it
        // presents no token or an invented one — and the probes leave the
        // winner's row byte-for-byte unchanged.
        for tok in ["", "invented-token"] {
            let l = send(lease_req(&ctx.ca, ctx.port, lose_jwt, &env, lose_client, tok)).await;
            assert_eq!(l.status, 409, "round {round}: loser lease(tok={tok:?})");
            let r = send(release_req(&ctx.ca, ctx.port, lose_jwt, &env, lose_client, tok)).await;
            assert_eq!(r.status, 409, "round {round}: loser release(tok={tok:?})");
        }
        assert_eq!(lock_row(&ctx.pool, &env).await.as_ref(), Some(&row), "round {round}");
        assert_eq!(env_version(&ctx.pool, &env).await, 0, "round {round}");
        assert!(snapshot_rows(&ctx.pool, &env).await.is_empty(), "round {round}");
    }
    ctx.pool.close().await;
}

// ------------------------------------------------------------- scenario 2 ---

/// An expired holder renewing its lease races a peer's takeover checkout.
/// Both are legal, but only one may win, and the surviving lock must match
/// whichever won.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_holder_lease_races_takeover_checkout() {
    let ctx = Ctx::new("renew", 38201).await;

    for round in 0..ROUNDS {
        let env = ctx.new_env(&format!("renew-{round}")).await;
        let alice_token = ctx.alice_holds(&env).await;
        let before_row = lock_row(&ctx.pool, &env).await.expect("alice's lock");
        age_lease(&ctx.pool, &env).await;
        ctx.warm_both().await;
        let started = chrono::Utc::now();

        let (lease, checkout) = race(
            send(lease_req(&ctx.ca, ctx.port, &ctx.alice, &env, "a", &alice_token)),
            send(checkout_req(&ctx.cb, ctx.port, &ctx.bob, &env, "b", None)),
            Duration::ZERO,
        )
        .await;

        let mut codes = [lease.status, checkout.status];
        codes.sort_unstable();
        assert_eq!(codes, [200, 409], "round {round}: lease={lease:?} checkout={checkout:?}");

        let row = lock_row(&ctx.pool, &env).await.expect("a lock still exists");
        if lease.status == 200 {
            // Soft lease renewed in time: alice keeps everything but the expiry.
            assert_eq!(row.owner_user_id, ctx.alice_id, "round {round}");
            assert_eq!(row.owner_client_id, "a", "round {round}");
            assert_eq!(row.lock_token, alice_token, "round {round}: token not rotated");
            assert_eq!(row.acquired_at, before_row.acquired_at, "round {round}");
            assert_eq!(row.lease_expires_at, lease.s("lease_expires_at"), "round {round}");
            assert!(parse_ts(&row.lease_expires_at) > started, "round {round}: expiry refreshed");
        } else {
            // Bob preempted the expired lease: holder and token both rotate.
            assert_eq!(checkout.status, 200, "round {round}");
            assert_eq!(checkout.body["stale_takeover"].as_bool(), Some(true), "round {round}");
            assert_eq!(checkout.body["previous_owner"].as_str(), Some("alice"), "round {round}");
            let bob_token = checkout.s("lock_token");
            assert!(!bob_token.is_empty(), "round {round}");
            assert_ne!(bob_token, alice_token, "round {round}: token rotated");
            assert_eq!(row.owner_user_id, ctx.bob_id, "round {round}");
            assert_eq!(row.owner_client_id, "b", "round {round}");
            assert_eq!(row.lock_token, bob_token, "round {round}");
            assert_eq!(row.lease_expires_at, checkout.s("lease_expires_at"), "round {round}");
            // Alice's token is dead now.
            let l = send(lease_req(&ctx.ca, ctx.port, &ctx.alice, &env, "a", &alice_token)).await;
            assert_eq!(l.status, 409, "round {round}: stale token can't renew");
            assert_eq!(lock_row(&ctx.pool, &env).await.as_ref(), Some(&row), "round {round}");
        }
        // Neither path touches env content.
        assert_eq!(lock_count(&ctx.pool, &env).await, 1, "round {round}");
        assert_eq!(env_version(&ctx.pool, &env).await, 0, "round {round}");
        assert!(snapshot_rows(&ctx.pool, &env).await.is_empty(), "round {round}");
    }
    ctx.pool.close().await;
}

// ------------------------------------------------------------- scenario 3 ---

/// An expired holder pushing its work races a peer's takeover checkout. The
/// takeover always succeeds (the lease is expired); the checkin either commits
/// first (200, version +1, then the peer takes a free slot) or loses the token
/// (409, nothing written). It must never overwrite the new holder's lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_holder_checkin_races_takeover_checkout() {
    let ctx = Ctx::new("checkin", 38202).await;
    let body = payload();
    let body_sha = sha_hex(&body);
    let mut seen = Coverage::new("checkin vs takeover", "checkin committed first", "checkout rotated first");
    let unit = calibrate_checkin(&ctx, body.clone()).await;

    for round in 0..ROUNDS {
        let env = ctx.new_env(&format!("checkin-{round}")).await;
        let alice_token = ctx.alice_holds(&env).await;
        age_lease(&ctx.pool, &env).await;
        ctx.warm_both().await;

        let (checkin, checkout) = race(
            send(checkin_req(
                &ctx.ca,
                ctx.port,
                &ctx.alice,
                &env,
                "a",
                &alice_token,
                body.clone(),
            )),
            send(checkout_req(&ctx.cb, ctx.port, &ctx.bob, &env, "b", None)),
            opponent_delay(round, unit),
        )
        .await;

        // The expired lease can always be taken; the checkin is the only
        // request whose outcome depends on the interleaving.
        assert_eq!(checkout.status, 200, "round {round}: takeover of an expired lease: {checkout:?}");
        assert!(
            checkin.status == 200 || checkin.status == 409,
            "round {round}: checkin must be 200 or 409, got {checkin:?}"
        );
        seen.record(checkin.status == 200);

        let version = env_version(&ctx.pool, &env).await;
        let snaps = snapshot_rows(&ctx.pool, &env).await;
        let blob_dir = env_blob_dir(&ctx.data, &env);
        if checkin.status == 200 {
            // Committed before the takeover, so the takeover must have observed
            // the NEW version — that binding is what stops a checkout from
            // handing out a stale snapshot_url.
            assert_eq!(version, 1, "round {round}: version bumped exactly once");
            assert_eq!(checkin.body["version"].as_i64(), Some(1), "round {round}");
            assert_eq!(checkin.s("sha256"), body_sha, "round {round}");
            assert_eq!(checkin.body["size"].as_i64(), Some(body.len() as i64), "round {round}");
            assert_eq!(checkout.body["version"].as_i64(), Some(1), "round {round}");
            assert_eq!(
                checkout.body["snapshot_url"].as_str(),
                Some(format!("/envs/{env}/snapshot/1").as_str()),
                "round {round}: takeover sees the just-committed snapshot"
            );
            assert_eq!(snaps.len(), 1, "round {round}: exactly one snapshot row");
            let (v, path, sha, size, by) = &snaps[0];
            assert_eq!(*v, 1, "round {round}");
            assert_eq!(sha, &body_sha, "round {round}");
            assert_eq!(*size, body.len() as i64, "round {round}");
            assert_eq!(by.as_deref(), Some(ctx.alice_id.as_str()), "round {round}");
            assert_eq!(std::fs::read(path).unwrap(), body, "round {round}: blob bytes match");
            // `stale_takeover` is a best-effort hint read before the upsert, so
            // in this branch it may legitimately go either way depending on
            // whether the checkin had committed when it was sampled.
            match checkout.body["stale_takeover"].as_bool() {
                Some(true) => assert_eq!(
                    checkout.body["previous_owner"].as_str(),
                    Some("alice"),
                    "round {round}"
                ),
                Some(false) => {
                    assert!(checkout.body.get("previous_owner").is_none(), "round {round}")
                }
                None => panic!("round {round}: stale_takeover must be a bool: {:?}", checkout.body),
            }
        } else {
            // Lost the token: the whole checkin is a no-op, no half-written
            // version and no orphaned blob.
            assert_eq!(version, 0, "round {round}: version untouched");
            assert!(snaps.is_empty(), "round {round}: no snapshot row");
            assert!(!blob_dir.join("1.blob").exists(), "round {round}: no orphan blob");
            assert_eq!(checkout.body["version"].as_i64(), Some(0), "round {round}");
            assert!(checkout.body["snapshot_url"].is_null(), "round {round}");
            // Bob replaced a lock row that was still alice's → definitely stale.
            assert_eq!(checkout.body["stale_takeover"].as_bool(), Some(true), "round {round}");
            assert_eq!(checkout.body["previous_owner"].as_str(), Some("alice"), "round {round}");
        }
        assert!(staging_temps(&blob_dir).is_empty(), "round {round}: no leftover upload temp");

        // Either way bob ends up holding the lock and alice's token is dead.
        let bob_token = checkout.s("lock_token");
        let row = lock_row(&ctx.pool, &env).await.expect("bob's lock");
        assert_eq!(lock_count(&ctx.pool, &env).await, 1, "round {round}");
        assert_eq!(row.owner_user_id, ctx.bob_id, "round {round}");
        assert_eq!(row.owner_client_id, "b", "round {round}");
        assert_eq!(row.lock_token, bob_token, "round {round}");
        assert_ne!(row.lock_token, alice_token, "round {round}");
        let l = send(lease_req(&ctx.ca, ctx.port, &ctx.alice, &env, "a", &alice_token)).await;
        assert_eq!(l.status, 409, "round {round}: alice's old token is dead");
        assert_eq!(
            lock_row(&ctx.pool, &env).await.as_ref(),
            Some(&row),
            "round {round}: the rejected probe changed nothing"
        );
    }
    ctx.pool.close().await;
}

// ------------------------------------------------------------- scenario 4 ---

/// An admin clearing a stuck lock races the holder's checkin. Exactly one of
/// them removes the row: either force-unlock wins (200) and the checkin is
/// rejected (409), or the checkin commits first (200) and force-unlock finds
/// nothing left (404). Both succeeding would mean the lock was deleted twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn force_unlock_races_holder_checkin() {
    let ctx = Ctx::new("force", 38203).await;
    let body = payload();
    let body_sha = sha_hex(&body);
    let mut seen = Coverage::new("force-unlock vs checkin", "checkin committed first", "force-unlock won");
    let unit = calibrate_checkin(&ctx, body.clone()).await;

    for round in 0..ROUNDS {
        let env = ctx.new_env(&format!("force-{round}")).await;
        // Lease stays LIVE here — the contention is the admin override, not
        // expiry.
        let alice_token = ctx.alice_holds(&env).await;
        ctx.warm_both().await;

        let (checkin, force) = race(
            send(checkin_req(
                &ctx.ca,
                ctx.port,
                &ctx.alice,
                &env,
                "a",
                &alice_token,
                body.clone(),
            )),
            send(force_unlock_req(&ctx.cb, ctx.port, &ctx.admin, &env)),
            opponent_delay(round, unit),
        )
        .await;

        let pair = (force.status, checkin.status);
        assert!(
            pair == (200, 409) || pair == (404, 200),
            "round {round}: force/checkin must be 200/409 or 404/200, got {pair:?} \
             force={force:?} checkin={checkin:?}"
        );
        seen.record(checkin.status == 200);

        // Whoever won, the lock is gone and nobody holds it.
        assert_eq!(lock_count(&ctx.pool, &env).await, 0, "round {round}: lock cleared");
        let version = env_version(&ctx.pool, &env).await;
        let snaps = snapshot_rows(&ctx.pool, &env).await;
        let blob_dir = env_blob_dir(&ctx.data, &env);
        if checkin.status == 200 {
            assert_eq!(version, 1, "round {round}: version bumped exactly once");
            assert_eq!(checkin.body["version"].as_i64(), Some(1), "round {round}");
            assert_eq!(checkin.s("sha256"), body_sha, "round {round}");
            assert_eq!(checkin.body["size"].as_i64(), Some(body.len() as i64), "round {round}");
            assert_eq!(snaps.len(), 1, "round {round}");
            let (v, path, sha, size, by) = &snaps[0];
            assert_eq!(*v, 1, "round {round}");
            assert_eq!(sha, &body_sha, "round {round}");
            assert_eq!(*size, body.len() as i64, "round {round}");
            assert_eq!(by.as_deref(), Some(ctx.alice_id.as_str()), "round {round}");
            assert_eq!(std::fs::read(path).unwrap(), body, "round {round}");
        } else {
            assert_eq!(version, 0, "round {round}: rejected checkin wrote nothing");
            assert!(snaps.is_empty(), "round {round}");
            assert!(!blob_dir.join("1.blob").exists(), "round {round}: no orphan blob");
        }
        assert!(staging_temps(&blob_dir).is_empty(), "round {round}: no leftover upload temp");

        // The unlocked env is freely re-checkoutable by anyone, with no
        // takeover flag (there is no previous holder to report).
        let re = send(checkout_req(&ctx.cb, ctx.port, &ctx.bob, &env, "b", None)).await;
        assert_eq!(re.status, 200, "round {round}: env re-checkoutable: {re:?}");
        assert_eq!(re.body["version"].as_i64(), Some(version), "round {round}");
        assert_eq!(re.body["stale_takeover"].as_bool(), Some(false), "round {round}");
    }
    ctx.pool.close().await;
}

// ------------------------------------------------------------- scenario 5 ---

/// Deterministic regression for the SOFT lease: `lease`, `release` and
/// `checkin` deliberately do NOT check `lease_expires_at`, so a holder whose
/// lease lapsed — but whom nobody preempted — can still renew, release and push
/// its work. Only a competing `checkout` (scenarios 2 and 3) ends the session.
///
/// The concurrent tests above can't pin this down: a race may be won by the
/// takeover every single run. Each behaviour gets its own env so they can't
/// mask each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn soft_lease_lets_expired_holder_lease_release_and_checkin() {
    let ctx = Ctx::new("soft", 38204).await;
    let body = payload();
    let body_sha = sha_hex(&body);

    // (a) an expired lease can still be renewed in place.
    {
        let env = ctx.new_env("soft-lease").await;
        let tok = ctx.alice_holds(&env).await;
        let before = lock_row(&ctx.pool, &env).await.expect("lock");
        age_lease(&ctx.pool, &env).await;
        let started = chrono::Utc::now();

        let r = send(lease_req(&ctx.ca, ctx.port, &ctx.alice, &env, "a", &tok)).await;
        assert_eq!(r.status, 200, "expired lease renews (soft lease): {r:?}");

        let row = lock_row(&ctx.pool, &env).await.expect("lock still held");
        assert_eq!(row.owner_user_id, ctx.alice_id);
        assert_eq!(row.owner_client_id, "a");
        assert_eq!(row.lock_token, tok, "renewal does not rotate the token");
        assert_eq!(row.acquired_at, before.acquired_at);
        assert_eq!(row.lease_expires_at, r.s("lease_expires_at"));
        assert!(parse_ts(&row.lease_expires_at) > started, "expiry moved into the future");
        assert_eq!(env_version(&ctx.pool, &env).await, 0);
    }

    // (b) an expired holder can still release.
    {
        let env = ctx.new_env("soft-release").await;
        let tok = ctx.alice_holds(&env).await;
        age_lease(&ctx.pool, &env).await;

        let r = send(release_req(&ctx.ca, ctx.port, &ctx.alice, &env, "a", &tok)).await;
        assert_eq!(r.status, 200, "expired holder releases (soft lease): {r:?}");
        assert_eq!(r.body["released"].as_bool(), Some(true));

        assert_eq!(lock_count(&ctx.pool, &env).await, 0, "lock gone");
        assert_eq!(env_version(&ctx.pool, &env).await, 0, "release discards, no version");
        assert!(snapshot_rows(&ctx.pool, &env).await.is_empty());
    }

    // (c) an expired holder can still push its work.
    {
        let env = ctx.new_env("soft-checkin").await;
        let tok = ctx.alice_holds(&env).await;
        age_lease(&ctx.pool, &env).await;

        let r = send(checkin_req(&ctx.ca, ctx.port, &ctx.alice, &env, "a", &tok, body.clone())).await;
        assert_eq!(r.status, 200, "expired holder checks in (soft lease): {r:?}");
        assert_eq!(r.body["version"].as_i64(), Some(1));
        assert_eq!(r.s("sha256"), body_sha);

        assert_eq!(lock_count(&ctx.pool, &env).await, 0, "checkin releases the lock");
        assert_eq!(env_version(&ctx.pool, &env).await, 1);
        let snaps = snapshot_rows(&ctx.pool, &env).await;
        assert_eq!(snaps.len(), 1);
        let (v, path, sha, size, by) = &snaps[0];
        assert_eq!(*v, 1);
        assert_eq!(sha, &body_sha);
        assert_eq!(*size, body.len() as i64);
        assert_eq!(by.as_deref(), Some(ctx.alice_id.as_str()));
        assert_eq!(std::fs::read(path).unwrap(), body);
        assert!(staging_temps(&env_blob_dir(&ctx.data, &env)).is_empty());
    }
    ctx.pool.close().await;
}
