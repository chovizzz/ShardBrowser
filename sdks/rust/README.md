# `shardx` — Rust SDK

Self-contained Rust SDK for the **ShardX anti-detect browser** by the
[ProxyShard](https://proxyshard.com?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher)
team. Same surface as the [Python](../python) and [Node](../node) SDKs: on
first use it downloads the engine, Widevine CDM, and the bundled fingerprint
library from the ProxyShard CDN into a per-user cache dir, then launches
isolated profiles with the exact spoofing flags the desktop launcher uses.

Supported hosts: **macOS arm64**, **Windows x64**, **Linux x64**.
On macOS/Linux the system `unzip` is used for extraction (preserves symlinks
and exec bits) — install it with `brew install unzip` / `apt install unzip`.

## Install

```toml
[dependencies]
shardx = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quickstart — launch **and drive** the browser

`session()` launches the engine and attaches a [chromiumoxide](https://docs.rs/chromiumoxide)
CDP browser in one call (the Rust equivalent of patchright in the Python/Node
SDKs). It's behind the default `control` feature.

```rust
use shardx::{ShardX, ShardXOptions, LaunchOptions, LaunchInput};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sdk = ShardX::new(ShardXOptions::default())?;

    // List / pick fingerprints (auto-installs the library on first call).
    let ids = sdk.list_profiles(Some("Windows")).await?;
    println!("{} Windows profiles", ids.len());

    // Launch a specific profile through a proxy and get a driven browser.
    let session = sdk
        .session(
            Some(LaunchInput::from("win-rtx4060")),
            LaunchOptions {
                proxy: Some("socks5://user:pass@host:1080".into()),
                randomize: true, // re-pick hw_concurrency / device_memory / platform_version
                ..Default::default()
            },
        )
        .await?;

    println!(
        "pid={}  quic={}  webrtc={:?}",
        session.engine.pid, session.engine.quic_enabled, session.engine.webrtc_mode,
    );

    // Drive it with chromiumoxide.
    let page = session.new_page("https://example.com").await?;
    println!("title: {:?}", page.get_title().await?);
    // `session.browser` is the full `chromiumoxide::Browser` for anything else.

    session.close().await?; // disconnect + stop the engine
    Ok(())
}
```

Pass `None` as the first arg to launch a **random** profile (filtered by
`LaunchOptions::platform`). You can also launch from a raw config:
`LaunchInput::from(serde_json::json!({ ... }))`.

### Without a driver (lighter build)

If you don't want the CDP client, disable the feature
(`shardx = { version = "0.1", default-features = false }`) and use
`launch` (no CDP) or `launch_cdp` (exposes `session.cdp_url` for your own
client):

```rust
let mut engine = sdk.launch_cdp(None, LaunchOptions::default()).await?;
println!("CDP: {:?}", engine.cdp_url);
engine.stop().await?;
```

## Validate a proxy before binding it

```rust
let res = sdk.check_proxy("socks5://user:pass@host:1080").await?;
println!(
    "udp={:?}ms  quic={}  webrtc={:?}  exit={} ({})",
    res.udp_ms, res.would_enable_quic, res.would_set_webrtc,
    res.geo.ip, res.geo.country_code,
);
```

The same SOCKS5 `UDP_ASSOCIATE` probe the launcher runs decides whether QUIC
is enabled and whether WebRTC is forced to `tcp_only`.

## What `launch` does for you

Before spawning the engine the SDK reproduces the launcher's pre-flight:

* **auto-resolve** — fills `"auto"` timezone / language / geolocation from a
  live geo lookup *through the bound proxy* ([`resolve_auto_fields`]).
* **screen strategy** — `CapToHost` on macOS, `UseHost` on Win/Linux
  ([`apply_screen_strategy`]); override via `LaunchOptions::screen_mode`.
* **UDP probe** — decides QUIC + WebRTC policy from a live relay probe.

## Lower-level building blocks

Everything the façade uses is public and reusable:

```rust
use shardx::{Runtime, FingerprintLibrary, parse_proxy, probe_udp, geo_check_via,
             randomize_hardware, host_screen_size};
```

`Runtime` (download/cache/extract), `FingerprintLibrary` + `Profile`,
`parse_proxy` / `proxy_to_arg` / `probe_udp`, `geo_check_via`,
`randomize_hardware` / `randomize_platform_version`, `host_*` probes, and the
`screen` / `auto_resolve` helpers.

## Links

* **Site:**  [https://proxyshard.com](https://proxyshard.com?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher)
* **Docs:**  [https://docs.proxyshard.com](https://docs.proxyshard.com?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher)
* **Usage:** [https://docs.proxyshard.com/eng/usage-instructions/shardx-browser](https://docs.proxyshard.com/eng/usage-instructions/shardx-browser?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher)

MIT licensed.
