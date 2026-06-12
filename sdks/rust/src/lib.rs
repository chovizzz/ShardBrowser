//! # ShardX Rust SDK
//!
//! Self-contained SDK for the [ShardX](https://proxyshard.com?utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher)
//! anti-detect browser. Mirrors the Python (`shardx`) and Node
//! (`@proxyshard/shardx`) SDKs: on first use it downloads the engine,
//! Widevine CDM, and the bundled fingerprint library from the ProxyShard
//! CDN into a per-user cache dir, then launches isolated profiles with the
//! same spoofing flags the desktop launcher uses.
//!
//! ```no_run
//! use shardx::{ShardX, ShardXOptions, LaunchOptions};
//!
//! # async fn run() -> anyhow::Result<()> {
//! let sdk = ShardX::new(ShardXOptions::default())?;
//!
//! // Launch a random profile through a proxy AND attach a CDP browser.
//! let session = sdk
//!     .session(None, LaunchOptions {
//!         proxy: Some("socks5://user:pass@host:1080".into()),
//!         ..Default::default()
//!     })
//!     .await?;
//!
//! let _page = session.new_page("https://example.com").await?;
//! // ... drive `session.browser` (chromiumoxide) ...
//! session.close().await?;
//! # Ok(())
//! # }
//! ```

mod auto_resolve;
mod browser;
#[cfg(feature = "control")]
mod control;
mod geo;
mod host;
mod profile;
mod proxy;
mod randomize;
mod runtime;
mod screen;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use rand::seq::SliceRandom;
use serde_json::Value;

pub use auto_resolve::{has_auto_fields, resolve_auto_fields};
pub use browser::{Browser, BrowserSession, LaunchOptions, WebRtcMode};
#[cfg(feature = "control")]
pub use chromiumoxide;
#[cfg(feature = "control")]
pub use control::Session;
pub use geo::{geo_check_via, GeoInfo};
pub use host::{host_logical_cores, host_ram_bucket_gb, host_ram_gb, host_screen_size, Size};
pub use profile::{apply_engine_version, user_data_dir, FingerprintLibrary, Profile};
pub use proxy::{parse_proxy, probe_udp, proxy_to_arg, ParsedProxy, ProxyScheme};
pub use randomize::{
    mac_hw_configs, randomize_hardware, randomize_platform_version, LINUX_PLATFORM_VERSIONS,
    MACOS_PLATFORM_VERSIONS, WINDOWS_PLATFORM_VERSIONS, X86_CORES,
};
pub use runtime::{
    default_cache_dir, host_spec, Archive, HostSpec, ProgressCb, Runtime, CHROMIUM_VERSION,
    PUB_BASE,
};
pub use screen::{apply_screen_strategy, default_screen_mode_for, ScreenStrategy};

/// Construction options for [`ShardX`].
#[derive(Default)]
pub struct ShardXOptions {
    /// Where the engine, Widevine, and fingerprint library live
    /// (defaults to the per-OS app-data dir — see [`default_cache_dir`]).
    pub cache_dir: Option<PathBuf>,
    /// Per-profile user-data-dir root. Defaults to `<cache_dir>/profiles/`.
    pub profiles_dir: Option<PathBuf>,
    /// Optional download-progress callback `(label, received, total)`.
    pub progress: Option<ProgressCb>,
}

/// What to launch: a library id, a ready [`Profile`], or a raw config object.
pub enum LaunchInput {
    Id(String),
    Profile(Profile),
    Config(Value),
}

impl From<&str> for LaunchInput {
    fn from(s: &str) -> Self {
        LaunchInput::Id(s.to_string())
    }
}
impl From<String> for LaunchInput {
    fn from(s: String) -> Self {
        LaunchInput::Id(s)
    }
}
impl From<Profile> for LaunchInput {
    fn from(p: Profile) -> Self {
        LaunchInput::Profile(p)
    }
}
impl From<Value> for LaunchInput {
    fn from(v: Value) -> Self {
        LaunchInput::Config(v)
    }
}

/// Result of [`ShardX::check_proxy`] — the same data the launcher uses to
/// decide QUIC + WebRTC policy.
#[derive(Debug, Clone)]
pub struct ProxyCheckResult {
    pub udp_ms: Option<u128>,
    pub geo: GeoInfo,
    pub would_enable_quic: bool,
    pub would_set_webrtc: WebRtcMode,
}

/// Top-level façade — bundles the runtime, fingerprint library, and browser
/// launcher. Mirrors the Python `ShardX` class / Node `ShardX`.
pub struct ShardX {
    pub runtime: Arc<Runtime>,
    library: FingerprintLibrary,
    browser: Browser,
}

impl ShardX {
    pub fn new(opts: ShardXOptions) -> Result<Self> {
        let runtime = Arc::new(Runtime::new(
            opts.cache_dir,
            opts.profiles_dir,
            opts.progress,
        )?);
        Ok(Self {
            library: FingerprintLibrary::new(runtime.clone()),
            browser: Browser::new(runtime.clone()),
            runtime,
        })
    }

    /// All bundled fingerprint ids, optionally filtered by `navigator.platform`
    /// substring. Auto-installs the fingerprint library on first call.
    pub async fn list_profiles(&self, platform: Option<&str>) -> Result<Vec<String>> {
        self.runtime.install(false).await?;
        Ok(match platform {
            Some(p) => self.library.filter(Some(p)),
            None => self.library.ids(),
        })
    }

    /// Pick a random profile from the library. Auto-installs on first call.
    pub async fn random_profile(&self, platform: Option<&str>) -> Result<Profile> {
        let ids = self.list_profiles(platform).await?;
        let id = ids.choose(&mut rand::thread_rng()).ok_or_else(|| {
            anyhow!(
                "No bundled profiles found{}.",
                platform.map(|p| format!(" for platform={p}")).unwrap_or_default()
            )
        })?;
        self.library.load(id)
    }

    /// Launch a profile.
    ///
    /// `input` is a library id, a [`Profile`], a raw config [`Value`], or
    /// `None` to pick a random profile (filtered by `opts.platform`).
    /// `opts.randomize` re-picks hardware_concurrency / device_memory /
    /// platform_version before launch.
    pub async fn launch(
        &self,
        input: Option<LaunchInput>,
        opts: LaunchOptions,
    ) -> Result<BrowserSession> {
        self.runtime.install(false).await?;
        let mut profile = match input {
            None => self.random_profile(opts.platform.as_deref()).await?,
            Some(LaunchInput::Id(id)) => self.library.load(&id)?,
            Some(LaunchInput::Profile(p)) => p,
            Some(LaunchInput::Config(v)) => Profile::new(v, None),
        };
        if opts.randomize {
            let id = profile.id.clone();
            randomize_hardware(&mut profile.config, Some(&id));
            randomize_platform_version(&mut profile.config);
        }
        self.browser.launch(profile, opts).await
    }

    /// Launch a profile **and connect a CDP browser** in one call (forces
    /// `cdp = true`). Returns a [`Session`] that owns both the driven
    /// `chromiumoxide` browser and the engine process; call
    /// [`Session::close`] to tear both down.
    ///
    /// Requires the default `control` feature.
    #[cfg(feature = "control")]
    pub async fn session(
        &self,
        input: Option<LaunchInput>,
        mut opts: LaunchOptions,
    ) -> Result<Session> {
        opts.cdp = true;
        let engine = self.launch(input, opts).await?;
        if engine.cdp_url.is_none() {
            let mut engine = engine;
            let _ = engine.stop().await;
            return Err(anyhow!(
                "CDP endpoint unavailable — engine failed to expose remote-debugging port"
            ));
        }
        Session::connect(engine).await
    }

    /// Launch with the CDP endpoint enabled but **without** attaching a
    /// driver — returns the raw [`BrowserSession`]; connect your own CDP
    /// client to [`BrowserSession::cdp_url`]. Always available (no `control`
    /// feature needed).
    pub async fn launch_cdp(
        &self,
        input: Option<LaunchInput>,
        mut opts: LaunchOptions,
    ) -> Result<BrowserSession> {
        opts.cdp = true;
        let mut session = self.launch(input, opts).await?;
        if session.cdp_url.is_none() {
            let _ = session.stop().await;
            return Err(anyhow!(
                "CDP endpoint unavailable — engine failed to expose remote-debugging port"
            ));
        }
        Ok(session)
    }

    /// Validate a proxy URL before binding it to a profile.
    pub async fn check_proxy(&self, proxy_url: &str) -> Result<ProxyCheckResult> {
        let parsed = parse_proxy(proxy_url)?;
        let udp_ms = if parsed.scheme == ProxyScheme::Socks5 {
            probe_udp(&parsed, 6000).await.ok()
        } else {
            None
        };
        let geo = geo_check_via(Some(&parsed), "ip-api.com").await?;
        let udp_ok = udp_ms.is_some();
        Ok(ProxyCheckResult {
            udp_ms,
            geo,
            would_enable_quic: udp_ok,
            would_set_webrtc: if udp_ok {
                WebRtcMode::Auto
            } else {
                WebRtcMode::TcpOnly
            },
        })
    }
}
