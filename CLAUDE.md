# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ShardX Launcher: a **Tauri 2 (Rust) + React 19 (TypeScript/Vite)** desktop app that
manages anti-detect browser *profiles* and launches a patched Chromium 149 engine
("ShardX") with per-profile fingerprint spoofing and proxy binding. The actual
fingerprint spoofing happens **inside the patched Chromium C++ engine** (not in this
repo) — this launcher's job is to manage on-disk profile state, resolve auto fields
(timezone/locale/geo) from the proxy, assemble the right `--flag` set, and start/stop
the browser process.

The same on-disk state is driven four ways, all in this repo:
- **Desktop UI** — `src/App.tsx` (single ~4.8k-line file), talks to Rust via Tauri `invoke`.
- **Local HTTP API** — axum server on `127.0.0.1:40325`, Bearer-JWT (`src-tauri/src/api.rs`).
- **MCP server** — `mcp/index.js`, wraps the HTTP API + browser-over-CDP via patchright.
- **Standalone SDKs** — `sdks/{python,node,rust}`, re-implement the launch pipeline with no GUI.

## Commands

```bash
npm install
npm run tauri dev      # dev with hot reload (frontend on 127.0.0.1:1420)
npm run tauri build    # release bundle → src-tauri/target/release/bundle/
npm run dev            # frontend-only Vite (rarely useful alone — needs the Rust host)
npm run build          # tsc typecheck + vite build (no Tauri)
```

Rust backend (run from `src-tauri/`):
```bash
cargo build            # or cargo check for a fast compile check
cargo fmt
cargo clippy
```

There is no automated test suite in this repo; verification is manual via the running app
or the live HTTP API. The README's `cd rust/shardx-launcher` is stale — the repo root *is*
the launcher.

## Architecture

### Rust backend (`src-tauri/src/`)
The frontend never touches the filesystem directly — every action is a `#[tauri::command]`
in `lib.rs` (the command list is registered in `generate_handler![...]` near the bottom of
`run()`). `lib.rs` is also where launcher-side fingerprint massaging lives (platform-version
pools, GPU-preset inference). Modules:

- `store.rs` — **storage layout authority**. Everything lives under `$CONFIG/shardx-launcher/`
  (`~/Library/Application Support/...` mac, `%APPDATA%\...` win, `~/.config/...` linux):
  `profiles/`, `fingerprints/`, `proxies.json`, `user-data/<profile-id>/`, `settings.json`.
- `profile.rs` — `ProfileMeta` (launcher view) wrapping a raw `FingerprintConfig` JSON blob.
- `launch.rs` — **the core orchestration**. `launch_profile()` resolves the binary, writes the
  resolved fingerprint file, resolves `"auto"` tz/locale/geo from the proxy, assembles all
  Chromium `--flags` (proxy, QUIC, WebRTC policy, CDP, headless, Widevine), spawns the child,
  and reads back the CDP endpoint from `DevToolsActivePort`.
- `proxy.rs` — proxy entries + live testing (TCP connect, SOCKS5 `UDP_ASSOCIATE` probe, geo lookup).
  The UDP probe result decides QUIC/WebRTC policy at launch.
- `proxy_auth.rs` — Chromium ignores credentials in `--proxy-server`, so for **CDP launches only**
  this answers `Fetch.authRequired` over the DevTools WebSocket. UI launches stay CDP-free.
- `process.rs` — `Tracker` (global `Mutex<HashMap<profile_id, child>>`) holds running children,
  pids, CDP info, and accumulates per-profile runtime.
- `runtime.rs` — **self-bootstrapping**: on first launch downloads the patched Chromium + Widevine
  + fingerprint library from Cloudflare R2, gated by etags in `runtime.json` (served from GitHub raw).
  Also migrates existing profiles' UA/client-hints on engine uprev (`ensure_profiles_migrated`).
- `cookies.rs` — import/export the profile's Chromium Cookies SQLite. Decryption differs per OS
  (mac/linux AES-128-CBC with fixed keys since the engine runs `--use-mock-keychain`; win AES-256-GCM
  + DPAPI). See the file header for the exact key derivation.
- `api.rs` — axum router; `serve(secret, port)` is spawned from `run()`'s setup. All routes except
  `GET /health` go through the `auth` middleware (HS256 Bearer). Routes mirror the OpenAPI spec.
- `fingerprints.rs` — user-curated fingerprint library; the GPU select in the editor reads from here.
- `settings.rs` / `mcp_setup.rs` / `psapi.rs` (ProxyShard account API) / `store.rs`.

### Frontend (`src/App.tsx`)
One large file, organized by sections (toasts, modals, tabs for Profiles / Proxies / Fingerprints /
Settings). State flows entirely through `invoke("command_name", {...})` and `listen(...)` for
runtime download progress (`runtime:progress` / `runtime:done`). `HOST_OS` is detected from the
webview UA and is the launcher's *real* OS — never spoofed; it drives the titlebar and default tab.

### Source of truth for shared concepts
- `openapi.yaml` — authoritative HTTP API schema. Keep `api.rs` routes and the SDKs in sync with it.
- `runtime.json` — the engine/fingerprint manifest (chromium_version, archive etags, GREASE brand/version).
  Bump `revision` + etags when shipping a new engine bundle.
- The launch pipeline is **duplicated** in `launch.rs` and each SDK (`sdks/*/.../browser.*`,
  `auto_resolve.*`, `randomize.*`). A change to launch behavior (new flag, changed auto-resolution,
  WebRTC policy logic) must be mirrored across all of them, not just the Rust backend.

## Team server (shared environments) — added feature

Beyond the original single-machine launcher, the repo now has an **optional self-hosted
team server** for multi-user shared environments with exclusive checkout locks. Full design
+ status in `docs/team-server.md`. Three pieces:

- `server/` — standalone axum + SQLite crate (`shardx-team-server`): users/roles/JWT auth,
  env/folder/proxy CRUD, per-user ACL, checkout locks (lease-based), and opaque snapshot
  blob storage. Self-contained (not in a workspace with `src-tauri`); `cargo run` / Docker.
  Integration test: `server/tests/e2e_sync.rs`.
- `shared/` — `shardx-core` crate (no Tauri dep): Chromium `os_crypt` v10 cookie/secret
  encryption with the key handled explicitly (so cookies re-encrypt across machines, incl.
  Mac↔Windows), and portable `user-data-dir` snapshot pack/unpack (excludes cache + the
  machine-bound key, rebuilds the Cookies DB on the destination). Unit-tested in isolation.
- Launcher side: `src-tauri/src/sync.rs` (team-server HTTP client; `pull` = checkout+unpack,
  `push` = pack+checkin) wired into `launch.rs` (pre-launch checkout + lease renewer) and
  `process.rs` (checkin on exit); `profile.rs` `StoredMeta.remote_env_id` maps a local profile
  to a remote env; `remote_*` Tauri commands in `lib.rs`; `TeamView` in `src/App.tsx`.

Note `cookies.rs` (existing) and `shared/src/cookies.rs` currently both implement the
os_crypt scheme — a future cleanup is to have `src-tauri` delegate to `shardx-core`.

## Conventions & gotchas

- **Tauri command pattern**: backend functions return `Result<T, String>` (errors stringified via
  `.map_err(|e| e.to_string())`); add new ones to the `generate_handler![]` list or they won't be callable.
- **Vite dev server must bind `127.0.0.1`** literally (see `vite.config.ts` comment) — `localhost`
  resolves IPv6-only on Windows and hangs Tauri's frontend health check.
- **Window close hides to tray** by default (`minimize_to_tray` setting); it does not quit.
- **Single-instance**: a second launch focuses the existing window (plugin must stay first in `run()`).
- macOS uses native traffic-light overlay; Win/Linux strip native decorations and draw a custom titlebar.
- The browser binary, Widevine, and fingerprint library are **not** in the repo — they're fetched at
  runtime. Don't commit them. `dist/` and `src-tauri/target/` are build output.
