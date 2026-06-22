//! CDP-side proxy authentication.
//!
//! Chromium ignores credentials embedded in `--proxy-server`, so an
//! authenticated HTTP/HTTPS proxy makes Chrome pop a Basic-auth dialog and the
//! page fails to load. On API launches (CDP enabled) we connect to the
//! browser's DevTools endpoint and answer `Fetch.authRequired` with the stored
//! credentials — invisible to the page, no extra process, no fingerprint
//! surface, and only on automated launches (UI launches stay CDP-free).
//!
//! SOCKS5 auth is a SOCKS-layer concern (no HTTP 407 challenge) and is not
//! handled here.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Spawn a background task that supplies proxy credentials over CDP for the
/// lifetime of the browser. It ends quietly when the DevTools WebSocket closes
/// (i.e. when the profile stops).
pub fn spawn(ws_url: String, username: String, password: String) {
    tokio::spawn(async move {
        if let Err(e) = run(&ws_url, &username, &password).await {
            eprintln!("[proxy-auth] handler stopped: {e}");
        }
    });
}

async fn run(ws_url: &str, username: &str, password: &str) -> anyhow::Result<()> {
    let (ws, _) = connect_async(ws_url).await?;
    let (mut tx, mut rx) = ws.split();
    let mut next_id: i64 = 0;

    // Build + send a CDP command; `session=None` targets the browser endpoint.
    macro_rules! send {
        ($method:expr, $params:expr, $session:expr) => {{
            next_id += 1;
            let mut msg = json!({ "id": next_id, "method": $method, "params": $params });
            if let Some(sid) = $session {
                msg["sessionId"] = json!(sid);
            }
            tx.send(Message::Text(serde_json::to_string(&msg)?.into())).await?;
        }};
    }

    // Attach to every current and future page target (flattened sessions), so
    // we receive each target's Fetch events on this one connection.
    send!(
        "Target.setAutoAttach",
        json!({ "autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true }),
        None::<&str>
    );

    while let Some(frame) = rx.next().await {
        let txt = match frame? {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            _ => continue,
        };
        let v: Value = match serde_json::from_str(&txt) {
            Ok(v) => v,
            Err(_) => continue,
        };

        match v.get("method").and_then(|m| m.as_str()) {
            // New target attached → start intercepting so auth challenges surface.
            Some("Target.attachedToTarget") => {
                if let Some(sid) = v["params"]["sessionId"].as_str() {
                    let sid = sid.to_string();
                    send!(
                        "Fetch.enable",
                        json!({ "handleAuthRequests": true, "patterns": [{ "urlPattern": "*" }] }),
                        Some(sid.as_str())
                    );
                }
            }
            // Proxy (or site) auth challenge → answer with the stored credentials.
            Some("Fetch.authRequired") => {
                let sid = v.get("sessionId").and_then(|s| s.as_str()).map(str::to_string);
                if let Some(rid) = v["params"]["requestId"].as_str() {
                    let rid = rid.to_string();
                    send!(
                        "Fetch.continueWithAuth",
                        json!({
                            "requestId": rid,
                            "authChallengeResponse": {
                                "response": "ProvideCredentials",
                                "username": username,
                                "password": password
                            }
                        }),
                        sid.as_deref()
                    );
                }
            }
            // Every intercepted request must be resumed or the page hangs.
            Some("Fetch.requestPaused") => {
                let sid = v.get("sessionId").and_then(|s| s.as_str()).map(str::to_string);
                if let Some(rid) = v["params"]["requestId"].as_str() {
                    let rid = rid.to_string();
                    send!("Fetch.continueRequest", json!({ "requestId": rid }), sid.as_deref());
                }
            }
            _ => {}
        }
    }

    Ok(())
}
