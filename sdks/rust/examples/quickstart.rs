//! Minimal end-to-end: install the engine, launch a random profile (optionally
//! through a proxy), drive it over CDP, then close.
//!
//! Run with:  cargo run --example quickstart

use shardx::{LaunchOptions, ShardX, ShardXOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sdk = ShardX::new(ShardXOptions::default())?;

    // Optionally validate a proxy first.
    // let check = sdk.check_proxy("socks5://user:pass@host:1080").await?;
    // println!("proxy exit {} ({})", check.geo.ip, check.geo.country_code);

    // Launch a random profile and attach a chromiumoxide browser.
    let session = sdk
        .session(
            None, // random profile
            LaunchOptions {
                // proxy: Some("socks5://user:pass@host:1080".into()),
                randomize: true,
                ..Default::default()
            },
        )
        .await?;

    println!(
        "launched pid={} udd={} quic={} webrtc={:?}",
        session.engine.pid,
        session.engine.user_data_dir.display(),
        session.engine.quic_enabled,
        session.engine.webrtc_mode,
    );

    let page = session.new_page("https://example.com").await?;
    println!("title: {:?}", page.get_title().await?);

    session.close().await?;
    Ok(())
}
