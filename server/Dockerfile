# ---- build ----
# NOTE: the build context is the REPO ROOT, not server/. The server crate has a
# dev-dependency on ../shared (shardx-core), which cargo resolves even for a
# release build, so both crates must be in the context. Build with:
#   docker build -f server/Dockerfile -t shardx-team-server .
# (docker compose in deploy/ already sets the context + dockerfile for you.)
FROM rust:1-bookworm AS build
WORKDIR /app
# `shardx-core` is referenced as ../shared → resolves to /shared from this WORKDIR.
COPY shared /shared
COPY server/Cargo.toml server/Cargo.lock ./
COPY server/migrations ./migrations
COPY server/src ./src
# --locked: build the exact committed Cargo.lock, never silently re-resolve.
RUN cargo build --release --locked

# ---- runtime ----
FROM debian:bookworm-slim
RUN useradd -m app && mkdir -p /data && chown app /data
COPY --from=build /app/target/release/shardx-team-server /usr/local/bin/shardx-team-server
USER app
# Binds 0.0.0.0 so the container is reachable via a mapped port / reverse proxy.
# Because that's network-facing, the server REFUSES to start on first run unless
# SHARDX_ADMIN_PASS is set to a real secret (see bootstrap_admin). Also set
# SHARDX_TOKEN_SECRET so issued tokens survive restarts.
ENV SHARDX_BIND=0.0.0.0:8080 \
    SHARDX_DATA_DIR=/data
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["shardx-team-server"]
