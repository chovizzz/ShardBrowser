# ---- build ----
FROM rust:1-bookworm AS build
WORKDIR /app
COPY Cargo.toml ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release

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
