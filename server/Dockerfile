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
ENV SHARDX_BIND=0.0.0.0:8080 \
    SHARDX_DATA_DIR=/data
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["shardx-team-server"]
