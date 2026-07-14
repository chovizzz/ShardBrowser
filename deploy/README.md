# Deploy: team server + Caddy (auto-HTTPS)

One-command deployment of the ShardX team server behind [Caddy](https://caddyserver.com),
which terminates HTTPS with an automatically issued & renewed Let's Encrypt
certificate. This is the recommended way to run the server on a remote host:
the snapshots it stores carry decrypted cookies, saved passwords, and card
numbers, so cross-machine traffic must be encrypted.

## Prerequisites

- A host with Docker + Docker Compose, reachable from the internet.
- A domain name whose public **DNS A/AAAA record points at this host**.
- Inbound **ports 80 and 443 open** (80 is needed for the ACME challenge and to
  redirect to HTTPS; 443 serves traffic).

## Steps

```bash
cd deploy
cp .env.example .env
# edit .env: set SHARDX_DOMAIN, and generate the two secrets:
#   openssl rand -hex 32      → SHARDX_TOKEN_SECRET
#   openssl rand -base64 18   → SHARDX_ADMIN_PASS
docker compose up -d --build
```

Caddy gets the certificate on first start (a few seconds once DNS + ports are
right). Check it:

```bash
curl https://team.example.com/health        # → ok
docker compose logs -f caddy                 # watch cert issuance
docker compose logs -f server                # watch the app
```

## Connecting the launcher

In each launcher's **Team** view, set the server URL to `https://<your domain>`
and log in with the admin account (or a member account the admin creates). No
warning should appear — plain `http://` to a remote host is flagged because the
payload is sensitive, which is exactly why this stack fronts the server with TLS.

## Notes

- **Only Caddy is exposed.** The server has no published port; it is reachable
  only through Caddy on the internal compose network. This is what makes
  `SHARDX_TRUST_PROXY=1` safe (see the comments in `docker-compose.yml`).
- **Data lives in the `shardx-data` volume** (SQLite DB + snapshot blobs) and
  **certs in `caddy-data`**. Both are named volumes that survive
  `docker compose down`; back them up. `docker compose down -v` deletes them.
- **Rotating `SHARDX_TOKEN_SECRET` logs everyone out** — set it once and keep it.
- To put this behind *another* proxy/CDN (Cloudflare, an ALB), add a
  `trusted_proxies` block to the `Caddyfile`; otherwise leave it as is.
