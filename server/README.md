# ShardX Team Server

Self-hosted team backend for ShardX: user/role management, shared environments,
and (in later phases) exclusive checkout locks + environment-data snapshots.

> Design & roadmap: [`../docs/team-server.md`](../docs/team-server.md).
> **Done: Phase 1** (accounts, roles, env/folder/proxy CRUD, per-user ACL) and
> **Phase 2** (exclusive checkout locks with leases + opaque snapshot
> upload/download with retention GC). Next: Phase 3 (client-side encryption
> normalization for Mac+Windows) and Phase 4 (launcher integration).

## Run

```bash
# dev
cd server
SHARDX_TOKEN_SECRET=dev-secret SHARDX_ADMIN_PASS=secret cargo run

# docker
docker build -t shardx-team-server server/
docker run -p 8080:8080 -v "$PWD/data:/data" \
  -e SHARDX_TOKEN_SECRET=$(openssl rand -hex 32) \
  -e SHARDX_ADMIN_USER=admin -e SHARDX_ADMIN_PASS=secret \
  shardx-team-server
```

Config is all environment variables — see [`.env.example`](.env.example).
SQLite DB + snapshot blobs live under `SHARDX_DATA_DIR` (`/data` in Docker).
On first start with an empty user table, an admin is bootstrapped from
`SHARDX_ADMIN_USER` / `SHARDX_ADMIN_PASS`.

## API (Phase 1)

Every route except `/health` and `/auth/login` needs `Authorization: Bearer <token>`.
Admin-only routes return `403` for members.

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/health` | — | liveness |
| POST | `/auth/login` | — | `{username,password}` → `{token,role,user_id}` |
| GET | `/me` | any | current identity |
| GET/POST | `/users` | admin | list / create (`{username,password,role?}`) |
| DELETE | `/users/:id` | admin | |
| PATCH | `/users/:id/role` | admin | `{role:"admin"\|"member"}` |
| GET/POST | `/folders` | any / admin | |
| PATCH/DELETE | `/folders/:id` | admin | |
| GET/POST | `/envs` | any / admin | list is ACL-filtered for members |
| GET/PATCH/DELETE | `/envs/:id` | access / admin | `config` is opaque JSON |
| POST/DELETE | `/acl` | admin | grant/revoke `{user_id,object_id,object_kind,perm?}` |
| GET/POST | `/proxies` | any / admin | |
| DELETE | `/proxies/:id` | admin | |
| POST | `/envs/:id/checkout` | access | acquire lock; `{client_id?}` → `{version,snapshot_url,lease_expires_at}`; `409` if held |
| POST | `/envs/:id/lease` | owner | renew lease |
| POST | `/envs/:id/checkin` | owner/admin | multipart `snapshot` (+`client_id`) → new version, releases lock |
| POST | `/envs/:id/release` | owner/admin | discard + unlock |
| POST | `/envs/:id/force-unlock` | admin | clear a stuck lock |
| GET | `/envs/:id/lock` | access | lock status + `expired` flag |
| GET | `/envs/:id/snapshot/:version` | access | download raw blob bytes |

### Checkout locks

One holder per environment at a time. `checkout` takes a lease
(`SHARDX_LEASE_TTL_SECS`, default 90s); the client renews via `lease` while the
browser runs. An expired lease can be reclaimed by anyone with access; admins
can `force-unlock`. The server stores snapshot blobs opaquely (the launcher
packs/encrypts them) and keeps the last `SHARDX_SNAPSHOT_KEEP` (default 5)
versions, GC'ing older blobs.

### Access model

A member sees an environment if they have a direct `env` grant **or** a grant on
the environment's `folder`. Admins see everything. Roles are re-read from the DB
on every request, so demotion/deletion takes effect immediately.

## Smoke test

```bash
BASE=http://127.0.0.1:8080
TOKEN=$(curl -s $BASE/auth/login -d '{"username":"admin","password":"secret"}' \
  -H 'content-type: application/json' | jq -r .token)

curl -s $BASE/me -H "Authorization: Bearer $TOKEN" | jq .
curl -s $BASE/envs -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"win-rtx4060","host_os":"Windows","config":{"webgl":{"renderer":"…"}}}' | jq .
```
