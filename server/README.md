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
# dev (binds 127.0.0.1 by default — loopback only, so a simple password is fine)
cd server
SHARDX_TOKEN_SECRET=dev-secret SHARDX_ADMIN_PASS=dev-strong-pass cargo run

# docker (binds 0.0.0.0 → network-facing, so a strong admin password is REQUIRED;
# a weak/placeholder one makes first start refuse to boot). Build from the REPO
# ROOT with -f: the image needs the sibling `shared` crate too, not just server/.
docker build -f server/Dockerfile -t shardx-team-server .
docker run -p 8080:8080 -v "$PWD/data:/data" \
  -e SHARDX_TOKEN_SECRET=$(openssl rand -hex 32) \
  -e SHARDX_ADMIN_USER=admin -e SHARDX_ADMIN_PASS="$(openssl rand -base64 18)" \
  shardx-team-server
```

The `docker run` above publishes plain HTTP — fine for a private/loopback test,
but for a real remote deployment use the **[`deploy/`](../deploy/) stack**: it
runs the server behind Caddy with automatic HTTPS (Let's Encrypt), and leaves
the server unpublished on an internal-only network. Snapshots carry decrypted
cookies / saved passwords / card numbers, so cross-machine traffic must be
encrypted. One-command deploy:

```bash
cd deploy && cp .env.example .env   # set domain + secrets, then:
docker compose up -d --build
```

Config is all environment variables — see [`.env.example`](.env.example).
SQLite DB + snapshot blobs live under `SHARDX_DATA_DIR` (`/data` in Docker).
On first start with an empty user table, an admin is bootstrapped from
`SHARDX_ADMIN_USER` / `SHARDX_ADMIN_PASS`. On a **non-loopback bind** (e.g. the
Docker default `0.0.0.0`), the server **refuses to start** if that password is
empty, too short, or a known placeholder (`admin`, `secret`, `change-me`, …), or
if an existing admin still uses one — set a strong `SHARDX_ADMIN_PASS`, bind
`127.0.0.1`, or set `SHARDX_ALLOW_INSECURE_ADMIN=1` to override.

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

**The lease is soft.** Expiry only makes the lock *reclaimable* — it does not by
itself invalidate the holder's `lock_token`. `checkout` is the only route where
`lease_expires_at` can change who owns the lock, and only to decide whether
someone else may take the slot over (`GET /envs/:id/lock` also reads it, but
just to report the `expired` flag). Until a takeover actually happens, a session
whose lease lapsed (laptop slept, renewer wedged, network blip) can still
`lease`, `checkin`, `release`, and download its snapshot normally. The token
dies only when the lock row is **replaced** (a new checkout, including the same
client's, which rotates the token) or **deleted** (`checkin`, `release`,
`force-unlock`).

This is deliberate: a client that merely lost its renewer still holds the only
copy of the un-pushed environment data, and rejecting its `checkin` would throw
that work away even though nobody else ever claimed the lock. Ownership is the
exact `user + client_id + lock_token` tuple, and the access-gated routes
(`lease`, `checkin`, snapshot download) re-check ACL on every call — so revoking
a user's grant ends their session regardless of the token. `release` skips that
check on purpose, so a holder can always hand the lock back.

### Database journal mode (WAL)

The server does not set `journal_mode`; a database created by recent sqlx runs
on SQLite's default rollback journal, where a reader and a writer block each
other. (WAL would not lift SQLite's single-writer limit — it stops readers and
the writer from serializing against each other.) On startup the server reads
`PRAGMA main.journal_mode` and `sqlite_version()` and logs both at `INFO` on
every start. It additionally **warns** when the mode isn't `wal` — or, louder,
when the DB *is* on WAL under a SQLite that predates the fix below. It never
changes the mode automatically: WAL is the one journal mode that sticks to the
database file (the rollback modes are
per-connection defaults), and switching into it needs exclusive access, for
which `busy_timeout` is no substitute. Plan it as downtime.

> **Prerequisite — settle this before anything else.** SQLite had a WAL-reset
> concurrency bug that can corrupt a WAL database when several connections
> write/checkpoint concurrently (fixed in 3.51.3, backported to 3.50.7 /
> 3.44.6). This server opens up to **8 connections**, squarely in the affected
> pattern. The version the server links against is on the startup `INFO` line,
> and the startup warning states outright whether it satisfies this prerequisite.
> As shipped it does: `libsqlite3-sys` is pinned high enough to bundle 3.51.3.
> If you change that pin, or build against a system SQLite, re-check the line.
> If the server's SQLite is affected, **do not enable WAL** — upgrade it first.
> Verify the *migration tool's* SQLite separately (`sqlite3 --version`): both it
> and the server runtime must be safe, and they are not the same build. (macOS
> currently ships 3.51.0 in `/usr/bin/sqlite3`, which is *not* safe — one common
> way to get this wrong.)
>
> Calibrate the urgency: upstream describes this bug as needing very tight
> timing, says they could not reproduce it organically (it took deliberately
> injected test logic), and puts the observed rate on par with SSD malfunctions
> or cosmic-ray bit flips. So an existing WAL deployment on an affected SQLite
> warrants a high-priority maintenance window, but not a same-hour scramble:
> do not switch without a backup, a version-checked SQLite, and exclusive
> access to the database. Rushing past those three is how you turn a rare
> corruption risk into a certain one.

Migration procedure, once the version prerequisite is satisfied:

1. Stop **every** server instance and any other process touching the database.
2. Take a full backup: the main DB file plus any existing `-wal` (it can hold
   committed transactions not yet checkpointed into the main file). The `-shm`
   is a rebuildable index, not a source of durable data — copying it is
   harmless but it is not what you are protecting.
3. Run `PRAGMA journal_mode=WAL;` from a `sqlite3` CLI you have version-checked
   above. The Docker image ships only the server binary and no `sqlite3`, so
   run it from the host or a one-off container against the mounted data volume.
4. **Check the returned value.** This PRAGMA reports the resulting mode and
   returns the *old* mode if the switch did not take (e.g. a lingering lock).
   Anything other than `wal` means it did not happen — do not assume success
   from a clean exit code.
5. Restart the service and confirm the startup log no longer emits the
   journal-mode warning.
6. **Do not enable WAL if the database lives on a network filesystem** (NFS,
   SMB, most container network volumes). WAL needs shared-memory locking
   between processes on one host; remote filesystems do not provide it safely.

To go the other way — the server warns that an existing DB is already on WAL
under an affected SQLite — the procedure is the same in reverse: stop every
process using the database, back it up (including the `-wal`), run
`PRAGMA journal_mode=DELETE;` with a version-checked `sqlite3`, and confirm the
statement returned `delete`. SQLite checkpoints the WAL into the main file as
part of the switch, so the stop-everything step is what protects the data.

### Access model

A member sees an environment if they have a direct `env` grant **or** a grant on
the environment's `folder`. Admins see everything. Roles are re-read from the DB
on every request, so demotion/deletion takes effect immediately.

## Smoke test

```bash
BASE=http://127.0.0.1:8080
TOKEN=$(curl -s $BASE/auth/login -d '{"username":"admin","password":"dev-strong-pass"}' \
  -H 'content-type: application/json' | jq -r .token)

curl -s $BASE/me -H "Authorization: Bearer $TOKEN" | jq .
curl -s $BASE/envs -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"win-rtx4060","host_os":"Windows","config":{"webgl":{"renderer":"…"}}}' | jq .
```
