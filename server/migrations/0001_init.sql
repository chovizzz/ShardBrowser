-- ShardX Team Server — initial schema.
-- Timestamps are RFC3339 TEXT (UTC). IDs are UUID v4 TEXT.

CREATE TABLE users (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    pw_hash    TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'member',   -- 'admin' | 'member'
    created_at TEXT NOT NULL
);

CREATE TABLE folders (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    parent_id  TEXT REFERENCES folders(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE proxies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL,                     -- socks5 | http | https
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    username   TEXT,
    password   TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE environments (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    folder_id       TEXT REFERENCES folders(id) ON DELETE SET NULL,
    config_json     TEXT NOT NULL DEFAULT '{}',   -- opaque FingerprintConfig blob
    proxy_id        TEXT REFERENCES proxies(id) ON DELETE SET NULL,
    host_os         TEXT,                          -- 'macOS' | 'Windows' | 'Linux'
    current_version INTEGER NOT NULL DEFAULT 0,    -- latest snapshot version, 0 = none
    notes           TEXT NOT NULL DEFAULT '',
    created_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
    updated_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- Access control: which user may reach which object. A folder grant
-- cascades to that folder's environments (resolved at query time).
CREATE TABLE acl (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    object_id   TEXT NOT NULL,
    object_kind TEXT NOT NULL,                     -- 'env' | 'folder'
    perm        TEXT NOT NULL DEFAULT 'use',       -- 'use' | 'edit'
    PRIMARY KEY (user_id, object_id, object_kind)
);

-- Exclusive checkout lock (Phase 2 uses these; table defined now so the
-- schema stays stable).
CREATE TABLE locks (
    env_id           TEXT PRIMARY KEY REFERENCES environments(id) ON DELETE CASCADE,
    owner_user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    owner_client_id  TEXT NOT NULL,
    acquired_at      TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL
);

CREATE TABLE snapshots (
    env_id     TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    version    INTEGER NOT NULL,
    blob_path  TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (env_id, version)
);

CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    actor  TEXT,
    action TEXT NOT NULL,
    env_id TEXT,
    detail TEXT,
    at     TEXT NOT NULL
);

CREATE INDEX idx_acl_user ON acl(user_id);
CREATE INDEX idx_env_folder ON environments(folder_id);
