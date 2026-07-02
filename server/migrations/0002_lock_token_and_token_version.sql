-- Lock sessions get an unguessable token so a stale client (crashed, lease
-- expired, lock reclaimed) can no longer lease/checkin/release; password
-- changes bump token_version so previously-issued JWTs stop verifying.

ALTER TABLE locks ADD COLUMN lock_token TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
