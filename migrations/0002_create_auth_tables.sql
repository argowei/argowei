-- Dashboard/API authentication.
--
-- Argowei has a single administrator. The unique index on the constant
-- expression `(true)` makes the database itself reject a second admin row,
-- so the one-time setup endpoint cannot race itself into creating two.
CREATE TABLE admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR NOT NULL,
    -- Argon2id hash in PHC string format (includes salt and parameters).
    password_hash VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ix_admin_users_single_admin ON admin_users ((true));

-- Server-side sessions. Only the SHA-256 of the random cookie token is
-- stored, so a database leak does not yield usable session cookies.
CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX ix_sessions_expires_at ON sessions (expires_at);
