ALTER TABLE oidc_clients
    ADD COLUMN forward_auth_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE oidc_clients
    ADD COLUMN forward_auth_external_url TEXT;

CREATE TABLE forward_auth_sessions
(
    id         UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    token      TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_forward_auth_sessions_token ON forward_auth_sessions (token);
CREATE INDEX idx_forward_auth_sessions_expires_at ON forward_auth_sessions (expires_at);

CREATE TABLE forward_auth_login_tokens
(
    id         UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    token      TEXT        NOT NULL,
    return_to  TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    user_id    UUID REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_forward_auth_login_tokens_token ON forward_auth_login_tokens (token);
CREATE INDEX idx_forward_auth_login_tokens_expires_at ON forward_auth_login_tokens (expires_at);
