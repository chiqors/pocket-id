ALTER TABLE oidc_clients
    ADD COLUMN forward_auth_upstream_headers JSONB NOT NULL DEFAULT '[]'::jsonb;
