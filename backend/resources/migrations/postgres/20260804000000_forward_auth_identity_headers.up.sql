ALTER TABLE oidc_clients
    ADD COLUMN forward_auth_inject_identity_headers BOOLEAN NOT NULL DEFAULT TRUE;
