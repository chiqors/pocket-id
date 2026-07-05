PRAGMA foreign_keys=OFF;
BEGIN;

ALTER TABLE oidc_clients
    ADD COLUMN forward_auth_upstream_headers TEXT NOT NULL DEFAULT '[]';

COMMIT;
PRAGMA foreign_keys=ON;
