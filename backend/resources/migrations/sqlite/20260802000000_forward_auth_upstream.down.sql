PRAGMA foreign_keys=OFF;
BEGIN;

ALTER TABLE oidc_clients
    DROP COLUMN forward_auth_upstream_url;

COMMIT;
PRAGMA foreign_keys=ON;
