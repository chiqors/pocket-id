PRAGMA foreign_keys=OFF;
BEGIN;

DROP TABLE forward_auth_login_tokens;
DROP TABLE forward_auth_sessions;

ALTER TABLE oidc_clients DROP COLUMN forward_auth_inject_identity_headers;
ALTER TABLE oidc_clients DROP COLUMN forward_auth_upstream_headers;
ALTER TABLE oidc_clients DROP COLUMN forward_auth_upstream_url;
ALTER TABLE oidc_clients DROP COLUMN forward_auth_external_url;
ALTER TABLE oidc_clients DROP COLUMN forward_auth_enabled;

COMMIT;
PRAGMA foreign_keys=ON;
