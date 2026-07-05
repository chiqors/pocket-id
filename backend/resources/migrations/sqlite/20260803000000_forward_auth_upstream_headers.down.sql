PRAGMA foreign_keys=OFF;
BEGIN;

CREATE TABLE oidc_clients_dg_tmp (
    id                             TEXT PRIMARY KEY,
    created_at                     DATETIME,
    name                           TEXT,
    secret                         TEXT,
    callback_urls                  BLOB,
    image_type                     TEXT,
    created_by_id                  TEXT REFERENCES users ON DELETE SET NULL,
    is_public                      BOOLEAN,
    pkce_enabled                   BOOLEAN,
    logout_callback_urls           BLOB,
    credentials                    BLOB,
    launch_url                     TEXT,
    dark_image_type                TEXT,
    is_group_restricted            BOOLEAN,
    pkce_supported                 BOOLEAN,
    forward_auth_enabled           BOOLEAN,
    forward_auth_external_url      TEXT,
    forward_auth_upstream_url      TEXT,
    requires_reauthentication      BOOLEAN,
    requires_pushed_authorization_requests BOOLEAN,
    skip_consent                   BOOLEAN
);

INSERT INTO oidc_clients_dg_tmp (
    id,
    created_at,
    name,
    secret,
    callback_urls,
    image_type,
    created_by_id,
    is_public,
    pkce_enabled,
    logout_callback_urls,
    credentials,
    launch_url,
    dark_image_type,
    is_group_restricted,
    pkce_supported,
    forward_auth_enabled,
    forward_auth_external_url,
    forward_auth_upstream_url,
    requires_reauthentication,
    requires_pushed_authorization_requests,
    skip_consent
)
SELECT
    id,
    created_at,
    name,
    secret,
    callback_urls,
    image_type,
    created_by_id,
    is_public,
    pkce_enabled,
    logout_callback_urls,
    credentials,
    launch_url,
    dark_image_type,
    is_group_restricted,
    pkce_supported,
    forward_auth_enabled,
    forward_auth_external_url,
    forward_auth_upstream_url,
    requires_reauthentication,
    requires_pushed_authorization_requests,
    skip_consent
FROM oidc_clients;

DROP TABLE oidc_clients;
ALTER TABLE oidc_clients_dg_tmp RENAME TO oidc_clients;

COMMIT;
PRAGMA foreign_keys=ON;
