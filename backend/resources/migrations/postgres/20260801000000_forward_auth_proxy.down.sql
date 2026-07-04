DROP TABLE forward_auth_login_tokens;
DROP TABLE forward_auth_sessions;

ALTER TABLE oidc_clients DROP COLUMN forward_auth_external_url;
ALTER TABLE oidc_clients DROP COLUMN forward_auth_enabled;
