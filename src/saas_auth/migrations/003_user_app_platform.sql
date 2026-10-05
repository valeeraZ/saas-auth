-- Remove tenancy from the active schema without granting broader app access.
-- Historical tenant records retain their original keys/FKs in a private archive.
CREATE SCHEMA IF NOT EXISTS legacy_tenancy;
REVOKE ALL ON SCHEMA legacy_tenancy FROM PUBLIC;
ALTER TABLE tenants SET SCHEMA legacy_tenancy;
ALTER TABLE memberships SET SCHEMA legacy_tenancy;
ALTER TABLE role_definitions SET SCHEMA legacy_tenancy;
ALTER TABLE role_assignments SET SCHEMA legacy_tenancy;
ALTER TABLE service_tenant_grants SET SCHEMA legacy_tenancy;
ALTER TABLE service_app_grants SET SCHEMA legacy_tenancy;
ALTER TABLE idempotency_records SET SCHEMA legacy_tenancy;
ALTER TABLE audit_entries SET SCHEMA legacy_tenancy;
ALTER TABLE outbox SET SCHEMA legacy_tenancy;
ALTER TABLE invitations SET SCHEMA legacy_tenancy;
ALTER TABLE private_tasks SET SCHEMA legacy_tenancy;
CREATE TABLE user_app_grants (
 user_id uuid NOT NULL REFERENCES users(id), app_id uuid NOT NULL,
 roles text[] NOT NULL CHECK(cardinality(roles) BETWEEN 1 AND 100),
 enabled boolean NOT NULL DEFAULT false, version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 PRIMARY KEY(user_id,app_id)
);
CREATE INDEX user_app_grants_app_idx ON user_app_grants(app_id,user_id);
CREATE TABLE platform_audit (
 id uuid PRIMARY KEY, actor text NOT NULL, action text NOT NULL,
 resource_id uuid NOT NULL, request_id uuid NOT NULL,
 details jsonb NOT NULL DEFAULT '{}'::jsonb,
 occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE app_operations (key text PRIMARY KEY, hash text NOT NULL, body jsonb NOT NULL);
CREATE TABLE session_tasks (
 id uuid PRIMARY KEY, resource_id text NOT NULL UNIQUE, ciphertext text,
 available_at timestamptz NOT NULL DEFAULT now(), lease_id uuid, lease_until timestamptz,
 attempts integer NOT NULL DEFAULT 0, completed_at timestamptz
);
INSERT INTO session_tasks SELECT id,resource_id,ciphertext,available_at,lease_id,lease_until,attempts,completed_at FROM legacy_tenancy.private_tasks WHERE kind='session_revoke';
CREATE INDEX session_tasks_pending_idx ON session_tasks(available_at,id) WHERE completed_at IS NULL;
