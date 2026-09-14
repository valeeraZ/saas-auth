ALTER TABLE audit_entries ALTER COLUMN tenant_id DROP NOT NULL;
CREATE TABLE auth_sessions (
    issuer text NOT NULL,
    sid text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (issuer,sid)
);
CREATE INDEX sessions_user_idx ON auth_sessions(user_id);
CREATE TABLE user_idempotency (
    user_id uuid NOT NULL REFERENCES users(id),
    method text NOT NULL,
    route text NOT NULL,
    key text NOT NULL CHECK (length(key) BETWEEN 16 AND 128),
    request_hash text NOT NULL,
    status integer NOT NULL,
    body jsonb,
    etag text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id,method,route,key)
);
CREATE INDEX user_idempotency_created_idx ON user_idempotency(created_at);
CREATE TABLE invitations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    email text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','expired','revoked')),
    expires_at timestamptz NOT NULL DEFAULT now()+interval '7 days',
    accepted_by uuid REFERENCES users(id),
    version bigint NOT NULL DEFAULT 1 CHECK (version>0)
);
CREATE UNIQUE INDEX invitations_pending_idx ON invitations(tenant_id,email) WHERE status='pending';
CREATE INDEX invitations_page_idx ON invitations(tenant_id,id);
CREATE INDEX invitations_user_idx ON invitations(accepted_by);
CREATE TABLE private_tasks (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('invitation_mail','session_revoke')),
    tenant_id uuid REFERENCES tenants(id),
    resource_id text NOT NULL,
    ciphertext text,
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_id uuid,
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    completed_at timestamptz,
    UNIQUE (kind,resource_id)
);
CREATE INDEX private_tasks_pending_idx ON private_tasks(available_at,id) WHERE completed_at IS NULL;
CREATE INDEX private_tasks_tenant_idx ON private_tasks(tenant_id);
