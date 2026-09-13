CREATE TABLE users (
    id uuid PRIMARY KEY,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    email text NOT NULL,
    email_verified boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted'))
);
CREATE TABLE external_identities (
    issuer text NOT NULL,
    subject text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id),
    PRIMARY KEY (issuer, subject)
);
CREATE INDEX external_identities_user_idx ON external_identities(user_id);
CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    slug text NOT NULL UNIQUE CHECK (length(slug) <= 63 AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleting','deleted')),
    suspension_source text NOT NULL DEFAULT 'none' CHECK (suspension_source IN ('none','owner','platform')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    authorization_version bigint NOT NULL DEFAULT 1 CHECK (authorization_version > 0),
    lifecycle_sequence bigint NOT NULL DEFAULT 0 CHECK (lifecycle_sequence >= 0),
    CHECK ((status = 'suspended') = (suspension_source <> 'none'))
);
CREATE TABLE memberships (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    user_id uuid NOT NULL REFERENCES users(id),
    tenant_role text NOT NULL CHECK (tenant_role IN ('owner','admin','member')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships(user_id,tenant_id);
CREATE TABLE role_definitions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    app_id uuid NOT NULL,
    key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    description text NOT NULL CHECK (length(description) <= 1000),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    UNIQUE (tenant_id, app_id, key),
    UNIQUE (tenant_id, id)
);
CREATE INDEX roles_page_idx ON role_definitions(tenant_id, app_id, id);
CREATE TABLE role_assignments (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    FOREIGN KEY (tenant_id,user_id) REFERENCES memberships(tenant_id,user_id),
    FOREIGN KEY (tenant_id,role_id) REFERENCES role_definitions(tenant_id,id) ON DELETE CASCADE,
    UNIQUE (tenant_id,user_id,role_id)
);
CREATE INDEX assignments_role_idx ON role_assignments(tenant_id,role_id);
CREATE TABLE service_principals (
    id uuid PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    client_id text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    UNIQUE (issuer,subject),
    UNIQUE (issuer,client_id)
);
CREATE TABLE service_tenant_grants (
    principal_id uuid NOT NULL REFERENCES service_principals(id),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    snapshot_read boolean NOT NULL DEFAULT false,
    PRIMARY KEY (principal_id,tenant_id)
);
CREATE INDEX service_tenant_idx ON service_tenant_grants(tenant_id);
CREATE TABLE service_app_grants (
    principal_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    app_id uuid NOT NULL,
    roles_read boolean NOT NULL DEFAULT false,
    roles_write boolean NOT NULL DEFAULT false,
    PRIMARY KEY (principal_id,tenant_id,app_id),
    FOREIGN KEY (principal_id,tenant_id) REFERENCES service_tenant_grants(principal_id,tenant_id)
);
CREATE TABLE idempotency_records (
    principal_id uuid NOT NULL REFERENCES service_principals(id),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    method text NOT NULL,
    route text NOT NULL,
    key text NOT NULL CHECK (length(key) BETWEEN 16 AND 128),
    request_hash text NOT NULL,
    status integer NOT NULL,
    body jsonb,
    etag text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id,tenant_id,method,route,key)
);
CREATE INDEX idempotency_tenant_idx ON idempotency_records(tenant_id);
CREATE INDEX idempotency_created_idx ON idempotency_records(created_at);
CREATE TABLE audit_entries (
    id uuid PRIMARY KEY,
    actor text NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    action text NOT NULL,
    resource_id uuid NOT NULL,
    request_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_tenant_idx ON audit_entries(tenant_id,occurred_at);
CREATE TABLE outbox (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    stream text NOT NULL CHECK (stream IN ('lifecycle','authorization')),
    sequence bigint NOT NULL CHECK (sequence > 0),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_id uuid,
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    delivered_at timestamptz,
    UNIQUE (tenant_id,stream,sequence)
);
CREATE INDEX outbox_pending_idx ON outbox(available_at,created_at) WHERE delivered_at IS NULL;
