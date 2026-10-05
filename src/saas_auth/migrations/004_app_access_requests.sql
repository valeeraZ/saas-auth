CREATE TABLE app_role_sets (
    app_id uuid PRIMARY KEY,
    version bigint NOT NULL DEFAULT 1 CHECK(version>0)
);
CREATE TABLE app_roles (
    app_id uuid NOT NULL REFERENCES app_role_sets(app_id),
    key text NOT NULL CHECK(key ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200),
    description text NOT NULL DEFAULT '' CHECK(length(description)<=1000),
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY(app_id,key)
);
-- Preserve explicit pre-existing grants. Do not invent default business roles.
INSERT INTO app_role_sets(app_id) SELECT DISTINCT app_id FROM user_app_grants;
INSERT INTO app_roles(app_id,key,name)
SELECT DISTINCT app_id,role,role FROM user_app_grants CROSS JOIN LATERAL unnest(roles) role;
CREATE TABLE app_access_requests (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    app_id uuid NOT NULL REFERENCES app_role_sets(app_id),
    roles text[] NOT NULL CHECK(cardinality(roles) BETWEEN 1 AND 100),
    reason text NOT NULL DEFAULT '' CHECK(length(reason)<=2000),
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    reviewer text,
    comment text CHECK(length(comment)<=2000),
    created_at timestamptz NOT NULL DEFAULT now(),
    reviewed_at timestamptz,
    CHECK((status='pending' AND reviewer IS NULL AND comment IS NULL AND reviewed_at IS NULL)
       OR (status<>'pending' AND reviewer IS NOT NULL AND comment IS NOT NULL AND reviewed_at IS NOT NULL))
);
CREATE UNIQUE INDEX one_pending_app_request ON app_access_requests(user_id,app_id) WHERE status='pending';
CREATE INDEX app_request_queue ON app_access_requests(status,id);
CREATE INDEX own_app_requests ON app_access_requests(user_id,app_id,id);
