# SaaS Auth

Auth owns platform users, external identity mappings, sessions and direct user/application grants. Keycloak owns authentication. Each application owns its business data and sharing policy. The platform has no active tenant or membership model.

- [User/application architecture and migration](docs/USER-APP-PLATFORM.md)
- [Executable API contract](contracts/openapi.json)

`GET /v1/me` returns the verified user; `GET /v1/apps/{appId}/permissions` returns the current user's online app grant. Unassigned users are denied by default. The private operator API requires `SAAS_APP_OPERATOR_KEY` (at least 32 random characters) and a trusted audit actor; human login tokens cannot grant access. Inject the matching key into the Admin console server only.

```sh
uv sync --frozen
uv run python scripts/prepare_local.py
docker compose up --build -d
curl --fail http://127.0.0.1:58000/health/ready
```

Local configuration is disposable, generated in ignored files and must not be used in production. Configure `SAAS_USER_CLIENTS`, introspection credentials and `SAAS_TASK_KEY` for user requests. Production OIDC requires HTTPS. Configure the Auth API and retry worker with `SAAS_SESSION_WORKER_CLIENT` and `SAAS_SESSION_WORKER_SECRET`. Logout commits the local revocation and calls Keycloak before responding. HTTP 204 confirms both sessions are revoked. HTTP 202 means local logout succeeded and upstream revocation is pending. Run `saas-auth private-tasks-worker` to retry failed or interrupted deliveries.

Migration 003 archives historical tenant tables in a private schema and creates empty direct grants. It preserves users and sessions, never flattens tenant permissions into global access, and does not modify child application business databases. Review and explicitly grant intended user access after migration. Applied Alembic revision identifiers remain stable.

```sh
uv run mypy
SAAS_TEST_DATABASE_URL=postgresql://…/isolated_test uv run pytest -q -m 'not keycloak'
uv run python scripts/generate_contracts.py
uv run python scripts/validate_contracts.py
```

Tests only reset a database whose name ends in `_test`. Real Keycloak tests additionally use `SAAS_TEST_KEYCLOAK_ISSUER` and generated local credentials. Earlier tenant documents are historical and superseded by the current architecture document.


## Database migrations

Alembic owns migration revisions and records the applied revision in `alembic_version`.
Set `SAAS_DATABASE_URL` in the environment, then run:

```sh
uv run alembic upgrade head
uv run alembic current
uv run alembic history
uv run alembic check
```

Compose and deployment jobs run `alembic upgrade head`. Concurrent upgrades
share a PostgreSQL transaction lock. Readiness requires the database revision
to match the packaged Alembic head.

For a schema change, update the ORM mappings and generate a revision:

```sh
uv run alembic revision --autogenerate -m "Describe the schema change"
```

Review the generated upgrade and downgrade operations, including constraints
and data transformations, before applying them. Revisions live in
`src/saas_auth/alembic/versions/`; ORM metadata is configured in `env.py`.
The `alembic check` command detects schema changes that need a revision.

All migrations are self-contained Alembic revisions using Alembic operations.
Version tracking uses `alembic_version`.

The four historical migrations have no automatic downgrade, including the
tenant archive conversion. Rollback across those revisions requires restoring
a database backup. New revisions can define their own downgrade operations.


## Kubernetes deployment

Auth's Helm chart is maintained in `deploy/charts/saas-auth/`. It deploys the API,
session revocation worker, Alembic migration hook, private TLS Service,
NetworkPolicy and readiness smoke test.

Use the platform configuration generator in `saas-admin/deploy/scripts/prepare.py`
to provision shared Secrets and generate `auth-values.json`. Set the API and
worker images to the same immutable Auth image digest.

```sh
helm upgrade --install saas-auth deploy/charts/saas-auth \
  --namespace saas-stage -f /secure/path/auth-values.json \
  --atomic --wait --timeout 10m
helm test saas-auth --namespace saas-stage --logs
```

Install Auth before the Admin/Portal platform release in the same namespace.
Existing installations whose Auth resources belong to the platform release
require a Helm ownership migration before switching to this separate release.
