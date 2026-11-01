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

Local configuration is disposable, generated in ignored files and must not be used in production. Configure `SAAS_USER_CLIENTS`, introspection credentials and `SAAS_TASK_KEY` for user requests. Production OIDC requires HTTPS. Run `saas-auth private-tasks-worker` with the restricted session-worker client credentials to durably revoke upstream sessions after local logout.

Migration 003 archives historical tenant tables in a private schema and creates empty direct grants. It preserves users and sessions, never flattens tenant permissions into global access, and does not modify child application business databases. Review and explicitly grant intended user access after migration. Existing migration checksums remain immutable.

```sh
SAAS_TEST_DATABASE_URL=postgresql://…/isolated_test uv run pytest -q -m 'not keycloak'
uv run python scripts/generate_contracts.py
uv run python scripts/validate_contracts.py
```

Tests only reset a database whose name ends in `_test`. Real Keycloak tests additionally use `SAAS_TEST_KEYCLOAK_ISSUER` and generated local credentials. Earlier tenant documents are historical and superseded by the current architecture document.
