import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from saas_auth.api import create_app
from saas_auth.cli import bootstrap
from saas_auth.db import migrate


def count(env, table):
    assert table in {
        "role_definitions",
        "outbox",
        "audit_entries",
        "role_assignments",
        "idempotency_records",
    }
    with env.pool.connection() as conn:
        return conn.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]


def test_health_and_schema_migration(env, database_url):
    migrate(database_url)
    assert env.client.get("/health/live").status_code == 200
    assert env.client.get("/health/ready").status_code == 200
    with env.pool.connection() as conn:
        assert conn.execute("SELECT count(*) AS n FROM schema_migrations").fetchone()["n"] == 1


def test_create_replay_delete_replay(env, headers):
    original_events, original_audit = count(env, "outbox"), count(env, "audit_entries")
    response = env.client.post(
        env.path, headers=headers, json={"key": "viewer", "description": "Read app"}
    )
    assert response.status_code == 201
    assert response.headers["etag"] == '"1"'
    assert (
        env.client.post(
            env.path, headers=headers, json={"description": "Read app", "key": "viewer"}
        ).json()
        == response.json()
    )
    assert count(env, "role_definitions") == 1
    assert count(env, "outbox") == original_events + 1
    assert count(env, "audit_entries") == original_audit + 1
    listed = env.client.get(env.path, headers=headers).json()
    assert listed == {"items": [response.json()], "nextCursor": None}
    delete_headers = headers | {"If-Match": '"1"', "Idempotency-Key": str(uuid4())}
    url = env.path + "/" + response.json()["id"]
    assert env.client.delete(url, headers=delete_headers).status_code == 204
    assert env.client.delete(url, headers=delete_headers).status_code == 204
    assert count(env, "role_definitions") == 0
    assert count(env, "outbox") == original_events + 2
    snapshot = env.client.get(f"/v1/tenants/{env.tenant}", headers=headers)
    assert snapshot.json()["authorizationVersion"] == 3
    assert snapshot.headers["etag"] == '"3"'


def test_concurrent_idempotency(env, headers):
    def write(_):
        return env.client.post(env.path, headers=headers, json={"key": "viewer", "description": ""})

    with ThreadPoolExecutor(max_workers=8) as executor:
        responses = list(executor.map(write, range(8)))
    assert {r.status_code for r in responses} == {201}
    assert len({r.json()["id"] for r in responses}) == 1
    assert count(env, "idempotency_records") == 1
    assert count(env, "outbox") == 3


def test_restart_replays_persisted_response(env, headers):
    payload = {"key": "viewer", "description": ""}
    original = env.client.post(env.path, headers=headers, json=payload)
    with TestClient(create_app(env.settings)) as restarted:
        replay = restarted.post(env.path, headers=headers, json=payload)
        assert replay.status_code == 201
        assert replay.json() == original.json()
        spec = restarted.get("/openapi.json").json()
        assert spec["paths"]["/v1/tenants/{tenantId}"]["get"]["security"] == [{"serviceAccess": []}]
    assert count(env, "outbox") == 3


def test_conflict_version_and_duplicate(env, headers):
    original = env.client.post(env.path, headers=headers, json={"key": "viewer", "description": ""})
    assert (
        env.client.post(
            env.path, headers=headers, json={"key": "editor", "description": ""}
        ).json()["code"]
        == "idempotency_conflict"
    )
    assert (
        env.client.post(
            env.path,
            headers=headers | {"Idempotency-Key": str(uuid4())},
            json={"key": "viewer", "description": ""},
        ).json()["code"]
        == "already_exists"
    )
    url = env.path + "/" + original.json()["id"]
    deletion = headers | {"If-Match": '"2"', "Idempotency-Key": str(uuid4())}
    assert env.client.delete(url, headers=deletion).status_code == 412
    assert count(env, "role_definitions") == 1
    assert count(env, "outbox") == 3


@pytest.mark.parametrize("status", ["suspended", "deleting", "deleted"])
def test_tenant_revocation_rechecks_before_replay(env, headers, status):
    payload = {"key": "viewer", "description": ""}
    assert env.client.post(env.path, headers=headers, json=payload).status_code == 201
    with env.pool.connection() as conn:
        conn.execute(
            "UPDATE tenants SET status=%s,suspension_source=%s WHERE id=%s",
            (status, "platform" if status == "suspended" else "none", env.tenant),
        )
    assert env.client.post(env.path, headers=headers, json=payload).status_code == 403
    assert env.client.get(env.path, headers=headers).status_code == 403
    assert env.client.get(f"/v1/tenants/{env.tenant}", headers=headers).json()["status"] == status


def test_service_disable_rejects_valid_token(env, headers):
    assert env.client.get(env.path, headers=headers).status_code == 200
    with env.pool.connection() as conn:
        conn.execute("UPDATE service_principals SET enabled=false")
    assert env.client.get(env.path, headers=headers).status_code == 403


def test_grant_revocation_is_authoritative(env, headers):
    assert (
        env.client.post(
            env.path, headers=headers, json={"key": "viewer", "description": ""}
        ).status_code
        == 201
    )
    with env.pool.connection() as conn:
        conn.execute("UPDATE service_app_grants SET roles_write=false")
    assert (
        env.client.post(
            env.path, headers=headers, json={"key": "viewer", "description": ""}
        ).status_code
        == 403
    )
    assert env.client.get(env.path, headers=headers).status_code == 200


def test_cross_tenant_app_and_human_impersonation(env, headers):
    assert (
        env.client.get(env.path.replace(str(env.tenant), str(uuid4())), headers=headers).status_code
        == 403
    )
    assert (
        env.client.get(env.path.replace(str(env.app_id), str(uuid4())), headers=headers).status_code
        == 403
    )
    human = headers | {
        "Authorization": "Bearer " + env.token(sub="owner-human"),
        "X-User-ID": "service-subject",
    }
    assert env.client.get(env.path, headers=human).status_code == 403
    assert env.client.get(f"/v1/tenants/{env.tenant}/members", headers=headers).status_code == 404


def test_foreign_role_cannot_be_deleted(env, headers):
    other_app, role_id = uuid4(), uuid4()
    with env.pool.connection() as conn:
        conn.execute(
            "INSERT INTO role_definitions(id,tenant_id,app_id,key,description) VALUES (%s,%s,%s,'foreign','')",
            (role_id, env.tenant, other_app),
        )
    result = env.client.delete(env.path + f"/{role_id}", headers=headers | {"If-Match": '"1"'})
    assert result.status_code == 404
    assert count(env, "role_definitions") == 1


def test_assignment_fk_isolation_and_cascade(env, headers):
    role = env.client.post(
        env.path, headers=headers, json={"key": "viewer", "description": ""}
    ).json()
    other_tenant = uuid4()
    bootstrap(
        env.pool,
        issuer=env.settings.issuer,
        subject="other-human",
        email="other@example.test",
        tenant_id=other_tenant,
        name="Other",
        slug="other",
        actor="operator:test",
    )
    with env.pool.connection() as conn:
        owner = conn.execute(
            "SELECT user_id FROM memberships WHERE tenant_id=%s", (env.tenant,)
        ).fetchone()["user_id"]
        other = conn.execute(
            "SELECT user_id FROM memberships WHERE tenant_id=%s", (other_tenant,)
        ).fetchone()["user_id"]
    for tenant, user in [(other_tenant, other), (env.tenant, other)]:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), env.pool.connection() as conn:
            conn.execute(
                "INSERT INTO role_assignments(id,tenant_id,user_id,role_id) VALUES (%s,%s,%s,%s)",
                (uuid4(), tenant, user, role["id"]),
            )
    with env.pool.connection() as conn:
        conn.execute(
            "INSERT INTO role_assignments(id,tenant_id,user_id,role_id) VALUES (%s,%s,%s,%s)",
            (uuid4(), env.tenant, owner, role["id"]),
        )
    assert (
        env.client.delete(
            env.path + "/" + role["id"], headers=headers | {"If-Match": '"1"'}
        ).status_code
        == 204
    )
    assert count(env, "role_assignments") == 0


def test_cursor_is_bound_to_scope_and_untampered(env, headers):
    for key in ["one", "two", "three"]:
        assert (
            env.client.post(
                env.path,
                headers=headers | {"Idempotency-Key": str(uuid4())},
                json={"key": key, "description": ""},
            ).status_code
            == 201
        )
    first = env.client.get(env.path, headers=headers, params={"limit": 2}).json()
    cursor = first["nextCursor"]
    second = env.client.get(env.path, headers=headers, params={"limit": 2, "cursor": cursor}).json()
    assert len(first["items"] + second["items"]) == 3
    assert len({r["id"] for r in first["items"] + second["items"]}) == 3
    assert second["nextCursor"] is None
    assert (
        env.client.get(env.path, headers=headers, params={"limit": 1, "cursor": cursor}).status_code
        == 422
    )
    assert (
        env.client.get(
            env.path, headers=headers, params={"limit": 2, "cursor": "!" + cursor}
        ).status_code
        == 422
    )


def test_commit_rollback_keeps_business_audit_outbox_atomic(env, headers):
    with env.pool.connection() as conn:
        conn.execute(
            "ALTER TABLE outbox ADD CONSTRAINT integration_failure CHECK (stream <> 'authorization') NOT VALID"
        )
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            env.client.post(env.path, headers=headers, json={"key": "viewer", "description": ""})
        assert count(env, "role_definitions") == 0
        assert count(env, "idempotency_records") == 0
        assert count(env, "audit_entries") == 2
        assert count(env, "outbox") == 2
    finally:
        with env.pool.connection() as conn:
            conn.execute("ALTER TABLE outbox DROP CONSTRAINT integration_failure")
    assert (
        env.client.post(
            env.path, headers=headers, json={"key": "viewer", "description": ""}
        ).status_code
        == 201
    )


def test_response_and_events_match_checked_in_contract(env, headers):
    spec = json.loads(Path("contracts/openapi.json").read_text())
    role = env.client.post(env.path, headers=headers, json={"key": "viewer", "description": ""})
    tenant = env.client.get(f"/v1/tenants/{env.tenant}", headers=headers)
    for name, value in [("RoleDefinition", role.json()), ("Tenant", tenant.json())]:
        Draft202012Validator(
            spec["components"]["schemas"][name], format_checker=FormatChecker()
        ).validate(value)
    with env.pool.connection() as conn:
        events = conn.execute("SELECT stream,payload FROM outbox").fetchall()
    for event in events:
        filename = "tenant-lifecycle" if event["stream"] == "lifecycle" else "authorization-changed"
        schema = json.loads(Path(f"contracts/events/{filename}.schema.json").read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(event["payload"])
