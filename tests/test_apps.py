from dataclasses import replace
from uuid import uuid4

import psycopg
import pytest


def mapped(env, headers):
    response = env.client.get("/v1/me", headers=headers)
    assert response.status_code == 200
    assert set(response.json()) == {"user"}
    return response.json()["user"]


def test_default_deny_grant_revoke_and_cross_user(env, headers, operator_headers):
    user = mapped(env, headers)
    path = f"/v1/apps/{env.app_id}/permissions"
    write = f"/v1/operator/apps/{env.app_id}/grants"
    assert env.client.get(path, headers=headers).json()["allowed"] is False
    body = {"userId": user["id"], "roles": ["viewer"], "enabled": True}
    assert env.client.put(write, headers=headers, json=body).status_code == 401
    created = env.client.put(write, headers=operator_headers, json=body)
    assert created.status_code == 200
    assert env.client.put(write, headers=operator_headers, json=body).json() == created.json()
    assert (
        env.client.put(write, headers=operator_headers, json=body | {"enabled": False}).status_code
        == 409
    )
    grant = env.client.get(path, headers=headers).json()
    assert grant["allowed"] and grant["roles"] == ["viewer"] and grant["userId"] == user["id"]
    other = {
        "Authorization": "Bearer "
        + env.token(sub="second-user", sid="second-session", email="other@example.test")
    }
    assert env.client.get(path, headers=other).json()["allowed"] is False
    assert (
        env.client.get(f"/v1/apps/{uuid4()}/permissions", headers=headers).json()["allowed"]
        is False
    )
    assert (
        env.client.put(
            write,
            headers=operator_headers | {"Idempotency-Key": str(uuid4())},
            json=body | {"enabled": False},
        ).status_code
        == 200
    )
    assert env.client.get(path, headers=headers).json()["allowed"] is False
    with env.pool.connection() as conn:
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM platform_audit WHERE action='application.grant.updated'"
            ).fetchone()["n"]
            == 2
        )


@pytest.mark.parametrize(
    "change",
    [
        {"userId": "invalid"},
        {"roles": []},
        {"roles": ["bad role"]},
        {"roles": ["viewer"] * 101},
        {"enabled": "true"},
        {"tenantId": str(uuid4())},
        {"actor": "forged"},
    ],
)
def test_invalid_operator_grants(env, headers, operator_headers, change):
    user = mapped(env, headers)
    body = {"userId": user["id"], "roles": ["viewer"], "enabled": True} | change
    assert (
        env.client.put(
            f"/v1/operator/apps/{env.app_id}/grants", headers=operator_headers, json=body
        ).status_code
        == 422
    )


def test_user_status_identity_mapping_and_live_introspection(env, headers):
    user = mapped(env, headers)
    assert mapped(env, headers)["id"] == user["id"]
    env.signing.state["inactive"].add("human-session")
    assert env.client.get("/v1/me", headers=headers).status_code == 401
    env.signing.state["inactive"].clear()
    with env.pool.connection() as conn:
        conn.execute("UPDATE users SET status='suspended' WHERE id=%s", (user["id"],))
    assert env.client.get("/v1/me", headers=headers).status_code == 403


def test_logout_idempotent_and_fail_closed(env, headers, monkeypatch):
    delivered = []
    monkeypatch.setattr(
        "saas_auth.worker.revocation.revoke_upstream",
        lambda settings, data: delivered.append(data.sid),
    )
    mapped(env, headers)
    assert env.client.delete("/v1/sessions/current", headers=headers).status_code == 204
    assert env.client.delete("/v1/sessions/current", headers=headers).status_code == 204
    assert delivered == ["human-session"]
    assert env.client.get("/v1/me", headers=headers).status_code == 401
    with env.pool.connection() as conn:
        assert conn.execute("SELECT count(*) AS n FROM session_tasks").fetchone()["n"] == 1


@pytest.mark.parametrize("path", ["/v1/tenants", "/v1/tenant-context", "/v1/invitations/accept"])
def test_removed_tenant_routes(env, headers, path):
    assert env.client.get(path, headers=headers).status_code == 404
    assert env.client.post(path, headers=headers, json={}).status_code == 404


def test_migration_archives_without_globalizing_grants(database_url):
    with psycopg.connect(database_url) as conn:
        assert conn.execute("SELECT to_regclass('public.tenants')").fetchone()[0] is None
        assert (
            conn.execute("SELECT to_regclass('legacy_tenancy.tenants')").fetchone()[0] is not None
        )


def test_distinct_subjects_never_link_by_email(env, headers):
    first = mapped(env, headers)
    other = {"Authorization": "Bearer " + env.token(sub="other-subject", sid="other-sid")}
    assert mapped(env, other)["id"] != first["id"]
    changed = {"Authorization": "Bearer " + env.token(email="changed@example.test")}
    assert mapped(env, changed)["id"] == first["id"]


@pytest.mark.parametrize("age", ["idle", "absolute", "revoked"])
def test_session_limits(env, headers, age):
    mapped(env, headers)
    update = {
        "idle": "last_seen_at=now()-interval '31 minutes'",
        "absolute": "created_at=now()-interval '9 hours'",
        "revoked": "revoked_at=now()",
    }[age]
    with env.pool.connection() as conn:
        conn.execute("UPDATE auth_sessions SET " + update)
    assert env.client.get("/v1/me", headers=headers).status_code == 401


def test_operator_key_and_actor_are_required(env, headers, operator_headers):
    mapped(env, headers)
    assert env.client.get("/v1/operator/users", headers=headers).status_code == 401
    assert (
        env.client.get(
            "/v1/operator/users", headers=operator_headers | {"X-Auth-Operator-Actor": ""}
        ).status_code
        == 422
    )
    assert env.client.get("/v1/operator/users", headers=operator_headers).status_code == 200


def test_durable_session_delivery_retry_and_lease_ownership(env, headers, monkeypatch):
    from saas_auth.worker import revocation as private_tasks

    def unavailable(settings, data):
        raise OSError("unavailable")

    monkeypatch.setattr(private_tasks, "revoke_upstream", unavailable)
    mapped(env, headers)
    response = env.client.delete("/v1/sessions/current", headers=headers)
    assert response.status_code == 202 and response.json() == {"upstreamRevocation": "pending"}
    assert env.client.get("/v1/me", headers=headers).status_code == 401
    assert env.client.delete("/v1/sessions/current", headers=headers).status_code == 202
    with env.pool.connection() as conn:
        conn.execute("UPDATE session_tasks SET available_at=now()-interval '1 second'")
    task = private_tasks.claim(env.database)
    assert task and task.attempts == 2
    assert private_tasks.claim(env.database) is None
    forged = replace(task, lease_id=uuid4())
    assert not private_tasks.finish(env.database, forged, True)
    assert private_tasks.finish(env.database, task, False)
    with env.pool.connection() as conn:
        conn.execute("UPDATE session_tasks SET available_at=now()-interval '1 second'")
    delivered = []
    monkeypatch.setattr(
        private_tasks, "revoke_upstream", lambda settings, data: delivered.append(data.sid)
    )
    assert private_tasks.deliver_once(env.database, env.settings)
    assert delivered == ["human-session"]
    assert env.client.delete("/v1/sessions/current", headers=headers).status_code == 204
    with env.pool.connection() as conn:
        task = conn.execute("SELECT * FROM session_tasks").fetchone()
        assert task["completed_at"] and task["ciphertext"] is None


def test_grant_audit_records_application_and_trusted_actor(env, headers, operator_headers):
    user = mapped(env, headers)
    response = env.client.put(
        f"/v1/operator/apps/{env.app_id}/grants",
        headers=operator_headers,
        json={"userId": user["id"], "roles": ["viewer"], "enabled": True},
    )
    assert response.status_code == 200
    with env.pool.connection() as conn:
        audit = conn.execute(
            "SELECT * FROM platform_audit WHERE action='application.grant.updated'"
        ).fetchone()
        assert audit["actor"] == "operator:test"
        assert audit["details"]["appId"] == str(env.app_id)
        assert audit["details"]["userId"] == user["id"]
