import json
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from aiosmtpd.controller import Controller
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from saas_auth.api import create_app
from saas_auth.private_tasks import claim, deliver_once, finish


@pytest.fixture
def human(env):
    settings = replace(
        env.settings,
        user_clients=("saas-portal",),
        introspection_client="test",
        introspection_secret="local-only",
        task_key=Fernet.generate_key().decode(),
    )

    def headers(
        subject="owner-human", email="owner@example.com", verified=True, sid=None, **claims
    ):
        return {
            "Authorization": "Bearer "
            + env.token(
                sub=subject,
                azp="saas-portal",
                sid=sid or "sid-" + subject,
                email=email,
                email_verified=verified,
                name=subject,
                **claims,
            ),
            "Idempotency-Key": str(uuid4()),
        }

    app = create_app(settings)
    with TestClient(app) as client:
        yield SimpleNamespace(
            **vars(env) | {"client": client, "settings": settings, "headers": headers, "app": app}
        )


def add_member(h, subject, role="member"):
    headers = h.headers(subject, subject + "@example.com")
    user = h.client.get("/v1/me", headers=headers).json()["user"]
    with h.pool.connection() as conn:
        conn.execute(
            "INSERT INTO memberships(tenant_id,user_id,tenant_role) VALUES (%s,%s,%s)",
            (h.tenant, user["id"], role),
        )
    return headers, user["id"]


def invite(h, email="invitee@example.com"):
    response = h.client.post(
        f"/v1/tenants/{h.tenant}/invitations", headers=h.headers(), json={"email": email}
    )
    assert response.status_code == 201, response.text
    with h.pool.connection() as conn:
        task = conn.execute(
            "SELECT * FROM private_tasks WHERE resource_id=%s", (response.json()["id"],)
        ).fetchone()
    data = json.loads(Fernet(h.settings.task_key.encode()).decrypt(task["ciphertext"].encode()))
    return response, data, task


def test_first_use_identity_and_no_email_linking(human):
    h = human
    a = h.client.get("/v1/me", headers=h.headers("new-one")).json()
    b = h.client.get("/v1/me", headers=h.headers("new-two")).json()
    assert a["user"]["id"] != b["user"]["id"]
    assert a["tenants"] == []
    assert a["user"]["emailVerified"] is True

    def read(_):
        return h.client.get("/v1/me", headers=h.headers("same-user")).json()["user"]["id"]

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert len(set(executor.map(read, range(4)))) == 1


def test_verified_create_tenant_and_per_request_context(human):
    h = human
    headers = h.headers("new")
    response = h.client.post("/v1/tenants", headers=headers, json={"name": "New", "slug": "new"})
    assert response.status_code == 201
    assert (
        h.client.post("/v1/tenants", headers=headers, json={"slug": "new", "name": "New"}).json()
        == response.json()
    )
    assert (
        h.client.post(
            "/v1/tenants", headers=headers, json={"slug": "different", "name": "New"}
        ).status_code
        == 409
    )
    own = response.json()["id"]
    assert (
        h.client.post("/v1/tenant-context", headers=headers, json={"tenantId": own}).json()[
            "membership"
        ]["tenantRole"]
        == "owner"
    )
    assert (
        h.client.post(
            "/v1/tenant-context", headers=headers, json={"tenantId": str(h.tenant)}
        ).status_code
        == 404
    )
    unverified = h.headers("unverified", verified=False)
    assert h.client.get("/v1/me", headers=unverified).status_code == 200
    assert (
        h.client.post(
            "/v1/tenants", headers=unverified, json={"name": "No", "slug": "no"}
        ).status_code
        == 403
    )


def test_invitation_is_private_idempotent_and_single_use(human):
    h = human
    response, data, task = invite(h)
    assert "token" not in response.text
    assert data["token"] not in task["ciphertext"]
    headers = h.headers("invitee", "invitee@example.com")
    wrong = h.headers("stranger", "wrong@example.com")
    body = {"token": data["token"]}
    assert h.client.post("/v1/invitations/accept", headers=wrong, json=body).status_code == 403
    assert (
        h.client.post(
            "/v1/invitations/accept",
            headers=h.headers("invitee", "invitee@example.com", False),
            json=body,
        ).status_code
        == 403
    )
    accepted = h.client.post("/v1/invitations/accept", headers=headers, json=body)
    assert accepted.status_code == 200
    assert accepted.json()["tenantRole"] == "member"
    assert (
        h.client.post("/v1/invitations/accept", headers=headers, json=body).json()
        == accepted.json()
    )
    assert (
        h.client.post(
            "/v1/invitations/accept", headers=headers | {"Idempotency-Key": str(uuid4())}, json=body
        ).status_code
        == 409
    )
    with h.pool.connection() as conn:
        assert (
            conn.execute(
                "SELECT ciphertext FROM private_tasks WHERE id=%s", (task["id"],)
            ).fetchone()["ciphertext"]
            is None
        )


def test_concurrent_invite_acceptance_one_membership(human):
    h = human
    _, data, _ = invite(h)

    def accept(n):
        return h.client.post(
            "/v1/invitations/accept",
            headers=h.headers("invitee" + str(n), "invitee@example.com"),
            json={"token": data["token"]},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(accept, range(2)))
    assert sorted(r.status_code for r in results) == [200, 409]
    with h.pool.connection() as conn:
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM memberships WHERE tenant_id=%s", (h.tenant,)
            ).fetchone()["n"]
            == 2
        )


@pytest.mark.parametrize("revoke", [True, False])
def test_expired_and_revoked_invitation(human, revoke):
    h = human
    invitation, data, _ = invite(h)
    if revoke:
        assert (
            h.client.delete(
                f"/v1/tenants/{h.tenant}/invitations/{invitation.json()['id']}",
                headers=h.headers() | {"If-Match": '"1"'},
            ).status_code
            == 204
        )
    else:
        with h.pool.connection() as conn:
            conn.execute("UPDATE invitations SET expires_at=now()-interval '1 second'")
    assert (
        h.client.post(
            "/v1/invitations/accept",
            headers=h.headers("invitee", "invitee@example.com"),
            json={"token": data["token"]},
        ).status_code
        == 409
    )


def test_last_owner_and_admin_privilege_escalation(human):
    h = human
    owner = h.client.get("/v1/me", headers=h.headers()).json()["user"]["id"]
    path = f"/v1/tenants/{h.tenant}/members/{owner}"
    assert (
        h.client.patch(
            path,
            headers=h.headers() | {"If-Match": '"1"'},
            json={"tenantRole": "member", "status": "active"},
        ).json()["code"]
        == "last_owner"
    )
    admin, admin_id = add_member(h, "admin", "admin")
    assert (
        h.client.patch(
            path,
            headers=admin | {"If-Match": '"1"'},
            json={"tenantRole": "member", "status": "active"},
        ).status_code
        == 403
    )
    assert (
        h.client.patch(
            f"/v1/tenants/{h.tenant}/members/{admin_id}",
            headers=admin | {"If-Match": '"1"'},
            json={"tenantRole": "owner", "status": "active"},
        ).status_code
        == 403
    )


def test_concurrent_owner_departure_keeps_one_owner(human):
    h = human
    owner = h.client.get("/v1/me", headers=h.headers()).json()["user"]["id"]
    second, second_id = add_member(h, "second", "owner")

    def demote(pair):
        headers, user_id = pair
        return h.client.patch(
            f"/v1/tenants/{h.tenant}/members/{user_id}",
            headers=headers | {"If-Match": '"1"'},
            json={"tenantRole": "member", "status": "active"},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(demote, [(h.headers(), owner), (second, second_id)]))
    assert sorted(r.status_code for r in results) == [200, 409]
    with h.pool.connection() as conn:
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM memberships WHERE tenant_id=%s AND tenant_role='owner' AND status='active'",
                (h.tenant,),
            ).fetchone()["n"]
            == 1
        )


def test_role_assignment_isolation_and_authoritative_revoke(human):
    h = human
    member, user_id = add_member(h, "member")
    role = h.client.post(h.path, headers=h.headers(), json={"key": "viewer", "description": ""})
    assert role.status_code == 201
    path = f"/v1/tenants/{h.tenant}/role-assignments"
    assert (
        h.client.post(
            path, headers=h.headers(), json={"roleId": str(uuid4()), "userId": user_id}
        ).status_code
        == 404
    )
    assigned = h.client.post(
        path, headers=h.headers(), json={"roleId": role.json()["id"], "userId": user_id}
    )
    assert assigned.status_code == 201
    permission = h.path.removesuffix("roles") + "permissions"
    assert h.client.get(permission, headers=member).json()["allowed"] is True
    assert (
        h.client.post(h.path, headers=member, json={"key": "owner", "description": ""}).status_code
        == 403
    )
    assert (
        h.client.delete(
            path + "/" + assigned.json()["id"], headers=h.headers() | {"If-Match": '"1"'}
        ).status_code
        == 204
    )
    assert h.client.get(permission, headers=member).json()["reason"] == "role_missing"
    h.client.post(path, headers=h.headers(), json={"roleId": role.json()["id"], "userId": user_id})
    assert (
        h.client.patch(
            f"/v1/tenants/{h.tenant}/members/{user_id}",
            headers=h.headers() | {"If-Match": '"1"'},
            json={"tenantRole": "member", "status": "revoked"},
        ).status_code
        == 200
    )
    assert h.client.get(permission, headers=member).json()["reason"] == "membership_inactive"
    assert h.client.get(f"/v1/tenants/{h.tenant}", headers=member).status_code == 403


def test_tenant_suspend_resume_and_platform_enforcement(human):
    h = human
    path = f"/v1/tenants/{h.tenant}"
    response = h.client.patch(
        path, headers=h.headers() | {"If-Match": '"1"'}, json={"status": "suspended"}
    )
    assert response.status_code == 200
    assert response.json()["lifecycleSequence"] == 2
    assert (
        h.client.post(
            "/v1/tenant-context", headers=h.headers(), json={"tenantId": str(h.tenant)}
        ).status_code
        == 403
    )
    resumed = h.client.patch(
        path,
        headers=h.headers() | {"If-Match": response.headers["etag"]},
        json={"status": "active"},
    )
    assert resumed.status_code == 200
    with h.pool.connection() as conn:
        conn.execute(
            "UPDATE tenants SET status='suspended',suspension_source='platform' WHERE id=%s",
            (h.tenant,),
        )
    assert (
        h.client.patch(
            path,
            headers=h.headers() | {"If-Match": resumed.headers["etag"]},
            json={"status": "active"},
        ).status_code
        == 403
    )


def test_local_session_logout_restart_and_outage(human):
    h = human
    headers = h.headers()
    assert h.client.get("/v1/me", headers=headers).status_code == 200
    h.signing.state["unavailable"] = True
    try:
        assert h.client.get("/v1/me", headers=headers).status_code == 503
        assert h.client.delete("/v1/sessions/current", headers=headers).status_code == 204
        assert h.client.delete("/v1/sessions/current", headers=headers).status_code == 204
    finally:
        h.signing.state["unavailable"] = False
    with TestClient(create_app(h.settings)) as restarted:
        assert restarted.get("/v1/me", headers=headers).status_code == 401
    fresh = h.headers(sid="new-login")
    assert h.client.get("/v1/me", headers=fresh).status_code == 200
    assert (
        h.client.delete(
            "/v1/sessions/current", headers=fresh | {"Idempotency-Key": headers["Idempotency-Key"]}
        ).status_code
        == 409
    )
    with h.pool.connection() as conn:
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM private_tasks WHERE kind='session_revoke'"
            ).fetchone()["n"]
            == 1
        )


@pytest.mark.parametrize(
    "column,interval", [("created_at", "9 hours"), ("last_seen_at", "31 minutes")]
)
def test_session_limits_and_upstream_invalidation(human, column, interval):
    h = human
    headers = h.headers()
    assert h.client.get("/v1/me", headers=headers).status_code == 200
    with h.pool.connection() as conn:
        conn.execute(f"UPDATE auth_sessions SET {column}=now()-%s::interval", (interval,))
    assert h.client.get("/v1/me", headers=headers).status_code == 401
    h.signing.state["inactive"].add("new-upstream-session")
    try:
        assert (
            h.client.get("/v1/me", headers=h.headers(sid="new-upstream-session")).status_code == 401
        )
    finally:
        h.signing.state["inactive"].clear()


def test_private_task_lease_fencing(human):
    h = human
    invite(h)
    first = claim(h.pool)
    assert claim(h.pool) is None
    with h.pool.connection() as conn:
        conn.execute("UPDATE private_tasks SET lease_until=now()-interval '1 second'")
    second = claim(h.pool)
    assert first["id"] == second["id"]
    assert finish(h.pool, first, True) is False
    assert finish(h.pool, second, False) is True
    assert claim(h.pool) is None


def test_mail_task_failure_retry_and_scrubbing(human, monkeypatch):
    h = human
    _, data, task = invite(h)
    messages = []

    class Handler:
        async def handle_DATA(self, server, session, envelope):
            messages.append(envelope.content)
            return "250 OK"

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    smtp = Controller(Handler(), hostname="127.0.0.1", port=port)
    monkeypatch.setenv("SAAS_SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("SAAS_SMTP_PORT", str(port))
    monkeypatch.setenv("SAAS_SMTP_STARTTLS", "false")
    monkeypatch.setenv("SAAS_ALLOW_INSECURE_LOCAL", "true")
    monkeypatch.setenv("SAAS_SMTP_FROM", "noreply@example.com")
    monkeypatch.setenv("SAAS_INVITATION_URL", "http://127.0.0.1:58999/auth/invitations/accept")
    assert deliver_once(h.pool, h.settings)
    with h.pool.connection() as conn:
        failed = conn.execute("SELECT * FROM private_tasks WHERE id=%s", (task["id"],)).fetchone()
        assert failed["completed_at"] is None and failed["attempts"] == 1
        conn.execute("UPDATE private_tasks SET available_at=now() WHERE id=%s", (task["id"],))
    smtp.start()
    try:
        assert deliver_once(h.pool, h.settings)
        assert len(messages) == 1
        assert (
            data["token"]
            in BytesParser(policy=policy.default).parsebytes(messages[0]).get_content()
        )
        assert not deliver_once(h.pool, h.settings)
        with h.pool.connection() as conn:
            done = conn.execute("SELECT * FROM private_tasks WHERE id=%s", (task["id"],)).fetchone()
            assert done["completed_at"] is not None and done["ciphertext"] is None
    finally:
        smtp.stop()


def test_invite_transaction_rollback_and_duplicate(human):
    h = human
    with h.pool.connection() as conn:
        conn.execute(
            "ALTER TABLE private_tasks ADD CONSTRAINT fail_invitation CHECK (kind<>'invitation_mail') NOT VALID"
        )
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            h.client.post(
                f"/v1/tenants/{h.tenant}/invitations",
                headers=h.headers(),
                json={"email": "rollback@example.com"},
            )
        with h.pool.connection() as conn:
            assert conn.execute("SELECT count(*) AS n FROM invitations").fetchone()["n"] == 0
    finally:
        with h.pool.connection() as conn:
            conn.execute("ALTER TABLE private_tasks DROP CONSTRAINT fail_invitation")
    response, _, _ = invite(h)
    assert (
        h.client.post(
            f"/v1/tenants/{h.tenant}/invitations",
            headers=h.headers(),
            json={"email": "INVITEE@example.com"},
        ).status_code
        == 409
    )
    assert (
        h.client.post(
            f"/v1/tenants/{h.tenant}/invitations",
            headers=h.headers(),
            json={"email": "another@example.com", "tenantRole": "owner"},
        ).status_code
        == 422
    )


def test_user_responses_and_implemented_operations_match_contract(human):
    h = human
    spec = json.loads(Path("contracts/openapi.json").read_text())

    def expand(schema):
        if isinstance(schema, dict):
            if "$ref" in schema:
                return expand(spec["components"]["schemas"][schema["$ref"].split("/")[-1]])
            return {k: expand(v) for k, v in schema.items()}
        if isinstance(schema, list):
            return [expand(v) for v in schema]
        return schema

    headers = h.headers()
    for path, name in [
        ("/v1/me", "CurrentUser"),
        ("/v1/tenants", "TenantPage"),
        (f"/v1/tenants/{h.tenant}/members", "MembershipPage"),
        (f"/v1/tenants/{h.tenant}/invitations", "InvitationPage"),
        (f"/v1/tenants/{h.tenant}/role-assignments", "RoleAssignmentPage"),
        (h.path.removesuffix("roles") + "permissions", "PermissionDecision"),
    ]:
        r = h.client.get(path, headers=headers)
        assert r.status_code == 200
        Draft202012Validator(
            expand(spec["components"]["schemas"][name]), format_checker=FormatChecker()
        ).validate(r.json())
    implemented = {
        o["operationId"]
        for p, ms in h.client.get("/openapi.json").json()["paths"].items()
        if p.startswith("/v1/")
        for o in ms.values()
    }
    expected = {o["operationId"] for ms in spec["paths"].values() for o in ms.values()}
    assert implemented == expected
