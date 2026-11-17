from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from saas_auth.errors import ApiError
from saas_auth.services.access import AccessService
from saas_auth.services.users import AppService


def roles(env, operator_headers, names=("viewer", "editor"), version=1):
    return env.client.put(
        f"/v1/operator/apps/{env.app_id}/roles",
        headers=operator_headers | {"Idempotency-Key": str(uuid4())},
        json={
            "version": version,
            "roles": [{"key": k, "name": k, "description": "", "active": True} for k in names],
        },
    )


def submit(env, headers, selected=("viewer", "editor")):
    return env.client.post(
        f"/v1/apps/{env.app_id}/requests",
        headers=headers,
        json={"roles": list(selected), "reason": "Need access"},
    )


def decide(env, operator_headers, request, decision="approved", comment="Business need verified"):
    return env.client.put(
        f"/v1/operator/requests/{request['id']}",
        headers=operator_headers,
        json={"decision": decision, "comment": comment},
    )


def test_multi_role_approval_identity_audit_and_replay(env, headers, operator_headers):
    assert roles(env, operator_headers).status_code == 200
    request = submit(env, headers).json()
    assert submit(env, headers).json() == request
    assert submit(env, headers | {"Idempotency-Key": str(uuid4())}).status_code == 409
    assert (
        env.client.get(f"/v1/apps/{env.app_id}/permissions", headers=headers).json()["allowed"]
        is False
    )
    approved = decide(env, operator_headers, request)
    assert approved.status_code == 200
    assert approved.json()["reviewer"] == "operator:test"
    assert approved.json()["comment"] == "Business need verified"
    assert approved.json()["reviewedAt"]
    assert decide(env, operator_headers, request).json() == approved.json()
    assert (
        decide(
            env, operator_headers | {"Idempotency-Key": str(uuid4())}, request, "rejected"
        ).status_code
        == 409
    )
    grant = env.client.get(f"/v1/apps/{env.app_id}/permissions", headers=headers).json()
    assert grant["roles"] == ["editor", "viewer"] and grant["allowed"]
    with env.pool.connection() as conn:
        assert (
            conn.execute(
                "SELECT count(*) n FROM platform_audit WHERE action='application.grant.approved'"
            ).fetchone()["n"]
            == 1
        )
    other = {"Authorization": "Bearer " + env.token(sub="other", sid="other")}
    assert env.client.get(f"/v1/apps/{env.app_id}/requests", headers=other).json()["items"] == []


def test_rejection_and_resubmission(env, headers, operator_headers):
    roles(env, operator_headers)
    request = submit(env, headers).json()
    assert decide(env, operator_headers, request, "rejected", "Not eligible").status_code == 200
    assert not env.client.get(f"/v1/apps/{env.app_id}/permissions", headers=headers).json()[
        "allowed"
    ]
    assert submit(env, headers | {"Idempotency-Key": str(uuid4())}).json()["status"] == "pending"


def test_undefined_retired_roles_and_stale_editor(env, headers, operator_headers):
    configured = roles(env, operator_headers).json()
    assert submit(env, headers, ("superuser",)).status_code == 409
    request = submit(env, headers | {"Idempotency-Key": str(uuid4())}).json()
    assert roles(env, operator_headers, ("viewer",), configured["version"]).status_code == 200
    assert roles(env, operator_headers, ("viewer",), configured["version"]).status_code == 409
    assert decide(env, operator_headers, request).status_code == 409
    assert (
        decide(
            env, operator_headers | {"Idempotency-Key": str(uuid4())}, request, "rejected"
        ).status_code
        == 200
    )


def test_approval_merges_and_role_retirement_revokes(env, headers, operator_headers):
    version = roles(env, operator_headers).json()["version"]
    user = env.client.get("/v1/me", headers=headers).json()["user"]
    assert (
        env.client.put(
            f"/v1/operator/apps/{env.app_id}/grants",
            headers=operator_headers,
            json={"userId": user["id"], "roles": ["viewer"], "enabled": True},
        ).status_code
        == 200
    )
    request = submit(env, headers, ("editor",)).json()
    assert (
        decide(env, operator_headers | {"Idempotency-Key": str(uuid4())}, request).status_code
        == 200
    )
    assert roles(env, operator_headers, ("viewer",), version).status_code == 200
    assert env.client.get(f"/v1/apps/{env.app_id}/permissions", headers=headers).json()[
        "roles"
    ] == ["viewer"]
    assert roles(env, operator_headers, (), version + 1).status_code == 200
    assert not env.client.get(f"/v1/apps/{env.app_id}/permissions", headers=headers).json()[
        "allowed"
    ]
    roles(env, operator_headers, ("editor", "viewer"), version + 2)
    assert not env.client.get(f"/v1/apps/{env.app_id}/permissions", headers=headers).json()[
        "allowed"
    ]


def test_browser_cannot_forge_reviewer_or_user(env, headers, operator_headers):
    roles(env, operator_headers)
    assert (
        env.client.post(
            f"/v1/apps/{env.app_id}/requests",
            headers=headers,
            json={"roles": ["viewer"], "userId": str(uuid4())},
        ).status_code
        == 422
    )
    request = submit(env, headers).json()
    assert decide(env, headers, request).status_code == 401
    assert (
        env.client.put(
            f"/v1/operator/requests/{request['id']}",
            headers=operator_headers,
            json={"decision": "approved", "comment": "yes", "reviewer": "forged"},
        ).status_code
        == 422
    )
    assert decide(env, operator_headers, request, comment="").status_code == 422
    assert env.client.get("/v1/operator/requests", headers=headers).status_code == 401


def test_concurrent_decisions_grant_exactly_once(env, headers, operator_headers):
    roles(env, operator_headers)
    request = submit(env, headers).json()
    service = AccessService(AppService(env.database, env.settings))

    def review(decision):
        try:
            return service.decide(
                request["id"],
                decision,
                "Concurrency test",
                str(uuid4()),
                "operator:" + decision,
                uuid4(),
            ).status
        except ApiError as e:
            return e.status

    with ThreadPoolExecutor(2) as pool:
        statuses = list(pool.map(review, ["approved", "rejected"]))
    assert sorted(statuses) == [200, 409]
    with env.pool.connection() as conn:
        row = conn.execute(
            "SELECT status FROM app_access_requests WHERE id=%s", (request["id"],)
        ).fetchone()
        count = conn.execute("SELECT count(*) n FROM user_app_grants").fetchone()["n"]
        assert count == (1 if row["status"] == "approved" else 0)
