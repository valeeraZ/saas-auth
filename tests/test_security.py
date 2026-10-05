import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "another-api"},
        {"iss": "https://untrusted.invalid/realms/test"},
        {"exp": 1},
        {"iat": int(time.time()) + 3600},
        {"typ": "ID"},
        {"azp": None},
        {"scope": ["roles:read"]},
        {"sub": None},
        {"exp": int(time.time()) + 3600},
    ],
)
def test_reject_invalid_tokens(env, claims):
    response = env.client.get(env.path, headers={"Authorization": "Bearer " + env.token(**claims)})
    assert response.status_code == 401
    assert response.json()["code"] == "unauthenticated"
    assert response.headers["www-authenticate"] == "Bearer"


def test_reject_untrusted_signature_and_algorithm(env):
    claims = jwt.decode(env.token(), options={"verify_signature": False})
    for key, algorithm in [
        (rsa.generate_private_key(public_exponent=65537, key_size=2048), "RS256"),
        ("a-test-secret-that-is-at-least-32-characters", "HS256"),
    ]:
        token = jwt.encode(claims, key, algorithm=algorithm, headers={"kid": "integration-key"})
        assert (
            env.client.get(env.path, headers={"Authorization": "Bearer " + token}).status_code
            == 401
        )


def test_scope_and_client_and_no_browser_auth(env):
    for overrides in [{"azp": "unknown-client"}]:
        assert (
            env.client.get(
                env.path, headers={"Authorization": "Bearer " + env.token(**overrides)}
            ).status_code
            == 403
        )
    assert env.client.get(env.path, headers={"Cookie": "session=" + env.token()}).status_code == 401
    assert env.client.get(env.path, headers={"Authorization": "Bearer broken"}).status_code == 401


def test_jwks_outage_fails_closed(env):
    env.signing.state["unavailable"] = True
    try:
        response = env.client.get(env.path, headers={"Authorization": "Bearer " + env.token()})
        assert response.status_code == 503
        assert response.json()["code"] == "dependency_unavailable"
    finally:
        env.signing.state["unavailable"] = False


def test_request_errors_do_not_echo_sensitive_inputs(env, headers, operator_headers):
    user = env.client.get("/v1/me", headers=headers).json()["user"]
    secret = "sensitive-value-do-not-echo"
    path = f"/v1/operator/apps/{env.app_id}/grants"
    body = {"userId": user["id"], "roles": ["viewer"], "enabled": True, "token": secret}
    response = env.client.put(path, headers=operator_headers, json=body)
    assert response.status_code == 422
    assert secret not in response.text
    assert set(response.json()) == {"code", "message", "requestId"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"] == response.json()["requestId"]
    body.pop("token")
    for key in ["short", "x" * 129]:
        assert (
            env.client.put(
                path, headers=operator_headers | {"Idempotency-Key": key}, json=body
            ).status_code
            == 422
        )
