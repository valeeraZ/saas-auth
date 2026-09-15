import time
from uuid import uuid4

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
    for overrides in [{"scope": ""}, {"azp": "unknown-client"}]:
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


def test_request_errors_do_not_echo_sensitive_inputs(env, headers):
    secret = "sensitive-value-do-not-echo"
    response = env.client.post(
        env.path, headers=headers, json={"key": "viewer", "description": "", "token": secret}
    )
    assert response.status_code == 422
    assert secret not in response.text
    assert set(response.json()) == {"code", "message", "requestId"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"] == response.json()["requestId"]
    for modified in [{"Idempotency-Key": "short"}, {"Idempotency-Key": "x" * 129}]:
        assert (
            env.client.post(
                env.path, headers=headers | modified, json={"key": "viewer", "description": ""}
            ).status_code
            == 422
        )
    assert (
        env.client.delete(
            env.path + "/" + str(uuid4()), headers=headers | {"If-Match": "*"}
        ).status_code
        == 422
    )
