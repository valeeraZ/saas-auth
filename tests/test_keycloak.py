import os
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from saas_auth.api import create_app
from saas_auth.cli import configure_service
from saas_auth.config import Settings


@pytest.mark.keycloak
def test_real_client_credentials(env):
    issuer = os.environ.get("SAAS_TEST_KEYCLOAK_ISSUER")
    if not issuer:
        pytest.skip("Set SAAS_TEST_KEYCLOAK_ISSUER for real Keycloak integration")
    secret = os.environ["SAAS_TEST_KEYCLOAK_SECRET"]
    response = httpx.post(
        issuer + "/protocol/openid-connect/token",
        timeout=10,
        data={
            "grant_type": "client_credentials",
            "client_id": "saas-admin",
            "client_secret": secret,
        },
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    settings = Settings(
        env.settings.database_url, issuer, env.settings.cursor_secret, allow_insecure_local=True
    )
    app = create_app(settings)
    # The service-account subject is explicitly fixed in the disposable realm import, not read from an unverified token.
    configure_service(
        env.pool,
        issuer=issuer,
        subject="00000000-0000-4000-8000-000000000010",
        client_id="saas-admin",
        tenant_id=env.tenant,
        app_id=env.app_id,
        scopes=["roles:read", "roles:write", "tenants:read"],
        actor="operator:keycloak-test",
    )
    headers = {"Authorization": "Bearer " + token, "Idempotency-Key": str(uuid4())}
    with TestClient(app) as client:
        assert client.get(env.path, headers=headers).status_code == 200
        assert (
            client.post(
                env.path, headers=headers, json={"key": "viewer", "description": ""}
            ).status_code
            == 201
        )
        with env.pool.connection() as conn:
            conn.execute("UPDATE service_principals SET enabled=false WHERE issuer=%s", (issuer,))
        assert client.get(env.path, headers=headers).status_code == 403
