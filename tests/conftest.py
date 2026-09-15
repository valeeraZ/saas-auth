import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from uuid import uuid4

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict

from saas_auth.api import create_app
from saas_auth.cli import bootstrap, configure_service
from saas_auth.config import Settings
from saas_auth.db import make_pool, migrate


@pytest.fixture(scope="session")
def signing():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="integration-key", use="sig", alg="RS256")
    state = {"keys": [jwk], "unavailable": False}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(503 if state["unavailable"] else 200)
            self.end_headers()
            self.wfile.write(json.dumps({"keys": state["keys"]}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield SimpleNamespace(
        key=key, issuer=f"http://127.0.0.1:{server.server_port}/realms/test", state=state
    )
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture(scope="session")
def database_url():
    url = os.environ.get("SAAS_TEST_DATABASE_URL")
    if not url:
        pytest.fail("Set SAAS_TEST_DATABASE_URL to an isolated PostgreSQL database ending in _test")
    if not conninfo_to_dict(url).get("dbname", "").endswith("_test"):
        pytest.fail("Refusing to reset a database whose name does not end in _test")
    migrate(url)
    return url


@pytest.fixture
def env(database_url, signing):
    with psycopg.connect(database_url) as conn:
        conn.execute("TRUNCATE tenants,users,service_principals CASCADE")
    pool = make_pool(database_url)
    pool.open(wait=True)
    tenant, app_id = uuid4(), uuid4()
    bootstrap(
        pool,
        issuer=signing.issuer,
        subject="owner-human",
        email="owner@example.test",
        tenant_id=tenant,
        name="Test tenant",
        slug="test-tenant",
        actor="operator:test",
    )
    configure_service(
        pool,
        issuer=signing.issuer,
        subject="service-subject",
        client_id="saas-admin",
        tenant_id=tenant,
        app_id=app_id,
        scopes=["tenants:read", "roles:read", "roles:write"],
        actor="operator:test",
    )
    settings = Settings(
        database_url,
        signing.issuer,
        "test-cursor-secret-32-characters-long",
        allow_insecure_local=True,
    )
    app = create_app(settings)

    def token(**overrides):
        now = int(time.time())
        claims = dict(
            iss=signing.issuer,
            aud="saas-auth",
            sub="service-subject",
            azp="saas-admin",
            exp=now + 300,
            iat=now,
            typ="Bearer",
            scope="tenants:read roles:read roles:write",
        )
        claims.update(overrides)
        return jwt.encode(
            claims, signing.key, algorithm="RS256", headers={"kid": "integration-key"}
        )

    with TestClient(app) as client:
        yield SimpleNamespace(
            pool=pool,
            tenant=tenant,
            app_id=app_id,
            settings=settings,
            app=app,
            client=client,
            token=token,
            signing=signing,
            path=f"/v1/tenants/{tenant}/apps/{app_id}/roles",
        )
    pool.close()


@pytest.fixture
def headers(env):
    return {"Authorization": "Bearer " + env.token(), "Idempotency-Key": str(uuid4())}
