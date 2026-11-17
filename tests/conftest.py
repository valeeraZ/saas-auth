import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import uuid4

import jwt
import psycopg
import pytest
from alembic import command
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from saas_auth.api import create_app
from saas_auth.config import Settings
from saas_auth.db.migrations import migration_config


@pytest.fixture(scope="session")
def signing():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="integration-key", use="sig", alg="RS256")
    state = {"keys": [jwk], "unavailable": False, "inactive": set()}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            if state["unavailable"]:
                self.send_response(503)
                self.end_headers()
                return
            claims = jwt.decode(
                body["token"][0],
                key.public_key(),
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "active": claims.get("sid") not in state["inactive"],
                        "sub": claims["sub"],
                        "sid": claims.get("sid"),
                    }
                ).encode()
            )

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
    config = migration_config()
    config.attributes["database_url"] = url
    command.upgrade(config, "head")
    return url


@pytest.fixture
def env(database_url, signing, monkeypatch):
    with psycopg.connect(database_url) as conn:
        conn.execute(
            "TRUNCATE app_role_sets,users,service_principals,app_operations,platform_audit,session_tasks CASCADE"
        )
    pool = ConnectionPool(database_url, open=False, kwargs={"row_factory": dict_row})
    pool.open(wait=True)
    settings = Settings(
        database_url,
        signing.issuer,
        "test-cursor-secret-32-characters-long",
        allow_insecure_local=True,
        user_clients=("saas-portal",),
        introspection_client="saas-auth",
        introspection_secret="test-only",
        operator_key="operator-key-32-characters-test-only",
        task_key=Fernet.generate_key().decode(),
    )
    app = create_app(settings)

    def token(**overrides):
        now = int(time.time())
        claims = dict(
            iss=signing.issuer,
            aud="saas-auth",
            sub="user-human",
            azp="saas-portal",
            exp=now + 300,
            iat=now,
            typ="Bearer",
            scope="openid profile email",
            sid="human-session",
            email="user@example.test",
            email_verified=True,
            name="Test user",
        )
        claims.update(overrides)
        return jwt.encode(
            claims, signing.key, algorithm="RS256", headers={"kid": "integration-key"}
        )

    signing.state["unavailable"] = False
    signing.state["inactive"].clear()
    app_id = uuid4()
    with pool.connection() as conn:
        conn.execute("INSERT INTO app_role_sets(app_id) VALUES(%s)", (app_id,))
        conn.execute(
            "INSERT INTO app_roles(app_id,key,name) VALUES(%s,'viewer','Viewer')", (app_id,)
        )
    with TestClient(app) as client:
        yield SimpleNamespace(
            pool=pool,
            database=app.state.database,
            settings=settings,
            app=app,
            client=client,
            token=token,
            signing=signing,
            path="/v1/me",
            app_id=app_id,
        )
    pool.close()


@pytest.fixture
def headers(env):
    return {"Authorization": "Bearer " + env.token(), "Idempotency-Key": str(uuid4())}


@pytest.fixture
def operator_headers():
    return {
        "X-Auth-Operator-Key": "operator-key-32-characters-test-only",
        "X-Auth-Operator-Actor": "operator:test",
        "Idempotency-Key": str(uuid4()),
    }
