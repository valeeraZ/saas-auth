import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.exceptions import ResponseValidationError
from fastapi.testclient import TestClient

from saas_auth.api import create_app
from saas_auth.api.dependencies import authenticate_user, get_users
from saas_auth.config import Settings
from saas_auth.services.operations import Result


@pytest.fixture
def client():
    app = create_app(
        Settings("dbname=unused", "https://id.example", "x" * 32, operator_key="k" * 32)
    )
    with TestClient(app) as client:
        yield client


def test_current_user_validates_service_output(client):
    client.app.dependency_overrides[authenticate_user] = lambda: None
    client.app.dependency_overrides[get_users] = lambda: SimpleNamespace(
        me=lambda _: Result(200, {"unexpected": "internal"})
    )
    with pytest.raises(ResponseValidationError):
        client.get("/v1/me")


def test_runtime_contract_matches_published_and_authentication(client):
    spec = client.get("/openapi.json").json()
    assert spec == json.loads(Path("contracts/openapi.json").read_text())
    for path, operations in spec["paths"].items():
        if path.startswith("/v1/operator/"):
            for operation in operations.values():
                assert operation["security"] == [{"operatorKey": []}]
                assert any(
                    p["name"] == "X-Auth-Operator-Actor" and p["required"]
                    for p in operation["parameters"]
                )
    route = "/v1/operator/users"
    assert client.get(route).status_code == 401
    invalid = client.get(route, headers={"X-Auth-Operator-Key": "k" * 32})
    assert invalid.status_code == 422
    assert invalid.json() == {
        "code": "invalid_input",
        "message": "Invalid request.",
        "requestId": invalid.headers["X-Request-ID"],
    }
    schema = spec["paths"][route]["get"]["responses"]["422"]["content"]["application/json"][
        "schema"
    ]
    assert schema["$ref"] == "#/components/schemas/ErrorResponse"


def test_wrong_method_retains_allow_header(client):
    response = client.post("/health/live")
    assert response.status_code == 405
    assert "GET" in response.headers["Allow"]
    assert response.json()["code"] == "method_not_allowed"
    assert client.get("/missing").json()["code"] == "not_found"
