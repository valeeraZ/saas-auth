"""Validate the current API contract and ensure removed tenancy is not exposed."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from openapi_spec_validator import validate

root = Path(__file__).resolve().parents[1]
spec = json.loads((root / "contracts/openapi.json").read_text())
validate(spec)
assert not any("tenant" in path for path in spec["paths"])
assert "/v1/apps/{appId}/permissions" in spec["paths"]
assert all(
    operation.get("security") == [{"operatorKey": []}]
    for path, methods in spec["paths"].items()
    if path.startswith("/v1/operator/")
    for operation in methods.values()
)
example = json.loads((root / "contracts/examples/current-user.json").read_text())
schema = {"$ref": "#/components/schemas/CurrentUser", "components": spec["components"]}
Draft202012Validator(schema, format_checker=FormatChecker()).validate(example)
assert list(Draft202012Validator(schema).iter_errors(example | {"tenants": []}))
print("Validated user/application OpenAPI and current-user example.")
