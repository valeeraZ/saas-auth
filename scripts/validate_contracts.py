"""Static contract checks, not authorization or integration tests."""
import copy
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from openapi_spec_validator import validate

root = Path(__file__).resolve().parents[1]
spec = json.loads((root / 'contracts/openapi.json').read_text())
validate(spec)
operations = []
for path, methods in spec['paths'].items():
    for method, operation in methods.items():
        operations.append(operation['operationId'])
        assert operation['security'] and operation['x-authorization-policy']
        if operation['x-mutating']:
            assert any(p.get('$ref', '').endswith('/IdempotencyKey') for p in operation['parameters'])
        if method in ('patch', 'delete') and '{' in path:
            assert any(p.get('$ref', '').endswith('/IfMatch') for p in operation['parameters'])
assert len(operations) == len(set(operations))

def expand(schema):
    if isinstance(schema, dict):
        if '$ref' in schema:
            return expand(spec['components']['schemas'][schema['$ref'].rsplit('/', 1)[1]])
        return {k: expand(v) for k, v in schema.items()}
    if isinstance(schema, list):
        return [expand(v) for v in schema]
    return schema

user_schema = expand(spec['components']['schemas']['CurrentUser'])
Draft202012Validator(user_schema, format_checker=FormatChecker()).validate(json.loads((root / 'contracts/examples/user-without-organization.json').read_text()))
event_schema = json.loads((root / 'contracts/events/organization-lifecycle.schema.json').read_text())
Draft202012Validator.check_schema(event_schema)
validator = Draft202012Validator(event_schema, format_checker=FormatChecker())
event = json.loads((root / 'contracts/examples/organization-created.json').read_text())
validator.validate(event)
for field, value in [('organizationId', 'not-a-uuid'), ('sequence', 0), ('schemaVersion', 2), ('accessToken', 'forbidden-secret')]:
    invalid = copy.deepcopy(event)
    invalid[field] = value
    assert list(validator.iter_errors(invalid)), field
invalid = copy.deepcopy(event)
invalid['data']['status'] = 'deleted'
assert list(validator.iter_errors(invalid))
print(f'Validated OpenAPI: {len(operations)} operations; event schema, 2 examples and 5 negative event cases.')
