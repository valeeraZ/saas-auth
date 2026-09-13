"""Generate disposable local credentials and a service-account-only Keycloak realm."""

import json
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
env_file = root / ".env"
realm_file = root / ".local" / "saas-local-realm.json"
if env_file.exists() or realm_file.exists():
    raise SystemExit(
        "Local configuration already exists; reuse it or remove it explicitly before regenerating."
    )
secret, password, cursor = (secrets.token_urlsafe(32) for _ in range(3))
realm = {
    "realm": "saas-local",
    "enabled": True,
    "sslRequired": "none",
    "accessTokenLifespan": 300,
    "registrationAllowed": False,
    "clients": [
        {
            "clientId": "saas-admin",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": secret,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False,
            "defaultClientScopes": ["tenants:read", "roles:read", "roles:write"],
            "protocolMappers": [
                {
                    "name": "auth-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                        "included.custom.audience": "saas-auth",
                        "access.token.claim": "true",
                    },
                }
            ],
        }
    ],
    "clientScopes": [
        {
            "name": scope,
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true"},
        }
        for scope in ["tenants:read", "roles:read", "roles:write"]
    ],
    "users": [
        {
            "id": "00000000-0000-4000-8000-000000000010",
            "username": "service-account-saas-admin",
            "enabled": True,
            "serviceAccountClientId": "saas-admin",
        }
    ],
}
realm_file.parent.mkdir(exist_ok=True)
realm_file.parent.chmod(0o700)
realm_file.write_text(json.dumps(realm, indent=2) + "\n")
# The private parent protects the host file; a single-file read-only mount lets
# Keycloak's unprivileged container user read it without exposing the directory.
realm_file.chmod(0o644)
env_file.write_text(
    f"SAAS_POSTGRES_PASSWORD={password}\nSAAS_CURSOR_SECRET={cursor}\n"
    f"SAAS_LOCAL_CLIENT_SECRET={secret}\n"
)
env_file.chmod(0o600)
print("Generated .env and .local/saas-local-realm.json (local testing only).")
