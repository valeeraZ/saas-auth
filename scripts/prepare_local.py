"""Generate disposable local credentials and an integration Keycloak realm."""

import json
import secrets
from pathlib import Path

from local_tls import create_tls
from realm_users import add_users

root = Path(__file__).resolve().parents[1]
env_file = root / ".env"
realm_file = root / ".local" / "saas-local-realm.json"
if env_file.exists() or realm_file.exists():
    raise SystemExit(
        "Local configuration already exists; reuse it or remove it explicitly before regenerating."
    )
password, cursor, operator = (secrets.token_urlsafe(32) for _ in range(3))
realm = {
    "realm": "saas-local",
    "enabled": True,
    "sslRequired": "none",
    "accessTokenLifespan": 300,
    "clients": [],
    "clientScopes": [],
    "users": [],
}
user_config = add_users(realm)
realm_file.parent.mkdir(exist_ok=True)
realm_file.parent.chmod(0o700)
create_tls(realm_file.parent)
realm_file.write_text(json.dumps(realm, indent=2) + "\n")
# The private parent protects the host file; a single-file read-only mount lets
# Keycloak's unprivileged container user read it without exposing the directory.
realm_file.chmod(0o644)
env_file.write_text(
    f"SAAS_POSTGRES_PASSWORD={password}\nSAAS_CURSOR_SECRET={cursor}\n"
    f"SAAS_APP_OPERATOR_KEY={operator}\n"
    + "".join(f"{key}={value}\n" for key, value in user_config.items())
)
env_file.chmod(0o600)
print("Generated .env and .local/saas-local-realm.json (local testing only).")
