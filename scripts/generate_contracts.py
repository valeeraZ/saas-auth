"""Generate the executable user/application API contract without connecting to a database."""

import json
from pathlib import Path

from saas_auth.api import create_app
from saas_auth.config import Settings

root = Path(__file__).resolve().parents[1]
settings = Settings(
    "postgresql://unused/unused",
    "https://identity.example.test/realms/platform",
    "unused-contract-secret-at-least-32",
)
spec = create_app(settings).openapi()
(root / "contracts/openapi.json").write_text(json.dumps(spec, indent=2) + "\n")
