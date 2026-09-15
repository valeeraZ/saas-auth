import os
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class Settings:
    database_url: str
    issuer: str
    cursor_secret: str
    audience: str = "saas-auth"
    allow_insecure_local: bool = False

    def __post_init__(self):
        url = urlparse(self.issuer)
        local = self.allow_insecure_local and url.hostname in {"localhost", "127.0.0.1", "keycloak"}
        if not url.netloc or url.query or url.fragment or url.username:
            raise ValueError("Invalid issuer URL")
        if url.scheme != "https" and not (local and url.scheme == "http"):
            raise ValueError("Issuer must use HTTPS (explicit local development exception only)")
        if len(self.cursor_secret) < 32:
            raise ValueError("SAAS_CURSOR_SECRET must contain at least 32 characters")

    @classmethod
    def from_env(cls):
        return cls(
            database_url=os.environ["SAAS_DATABASE_URL"],
            issuer=os.environ["SAAS_OIDC_ISSUER"].rstrip("/"),
            cursor_secret=os.environ["SAAS_CURSOR_SECRET"],
            audience=os.environ.get("SAAS_OIDC_AUDIENCE", "saas-auth"),
            allow_insecure_local=os.environ.get("SAAS_ALLOW_INSECURE_LOCAL") == "true",
        )
