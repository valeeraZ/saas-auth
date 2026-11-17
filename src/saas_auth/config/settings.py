import os
from dataclasses import dataclass, field
from typing import Self
from urllib.parse import urlparse


@dataclass(frozen=True)
class Settings:
    database_url: str = field(repr=False)
    issuer: str
    cursor_secret: str = field(repr=False)
    audience: str = "saas-auth"
    allow_insecure_local: bool = False
    user_clients: tuple[str, ...] = ()
    introspection_client: str = ""
    introspection_secret: str = field(default="", repr=False)
    task_key: str = field(default="", repr=False)

    operator_key: str = field(
        default_factory=lambda: os.environ.get("SAAS_APP_OPERATOR_KEY", ""), repr=False
    )
    worker_client: str = field(
        default_factory=lambda: os.environ.get("SAAS_SESSION_WORKER_CLIENT", "")
    )
    worker_secret: str = field(
        default_factory=lambda: os.environ.get("SAAS_SESSION_WORKER_SECRET", ""), repr=False
    )

    def __post_init__(self) -> None:
        url = urlparse(self.issuer)
        local = self.allow_insecure_local and url.hostname in {"localhost", "127.0.0.1", "keycloak"}
        if not url.netloc or url.query or url.fragment or url.username:
            raise ValueError("Invalid issuer URL")
        if url.scheme != "https" and not (local and url.scheme == "http"):
            raise ValueError("Issuer must use HTTPS (explicit local development exception only)")
        if len(self.cursor_secret) < 32:
            raise ValueError("SAAS_CURSOR_SECRET must contain at least 32 characters")
        if self.user_clients:
            from cryptography.fernet import Fernet

            if not self.introspection_client or not self.introspection_secret:
                raise ValueError("User clients require introspection credentials")
            Fernet(self.task_key.encode())

    @classmethod
    def from_env(cls) -> Self:
        return cls(
            database_url=os.environ["SAAS_DATABASE_URL"],
            issuer=os.environ["SAAS_OIDC_ISSUER"].rstrip("/"),
            cursor_secret=os.environ["SAAS_CURSOR_SECRET"],
            audience=os.environ.get("SAAS_OIDC_AUDIENCE", "saas-auth"),
            allow_insecure_local=os.environ.get("SAAS_ALLOW_INSECURE_LOCAL") == "true",
            user_clients=tuple(filter(None, os.environ.get("SAAS_USER_CLIENTS", "").split(","))),
            introspection_client=os.environ.get("SAAS_INTROSPECTION_CLIENT", ""),
            introspection_secret=os.environ.get("SAAS_INTROSPECTION_SECRET", ""),
            task_key=os.environ.get("SAAS_TASK_KEY", ""),
        )
