from urllib.parse import quote

import httpx
from pydantic import BaseModel

from saas_auth.config import Settings
from saas_auth.errors import ApiError, unavailable


def introspect(settings: Settings, token: str, subject: str, sid: str) -> None:
    try:
        response = httpx.post(
            settings.issuer + "/protocol/openid-connect/token/introspect",
            data={
                "token": token,
                "client_id": settings.introspection_client,
                "client_secret": settings.introspection_secret,
            },
            timeout=3,
        )
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError):
        raise unavailable() from None
    if not isinstance(data, dict):
        raise unavailable()
    if data.get("active") is not True or data.get("sub") != subject or data.get("sid") != sid:
        raise ApiError(401, "unauthenticated", "A current user session is required.")


class Revocation(BaseModel):
    issuer: str
    sid: str


def revoke_upstream(settings: Settings, data: Revocation) -> None:
    if data.issuer != settings.issuer or "/realms/" not in settings.issuer:
        raise ValueError("Unexpected issuer")
    if not settings.worker_client or not settings.worker_secret:
        raise ValueError("Session revocation credentials unavailable")
    prefix, realm = settings.issuer.rsplit("/realms/", 1)
    response = httpx.post(
        settings.issuer + "/protocol/openid-connect/token",
        timeout=3,
        data={
            "grant_type": "client_credentials",
            "client_id": settings.worker_client,
            "client_secret": settings.worker_secret,
        },
    )
    response.raise_for_status()
    token = response.json()["access_token"]
    response = httpx.delete(
        f"{prefix}/admin/realms/{quote(realm, safe='')}/sessions/{quote(data.sid, safe='')}",
        headers={"Authorization": "Bearer " + token},
        timeout=3,
    )
    if response.status_code != 404:
        response.raise_for_status()
