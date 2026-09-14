import httpx

from saas_auth.errors import ApiError, unavailable


def introspect(settings, token, subject, sid):
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
