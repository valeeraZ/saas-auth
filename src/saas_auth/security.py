from dataclasses import dataclass

import jwt
from jwt.exceptions import PyJWKClientConnectionError

from saas_auth.errors import ApiError, unavailable


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    client_id: str
    scopes: frozenset[str]


class TokenVerifier:
    def __init__(self, settings):
        self.settings = settings
        self.jwks = jwt.PyJWKClient(
            settings.issuer + "/protocol/openid-connect/certs",
            timeout=3,
            cache_jwk_set=True,
            lifespan=60,
        )

    def verify(self, authorization: str | None) -> Identity:
        if (
            not authorization
            or not authorization.startswith("Bearer ")
            or len(authorization) > 16384
        ):
            raise ApiError(401, "unauthenticated", "A valid access token is required.")
        token = authorization[7:]
        try:
            # Algorithms and JWKS location come from server policy, never untrusted token URLs.
            if jwt.get_unverified_header(token).get("alg") != "RS256":
                raise jwt.InvalidTokenError()
            key = self.jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                issuer=self.settings.issuer,
                audience=self.settings.audience,
                options={"require": ["iss", "aud", "sub", "azp", "exp", "iat", "typ"]},
            )
            if (
                claims["typ"] != "Bearer"
                or not isinstance(claims["azp"], str)
                or not claims["azp"]
                or not isinstance(claims.get("scope", ""), str)
                or type(claims["exp"]) is not int
                or type(claims["iat"]) is not int
                or not 0 < claims["exp"] - claims["iat"] <= 300
            ):
                raise jwt.InvalidTokenError()
            return Identity(
                claims["iss"],
                claims["sub"],
                claims["azp"],
                frozenset(claims.get("scope", "").split()),
            )
        except PyJWKClientConnectionError:
            raise unavailable() from None
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            raise ApiError(401, "unauthenticated", "A valid access token is required.") from None
