from dataclasses import dataclass

import jwt
from jwt.exceptions import PyJWKClientConnectionError

from saas_auth.config import Settings
from saas_auth.errors import ApiError, unavailable


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    client_id: str
    scopes: frozenset[str]
    human: bool = False
    sid: str = ""
    email: str = ""
    email_verified: bool = False
    display_name: str = ""


class TokenVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.jwks = jwt.PyJWKClient(
            settings.issuer + "/protocol/openid-connect/certs",
            timeout=3,
            cache_jwk_set=True,
            lifespan=60,
        )

    def verify(self, authorization: str | None, *, check_session: bool = True) -> Identity:
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
            human = claims["azp"] in self.settings.user_clients
            if human:
                if (
                    not isinstance(claims.get("sid"), str)
                    or not 1 <= len(claims["sid"]) <= 200
                    or not isinstance(claims.get("email"), str)
                    or not 3 <= len(claims["email"]) <= 254
                    or "@" not in claims["email"]
                    or type(claims.get("email_verified")) is not bool
                ):
                    raise jwt.InvalidTokenError()
                if check_session:
                    from saas_auth.identity.provider import introspect

                    introspect(self.settings, token, claims["sub"], claims["sid"])
            return Identity(
                claims["iss"],
                claims["sub"],
                claims["azp"],
                frozenset(claims.get("scope", "").split()),
                human,
                claims.get("sid", "") if human else "",
                claims.get("email", "").casefold() if human else "",
                claims.get("email_verified", False) if human else False,
                str(claims.get("name") or claims.get("preferred_username") or "User")[:200],
            )
        except PyJWKClientConnectionError:
            raise unavailable() from None
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            raise ApiError(401, "unauthenticated", "A valid access token is required.") from None
