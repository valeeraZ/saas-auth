import hmac
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, Request
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from saas_auth.config import Settings
from saas_auth.db import Database
from saas_auth.errors import ApiError
from saas_auth.identity.security import Identity, TokenVerifier
from saas_auth.services.access import AccessService
from saas_auth.services.users import AppService


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_verifier(request: Request) -> TokenVerifier:
    return request.app.state.verifier


def get_users(
    database: Annotated[Database, Depends(get_database)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AppService:
    return AppService(database, settings)


Users = Annotated[AppService, Depends(get_users)]


def get_access(users: Users) -> AccessService:
    return AccessService(users)


Access = Annotated[AccessService, Depends(get_access)]
user_bearer = HTTPBearer(auto_error=False, scheme_name="userAccess")


def authenticate_user(
    verifier: Annotated[TokenVerifier, Depends(get_verifier)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(user_bearer)],
) -> Identity:
    return verifier.verify("Bearer " + credentials.credentials if credentials else None)


def logout_authenticate(
    verifier: Annotated[TokenVerifier, Depends(get_verifier)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(user_bearer)],
) -> Identity:
    # Only a previously established, matching local session may be revoked or replayed.
    # Local logout must remain available during an IdP outage.
    return verifier.verify(
        "Bearer " + credentials.credentials if credentials else None, check_session=False
    )


operator_key = APIKeyHeader(
    name="X-Auth-Operator-Key",
    scheme_name="operatorKey",
    auto_error=False,
    description="Private operator credential held by the Admin server.",
)


def verify_operator_key(
    actual: Annotated[str | None, Depends(operator_key)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    expected = settings.operator_key
    if (
        actual is None
        or len(expected) < 32
        or not hmac.compare_digest(expected.encode(), actual.encode())
    ):
        raise ApiError(401, "unauthenticated", "Operator authentication required.")


def operator(
    actor: Annotated[
        str,
        Header(
            alias="X-Auth-Operator-Actor",
            description="Trusted operator identity for the audit log.",
        ),
    ],
    _: Annotated[None, Depends(verify_operator_key)],
) -> str:
    if not actor.strip() or len(actor) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in actor):
        raise ApiError(422, "invalid_input", "Operator actor required.")
    return actor


def request_id(request: Request) -> UUID:
    return request.state.request_id


RequestId = Annotated[UUID, Depends(request_id)]
Operator = Annotated[str, Depends(operator)]
