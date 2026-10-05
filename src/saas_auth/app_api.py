"""Public identity/app authorization and a separately authenticated operator boundary."""

import hmac
import os
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from saas_auth.errors import ApiError
from saas_auth.security import Identity


class Grant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    userId: UUID
    roles: Annotated[
        list[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]],
        Field(min_length=1, max_length=100),
    ]
    enabled: StrictBool


class User(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    displayName: str
    email: str
    emailVerified: bool
    status: str


class CurrentUser(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user: User


class AppPermissions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    userId: UUID
    appId: UUID
    allowed: bool
    roles: list[str]
    authorizationVersion: int
    evaluatedAt: str


class UserPage(BaseModel):
    items: list[User]
    nextCursor: UUID | None


class AppGrant(BaseModel):
    userId: UUID
    appId: UUID
    roles: list[str]
    enabled: bool
    version: int


class ListedGrant(AppGrant):
    displayName: str
    email: str


class GrantPage(BaseModel):
    items: list[ListedGrant]
    nextCursor: UUID | None


Idem = Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)]


def app_router(service, authenticate, logout_authenticate, response):
    router = APIRouter()
    IdentityDep = Annotated[Identity, Depends(authenticate)]

    def operator(request: Request):
        expected = os.environ.get("SAAS_APP_OPERATOR_KEY", "")
        actual = request.headers.get("x-auth-operator-key", "")
        if len(expected) < 32 or not hmac.compare_digest(expected.encode(), actual.encode()):
            raise ApiError(401, "unauthenticated", "Operator authentication required.")
        actor = request.headers.get("x-auth-operator-actor", "")
        if (
            not actor.strip()
            or len(actor) > 200
            or any(ord(c) < 32 or ord(c) == 127 for c in actor)
        ):
            raise ApiError(422, "invalid_input", "Operator actor required.")
        return actor

    @router.get("/v1/me", operation_id="getCurrentUser", response_model=CurrentUser)
    def me(identity: IdentityDep):
        return response(service.me(identity))

    @router.get(
        "/v1/apps/{appId}/permissions",
        operation_id="evaluateOwnAppPermissions",
        response_model=AppPermissions,
    )
    def permissions(appId: UUID, identity: IdentityDep):
        return response(service.permissions(identity, appId))

    @router.delete("/v1/sessions/current", status_code=204, operation_id="revokeCurrentSession")
    def logout(
        identity: Annotated[Identity, Depends(logout_authenticate)], key: Idem, request: Request
    ):
        return response(service.logout(identity, key, request.state.request_id))

    @router.get("/v1/operator/users", response_model=UserPage)
    def users(actor: Annotated[str, Depends(operator)], cursor: UUID = UUID(int=0)):
        return response(service.users(cursor))

    @router.get("/v1/operator/apps/{appId}/grants", response_model=GrantPage)
    def grants(appId: UUID, actor: Annotated[str, Depends(operator)], cursor: UUID = UUID(int=0)):
        return response(service.grants(appId, cursor))

    @router.put("/v1/operator/apps/{appId}/grants", response_model=AppGrant)
    def grant(
        appId: UUID,
        body: Grant,
        actor: Annotated[str, Depends(operator)],
        key: Idem,
        request: Request,
    ):
        return response(
            service.grant(
                appId,
                body.userId,
                sorted(set(body.roles)),
                body.enabled,
                key,
                actor,
                request.state.request_id,
            )
        )

    return router
