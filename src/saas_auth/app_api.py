"""Public identity/app authorization and a separately authenticated operator boundary."""

import hmac
import os
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from saas_auth.access_service import AccessService
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


RoleKey = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]


class RoleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: RoleKey
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    active: StrictBool = True


class RoleConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=0, strict=True)
    roles: list[RoleDefinition] = Field(max_length=100)


class AccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    roles: list[RoleKey] = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=2000)


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Annotated[str, Field(pattern=r"^(approved|rejected)$")]
    comment: str = Field(min_length=1, max_length=2000, pattern=r"\S")


class RoleSet(BaseModel):
    appId: UUID
    version: int
    roles: list[RoleDefinition]


class RequestRecord(BaseModel):
    id: UUID
    userId: UUID
    appId: UUID
    roles: list[RoleKey]
    reason: str
    status: Annotated[str, Field(pattern=r"^(pending|approved|rejected)$")]
    reviewer: str | None
    comment: str | None
    createdAt: datetime
    reviewedAt: datetime | None
    displayName: str
    email: str


class OwnRequestPage(BaseModel):
    items: list[RequestRecord]


class RequestPage(OwnRequestPage):
    nextCursor: UUID | None


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
    access = AccessService(service)
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

    @router.get(
        "/v1/apps/{appId}/roles", operation_id="listApplicationRoles", response_model=RoleSet
    )
    def own_roles(appId: UUID, identity: IdentityDep):
        service.me(identity)
        result = access.roles(appId)
        result.body["roles"] = [r for r in result.body["roles"] if r["active"]]
        return response(result)

    @router.get(
        "/v1/apps/{appId}/requests",
        operation_id="listOwnAccessRequests",
        response_model=OwnRequestPage,
    )
    def own_requests(appId: UUID, identity: IdentityDep):
        return response(access.own(identity, appId))

    @router.post(
        "/v1/apps/{appId}/requests",
        operation_id="requestApplicationAccess",
        response_model=RequestRecord,
    )
    def submit(
        appId: UUID, body: AccessRequest, identity: IdentityDep, key: Idem, request: Request
    ):
        return response(
            access.submit(
                identity, appId, sorted(set(body.roles)), body.reason, key, request.state.request_id
            )
        )

    @router.get("/v1/operator/apps/{appId}/roles", response_model=RoleSet)
    def role_definitions(appId: UUID, actor: Annotated[str, Depends(operator)]):
        return response(access.roles(appId))

    @router.put("/v1/operator/apps/{appId}/roles", response_model=RoleSet)
    def configure_roles(
        appId: UUID,
        body: RoleConfiguration,
        actor: Annotated[str, Depends(operator)],
        key: Idem,
        request: Request,
    ):
        return response(
            access.configure(
                appId,
                [r.model_dump() for r in body.roles],
                body.version,
                key,
                actor,
                request.state.request_id,
            )
        )

    @router.get("/v1/operator/requests", response_model=RequestPage)
    def requests(
        actor: Annotated[str, Depends(operator)],
        cursor: UUID = UUID(int=0),
        status: Annotated[str | None, Field(pattern=r"^(pending|approved|rejected)$")] = None,
    ):
        return response(access.queue(cursor, status))

    @router.put("/v1/operator/requests/{requestId}", response_model=RequestRecord)
    def decide(
        requestId: UUID,
        body: Decision,
        actor: Annotated[str, Depends(operator)],
        key: Idem,
        request: Request,
    ):
        return response(
            access.decide(
                requestId, body.decision, body.comment, key, actor, request.state.request_id
            )
        )

    return router
