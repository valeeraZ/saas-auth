from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Response
from fastapi.responses import JSONResponse

from saas_auth.identity.security import Identity
from saas_auth.services.operations import Result

from .dependencies import (
    Access,
    Operator,
    RequestId,
    Users,
    authenticate_user,
    logout_authenticate,
    operator,
)
from .schemas import (
    AccessRequest,
    AppGrant,
    AppPermissions,
    CurrentUser,
    Decision,
    ErrorResponse,
    Grant,
    GrantPage,
    OwnRequestPage,
    RequestPage,
    RequestRecord,
    RevocationPending,
    RoleConfiguration,
    RoleSet,
    UserPage,
)

router = APIRouter(
    prefix="/v1", responses={422: {"model": ErrorResponse, "description": "Invalid request"}}
)
operator_router = APIRouter(prefix="/operator", dependencies=[Depends(operator)])
IdentityDep = Annotated[Identity, Depends(authenticate_user)]
Idem = Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)]


def response_body(result: Result, response: Response) -> dict[str, object] | None:
    response.status_code = result.status
    if result.etag:
        response.headers["ETag"] = result.etag
    return result.body


@router.get("/me", operation_id="getCurrentUser", response_model=CurrentUser)
def me(response: Response, service: Users, identity: IdentityDep) -> dict[str, object] | None:
    return response_body(service.me(identity), response)


@router.get(
    "/apps/{appId}/permissions",
    operation_id="evaluateOwnAppPermissions",
    response_model=AppPermissions,
)
def permissions(
    response: Response, service: Users, appId: UUID, identity: IdentityDep
) -> dict[str, object] | None:
    return response_body(service.permissions(identity, appId), response)


@router.delete(
    "/sessions/current",
    status_code=204,
    operation_id="revokeCurrentSession",
    responses={
        204: {"description": "Local and Keycloak sessions revoked"},
        202: {
            "description": "Local session revoked; upstream revocation pending",
            "model": RevocationPending,
        },
    },
)
def logout(
    service: Users,
    identity: Annotated[Identity, Depends(logout_authenticate)],
    key: Idem,
    request_id: RequestId,
) -> Response:
    result = service.logout(identity, key, request_id)
    if result.status == 204:
        return Response(status_code=204)
    pending = RevocationPending.model_validate(result.body)
    return JSONResponse(pending.model_dump(mode="json"), status_code=result.status)


@operator_router.get("/users", response_model=UserPage)
def users(
    response: Response, service: Users, cursor: UUID = UUID(int=0)
) -> dict[str, object] | None:
    return response_body(service.users(cursor), response)


@operator_router.get("/apps/{appId}/grants", response_model=GrantPage)
def grants(
    response: Response,
    service: Users,
    appId: UUID,
    cursor: UUID = UUID(int=0),
) -> dict[str, object] | None:
    return response_body(service.grants(appId, cursor), response)


@operator_router.put("/apps/{appId}/grants", response_model=AppGrant)
def grant(
    response: Response,
    service: Users,
    appId: UUID,
    body: Grant,
    actor: Operator,
    key: Idem,
    request_id: RequestId,
) -> dict[str, object] | None:
    return response_body(
        service.grant(
            appId,
            body.userId,
            sorted(set(body.roles)),
            body.enabled,
            key,
            actor,
            request_id,
        ),
        response,
    )


@router.get("/apps/{appId}/roles", operation_id="listApplicationRoles", response_model=RoleSet)
def own_roles(
    response: Response, service: Users, access: Access, appId: UUID, identity: IdentityDep
) -> dict[str, object] | None:
    service.me(identity)
    return response_body(access.roles(appId, active_only=True), response)


@router.get(
    "/apps/{appId}/requests",
    operation_id="listOwnAccessRequests",
    response_model=OwnRequestPage,
)
def own_requests(
    response: Response, access: Access, appId: UUID, identity: IdentityDep
) -> dict[str, object] | None:
    return response_body(access.own(identity, appId), response)


@router.post(
    "/apps/{appId}/requests",
    operation_id="requestApplicationAccess",
    response_model=RequestRecord,
)
def submit(
    response: Response,
    access: Access,
    appId: UUID,
    body: AccessRequest,
    identity: IdentityDep,
    key: Idem,
    request_id: RequestId,
) -> dict[str, object] | None:
    return response_body(
        access.submit(identity, appId, sorted(set(body.roles)), body.reason, key, request_id),
        response,
    )


@operator_router.get("/apps/{appId}/roles", response_model=RoleSet)
def role_definitions(response: Response, access: Access, appId: UUID) -> dict[str, object] | None:
    return response_body(access.roles(appId), response)


@operator_router.put("/apps/{appId}/roles", response_model=RoleSet)
def configure_roles(
    response: Response,
    access: Access,
    appId: UUID,
    body: RoleConfiguration,
    actor: Operator,
    key: Idem,
    request_id: RequestId,
) -> dict[str, object] | None:
    return response_body(
        access.configure(
            appId,
            body.roles,
            body.version,
            key,
            actor,
            request_id,
        ),
        response,
    )


@operator_router.get("/requests", response_model=RequestPage)
def requests(
    response: Response,
    access: Access,
    cursor: UUID = UUID(int=0),
    status: Annotated[str | None, Query(pattern=r"^(pending|approved|rejected)$")] = None,
) -> dict[str, object] | None:
    return response_body(access.queue(cursor, status), response)


@operator_router.put("/requests/{requestId}", response_model=RequestRecord)
def decide(
    response: Response,
    access: Access,
    requestId: UUID,
    body: Decision,
    actor: Operator,
    key: Idem,
    request_id: RequestId,
) -> dict[str, object] | None:
    return response_body(
        access.decide(requestId, body.decision, body.comment, key, actor, request_id), response
    )


router.include_router(operator_router)
