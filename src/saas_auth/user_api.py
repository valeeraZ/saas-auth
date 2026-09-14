from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from saas_auth.security import Identity


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateTenant(Input):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    slug: Annotated[str, Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=63)]


class ChangeTenant(Input):
    status: Literal["active", "suspended", "deleting"]


class SelectTenant(Input):
    tenantId: UUID


class UpdateMember(Input):
    tenantRole: Literal["owner", "admin", "member"]
    status: Literal["active", "suspended", "revoked"]


class Invite(Input):
    email: Annotated[EmailStr, Field(max_length=254)]


class AcceptInvite(Input):
    token: Annotated[str, Field(min_length=32, max_length=2048)]


class AssignRole(Input):
    userId: UUID
    roleId: UUID


Idem = Annotated[str, Header(alias="Idempotency-Key", min_length=16, max_length=128)]
ETag = Annotated[str, Header(alias="If-Match", pattern=r'^"[1-9][0-9]*"$')]
Limit = Annotated[int, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(max_length=4096)]


def user_router(service, authenticate, logout_authenticate, response):
    router = APIRouter()
    IdentityDep = Annotated[Identity, Depends(authenticate)]

    @router.get("/v1/me", operation_id="getCurrentUser")
    def me(identity: IdentityDep):
        return response(service.me(identity))

    @router.get("/v1/tenants", operation_id="listTenants")
    def tenants(identity: IdentityDep, limit: Limit = 50, cursor: Cursor = None):
        return response(service.tenants(identity, limit, cursor))

    @router.post("/v1/tenants", operation_id="createTenant", status_code=201)
    def create_tenant(body: CreateTenant, identity: IdentityDep, key: Idem, request: Request):
        return response(
            service.create_tenant(identity, body.model_dump(), key, request.state.request_id)
        )

    @router.post("/v1/tenant-context", operation_id="selectTenant")
    def context(body: SelectTenant, identity: IdentityDep):
        return response(service.snapshot(identity, body.tenantId, True))

    @router.patch("/v1/tenants/{tenantId}", operation_id="changeTenantStatus")
    def change_tenant(
        tenantId: UUID,
        body: ChangeTenant,
        identity: IdentityDep,
        key: Idem,
        etag: ETag,
        request: Request,
    ):
        return response(
            service.change_tenant(
                identity, tenantId, body.model_dump(), key, etag, request.state.request_id
            )
        )

    @router.get("/v1/tenants/{tenantId}/members", operation_id="listMembers")
    def members(tenantId: UUID, identity: IdentityDep, limit: Limit = 50, cursor: Cursor = None):
        return response(service.list_resources(identity, tenantId, "members", limit, cursor))

    @router.patch("/v1/tenants/{tenantId}/members/{userId}", operation_id="updateMember")
    def update_member(
        tenantId: UUID,
        userId: UUID,
        body: UpdateMember,
        identity: IdentityDep,
        key: Idem,
        etag: ETag,
        request: Request,
    ):
        return response(
            service.update_member(
                identity, tenantId, userId, body.model_dump(), key, etag, request.state.request_id
            )
        )

    @router.get("/v1/tenants/{tenantId}/invitations", operation_id="listInvitations")
    def invitations(
        tenantId: UUID, identity: IdentityDep, limit: Limit = 50, cursor: Cursor = None
    ):
        return response(service.list_resources(identity, tenantId, "invitations", limit, cursor))

    @router.post("/v1/tenants/{tenantId}/invitations", operation_id="inviteMember", status_code=201)
    def invite(tenantId: UUID, body: Invite, identity: IdentityDep, key: Idem, request: Request):
        return response(
            service.invite(identity, tenantId, body.model_dump(), key, request.state.request_id)
        )

    @router.delete(
        "/v1/tenants/{tenantId}/invitations/{invitationId}",
        operation_id="revokeInvitation",
        status_code=204,
    )
    def revoke_invite(
        tenantId: UUID,
        invitationId: UUID,
        identity: IdentityDep,
        key: Idem,
        etag: ETag,
        request: Request,
    ):
        return response(
            service.revoke_invite(
                identity, tenantId, invitationId, key, etag, request.state.request_id
            )
        )

    @router.post("/v1/invitations/accept", operation_id="acceptInvitation")
    def accept(body: AcceptInvite, identity: IdentityDep, key: Idem, request: Request):
        return response(
            service.accept_invite(identity, body.model_dump(), key, request.state.request_id)
        )

    @router.get("/v1/tenants/{tenantId}/role-assignments", operation_id="listAssignments")
    def assignments(
        tenantId: UUID, identity: IdentityDep, limit: Limit = 50, cursor: Cursor = None
    ):
        return response(
            service.list_resources(identity, tenantId, "role-assignments", limit, cursor)
        )

    @router.post(
        "/v1/tenants/{tenantId}/role-assignments", operation_id="assignRole", status_code=201
    )
    def assign(
        tenantId: UUID, body: AssignRole, identity: IdentityDep, key: Idem, request: Request
    ):
        return response(
            service.assign(
                identity, tenantId, body.model_dump(mode="json"), key, request.state.request_id
            )
        )

    @router.delete(
        "/v1/tenants/{tenantId}/role-assignments/{assignmentId}",
        operation_id="revokeRoleAssignment",
        status_code=204,
    )
    def revoke(
        tenantId: UUID,
        assignmentId: UUID,
        identity: IdentityDep,
        key: Idem,
        etag: ETag,
        request: Request,
    ):
        return response(
            service.revoke_assignment(
                identity, tenantId, assignmentId, key, etag, request.state.request_id
            )
        )

    @router.get(
        "/v1/tenants/{tenantId}/apps/{appId}/permissions", operation_id="evaluateOwnPermissions"
    )
    def permissions(tenantId: UUID, appId: UUID, identity: IdentityDep):
        return response(service.permissions(identity, tenantId, appId))

    @router.delete("/v1/sessions/current", operation_id="revokeCurrentSession", status_code=204)
    def logout(
        identity: Annotated[Identity, Depends(logout_authenticate)], key: Idem, request: Request
    ):
        return response(service.logout(identity, key, request.state.request_id))

    return router
