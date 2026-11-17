from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from saas_auth.services.roles import RoleDefinition, RoleKey


class Grant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    userId: UUID
    roles: Annotated[
        list[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]],
        Field(min_length=1, max_length=100),
    ]
    enabled: StrictBool


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


class RevocationPending(BaseModel):
    upstreamRevocation: Literal["pending"]


class ErrorResponse(BaseModel):
    code: str
    message: str
    requestId: UUID
