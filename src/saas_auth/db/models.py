"""Mappings for the live PostgreSQL schema. Versioned migrations own DDL."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    type_annotation_map = {str: Text(), datetime: DateTime(timezone=True)}


class User(Base):
    __tablename__ = "users"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    display_name: Mapped[str]
    email: Mapped[str]
    email_verified: Mapped[bool] = mapped_column(server_default=text("false"))
    status: Mapped[str] = mapped_column(server_default="active")


class ExternalIdentity(Base):
    __tablename__ = "external_identities"
    issuer: Mapped[str] = mapped_column(primary_key=True)
    subject: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))


class Principal(Base):
    __tablename__ = "service_principals"
    __table_args__ = (
        UniqueConstraint("issuer", "subject"),
        UniqueConstraint("issuer", "client_id"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True)
    issuer: Mapped[str]
    subject: Mapped[str]
    client_id: Mapped[str]
    enabled: Mapped[bool] = mapped_column(server_default=text("true"))


class LoginSession(Base):
    __tablename__ = "auth_sessions"
    issuer: Mapped[str] = mapped_column(primary_key=True)
    sid: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    revoked_at: Mapped[datetime | None]


class UserOperation(Base):
    __tablename__ = "user_idempotency"
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    method: Mapped[str] = mapped_column(primary_key=True)
    route: Mapped[str] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(primary_key=True)
    request_hash: Mapped[str]
    status: Mapped[int]
    body: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    etag: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Grant(Base):
    __tablename__ = "user_app_grants"
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    app_id: Mapped[UUID] = mapped_column(primary_key=True)
    roles: Mapped[list[str]] = mapped_column(ARRAY(Text))
    enabled: Mapped[bool] = mapped_column(server_default=text("false"))
    version: Mapped[int] = mapped_column(BigInteger, server_default=text("1"))


class Audit(Base):
    __tablename__ = "platform_audit"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    actor: Mapped[str]
    action: Mapped[str]
    resource_id: Mapped[UUID]
    request_id: Mapped[UUID]
    details: Mapped[dict[str, object]] = mapped_column(JSONB, server_default="{}")
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Operation(Base):
    __tablename__ = "app_operations"
    key: Mapped[str] = mapped_column(primary_key=True)
    hash: Mapped[str]
    body: Mapped[dict[str, object]] = mapped_column(JSONB)


class SessionTask(Base):
    __tablename__ = "session_tasks"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    resource_id: Mapped[str] = mapped_column(unique=True)
    ciphertext: Mapped[str | None]
    available_at: Mapped[datetime] = mapped_column(server_default=func.now())
    lease_id: Mapped[UUID | None]
    lease_until: Mapped[datetime | None]
    attempts: Mapped[int] = mapped_column(server_default=text("0"))
    completed_at: Mapped[datetime | None]


class RoleSet(Base):
    __tablename__ = "app_role_sets"
    app_id: Mapped[UUID] = mapped_column(primary_key=True)
    version: Mapped[int] = mapped_column(BigInteger, server_default=text("1"))


class Role(Base):
    __tablename__ = "app_roles"
    app_id: Mapped[UUID] = mapped_column(ForeignKey("app_role_sets.app_id"), primary_key=True)
    key: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str]
    description: Mapped[str] = mapped_column(server_default="")
    active: Mapped[bool] = mapped_column(server_default=text("true"))


class AccessRequest(Base):
    __tablename__ = "app_access_requests"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    app_id: Mapped[UUID] = mapped_column(ForeignKey("app_role_sets.app_id"))
    roles: Mapped[list[str]] = mapped_column(ARRAY(Text))
    reason: Mapped[str] = mapped_column(server_default="")
    status: Mapped[str] = mapped_column(server_default="pending")
    reviewer: Mapped[str | None]
    comment: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    reviewed_at: Mapped[datetime | None]


# Keep ORM metadata aligned with the existing indexes for Alembic autogeneration.
Index("external_identities_user_idx", ExternalIdentity.user_id)
Index("sessions_user_idx", LoginSession.user_id)
Index("user_idempotency_created_idx", UserOperation.created_at)
Index("user_app_grants_app_idx", Grant.app_id, Grant.user_id)
Index(
    "session_tasks_pending_idx",
    SessionTask.available_at,
    SessionTask.id,
    postgresql_where=SessionTask.completed_at.is_(None),
)
Index(
    "one_pending_app_request",
    AccessRequest.user_id,
    AccessRequest.app_id,
    unique=True,
    postgresql_where=AccessRequest.status == "pending",
)
Index("app_request_queue", AccessRequest.status, AccessRequest.id)
Index("own_app_requests", AccessRequest.user_id, AccessRequest.app_id, AccessRequest.id)
