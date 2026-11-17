import hashlib
import json
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saas_auth.db.models import Audit, Grant, Operation, Role
from saas_auth.errors import ApiError


@dataclass
class Result:
    status: int
    body: dict[str, object] | None = None
    etag: str | None = None


def lock(session: Session, key: str) -> None:
    session.execute(select(func.pg_advisory_xact_lock(func.hashtextextended(key, 0))))


def app_lock(session: Session, app_id: UUID) -> None:
    # Role edits, decisions and grant updates must see one another in commit order.
    lock(session, "app:" + str(app_id))


def audit(
    session: Session,
    actor: str,
    action: str,
    resource_id: UUID,
    request_id: UUID,
    details: dict[str, object] | None = None,
) -> None:
    session.add(
        Audit(
            id=uuid4(),
            actor=actor,
            action=action,
            resource_id=resource_id,
            request_id=request_id,
            details=details or {},
        )
    )


def replay(session: Session, key: str, body: list[object]) -> tuple[str, dict[str, object] | None]:
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    lock(session, key)
    saved = session.get(Operation, key)
    if saved and saved.hash != digest:
        raise ApiError(409, "idempotency_conflict", "Key already used for a different request.")
    return digest, saved.body if saved else None


def save(session: Session, key: str, digest: str, body: dict[str, object]) -> None:
    session.add(Operation(key=key, hash=digest, body=body))


def valid_roles(session: Session, app_id: UUID, roles: list[str]) -> None:
    active = session.scalars(select(Role.key).where(Role.app_id == app_id, Role.active))
    if not roles or not set(roles).issubset(active):
        raise ApiError(409, "invalid_roles", "Select currently declared application roles.")


def set_grant(
    session: Session, user_id: UUID, app_id: UUID, roles: list[str], enabled: bool
) -> Grant:
    """Caller holds the application lock while changing a grant."""
    grant = session.get(Grant, (user_id, app_id))
    if grant is None:
        grant = Grant(user_id=user_id, app_id=app_id, version=1)
        session.add(grant)
    else:
        grant.version += 1
    grant.roles, grant.enabled = roles, enabled
    return grant
