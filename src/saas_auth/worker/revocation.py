"""Deliver a revocation outside its database transaction and acknowledge the lease."""

from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID, uuid4

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from saas_auth.config import Settings
from saas_auth.db import Database
from saas_auth.db.models import SessionTask
from saas_auth.identity.provider import Revocation, revoke_upstream


@dataclass(frozen=True)
class Lease:
    id: UUID
    lease_id: UUID
    attempts: int
    ciphertext: str


def reserve(session: Session, resource_id: str | None = None) -> Lease | None:
    query = select(SessionTask).where(
        SessionTask.completed_at.is_(None),
        SessionTask.available_at <= func.now(),
        or_(SessionTask.lease_until.is_(None), SessionTask.lease_until <= func.now()),
    )
    if resource_id is not None:
        query = query.where(SessionTask.resource_id == resource_id)
    task = session.scalar(
        query.order_by(SessionTask.available_at, SessionTask.id)
        .limit(1)
        .with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    )
    if task is None:
        return None
    assert task.ciphertext is not None
    task.lease_id = uuid4()
    task.lease_until = session.execute(select(func.now())).scalar_one() + timedelta(seconds=60)
    task.attempts += 1
    return Lease(task.id, task.lease_id, task.attempts, task.ciphertext)


def claim(database: Database) -> Lease | None:
    with database.sessions.begin() as session:
        return reserve(session)


def finish(database: Database, task: Lease, success: bool) -> bool:
    # A worker whose lease expired cannot overwrite a newer delivery attempt.
    stmt = (
        update(SessionTask)
        .where(
            SessionTask.id == task.id,
            SessionTask.lease_id == task.lease_id,
            SessionTask.lease_until > func.now(),
            SessionTask.completed_at.is_(None),
        )
        .values(
            lease_id=None,
            lease_until=None,
            available_at=func.now() + timedelta(seconds=2 ** min(task.attempts, 8)),
        )
    )
    if success:
        stmt = stmt.values(completed_at=func.now(), ciphertext=None)
    with database.sessions.begin() as session:
        return session.scalar(stmt.returning(SessionTask.id)) is not None


def deliver_claimed(database: Database, settings: Settings, task: Lease) -> bool:
    """Return true only after the upstream result is acknowledged under this lease."""
    try:
        data = Revocation.model_validate_json(
            Fernet(settings.task_key.encode()).decrypt(task.ciphertext.encode())
        )
        revoke_upstream(settings, data)
        success = True
    except (httpx.HTTPError, OSError, ValueError, KeyError, InvalidToken):
        # Do not log exception contents: SMTP/HTTP errors can include credentials.
        success = False
    acknowledged = finish(database, task, success)
    return acknowledged and success


def deliver_once(database: Database, settings: Settings) -> bool:
    task = claim(database)
    if not task:
        return False
    deliver_claimed(database, settings, task)
    return True
