"""Verified users, local sessions and direct application grants."""

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saas_auth.config import Settings
from saas_auth.db import Database
from saas_auth.db.models import (
    ExternalIdentity,
    Grant,
    LoginSession,
    Principal,
    SessionTask,
    User,
    UserOperation,
)
from saas_auth.errors import ApiError, forbidden
from saas_auth.identity.provider import Revocation
from saas_auth.identity.security import Identity
from saas_auth.worker.revocation import deliver_claimed, reserve

from .operations import Result, app_lock, audit, lock, replay, save, set_grant, valid_roles


def user_json(user: User) -> dict[str, object]:
    return {
        "id": str(user.id),
        "displayName": user.display_name,
        "email": user.email,
        "emailVerified": user.email_verified,
        "status": user.status,
    }


class AppService:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings
        self.cipher = Fernet(settings.task_key.encode()) if settings.task_key else None

    def user(self, session: Session, identity: Identity, *, logout: bool = False) -> User:
        if not identity.human:
            raise forbidden()
        # Verified issuer and subject identify a user, including on concurrent first login.
        lock(session, json.dumps([identity.issuer, identity.subject]))
        if session.scalar(
            select(Principal.id).where(
                Principal.issuer == identity.issuer, Principal.subject == identity.subject
            )
        ):
            raise forbidden()
        external = session.get(ExternalIdentity, (identity.issuer, identity.subject))
        if external is None:
            if logout:
                raise forbidden()
            user = User(
                id=uuid4(),
                display_name=identity.display_name,
                email=identity.email,
                email_verified=identity.email_verified,
            )
            session.add(user)
            session.flush()
            session.add(
                ExternalIdentity(issuer=identity.issuer, subject=identity.subject, user_id=user.id)
            )
            audit(session, "user:" + str(user.id), "user.mapped", user.id, uuid4())
        else:
            existing = session.get(User, external.user_id, with_for_update=True)
            if existing is None or existing.status != "active":
                raise forbidden()
            user = existing
        login = session.get(LoginSession, (identity.issuer, identity.sid), with_for_update=True)
        now = session.execute(select(func.now())).scalar_one()
        if login:
            if login.user_id != user.id:
                raise forbidden()
            if not logout and (
                login.revoked_at
                or (now - login.last_seen_at).total_seconds() >= 1800
                or (now - login.created_at).total_seconds() >= 28800
            ):
                raise ApiError(401, "unauthenticated", "A current user session is required.")
        elif logout:
            raise forbidden()
        else:
            login = LoginSession(issuer=identity.issuer, sid=identity.sid, user_id=user.id)
            session.add(login)
        if not logout:
            login.last_seen_at = now
            user.display_name, user.email, user.email_verified = (
                identity.display_name,
                identity.email,
                identity.email_verified,
            )
        return user

    def me(self, identity: Identity) -> Result:
        with self.database.sessions.begin() as session:
            return Result(200, {"user": user_json(self.user(session, identity))})

    def permissions(self, identity: Identity, app_id: UUID) -> Result:
        with self.database.sessions.begin() as session:
            user = self.user(session, identity)
            grant = session.get(Grant, (user.id, app_id))
            roles = grant.roles if grant and grant.enabled else []
            return Result(
                200,
                {
                    "userId": str(user.id),
                    "appId": str(app_id),
                    "allowed": bool(roles),
                    "roles": roles,
                    "authorizationVersion": grant.version if grant else 0,
                    "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                },
            )

    def grant(
        self,
        app_id: UUID,
        user_id: UUID,
        roles: list[str],
        enabled: bool,
        key: str,
        actor: str,
        request_id: UUID,
    ) -> Result:
        with self.database.sessions.begin() as session:
            digest, saved = replay(session, key, [str(app_id), str(user_id), roles, enabled, actor])
            if saved is not None:
                return Result(200, saved)
            user = session.get(User, user_id, with_for_update={"read": True})
            if user is None:
                raise ApiError(404, "not_found", "User not found.")
            if enabled and user.status != "active":
                raise forbidden()
            app_lock(session, app_id)
            if enabled:
                valid_roles(session, app_id, roles)
            grant = set_grant(session, user_id, app_id, roles, enabled)
            body = {
                "userId": str(user_id),
                "appId": str(app_id),
                "roles": roles,
                "enabled": enabled,
                "version": grant.version,
            }
            save(session, key, digest, body)
            audit(session, actor, "application.grant.updated", user_id, request_id, body)
            return Result(200, body)

    def grants(self, app_id: UUID, after: UUID, limit: int = 50) -> Result:
        with self.database.sessions.begin() as session:
            rows = session.execute(
                select(Grant, User)
                .join(User)
                .where(Grant.app_id == app_id, Grant.user_id > after)
                .order_by(Grant.user_id)
                .limit(limit + 1)
            ).all()
            items = [
                {
                    "userId": str(user.id),
                    "displayName": user.display_name,
                    "email": user.email,
                    "appId": str(app_id),
                    "roles": grant.roles,
                    "enabled": grant.enabled,
                    "version": grant.version,
                }
                for grant, user in rows[:limit]
            ]
            return Result(
                200,
                {"items": items, "nextCursor": items[-1]["userId"] if len(rows) > limit else None},
            )

    def users(self, after: UUID, limit: int = 50) -> Result:
        with self.database.sessions.begin() as session:
            rows = session.scalars(
                select(User).where(User.id > after).order_by(User.id).limit(limit + 1)
            ).all()
            items = [user_json(u) for u in rows[:limit]]
            return Result(
                200, {"items": items, "nextCursor": items[-1]["id"] if len(rows) > limit else None}
            )

    def logout(self, identity: Identity, key: str, request_id: UUID) -> Result:
        with self.database.sessions.begin() as session:
            user = self.user(session, identity, logout=True)
            resource = json.dumps([identity.issuer, identity.sid])
            digest = hashlib.sha256(resource.encode()).hexdigest()
            route = "/v1/sessions/current"
            saved = session.get(UserOperation, (user.id, "DELETE", route, key))
            if saved and saved.request_hash != digest:
                raise ApiError(
                    409, "idempotency_conflict", "Key already used for a different request."
                )
            if not saved:
                login = session.get_one(LoginSession, (identity.issuer, identity.sid))
                if login.revoked_at is None:
                    login.revoked_at = session.execute(select(func.now())).scalar_one()
                    audit(session, "user:" + str(user.id), "session.revoked", user.id, request_id)
                session.add(
                    UserOperation(
                        user_id=user.id,
                        method="DELETE",
                        route=route,
                        key=key,
                        request_hash=digest,
                        status=204,
                    )
                )
            task = session.scalar(select(SessionTask).where(SessionTask.resource_id == resource))
            if task is None:
                if self.cipher is None:
                    raise ApiError(503, "dependency_unavailable", "Session worker unavailable.")
                data = (
                    Revocation(issuer=identity.issuer, sid=identity.sid).model_dump_json().encode()
                )
                session.add(
                    SessionTask(
                        id=uuid4(),
                        resource_id=resource,
                        ciphertext=self.cipher.encrypt(data).decode(),
                    )
                )
            elif task.completed_at is not None:
                return Result(204)
            lease = reserve(session, resource)
        # Release row locks and commit local logout before contacting Keycloak.
        if lease and deliver_claimed(self.database, self.settings, lease):
            return Result(204)
        return Result(202, {"upstreamRevocation": "pending"})
