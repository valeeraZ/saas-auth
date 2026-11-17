"""Role declarations and transactional access-request decisions."""

from uuid import UUID, uuid4

from sqlalchemy import func, select

from saas_auth.db.models import AccessRequest, Grant, Role, RoleSet, User
from saas_auth.errors import ApiError, forbidden
from saas_auth.identity.security import Identity

from .operations import Result, app_lock, audit, replay, save, set_grant, valid_roles
from .roles import RoleDefinition
from .users import AppService


def request_json(row: AccessRequest, user: User | None = None) -> dict[str, object]:
    return {
        "id": str(row.id),
        "userId": str(row.user_id),
        "appId": str(row.app_id),
        "roles": row.roles,
        "reason": row.reason,
        "status": row.status,
        "reviewer": row.reviewer,
        "comment": row.comment,
        "createdAt": row.created_at.isoformat(),
        "reviewedAt": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "displayName": user.display_name if user else "",
        "email": user.email if user else "",
    }


class AccessService:
    def __init__(self, users: AppService) -> None:
        self.users = users
        self.database = users.database

    def roles(self, app_id: UUID, *, active_only: bool = False) -> Result:
        with self.database.sessions.begin() as session:
            # Read the role set and version in one snapshot, even during an edit.
            join = Role.app_id == RoleSet.app_id
            if active_only:
                join = join & Role.active
            rows = session.execute(
                select(RoleSet.version, Role)
                .outerjoin(Role, join)
                .where(RoleSet.app_id == app_id)
                .order_by(Role.key)
            ).all()
            roles = [
                {"key": r.key, "name": r.name, "description": r.description, "active": r.active}
                for _, r in rows
                if r is not None
            ]
            return Result(
                200,
                {"appId": str(app_id), "version": rows[0].version if rows else 0, "roles": roles},
            )

    def configure(
        self,
        app_id: UUID,
        roles: list[RoleDefinition],
        version: int,
        key: str,
        actor: str,
        request_id: UUID,
    ) -> Result:
        definitions = [r.model_dump() for r in roles]
        with self.database.sessions.begin() as session:
            digest, saved = replay(
                session, key, ["roles", str(app_id), definitions, version, actor]
            )
            if saved is not None:
                return Result(200, saved)
            app_lock(session, app_id)
            current = session.get(RoleSet, app_id)
            if (current.version if current else 0) != version:
                raise ApiError(
                    409, "version_conflict", "Role definitions changed. Reload before editing."
                )
            keys = {r.key for r in roles}
            if len(keys) != len(roles):
                raise ApiError(422, "invalid_input", "Role keys must be unique.")
            if current:
                current.version += 1
            else:
                session.add(RoleSet(app_id=app_id, version=1))
                session.flush()
            existing = {
                role.key: role
                for role in session.scalars(select(Role).where(Role.app_id == app_id))
            }
            for definition in roles:
                role = existing.pop(definition.key, None)
                if role is None:
                    session.add(Role(app_id=app_id, **definition.model_dump()))
                else:
                    role.name, role.description, role.active = (
                        definition.name,
                        definition.description,
                        definition.active,
                    )
            for removed in existing.values():
                session.delete(removed)
            # Retiring the last active role disables the grant permanently.
            active = {r.key for r in roles if r.active}
            for grant in session.scalars(
                select(Grant).where(Grant.app_id == app_id).with_for_update()
            ):
                remaining = sorted(active.intersection(grant.roles))
                if remaining != grant.roles:
                    grant.roles = remaining or grant.roles
                    grant.enabled = bool(remaining) and grant.enabled
                    grant.version += 1
            body = {"appId": str(app_id), "version": version + 1, "roles": definitions}
            save(session, key, digest, body)
            audit(session, actor, "application.roles.updated", app_id, request_id, body)
            return Result(200, body)

    def own(self, identity: Identity, app_id: UUID) -> Result:
        with self.database.sessions.begin() as session:
            user = self.users.user(session, identity)
            rows = session.scalars(
                select(AccessRequest)
                .where(AccessRequest.user_id == user.id, AccessRequest.app_id == app_id)
                .order_by(AccessRequest.created_at.desc(), AccessRequest.id.desc())
                .limit(20)
            )
            return Result(200, {"items": [request_json(row) for row in rows]})

    def submit(
        self,
        identity: Identity,
        app_id: UUID,
        roles: list[str],
        reason: str,
        key: str,
        request_id: UUID,
    ) -> Result:
        with self.database.sessions.begin() as session:
            user = self.users.user(session, identity)
            key = "request:" + str(user.id) + ":" + key
            digest, saved = replay(session, key, ["request", str(app_id), roles, reason])
            if saved is not None:
                return Result(200, saved)
            app_lock(session, app_id)
            valid_roles(session, app_id, roles)
            if session.scalar(
                select(AccessRequest.id).where(
                    AccessRequest.user_id == user.id,
                    AccessRequest.app_id == app_id,
                    AccessRequest.status == "pending",
                )
            ):
                raise ApiError(409, "pending_request", "There is already a pending request.")
            grant = session.get(Grant, (user.id, app_id))
            if grant and grant.enabled and set(roles).issubset(grant.roles):
                raise ApiError(409, "already_authorized", "These roles are already authorized.")
            row = AccessRequest(
                id=uuid4(), user_id=user.id, app_id=app_id, roles=roles, reason=reason
            )
            session.add(row)
            session.flush()
            body = request_json(row)
            save(session, key, digest, body)
            audit(
                session,
                "user:" + str(user.id),
                "application.access.requested",
                row.id,
                request_id,
                body,
            )
            return Result(200, body)

    def queue(self, after: UUID, status: str | None = None, limit: int = 20) -> Result:
        with self.database.sessions.begin() as session:
            query = select(AccessRequest, User).join(User).where(AccessRequest.id > after)
            if status is not None:
                query = query.where(AccessRequest.status == status)
            rows = session.execute(query.order_by(AccessRequest.id).limit(limit + 1)).all()
            items = [request_json(r, u) for r, u in rows[:limit]]
            return Result(
                200, {"items": items, "nextCursor": items[-1]["id"] if len(rows) > limit else None}
            )

    def decide(
        self, id: UUID, decision: str, comment: str, key: str, actor: str, request_id: UUID
    ) -> Result:
        with self.database.sessions.begin() as session:
            digest, saved = replay(session, key, ["decision", str(id), decision, comment, actor])
            if saved is not None:
                return Result(200, saved)
            # Discover lock keys without caching a potentially stale request entity.
            owner = session.execute(
                select(AccessRequest.user_id, AccessRequest.app_id).where(AccessRequest.id == id)
            ).one_or_none()
            if owner is None:
                raise ApiError(404, "not_found", "Request not found.")
            user = session.get(User, owner.user_id, with_for_update=True)
            app_lock(session, owner.app_id)
            row = session.get(AccessRequest, id, with_for_update=True)
            if row is None:
                raise ApiError(404, "not_found", "Request not found.")
            if row.status != "pending":
                raise ApiError(409, "already_reviewed", "Request was already reviewed.")
            if decision == "approved":
                if user is None or user.status != "active":
                    raise forbidden()
                grant = session.get(Grant, (row.user_id, row.app_id), with_for_update=True)
                roles = sorted(set(row.roles).union(grant.roles if grant and grant.enabled else []))
                valid_roles(session, row.app_id, roles)
                set_grant(session, row.user_id, row.app_id, roles, True)
                audit(
                    session,
                    actor,
                    "application.grant.approved",
                    row.user_id,
                    request_id,
                    {"appId": str(row.app_id), "roles": roles, "requestId": str(id)},
                )
            row.status, row.reviewer, row.comment = decision, actor, comment
            row.reviewed_at = session.execute(select(func.now())).scalar_one()
            body = request_json(row)
            save(session, key, digest, body)
            audit(session, actor, "application.access." + decision, id, request_id, body)
            return Result(200, body)
