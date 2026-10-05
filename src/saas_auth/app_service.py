"""User identity, sessions and direct application grants. No platform data tenancy."""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.fernet import Fernet
from psycopg.types.json import Jsonb

from saas_auth.errors import ApiError, forbidden


@dataclass
class Result:
    status: int
    body: dict | None = None
    etag: str | None = None


def audit(conn, actor, action, resource_id, request_id, details=None):
    conn.execute(
        "INSERT INTO platform_audit(id,actor,action,resource_id,request_id,details) VALUES(%s,%s,%s,%s,%s,%s)",
        (uuid4(), str(actor), action, resource_id, request_id, Jsonb(details or {})),
    )


def user_json(row):
    return {
        "id": str(row["id"]),
        "displayName": row["display_name"],
        "email": row["email"],
        "emailVerified": row["email_verified"],
        "status": row["status"],
    }


class AppService:
    def __init__(self, pool, settings):
        self.pool = pool
        self.cipher = Fernet(settings.task_key.encode()) if settings.task_key else None

    def user(self, conn, identity, *, logout=False):
        if not identity.human:
            raise forbidden()
        # Serialize first-use mapping by verified issuer/subject; never link by email.
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
            (json.dumps([identity.issuer, identity.subject]),),
        )
        if conn.execute(
            "SELECT 1 FROM service_principals WHERE issuer=%s AND subject=%s",
            (identity.issuer, identity.subject),
        ).fetchone():
            raise forbidden()
        external = conn.execute(
            "SELECT user_id FROM external_identities WHERE issuer=%s AND subject=%s",
            (identity.issuer, identity.subject),
        ).fetchone()
        if not external:
            if logout:
                raise forbidden()
            user_id = uuid4()
            conn.execute(
                "INSERT INTO users(id,display_name,email,email_verified) VALUES (%s,%s,%s,%s)",
                (user_id, identity.display_name, identity.email, identity.email_verified),
            )
            conn.execute(
                "INSERT INTO external_identities(issuer,subject,user_id) VALUES (%s,%s,%s)",
                (identity.issuer, identity.subject, user_id),
            )
            audit(conn, "user:" + str(user_id), "user.mapped", user_id, uuid4())
        else:
            user_id = external["user_id"]
        user = conn.execute("SELECT * FROM users WHERE id=%s FOR UPDATE", (user_id,)).fetchone()
        if user["status"] != "active":
            raise forbidden()
        session = conn.execute(
            "SELECT *,now() AS current_time FROM auth_sessions WHERE issuer=%s AND sid=%s FOR UPDATE",
            (identity.issuer, identity.sid),
        ).fetchone()
        if session:
            if session["user_id"] != user_id:
                raise forbidden()
            if not logout and (
                session["revoked_at"] is not None
                or (session["current_time"] - session["last_seen_at"]).total_seconds() >= 1800
                or (session["current_time"] - session["created_at"]).total_seconds() >= 28800
            ):
                raise ApiError(401, "unauthenticated", "A current user session is required.")
        elif logout:
            raise forbidden()
        else:
            conn.execute(
                "INSERT INTO auth_sessions(issuer,sid,user_id) VALUES (%s,%s,%s)",
                (identity.issuer, identity.sid, user_id),
            )
        if not logout:
            conn.execute(
                "UPDATE auth_sessions SET last_seen_at=now() WHERE issuer=%s AND sid=%s",
                (identity.issuer, identity.sid),
            )
            user = conn.execute(
                "UPDATE users SET email=%s,email_verified=%s,display_name=%s WHERE id=%s RETURNING *",
                (identity.email, identity.email_verified, identity.display_name, user_id),
            ).fetchone()
        return user

    def me(self, identity):
        with self.pool.connection() as conn:
            return Result(200, {"user": user_json(self.user(conn, identity))})

    def permissions(self, identity, app_id):
        with self.pool.connection() as conn:
            user = self.user(conn, identity)
            grant = conn.execute(
                "SELECT *, now() AS evaluated_at FROM user_app_grants WHERE user_id=%s AND app_id=%s",
                (user["id"], app_id),
            ).fetchone()
            roles = grant["roles"] if grant and grant["enabled"] else []
            return Result(
                200,
                {
                    "userId": str(user["id"]),
                    "appId": str(app_id),
                    "allowed": bool(roles),
                    "roles": roles,
                    "authorizationVersion": grant["version"] if grant else 0,
                    "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                },
            )

    def task(self, conn, resource_id, data):
        if not self.cipher:
            raise ApiError(503, "dependency_unavailable", "Session worker unavailable.")
        conn.execute(
            "INSERT INTO session_tasks(id,resource_id,ciphertext) VALUES(%s,%s,%s) ON CONFLICT(resource_id) DO NOTHING",
            (uuid4(), resource_id, self.cipher.encrypt(json.dumps(data).encode()).decode()),
        )

    def grant(self, app_id, user_id, roles, enabled, key, actor, request_id):
        digest = hashlib.sha256(
            json.dumps([str(app_id), str(user_id), roles, enabled, actor], sort_keys=True).encode()
        ).hexdigest()
        with self.pool.connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (key,))
            saved = conn.execute(
                "SELECT hash,body FROM app_operations WHERE key=%s", (key,)
            ).fetchone()
            if saved:
                if saved["hash"] != digest:
                    raise ApiError(
                        409, "idempotency_conflict", "Key already used for a different request."
                    )
                return Result(200, saved["body"])
            user = conn.execute(
                "SELECT status FROM users WHERE id=%s FOR SHARE", (user_id,)
            ).fetchone()
            if not user:
                raise ApiError(404, "not_found", "User not found.")
            if enabled and user["status"] != "active":
                raise forbidden()
            from saas_auth.access_service import app_lock, valid_roles

            app_lock(conn, app_id)
            if enabled:
                valid_roles(conn, app_id, roles)
            row = conn.execute(
                "INSERT INTO user_app_grants(user_id,app_id,roles,enabled) VALUES(%s,%s,%s,%s) ON CONFLICT(user_id,app_id) DO UPDATE SET roles=excluded.roles,enabled=excluded.enabled,version=user_app_grants.version+1 RETURNING version",
                (user_id, app_id, roles, enabled),
            ).fetchone()
            result = {
                "userId": str(user_id),
                "appId": str(app_id),
                "roles": roles,
                "enabled": enabled,
                "version": row["version"],
            }
            conn.execute(
                "INSERT INTO app_operations(key,hash,body) VALUES(%s,%s,%s)",
                (key, digest, Jsonb(result)),
            )
            audit(conn, actor, "application.grant.updated", user_id, request_id, result)
            return Result(200, result)

    def grants(self, app_id, after, limit=50):
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT g.*,u.display_name,u.email FROM user_app_grants g JOIN users u ON u.id=g.user_id WHERE g.app_id=%s AND g.user_id>%s ORDER BY g.user_id LIMIT %s",
                (app_id, after, limit + 1),
            ).fetchall()
            items = [
                {
                    "userId": str(x["user_id"]),
                    "displayName": x["display_name"],
                    "email": x["email"],
                    "appId": str(app_id),
                    "roles": x["roles"],
                    "enabled": x["enabled"],
                    "version": x["version"],
                }
                for x in rows[:limit]
            ]
            return Result(
                200,
                {"items": items, "nextCursor": items[-1]["userId"] if len(rows) > limit else None},
            )

    def users(self, after, limit=50):
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM users WHERE id>%s ORDER BY id LIMIT %s", (after, limit + 1)
            ).fetchall()
            items = [user_json(x) for x in rows[:limit]]
            return Result(
                200, {"items": items, "nextCursor": items[-1]["id"] if len(rows) > limit else None}
            )

    def logout(self, identity, key, request_id):
        with self.pool.connection() as conn:
            user = self.user(conn, identity, logout=True)
            digest = hashlib.sha256(
                json.dumps([identity.issuer, identity.sid]).encode()
            ).hexdigest()
            args = (user["id"], "DELETE", "/v1/sessions/current", key)
            saved = conn.execute(
                "SELECT request_hash FROM user_idempotency WHERE user_id=%s AND method=%s AND route=%s AND key=%s",
                args,
            ).fetchone()
            if saved:
                if saved["request_hash"] != digest:
                    raise ApiError(
                        409, "idempotency_conflict", "Key already used for a different request."
                    )
                return Result(204)
            changed = conn.execute(
                "UPDATE auth_sessions SET revoked_at=now() WHERE issuer=%s AND sid=%s AND revoked_at IS NULL RETURNING sid",
                (identity.issuer, identity.sid),
            ).fetchone()
            if changed:
                self.task(
                    conn,
                    json.dumps([identity.issuer, identity.sid]),
                    {"issuer": identity.issuer, "sid": identity.sid},
                )
                audit(conn, "user:" + str(user["id"]), "session.revoked", user["id"], request_id)
            conn.execute(
                "INSERT INTO user_idempotency(user_id,method,route,key,request_hash,status) VALUES (%s,%s,%s,%s,%s,204)",
                (*args, digest),
            )
            return Result(204)
