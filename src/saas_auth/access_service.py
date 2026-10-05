"""Declared app roles and durable, transactional request decisions."""

import hashlib
import json
from uuid import uuid4

from psycopg.types.json import Jsonb

from saas_auth.app_service import Result, audit
from saas_auth.errors import ApiError, forbidden


def app_lock(conn, app_id):
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", ("app:" + str(app_id),))


def valid_roles(conn, app_id, roles):
    active = {
        r["key"]
        for r in conn.execute(
            "SELECT key FROM app_roles WHERE app_id=%s AND active", (app_id,)
        ).fetchall()
    }
    if not roles or not set(roles).issubset(active):
        raise ApiError(409, "invalid_roles", "Select currently declared application roles.")


def request_json(row):
    return {
        "id": str(row["id"]),
        "userId": str(row["user_id"]),
        "appId": str(row["app_id"]),
        "roles": row["roles"],
        "reason": row["reason"],
        "status": row["status"],
        "reviewer": row["reviewer"],
        "comment": row["comment"],
        "createdAt": row["created_at"].isoformat(),
        "reviewedAt": row["reviewed_at"].isoformat() if row["reviewed_at"] else None,
        "displayName": row.get("display_name", ""),
        "email": row.get("email", ""),
    }


def replay(conn, key, body):
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (key,))
    saved = conn.execute("SELECT hash,body FROM app_operations WHERE key=%s", (key,)).fetchone()
    if saved and saved["hash"] != digest:
        raise ApiError(409, "idempotency_conflict", "Key already used for a different request.")
    return digest, saved["body"] if saved else None


def save(conn, key, digest, body):
    conn.execute(
        "INSERT INTO app_operations(key,hash,body) VALUES(%s,%s,%s)", (key, digest, Jsonb(body))
    )


class AccessService:
    def __init__(self, users):
        self.users = users
        self.pool = users.pool

    def roles(self, app_id):
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT version FROM app_role_sets WHERE app_id=%s", (app_id,)
            ).fetchone()
            roles = conn.execute(
                "SELECT key,name,description,active FROM app_roles WHERE app_id=%s ORDER BY key",
                (app_id,),
            ).fetchall()
            return Result(
                200, {"appId": str(app_id), "version": row["version"] if row else 0, "roles": roles}
            )

    def configure(self, app_id, roles, version, key, actor, request_id):
        with self.pool.connection() as conn:
            digest, saved = replay(conn, key, ["roles", str(app_id), roles, version, actor])
            if saved:
                return Result(200, saved)
            app_lock(conn, app_id)
            current = conn.execute(
                "SELECT version FROM app_role_sets WHERE app_id=%s", (app_id,)
            ).fetchone()
            if (current["version"] if current else 0) != version:
                raise ApiError(
                    409, "version_conflict", "Role definitions changed. Reload before editing."
                )
            keys = [r["key"] for r in roles]
            if len(set(keys)) != len(keys):
                raise ApiError(422, "invalid_input", "Role keys must be unique.")
            conn.execute(
                "INSERT INTO app_role_sets(app_id) VALUES(%s) ON CONFLICT(app_id) DO UPDATE SET version=app_role_sets.version+1",
                (app_id,),
            )
            conn.execute(
                "DELETE FROM app_roles WHERE app_id=%s AND NOT (key=ANY(%s::text[]))",
                (app_id, keys),
            )
            for r in roles:
                conn.execute(
                    "INSERT INTO app_roles(app_id,key,name,description,active) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(app_id,key) DO UPDATE SET name=excluded.name,description=excluded.description,active=excluded.active",
                    (app_id, r["key"], r["name"], r["description"], r["active"]),
                )
            # Retirement revokes this role permanently, including from existing grants.
            # A later reactivation never silently restores the old permission.
            active = [r["key"] for r in roles if r["active"]]
            rows = conn.execute(
                "SELECT * FROM user_app_grants WHERE app_id=%s FOR UPDATE", (app_id,)
            ).fetchall()
            for grant in rows:
                remaining = sorted(set(grant["roles"]).intersection(active))
                if remaining != grant["roles"]:
                    conn.execute(
                        "UPDATE user_app_grants SET roles=%s,enabled=%s,version=version+1 WHERE user_id=%s AND app_id=%s",
                        (
                            remaining or grant["roles"],
                            bool(remaining) and grant["enabled"],
                            grant["user_id"],
                            app_id,
                        ),
                    )
            result = {"appId": str(app_id), "version": version + 1, "roles": roles}
            save(conn, key, digest, result)
            audit(conn, actor, "application.roles.updated", app_id, request_id, result)
            return Result(200, result)

    def own(self, identity, app_id):
        with self.pool.connection() as conn:
            user = self.users.user(conn, identity)
            rows = conn.execute(
                "SELECT * FROM app_access_requests WHERE user_id=%s AND app_id=%s ORDER BY created_at DESC,id DESC LIMIT 20",
                (user["id"], app_id),
            ).fetchall()
            return Result(200, {"items": [request_json(r) for r in rows]})

    def submit(self, identity, app_id, roles, reason, key, request_id):
        with self.pool.connection() as conn:
            user = self.users.user(conn, identity)
            key = "request:" + str(user["id"]) + ":" + key
            digest, saved = replay(conn, key, ["request", str(app_id), roles, reason])
            if saved:
                return Result(200, saved)
            app_lock(conn, app_id)
            valid_roles(conn, app_id, roles)
            if conn.execute(
                "SELECT 1 FROM app_access_requests WHERE user_id=%s AND app_id=%s AND status='pending'",
                (user["id"], app_id),
            ).fetchone():
                raise ApiError(409, "pending_request", "There is already a pending request.")
            grant = conn.execute(
                "SELECT * FROM user_app_grants WHERE user_id=%s AND app_id=%s", (user["id"], app_id)
            ).fetchone()
            if grant and grant["enabled"] and set(roles).issubset(grant["roles"]):
                raise ApiError(409, "already_authorized", "These roles are already authorized.")
            row = conn.execute(
                "INSERT INTO app_access_requests(id,user_id,app_id,roles,reason) VALUES(%s,%s,%s,%s,%s) RETURNING *",
                (uuid4(), user["id"], app_id, roles, reason),
            ).fetchone()
            result = request_json(row)
            save(conn, key, digest, result)
            audit(
                conn,
                "user:" + str(user["id"]),
                "application.access.requested",
                row["id"],
                request_id,
                result,
            )
            return Result(200, result)

    def queue(self, after, status=None, limit=20):
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT r.*,u.display_name,u.email FROM app_access_requests r JOIN users u ON u.id=r.user_id WHERE r.id>%s AND (%s::text IS NULL OR r.status=%s) ORDER BY r.id LIMIT %s",
                (after, status, status, limit + 1),
            ).fetchall()
            items = [request_json(r) for r in rows[:limit]]
            return Result(
                200, {"items": items, "nextCursor": items[-1]["id"] if len(rows) > limit else None}
            )

    def decide(self, id, decision, comment, key, actor, request_id):
        with self.pool.connection() as conn:
            digest, saved = replay(conn, key, ["decision", str(id), decision, comment, actor])
            if saved:
                return Result(200, saved)
            found = conn.execute(
                "SELECT user_id,app_id FROM app_access_requests WHERE id=%s", (id,)
            ).fetchone()
            if not found:
                raise ApiError(404, "not_found", "Request not found.")
            user = conn.execute(
                "SELECT status FROM users WHERE id=%s FOR UPDATE", (found["user_id"],)
            ).fetchone()
            app_lock(conn, found["app_id"])
            row = conn.execute(
                "SELECT * FROM app_access_requests WHERE id=%s FOR UPDATE", (id,)
            ).fetchone()
            if row["status"] != "pending":
                raise ApiError(409, "already_reviewed", "Request was already reviewed.")
            if decision == "approved":
                if user["status"] != "active":
                    raise forbidden()
                valid_roles(conn, row["app_id"], row["roles"])
                grant = conn.execute(
                    "SELECT roles,enabled FROM user_app_grants WHERE user_id=%s AND app_id=%s FOR UPDATE",
                    (row["user_id"], row["app_id"]),
                ).fetchone()
                roles = sorted(
                    set(row["roles"])
                    | (set(grant["roles"]) if grant and grant["enabled"] else set())
                )
                valid_roles(conn, row["app_id"], roles)
                conn.execute(
                    "INSERT INTO user_app_grants(user_id,app_id,roles,enabled) VALUES(%s,%s,%s,true) ON CONFLICT(user_id,app_id) DO UPDATE SET roles=excluded.roles,enabled=true,version=user_app_grants.version+1",
                    (row["user_id"], row["app_id"], roles),
                )
                audit(
                    conn,
                    actor,
                    "application.grant.approved",
                    row["user_id"],
                    request_id,
                    {"appId": str(row["app_id"]), "roles": roles, "requestId": str(id)},
                )
            row = conn.execute(
                "UPDATE app_access_requests SET status=%s,reviewer=%s,comment=%s,reviewed_at=now() WHERE id=%s RETURNING *",
                (decision, actor, comment, id),
            ).fetchone()
            result = request_json(row)
            save(conn, key, digest, result)
            audit(conn, actor, "application.access." + decision, id, request_id, result)
            return Result(200, result)
