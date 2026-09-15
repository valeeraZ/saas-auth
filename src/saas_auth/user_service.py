import hashlib
import json
import secrets
from datetime import datetime, timezone
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from psycopg.types.json import Jsonb

from saas_auth.errors import ApiError, forbidden
from saas_auth.service import (
    Result,
    Service,
    append_event,
    audit,
    change_role,
    role_json,
    tenant_json,
)


def missing():
    return ApiError(404, "not_found", "Resource not found.")


def version(row, etag):
    if etag != f'"{row["version"]}"':
        raise ApiError(412, "version_conflict", "Resource version changed.")


def member_json(row):
    return {
        "tenantId": str(row["tenant_id"]),
        "userId": str(row["user_id"]),
        "tenantRole": row["tenant_role"],
        "status": row["status"],
        "version": row["version"],
    }


def invite_json(row):
    status = row["status"]
    if status == "pending" and row["expires_at"] <= datetime.now(timezone.utc):
        status = "expired"
    return {
        "id": str(row["id"]),
        "tenantId": str(row["tenant_id"]),
        "email": row["email"],
        "status": status,
        "expiresAt": row["expires_at"].isoformat(),
        "version": row["version"],
    }


def assignment_json(row):
    return {
        "id": str(row["id"]),
        "tenantId": str(row["tenant_id"]),
        "userId": str(row["user_id"]),
        "roleId": str(row["role_id"]),
        "version": row["version"],
    }


class UserService(Service):
    def __init__(self, pool, settings):
        super().__init__(pool, settings.cursor_secret)
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
            audit(conn, "user:" + str(user_id), None, "user.mapped", user_id, uuid4())
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

    def access(self, conn, user, tenant_id, mode="member", write=False):
        lock = "FOR UPDATE" if write else "FOR SHARE"
        tenant = conn.execute(f"SELECT * FROM tenants WHERE id=%s {lock}", (tenant_id,)).fetchone()
        member = conn.execute(
            "SELECT * FROM memberships WHERE tenant_id=%s AND user_id=%s", (tenant_id, user["id"])
        ).fetchone()
        if not tenant or not member:
            raise missing()
        if member["status"] != "active":
            raise forbidden()
        if mode in {"manage", "owner", "recover"} and member["tenant_role"] not in {
            "owner",
            "admin",
        }:
            raise forbidden()
        if mode in {"owner", "recover"} and member["tenant_role"] != "owner":
            raise forbidden()
        if tenant["status"] != "active":
            if not (
                mode in {"snapshot", "recover"}
                and member["tenant_role"] == "owner"
                and tenant["status"] == "suspended"
            ):
                raise forbidden()
        return tenant, member

    def mutate(
        self, identity, tenant_id, method, route, body, key, etag, request_id, mode, handler
    ):
        digest = hashlib.sha256(
            json.dumps(
                {"body": body, "ifMatch": etag}, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        with self.pool.connection() as conn:
            user = self.user(conn, identity)
            tenant = member = None
            if mode == "invite":
                if not user["email_verified"]:
                    raise forbidden()
                tenant = conn.execute(
                    "SELECT * FROM tenants WHERE id=%s FOR UPDATE", (tenant_id,)
                ).fetchone()
                if not tenant or tenant["status"] != "active":
                    raise forbidden()
                current_member = conn.execute(
                    "SELECT status FROM memberships WHERE tenant_id=%s AND user_id=%s",
                    (tenant_id, user["id"]),
                ).fetchone()
                if current_member and current_member["status"] != "active":
                    raise forbidden()
            elif tenant_id:
                tenant, member = self.access(conn, user, tenant_id, mode, True)
            elif mode == "verified" and not user["email_verified"]:
                raise forbidden()
            args = (user["id"], method, route, key)
            saved = conn.execute(
                "SELECT * FROM user_idempotency WHERE user_id=%s AND method=%s AND route=%s AND key=%s",
                args,
            ).fetchone()
            if saved:
                if saved["request_hash"] != digest:
                    raise ApiError(
                        409, "idempotency_conflict", "Key already used for a different request."
                    )
                return Result(saved["status"], saved["body"], saved["etag"])
            result = handler(conn, user, tenant, member)
            conn.execute(
                "INSERT INTO user_idempotency(user_id,method,route,key,request_hash,status,body,etag) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (*args, digest, result.status, Jsonb(result.body), result.etag),
            )
            return result

    def bump(self, conn, tenant_id):
        tenant = conn.execute(
            "UPDATE tenants SET version=version+1,authorization_version=authorization_version+1 "
            "WHERE id=%s RETURNING *",
            (tenant_id,),
        ).fetchone()
        append_event(conn, tenant, "authorization", "tenant.authorization_changed")
        return tenant

    def task(self, conn, kind, tenant_id, resource_id, data):
        conn.execute(
            "INSERT INTO private_tasks(id,kind,tenant_id,resource_id,ciphertext) VALUES (%s,%s,%s,%s,%s) "
            "ON CONFLICT (kind,resource_id) DO NOTHING",
            (
                uuid4(),
                kind,
                tenant_id,
                str(resource_id),
                self.cipher.encrypt(json.dumps(data).encode()).decode(),
            ),
        )

    def tenant_page(self, conn, user, limit, cursor):
        context = ["tenants", str(user["id"]), limit]
        after = self.cursor_decode(cursor, context) if cursor else UUID(int=0)
        rows = conn.execute(
            "SELECT t.* FROM tenants t JOIN memberships m ON m.tenant_id=t.id "
            "WHERE m.user_id=%s AND m.status='active' AND t.id>%s "
            "AND (t.status='active' OR (t.status='suspended' AND m.tenant_role='owner')) "
            "ORDER BY t.id LIMIT %s",
            (user["id"], after, limit + 1),
        ).fetchall()
        return {
            "items": [tenant_json(r) for r in rows[:limit]],
            "nextCursor": self.cursor_encode(context, rows[limit - 1]["id"])
            if len(rows) > limit
            else None,
        }

    def me(self, identity):
        with self.pool.connection() as conn:
            user = self.user(conn, identity)
            page = self.tenant_page(conn, user, 100, None)
            return Result(
                200,
                {
                    "user": {
                        "id": str(user["id"]),
                        "displayName": user["display_name"],
                        "email": user["email"],
                        "emailVerified": user["email_verified"],
                        "status": user["status"],
                    },
                    "tenants": page["items"],
                    "nextTenantsCursor": page["nextCursor"],
                },
            )

    def tenants(self, identity, limit, cursor):
        with self.pool.connection() as conn:
            return Result(200, self.tenant_page(conn, self.user(conn, identity), limit, cursor))

    def snapshot(self, identity, tenant_id, context=False):
        with self.pool.connection() as conn:
            user = self.user(conn, identity)
            tenant, member = self.access(conn, user, tenant_id, "member" if context else "snapshot")
            body = (
                {
                    "tenant": tenant_json(tenant),
                    "membership": member_json(member),
                    "authorizationVersion": tenant["authorization_version"],
                }
                if context
                else tenant_json(tenant)
            )
            return Result(200, body, f'"{tenant["version"]}"')

    def create_tenant(self, identity, body, key, request_id):
        def create(conn, user, tenant, member):
            tenant_id = uuid4()
            tenant = conn.execute(
                "INSERT INTO tenants(id,name,slug,lifecycle_sequence) VALUES (%s,%s,%s,1) "
                "ON CONFLICT (slug) DO NOTHING RETURNING *",
                (tenant_id, body["name"], body["slug"]),
            ).fetchone()
            if not tenant:
                raise ApiError(409, "already_exists", "Resource already exists.")
            conn.execute(
                "INSERT INTO memberships(tenant_id,user_id,tenant_role) VALUES (%s,%s,'owner')",
                (tenant_id, user["id"]),
            )
            append_event(conn, tenant, "lifecycle", "tenant.created")
            append_event(conn, tenant, "authorization", "tenant.authorization_changed")
            audit(
                conn, "user:" + str(user["id"]), tenant_id, "tenant.created", tenant_id, request_id
            )
            return Result(201, tenant_json(tenant), '"1"')

        return self.mutate(
            identity, None, "POST", "/v1/tenants", body, key, None, request_id, "verified", create
        )

    def change_tenant(self, identity, tenant_id, body, key, etag, request_id):
        def change(conn, user, tenant, member):
            version(tenant, etag)
            target = body["status"]
            if target == tenant["status"]:
                return Result(200, tenant_json(tenant), etag)
            if tenant["status"] == "suspended" and tenant["suspension_source"] != "owner":
                raise forbidden()
            event = {
                "active": "tenant.reactivated",
                "suspended": "tenant.suspended",
                "deleting": "tenant.deletion_requested",
            }[target]
            tenant = conn.execute(
                "UPDATE tenants SET status=%s,suspension_source=%s,lifecycle_sequence=lifecycle_sequence+1 "
                "WHERE id=%s RETURNING *",
                (target, "owner" if target == "suspended" else "none", tenant_id),
            ).fetchone()
            tenant = self.bump(conn, tenant_id)
            append_event(conn, tenant, "lifecycle", event)
            audit(conn, "user:" + str(user["id"]), tenant_id, event, tenant_id, request_id)
            return Result(200, tenant_json(tenant), f'"{tenant["version"]}"')

        return self.mutate(
            identity,
            tenant_id,
            "PATCH",
            f"/v1/tenants/{tenant_id}",
            body,
            key,
            etag,
            request_id,
            "recover",
            change,
        )

    def list_resources(self, identity, tenant_id, resource, limit, cursor, app_id=None):
        table, formatter, id_column = {
            "members": ("memberships", member_json, "user_id"),
            "invitations": ("invitations", invite_json, "id"),
            "role-assignments": ("role_assignments", assignment_json, "id"),
            "roles": ("role_definitions", role_json, "id"),
        }[resource]
        with self.pool.connection() as conn:
            user = self.user(conn, identity)
            self.access(conn, user, tenant_id, "manage")
            context = [resource, str(user["id"]), str(tenant_id), str(app_id), limit]
            after = self.cursor_decode(cursor, context) if cursor else UUID(int=0)
            params = (
                (tenant_id, after, app_id, limit + 1) if app_id else (tenant_id, after, limit + 1)
            )
            extra = "AND app_id=%s" if app_id else ""
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE tenant_id=%s AND {id_column}>%s {extra} ORDER BY {id_column} LIMIT %s",
                params,
            ).fetchall()
            return Result(
                200,
                {
                    "items": [formatter(r) for r in rows[:limit]],
                    "nextCursor": self.cursor_encode(context, rows[limit - 1][id_column])
                    if len(rows) > limit
                    else None,
                },
            )

    def update_member(self, identity, tenant_id, user_id, body, key, etag, request_id):
        def update(conn, user, tenant, actor):
            target = conn.execute(
                "SELECT * FROM memberships WHERE tenant_id=%s AND user_id=%s", (tenant_id, user_id)
            ).fetchone()
            if not target:
                raise missing()
            version(target, etag)
            if actor["tenant_role"] != "owner" and (
                target["tenant_role"] != "member" or body["tenantRole"] != "member"
            ):
                raise forbidden()
            if body["tenantRole"] == "owner" and target["status"] != "active":
                raise forbidden()
            removing_owner = (
                target["tenant_role"] == "owner"
                and target["status"] == "active"
                and (body["tenantRole"] != "owner" or body["status"] != "active")
            )
            if removing_owner:
                n = conn.execute(
                    "SELECT count(*) AS n FROM memberships WHERE tenant_id=%s AND tenant_role='owner' AND status='active'",
                    (tenant_id,),
                ).fetchone()["n"]
                if n <= 1:
                    raise ApiError(409, "last_owner", "The last active owner cannot be removed.")
            target = conn.execute(
                "UPDATE memberships SET tenant_role=%s,status=%s,version=version+1 WHERE tenant_id=%s AND user_id=%s RETURNING *",
                (body["tenantRole"], body["status"], tenant_id, user_id),
            ).fetchone()
            if body["status"] == "revoked":
                conn.execute(
                    "DELETE FROM role_assignments WHERE tenant_id=%s AND user_id=%s",
                    (tenant_id, user_id),
                )
            self.bump(conn, tenant_id)
            audit(conn, "user:" + str(user["id"]), tenant_id, "member.updated", user_id, request_id)
            return Result(200, member_json(target), f'"{target["version"]}"')

        return self.mutate(
            identity,
            tenant_id,
            "PATCH",
            f"/v1/tenants/{tenant_id}/members/{user_id}",
            body,
            key,
            etag,
            request_id,
            "manage",
            update,
        )

    def invite(self, identity, tenant_id, body, key, request_id):
        def create(conn, user, tenant, member):
            email = body["email"].casefold()
            conn.execute(
                "UPDATE invitations SET status='expired',version=version+1 WHERE tenant_id=%s AND email=%s AND status='pending' AND expires_at<=now()",
                (tenant_id, email),
            )
            token, invitation_id = secrets.token_urlsafe(32), uuid4()
            row = conn.execute(
                "INSERT INTO invitations(id,tenant_id,email,token_hash) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (tenant_id,email) WHERE status='pending' DO NOTHING RETURNING *",
                (invitation_id, tenant_id, email, hashlib.sha256(token.encode()).hexdigest()),
            ).fetchone()
            if not row:
                raise ApiError(409, "already_exists", "A pending invitation already exists.")
            self.task(
                conn,
                "invitation_mail",
                tenant_id,
                invitation_id,
                {"email": email, "token": token, "tenantName": tenant["name"]},
            )
            audit(
                conn,
                "user:" + str(user["id"]),
                tenant_id,
                "invitation.created",
                invitation_id,
                request_id,
            )
            return Result(201, invite_json(row), '"1"')

        return self.mutate(
            identity,
            tenant_id,
            "POST",
            f"/v1/tenants/{tenant_id}/invitations",
            body,
            key,
            None,
            request_id,
            "manage",
            create,
        )

    def revoke_invite(self, identity, tenant_id, invitation_id, key, etag, request_id):
        def revoke(conn, user, tenant, member):
            row = conn.execute(
                "SELECT * FROM invitations WHERE id=%s AND tenant_id=%s", (invitation_id, tenant_id)
            ).fetchone()
            if not row:
                raise missing()
            version(row, etag)
            if row["status"] != "pending":
                raise ApiError(409, "already_exists", "Invitation is no longer pending.")
            conn.execute(
                "UPDATE invitations SET status='revoked',version=version+1 WHERE id=%s",
                (invitation_id,),
            )
            conn.execute(
                "UPDATE private_tasks SET completed_at=now(),ciphertext=NULL WHERE kind='invitation_mail' AND resource_id=%s",
                (str(invitation_id),),
            )
            audit(
                conn,
                "user:" + str(user["id"]),
                tenant_id,
                "invitation.revoked",
                invitation_id,
                request_id,
            )
            return Result(204)

        return self.mutate(
            identity,
            tenant_id,
            "DELETE",
            f"/v1/tenants/{tenant_id}/invitations/{invitation_id}",
            None,
            key,
            etag,
            request_id,
            "manage",
            revoke,
        )

    def accept_invite(self, identity, body, key, request_id):
        token_hash = hashlib.sha256(body["token"].encode()).hexdigest()
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT tenant_id FROM invitations WHERE token_hash=%s", (token_hash,)
            ).fetchone()
        if not row:
            raise missing()
        tenant_id = row["tenant_id"]

        def accept(conn, user, tenant, actor):
            invitation = conn.execute(
                "SELECT *,now() AS current_time FROM invitations WHERE token_hash=%s FOR UPDATE",
                (token_hash,),
            ).fetchone()
            if invitation["email"] != user["email"] or not user["email_verified"]:
                raise forbidden()
            if (
                invitation["status"] != "pending"
                or invitation["expires_at"] <= invitation["current_time"]
            ):
                raise ApiError(409, "already_exists", "Invitation is no longer pending.")
            member = conn.execute(
                "SELECT * FROM memberships WHERE tenant_id=%s AND user_id=%s",
                (tenant_id, user["id"]),
            ).fetchone()
            if member and member["status"] != "active":
                # Invitations may not bypass an explicit suspension/revocation.
                raise forbidden()
            if not member:
                member = conn.execute(
                    "INSERT INTO memberships(tenant_id,user_id,tenant_role) VALUES (%s,%s,'member') RETURNING *",
                    (tenant_id, user["id"]),
                ).fetchone()
            conn.execute(
                "UPDATE invitations SET status='accepted',accepted_by=%s,version=version+1 WHERE id=%s",
                (user["id"], invitation["id"]),
            )
            conn.execute(
                "UPDATE private_tasks SET completed_at=now(),ciphertext=NULL WHERE kind='invitation_mail' AND resource_id=%s",
                (str(invitation["id"]),),
            )
            self.bump(conn, tenant_id)
            audit(
                conn,
                "user:" + str(user["id"]),
                tenant_id,
                "invitation.accepted",
                invitation["id"],
                request_id,
            )
            return Result(200, member_json(member), f'"{member["version"]}"')

        # Hash is sufficient for deduplication; the credential never enters idempotency storage.
        return self.mutate(
            identity,
            tenant_id,
            "POST",
            "/v1/invitations/accept",
            {"tokenHash": token_hash},
            key,
            None,
            request_id,
            "invite",
            accept,
        )

    def assign(self, identity, tenant_id, body, key, request_id):
        def create(conn, user, tenant, actor):
            role = conn.execute(
                "SELECT 1 FROM role_definitions WHERE tenant_id=%s AND id=%s",
                (tenant_id, body["roleId"]),
            ).fetchone()
            member = conn.execute(
                "SELECT status FROM memberships WHERE tenant_id=%s AND user_id=%s",
                (tenant_id, body["userId"]),
            ).fetchone()
            if not role or not member:
                raise missing()
            if member["status"] != "active":
                raise forbidden()
            row = conn.execute(
                "INSERT INTO role_assignments(id,tenant_id,user_id,role_id) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (tenant_id,user_id,role_id) DO NOTHING RETURNING *",
                (uuid4(), tenant_id, body["userId"], body["roleId"]),
            ).fetchone()
            if not row:
                raise ApiError(409, "already_exists", "Role is already assigned.")
            self.bump(conn, tenant_id)
            audit(
                conn, "user:" + str(user["id"]), tenant_id, "role.assigned", row["id"], request_id
            )
            return Result(201, assignment_json(row), '"1"')

        return self.mutate(
            identity,
            tenant_id,
            "POST",
            f"/v1/tenants/{tenant_id}/role-assignments",
            body,
            key,
            None,
            request_id,
            "manage",
            create,
        )

    def revoke_assignment(self, identity, tenant_id, assignment_id, key, etag, request_id):
        def revoke(conn, user, tenant, actor):
            row = conn.execute(
                "SELECT * FROM role_assignments WHERE tenant_id=%s AND id=%s",
                (tenant_id, assignment_id),
            ).fetchone()
            if not row:
                raise missing()
            version(row, etag)
            conn.execute(
                "DELETE FROM role_assignments WHERE tenant_id=%s AND id=%s",
                (tenant_id, assignment_id),
            )
            self.bump(conn, tenant_id)
            audit(
                conn,
                "user:" + str(user["id"]),
                tenant_id,
                "role.revoked",
                assignment_id,
                request_id,
            )
            return Result(204)

        return self.mutate(
            identity,
            tenant_id,
            "DELETE",
            f"/v1/tenants/{tenant_id}/role-assignments/{assignment_id}",
            None,
            key,
            etag,
            request_id,
            "manage",
            revoke,
        )

    def permissions(self, identity, tenant_id, app_id):
        with self.pool.connection() as conn:
            user = self.user(conn, identity)
            tenant = conn.execute(
                "SELECT * FROM tenants WHERE id=%s FOR SHARE", (tenant_id,)
            ).fetchone()
            member = conn.execute(
                "SELECT * FROM memberships WHERE tenant_id=%s AND user_id=%s",
                (tenant_id, user["id"]),
            ).fetchone()
            if not tenant or not member:
                raise missing()
            roles = []
            if tenant["status"] != "active":
                reason = "tenant_inactive"
            elif member["status"] != "active":
                reason = "membership_inactive"
            else:
                roles = [
                    r["key"]
                    for r in conn.execute(
                        "SELECT r.key FROM role_assignments a JOIN role_definitions r ON r.id=a.role_id AND r.tenant_id=a.tenant_id WHERE a.tenant_id=%s AND a.user_id=%s AND r.app_id=%s ORDER BY r.key",
                        (tenant_id, user["id"], app_id),
                    ).fetchall()
                ]
                reason = "granted" if roles else "role_missing"
            return Result(
                200,
                {
                    "tenantId": str(tenant_id),
                    "userId": str(user["id"]),
                    "appId": str(app_id),
                    "allowed": bool(roles),
                    "roles": roles,
                    "authorizationVersion": tenant["authorization_version"],
                    "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                    "reason": reason,
                },
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
                    "session_revoke",
                    None,
                    json.dumps([identity.issuer, identity.sid]),
                    {"issuer": identity.issuer, "sid": identity.sid},
                )
                audit(
                    conn, "user:" + str(user["id"]), None, "session.revoked", user["id"], request_id
                )
            conn.execute(
                "INSERT INTO user_idempotency(user_id,method,route,key,request_hash,status) VALUES (%s,%s,%s,%s,%s,204)",
                (*args, digest),
            )
            return Result(204)

    def write_role(self, identity, tenant_id, app_id, role_id, body, key, etag, request_id):
        method = "DELETE" if role_id else "POST"
        route = f"/v1/tenants/{tenant_id}/apps/{app_id}/roles" + (f"/{role_id}" if role_id else "")

        def update(conn, user, tenant, actor):
            result, resource_id, action = change_role(conn, tenant_id, app_id, role_id, body, etag)
            self.bump(conn, tenant_id)
            audit(conn, "user:" + str(user["id"]), tenant_id, action, resource_id, request_id)
            return result

        return self.mutate(
            identity, tenant_id, method, route, body, key, etag, request_id, "manage", update
        )
