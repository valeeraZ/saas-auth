import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from saas_auth.errors import ApiError, forbidden, invalid


@dataclass
class Result:
    status: int
    body: dict | None = None
    etag: str | None = None


def tenant_json(row):
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "slug": row["slug"],
        "status": row["status"],
        "version": row["version"],
        "authorizationVersion": row["authorization_version"],
        "lifecycleSequence": row["lifecycle_sequence"],
        "suspensionSource": row["suspension_source"],
    }


def role_json(row):
    return {
        "id": str(row["id"]),
        "tenantId": str(row["tenant_id"]),
        "appId": str(row["app_id"]),
        "key": row["key"],
        "description": row["description"],
        "version": row["version"],
    }


def audit(conn, actor, tenant_id, action, resource_id, request_id):
    conn.execute(
        "INSERT INTO audit_entries(id,actor,tenant_id,action,resource_id,request_id) "
        "VALUES (%s,%s,%s,%s,%s,%s)",
        (uuid4(), str(actor), tenant_id, action, resource_id, request_id),
    )


def append_event(conn, tenant, stream, kind):
    event_id = uuid4()
    sequence = (
        tenant["lifecycle_sequence"] if stream == "lifecycle" else tenant["authorization_version"]
    )
    payload = {
        "eventId": str(event_id),
        "schemaVersion": 1,
        "type": kind,
        "occurredAt": datetime.now(timezone.utc).isoformat(),
        "tenantId": str(tenant["id"]),
        "sequence": sequence,
        "authorizationVersion": tenant["authorization_version"],
        "data": {"status": tenant["status"]},
    }
    conn.execute(
        "INSERT INTO outbox(event_id,tenant_id,stream,sequence,payload) VALUES (%s,%s,%s,%s,%s)",
        (event_id, tenant["id"], stream, sequence, Jsonb(payload)),
    )


class Service:
    def __init__(self, pool, cursor_secret):
        self.pool = pool
        self.cursor_secret = cursor_secret.encode()

    def authorize(self, conn, identity, tenant_id, app_id, scope, write=False):
        if scope not in identity.scopes:
            raise forbidden()
        principal = conn.execute(
            "SELECT id FROM service_principals WHERE issuer=%s AND subject=%s "
            "AND client_id=%s AND enabled FOR SHARE",
            (identity.issuer, identity.subject, identity.client_id),
        ).fetchone()
        if not principal:
            raise forbidden()
        grant = conn.execute(
            "SELECT snapshot_read FROM service_tenant_grants "
            "WHERE principal_id=%s AND tenant_id=%s FOR SHARE",
            (principal["id"], tenant_id),
        ).fetchone()
        if not grant:
            raise forbidden()
        if scope == "tenants:read":
            if not grant["snapshot_read"]:
                raise forbidden()
        else:
            app_grant = conn.execute(
                "SELECT roles_read,roles_write FROM service_app_grants "
                "WHERE principal_id=%s AND tenant_id=%s AND app_id=%s FOR SHARE",
                (principal["id"], tenant_id, app_id),
            ).fetchone()
            if not app_grant or not app_grant["roles_write" if write else "roles_read"]:
                raise forbidden()
        # Lock order is principal -> grants -> tenant in every API operation.
        # A committed disable/revocation takes effect on the next decision.
        lock = "FOR UPDATE" if write else "FOR SHARE"
        tenant = conn.execute(f"SELECT * FROM tenants WHERE id=%s {lock}", (tenant_id,)).fetchone()
        if not tenant:
            raise ApiError(404, "not_found", "Resource not found.")
        if scope != "tenants:read" and tenant["status"] != "active":
            raise forbidden()
        return principal["id"], tenant

    def snapshot(self, identity, tenant_id):
        with self.pool.connection() as conn:
            _, tenant = self.authorize(conn, identity, tenant_id, None, "tenants:read")
            return Result(200, tenant_json(tenant), f'"{tenant["version"]}"')

    def cursor_encode(self, context, last):
        raw = json.dumps({"context": context, "last": str(last)}, sort_keys=True).encode()
        signature = hmac.digest(self.cursor_secret, raw, "sha256")
        return base64.urlsafe_b64encode(raw + signature).decode()

    def cursor_decode(self, cursor, context):
        try:
            raw = base64.b64decode(cursor, altchars=b"-_", validate=True)
            body, signature = raw[:-32], raw[-32:]
            if not hmac.compare_digest(hmac.digest(self.cursor_secret, body, "sha256"), signature):
                raise ValueError()
            data = json.loads(body)
            if data["context"] != context:
                raise ValueError()
            return UUID(data["last"])
        except (ValueError, KeyError, TypeError):
            raise invalid() from None

    def list_roles(self, identity, tenant_id, app_id, limit, cursor):
        with self.pool.connection() as conn:
            principal, _ = self.authorize(conn, identity, tenant_id, app_id, "roles:read")
            context = [str(principal), str(tenant_id), str(app_id), limit]
            after = self.cursor_decode(cursor, context) if cursor else UUID(int=0)
            rows = conn.execute(
                "SELECT * FROM role_definitions WHERE tenant_id=%s AND app_id=%s AND id>%s "
                "ORDER BY id LIMIT %s",
                (tenant_id, app_id, after, limit + 1),
            ).fetchall()
            return Result(
                200,
                {
                    "items": [role_json(r) for r in rows[:limit]],
                    "nextCursor": self.cursor_encode(context, rows[limit - 1]["id"])
                    if len(rows) > limit
                    else None,
                },
            )

    def write_role(self, identity, tenant_id, app_id, role_id, body, key, etag, request_id):
        method = "DELETE" if role_id else "POST"
        route = f"/v1/tenants/{tenant_id}/apps/{app_id}/roles"
        if role_id:
            route += f"/{role_id}"
        digest = hashlib.sha256(
            json.dumps(
                {"body": body, "ifMatch": etag}, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        with self.pool.connection() as conn:
            principal, tenant = self.authorize(
                conn, identity, tenant_id, app_id, "roles:write", True
            )
            # The tenant lock serializes mutation, idempotency, version and outbox checks.
            idem_args = (principal, tenant_id, method, route, key)
            previous = conn.execute(
                "SELECT * FROM idempotency_records WHERE principal_id=%s AND tenant_id=%s "
                "AND method=%s AND route=%s AND key=%s",
                idem_args,
            ).fetchone()
            if previous:
                if previous["request_hash"] != digest:
                    raise ApiError(
                        409, "idempotency_conflict", "Key already used for a different request."
                    )
                return Result(previous["status"], previous["body"], previous["etag"])
            result, role_id, action = change_role(conn, tenant_id, app_id, role_id, body, etag)
            tenant = conn.execute(
                "UPDATE tenants SET authorization_version=authorization_version+1, version=version+1 "
                "WHERE id=%s RETURNING *",
                (tenant_id,),
            ).fetchone()
            append_event(conn, tenant, "authorization", "tenant.authorization_changed")
            audit(conn, principal, tenant_id, action, role_id, request_id)
            conn.execute(
                "INSERT INTO idempotency_records(principal_id,tenant_id,method,route,key,"
                "request_hash,status,body,etag) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (*idem_args, digest, result.status, Jsonb(result.body), result.etag),
            )
            return result


def change_role(conn, tenant_id, app_id, role_id, body, etag):
    if role_id:
        role = conn.execute(
            "SELECT * FROM role_definitions WHERE tenant_id=%s AND app_id=%s AND id=%s",
            (tenant_id, app_id, role_id),
        ).fetchone()
        if not role:
            raise ApiError(404, "not_found", "Resource not found.")
        if etag != f'"{role["version"]}"':
            raise ApiError(412, "version_conflict", "Resource version changed.")
        conn.execute(
            "DELETE FROM role_definitions WHERE tenant_id=%s AND app_id=%s AND id=%s",
            (tenant_id, app_id, role_id),
        )
        result = Result(204)
        action = "role.deleted"
    else:
        role_id = uuid4()
        role = conn.execute(
            "INSERT INTO role_definitions(id,tenant_id,app_id,key,description) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (tenant_id,app_id,key) DO NOTHING RETURNING *",
            (role_id, tenant_id, app_id, body["key"], body["description"]),
        ).fetchone()
        if not role:
            raise ApiError(409, "already_exists", "Resource already exists.")
        result = Result(201, role_json(role), '"1"')
        action = "role.created"
    return result, role_id, action
