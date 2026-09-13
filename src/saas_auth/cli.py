import argparse
import os
import time
from urllib.parse import urlparse
from uuid import UUID, uuid4

from saas_auth.db import make_pool, migrate
from saas_auth.service import append_event, audit


def bootstrap(pool, *, issuer, subject, email, tenant_id, name, slug, actor):
    """Operator-only initial tenant owner; no password or global administrator role."""
    with pool.connection() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(72401103)")
        existing = conn.execute(
            "SELECT user_id FROM external_identities WHERE issuer=%s AND subject=%s",
            (issuer, subject),
        ).fetchone()
        user_id = existing["user_id"] if existing else uuid4()
        if not existing:
            conn.execute(
                "INSERT INTO users(id,display_name,email) VALUES (%s,%s,%s)",
                (user_id, email, email),
            )
            conn.execute(
                "INSERT INTO external_identities(issuer,subject,user_id) VALUES (%s,%s,%s)",
                (issuer, subject, user_id),
            )
        else:
            user = conn.execute(
                "SELECT status FROM users WHERE id=%s FOR SHARE", (user_id,)
            ).fetchone()
            if user["status"] != "active":
                raise ValueError("Bootstrap owner must be active")
        tenant = conn.execute(
            "INSERT INTO tenants(id,name,slug,lifecycle_sequence) VALUES (%s,%s,%s,1) RETURNING *",
            (tenant_id, name, slug),
        ).fetchone()
        conn.execute(
            "INSERT INTO memberships(tenant_id,user_id,tenant_role) VALUES (%s,%s,'owner')",
            (tenant_id, user_id),
        )
        append_event(conn, tenant, "lifecycle", "tenant.created")
        append_event(conn, tenant, "authorization", "tenant.authorization_changed")
        audit(conn, actor, tenant_id, "tenant.bootstrapped", tenant_id, uuid4())


def configure_service(pool, *, issuer, subject, client_id, tenant_id, app_id, scopes, actor):
    with pool.connection() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(72401103)")
        principal = conn.execute(
            "INSERT INTO service_principals(id,issuer,subject,client_id) VALUES (%s,%s,%s,%s) "
            "ON CONFLICT (issuer,client_id) DO NOTHING RETURNING *",
            (uuid4(), issuer, subject, client_id),
        ).fetchone()
        if not principal:
            principal = conn.execute(
                "SELECT * FROM service_principals WHERE issuer=%s AND client_id=%s FOR UPDATE",
                (issuer, client_id),
            ).fetchone()
            if principal["subject"] != subject or not principal["enabled"]:
                raise ValueError("Existing principal does not match or is disabled")
        conn.execute(
            "INSERT INTO service_tenant_grants(principal_id,tenant_id,snapshot_read) "
            "VALUES (%s,%s,%s) ON CONFLICT (principal_id,tenant_id) DO UPDATE "
            "SET snapshot_read=EXCLUDED.snapshot_read",
            (principal["id"], tenant_id, "tenants:read" in scopes),
        )
        conn.execute(
            "INSERT INTO service_app_grants(principal_id,tenant_id,app_id,roles_read,roles_write) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (principal_id,tenant_id,app_id) DO UPDATE "
            "SET roles_read=EXCLUDED.roles_read,roles_write=EXCLUDED.roles_write",
            (principal["id"], tenant_id, app_id, "roles:read" in scopes, "roles:write" in scopes),
        )
        audit(conn, actor, tenant_id, "service.configured", principal["id"], uuid4())


def main():
    parser = argparse.ArgumentParser(
        description="Auth operations; no credentials are accepted as CLI arguments"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    boot = sub.add_parser("bootstrap-tenant")
    for flag in ("issuer", "subject", "email", "name", "slug"):
        boot.add_argument("--" + flag, required=True)
    boot.add_argument("--tenant-id", required=True, type=UUID)
    grant = sub.add_parser("configure-service")
    for flag in ("issuer", "subject", "client-id"):
        grant.add_argument("--" + flag, required=True)
    for flag in ("tenant-id", "app-id"):
        grant.add_argument("--" + flag, required=True, type=UUID)
    grant.add_argument(
        "--scope",
        action="append",
        choices=["tenants:read", "roles:read", "roles:write"],
        default=[],
    )
    sub.add_parser("outbox-once")
    sub.add_parser("outbox-worker")
    args = parser.parse_args()
    database_url = os.environ["SAAS_DATABASE_URL"]
    if args.command == "migrate":
        migrate(database_url)
        return
    if args.command in {"bootstrap-tenant", "configure-service"}:
        if os.environ.get("SAAS_ENABLE_BOOTSTRAP") != "true" or not os.environ.get(
            "SAAS_OPERATOR_ID"
        ):
            parser.error("Operations require SAAS_ENABLE_BOOTSTRAP=true and SAAS_OPERATOR_ID")
    pool = make_pool(database_url)
    pool.open(wait=True)
    try:
        if args.command == "bootstrap-tenant":
            bootstrap(
                pool,
                issuer=args.issuer,
                subject=args.subject,
                email=args.email,
                tenant_id=args.tenant_id,
                name=args.name,
                slug=args.slug,
                actor="operator:" + os.environ["SAAS_OPERATOR_ID"],
            )
        elif args.command == "configure-service":
            configure_service(
                pool,
                issuer=args.issuer,
                subject=args.subject,
                client_id=args.client_id,
                tenant_id=args.tenant_id,
                app_id=args.app_id,
                scopes=args.scope,
                actor="operator:" + os.environ["SAAS_OPERATOR_ID"],
            )
        else:
            from saas_auth.outbox import deliver_once

            endpoint = os.environ["SAAS_OUTBOX_ENDPOINT"]
            parsed = urlparse(endpoint)
            local = os.environ.get("SAAS_ALLOW_INSECURE_LOCAL") == "true" and parsed.hostname in {
                "localhost",
                "127.0.0.1",
            }
            if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
                parser.error("Outbox endpoint requires HTTPS")
            secret = os.environ["SAAS_OUTBOX_SECRET"]
            if len(secret) < 32:
                parser.error("Outbox secret must contain at least 32 characters")
            while True:
                worked = deliver_once(pool, endpoint, secret)
                if args.command == "outbox-once":
                    break
                if not worked:
                    time.sleep(1)
    finally:
        pool.close()


if __name__ == "__main__":
    main()
