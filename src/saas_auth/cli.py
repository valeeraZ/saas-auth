"""Explicit operator commands for the user/application platform."""

import argparse
import os
import time
from uuid import UUID, uuid4

from saas_auth.db import make_pool, migrate


def main():
    parser = argparse.ArgumentParser(
        description="Auth operations; credentials come only from environment"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    sub.add_parser("private-tasks-once")
    sub.add_parser("private-tasks-worker")
    grant = sub.add_parser("grant-app")
    grant.add_argument("--user-id", type=UUID, required=True)
    grant.add_argument("--app-id", type=UUID, required=True)
    grant.add_argument("--role", action="append", required=True)
    grant.add_argument("--revoke", action="store_true")
    grant.add_argument("--operation-key", required=True)
    args = parser.parse_args()
    url = os.environ["SAAS_DATABASE_URL"]
    if args.command == "migrate":
        migrate(url)
        return
    if args.command == "grant-app" and (
        os.environ.get("SAAS_ENABLE_BOOTSTRAP") != "true" or not os.environ.get("SAAS_OPERATOR_ID")
    ):
        parser.error("Writes require SAAS_ENABLE_BOOTSTRAP=true and SAAS_OPERATOR_ID")
    from saas_auth.config import Settings

    settings = Settings.from_env()
    pool = make_pool(url)
    pool.open(wait=True)
    try:
        if args.command == "grant-app":
            if os.environ.get("SAAS_ENABLE_BOOTSTRAP") != "true" or not os.environ.get(
                "SAAS_OPERATOR_ID"
            ):
                parser.error("Writes require SAAS_ENABLE_BOOTSTRAP=true and SAAS_OPERATOR_ID")
            from saas_auth.app_api import Grant
            from saas_auth.app_service import AppService

            body = Grant(userId=args.user_id, roles=args.role, enabled=not args.revoke)
            if not 16 <= len(args.operation_key) <= 128:
                parser.error("Operation key must be 16-128 characters")
            AppService(pool, settings).grant(
                args.app_id,
                body.userId,
                sorted(set(body.roles)),
                body.enabled,
                args.operation_key,
                "operator:" + os.environ["SAAS_OPERATOR_ID"],
                uuid4(),
            )
            print("Application grant updated")
        else:
            from saas_auth.private_tasks import deliver_once

            while True:
                worked = deliver_once(pool, settings)
                if args.command == "private-tasks-once":
                    break
                if not worked:
                    time.sleep(1)
    finally:
        pool.close()


if __name__ == "__main__":
    main()
