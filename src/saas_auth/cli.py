"""Explicit operator commands for the user/application platform."""

import argparse
import os
import time
from uuid import UUID, uuid4

from saas_auth.db import Database


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auth operations; credentials come only from environment"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("private-tasks-worker", help="Continuously deliver queued session revocations")
    grant = sub.add_parser("grant-app", help="Set or revoke a direct application grant for a user")
    grant.add_argument("--user-id", type=UUID, required=True)
    grant.add_argument("--app-id", type=UUID, required=True)
    grant.add_argument("--role", action="append", required=True)
    grant.add_argument("--revoke", action="store_true")
    grant.add_argument("--operation-key", required=True)
    args = parser.parse_args()
    url = os.environ["SAAS_DATABASE_URL"]
    if args.command == "grant-app" and (
        os.environ.get("SAAS_ENABLE_BOOTSTRAP") != "true" or not os.environ.get("SAAS_OPERATOR_ID")
    ):
        parser.error("Writes require SAAS_ENABLE_BOOTSTRAP=true and SAAS_OPERATOR_ID")
    from saas_auth.config import Settings

    settings = Settings.from_env()
    database = Database(url)
    try:
        if args.command == "grant-app":
            from saas_auth.api.schemas import Grant
            from saas_auth.services.users import AppService

            body = Grant(userId=args.user_id, roles=args.role, enabled=not args.revoke)
            if not 16 <= len(args.operation_key) <= 128:
                parser.error("Operation key must be 16-128 characters")
            AppService(database, settings).grant(
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
            from saas_auth.worker.revocation import deliver_once

            while True:
                if not deliver_once(database, settings):
                    time.sleep(1)
    finally:
        database.close()


if __name__ == "__main__":
    main()
