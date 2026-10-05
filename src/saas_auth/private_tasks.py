"""Durable private delivery; payloads are encrypted, never sent to public event consumers."""

import json
import os
from urllib.parse import quote
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet, InvalidToken


def claim(pool):
    with pool.connection() as conn:
        return conn.execute(
            "UPDATE session_tasks SET lease_id=%s,lease_until=now()+interval '60 seconds',attempts=attempts+1 "
            "WHERE id=(SELECT id FROM session_tasks WHERE completed_at IS NULL AND available_at<=now() "
            "AND (lease_until IS NULL OR lease_until<now()) ORDER BY available_at,id "
            "FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *",
            (uuid4(),),
        ).fetchone()


def finish(pool, task, success):
    with pool.connection() as conn:
        return (
            conn.execute(
                "UPDATE session_tasks SET completed_at=CASE WHEN %s THEN now() ELSE NULL END, "
                "ciphertext=CASE WHEN %s THEN NULL ELSE ciphertext END,lease_id=NULL,lease_until=NULL,"
                "available_at=now()+make_interval(secs => %s) WHERE id=%s AND lease_id=%s "
                "AND lease_until>now() AND completed_at IS NULL RETURNING id",
                (
                    success,
                    success,
                    min(300, 2 ** min(task["attempts"], 8)),
                    task["id"],
                    task["lease_id"],
                ),
            ).fetchone()
            is not None
        )


def revoke_upstream(settings, data):
    if data["issuer"] != settings.issuer or "/realms/" not in settings.issuer:
        raise ValueError("Unexpected issuer")
    prefix, realm = settings.issuer.rsplit("/realms/", 1)
    response = httpx.post(
        settings.issuer + "/protocol/openid-connect/token",
        timeout=5,
        data={
            "grant_type": "client_credentials",
            "client_id": os.environ["SAAS_SESSION_WORKER_CLIENT"],
            "client_secret": os.environ["SAAS_SESSION_WORKER_SECRET"],
        },
    )
    response.raise_for_status()
    token = response.json()["access_token"]
    response = httpx.delete(
        f"{prefix}/admin/realms/{quote(realm, safe='')}/sessions/{quote(data['sid'], safe='')}",
        headers={"Authorization": "Bearer " + token},
        timeout=5,
    )
    if response.status_code != 404:
        response.raise_for_status()


def deliver_once(pool, settings):
    task = claim(pool)
    if not task:
        return False
    try:
        data = json.loads(Fernet(settings.task_key.encode()).decrypt(task["ciphertext"].encode()))
        revoke_upstream(settings, data)
        success = True
    except (httpx.HTTPError, OSError, ValueError, KeyError, InvalidToken):
        # Do not log exception contents: SMTP/HTTP errors can include credentials.
        success = False
    finish(pool, task, success)
    return True
