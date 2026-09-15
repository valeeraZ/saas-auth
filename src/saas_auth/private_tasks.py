"""Durable private delivery; payloads are encrypted, never sent to public event consumers."""

import json
import os
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import quote, urlparse
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet, InvalidToken


def claim(pool):
    with pool.connection() as conn:
        return conn.execute(
            "UPDATE private_tasks SET lease_id=%s,lease_until=now()+interval '60 seconds',attempts=attempts+1 "
            "WHERE id=(SELECT id FROM private_tasks WHERE completed_at IS NULL AND available_at<=now() "
            "AND (lease_until IS NULL OR lease_until<now()) ORDER BY available_at,id "
            "FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *",
            (uuid4(),),
        ).fetchone()


def finish(pool, task, success):
    with pool.connection() as conn:
        return (
            conn.execute(
                "UPDATE private_tasks SET completed_at=CASE WHEN %s THEN now() ELSE NULL END, "
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


def send_invitation(data, task_id):
    link = os.environ["SAAS_INVITATION_URL"]
    parsed = urlparse(link)
    local = os.environ.get("SAAS_ALLOW_INSECURE_LOCAL") == "true"
    if parsed.fragment or parsed.query or not parsed.hostname or parsed.username:
        raise ValueError("Invalid invitation URL")
    if parsed.scheme != "https" and not (
        local and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
    ):
        raise ValueError("Invitation URL requires HTTPS")
    message = EmailMessage()
    message["From"] = os.environ["SAAS_SMTP_FROM"]
    message["To"] = data["email"]
    message["Subject"] = "Tenant invitation"
    message["Message-ID"] = f"<{task_id}@saas-auth.invalid>"
    message.set_content(
        f"You have been invited to join {data['tenantName']}.\n\n"
        f"{link}#token={quote(data['token'], safe='')}\n\nThis invitation expires in 7 days.\n"
    )
    host = os.environ["SAAS_SMTP_HOST"]
    tls = os.environ.get("SAAS_SMTP_STARTTLS", "true") == "true"
    if not tls and not (local and host in {"localhost", "127.0.0.1", "mailpit"}):
        raise ValueError("SMTP requires TLS")
    with smtplib.SMTP(host, int(os.environ.get("SAAS_SMTP_PORT", "587")), timeout=5) as smtp:
        if tls:
            smtp.starttls(context=ssl.create_default_context())
        if os.environ.get("SAAS_SMTP_USER"):
            smtp.login(os.environ["SAAS_SMTP_USER"], os.environ["SAAS_SMTP_PASSWORD"])
        smtp.send_message(message)


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
        if task["kind"] == "invitation_mail":
            with pool.connection() as conn:
                pending = conn.execute(
                    "SELECT 1 FROM invitations i JOIN tenants t ON t.id=i.tenant_id "
                    "WHERE i.id=%s AND i.status='pending' AND i.expires_at>now() AND t.status='active'",
                    (task["resource_id"],),
                ).fetchone()
            if pending:
                send_invitation(data, task["id"])
        else:
            revoke_upstream(settings, data)
        success = True
    except (httpx.HTTPError, smtplib.SMTPException, OSError, ValueError, KeyError, InvalidToken):
        # Do not log exception contents: SMTP/HTTP errors can include credentials.
        success = False
    finish(pool, task, success)
    return True
