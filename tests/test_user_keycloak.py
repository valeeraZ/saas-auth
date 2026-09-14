import base64
import hashlib
import os
import re
import secrets
import time
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse
from uuid import uuid4

import httpx
import jwt
import pytest
from aiosmtpd.controller import Controller
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from saas_auth.api import create_app
from saas_auth.private_tasks import deliver_once

pytestmark = pytest.mark.keycloak
CALLBACK = "http://127.0.0.1:58999/callback"


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.action = None
        self.fields = {}
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs.get("action")
        if tag == "input" and attrs.get("name") and attrs.get("type") == "hidden":
            self.fields[attrs["name"]] = attrs.get("value", "")
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])


class Flow:
    def __init__(self, issuer):
        self.issuer = issuer
        self.http = httpx.Client(timeout=10)

    def start(self):
        self.state = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(32)
        self.verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        response = self.http.get(
            self.issuer + "/protocol/openid-connect/auth",
            params={
                "client_id": "saas-portal",
                "redirect_uri": CALLBACK,
                "response_type": "code",
                "scope": "openid profile email",
                "state": self.state,
                "nonce": self.nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "prompt": "login",
            },
        )
        assert response.status_code == 200
        return response

    def follow(self, response):
        for _ in range(10):
            if response.status_code not in {302, 303}:
                return response
            location = urljoin(str(response.url), response.headers["location"])
            if location.startswith(CALLBACK):
                return response
            assert urlparse(location).netloc == urlparse(self.issuer).netloc
            response = self.http.get(location)
        raise AssertionError("Too many IdP redirects")

    def submit(self, response, fields):
        page = Page(response.text)
        assert page.action is not None, "Expected Keycloak form"
        return self.follow(
            self.http.post(urljoin(str(response.url), page.action), data=page.fields | fields)
        )

    def login(self, username, password):
        return self.submit(self.start(), {"username": username, "password": password})

    def tokens(self, response, wrong_pkce=False):
        # Report only the fixed UI heading, never full HTML, tokens or callback URLs.
        heading = re.search(r"<h1[^>]*>(.*?)</h1>", response.text, re.S)
        title = re.sub(r"<[^>]+>", "", heading[1]).strip() if heading else "no heading"
        known_errors = [
            message
            for message in (
                "Invalid username or password",
                "Invalid password",
                "Invalid username",
                "You are already logged in",
                "Your login attempt timed out",
                "Cookie not found",
                "Email verified",
                "You need to verify your email",
                "Account is disabled",
                "Account is temporarily disabled",
                "Please login again",
            )
            if message.casefold() in response.text.casefold()
        ]
        assert response.status_code in {302, 303}, (
            f"Expected callback redirect ({title}; {known_errors})"
        )
        location = response.headers["location"]
        assert location.startswith(CALLBACK)
        query = parse_qs(urlparse(location).query)
        assert query["state"] == [self.state]
        payload = {
            "grant_type": "authorization_code",
            "client_id": "saas-portal",
            "client_secret": os.environ["SAAS_LOCAL_PORTAL_SECRET"],
            "redirect_uri": CALLBACK,
            "code": query["code"][0],
            "code_verifier": "incorrect-proof" if wrong_pkce else self.verifier,
        }
        tokens = self.http.post(self.issuer + "/protocol/openid-connect/token", data=payload)
        if wrong_pkce:
            assert tokens.status_code == 400
            return None
        assert tokens.status_code == 200, "Authorization-code exchange failed"
        data = tokens.json()
        key = jwt.PyJWKClient(
            self.issuer + "/protocol/openid-connect/certs"
        ).get_signing_key_from_jwt(data["id_token"])
        claims = jwt.decode(
            data["id_token"],
            key.key,
            algorithms=["RS256"],
            audience="saas-portal",
            issuer=self.issuer,
        )
        assert claims["nonce"] == self.nonce
        self.exchange_request = payload
        return data


@pytest.fixture
def oidc(env):
    issuer = os.environ.get("SAAS_TEST_KEYCLOAK_ISSUER")
    if not issuer:
        pytest.skip("Set SAAS_TEST_KEYCLOAK_ISSUER for real user OIDC")
    settings = replace(
        env.settings,
        issuer=issuer,
        user_clients=("saas-portal",),
        introspection_client="saas-auth",
        introspection_secret=os.environ["SAAS_INTROSPECTION_SECRET"],
        task_key=Fernet.generate_key().decode(),
    )
    flow = Flow(issuer)
    with TestClient(create_app(settings)) as client:
        yield flow, client, settings
    flow.http.close()


def test_code_pkce_exchange_and_durable_upstream_logout(env, oidc, monkeypatch):
    flow, client, settings = oidc
    tokens = flow.tokens(flow.login("local-user", os.environ["SAAS_LOCAL_USER_PASSWORD"]))
    exchanged = flow.http.post(
        flow.issuer + "/protocol/openid-connect/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": "saas-portal",
            "client_secret": os.environ["SAAS_LOCAL_PORTAL_SECRET"],
            "subject_token": tokens["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "saas-auth",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        },
    )
    assert exchanged.status_code == 200, "Standard V2 exchange failed"
    headers = {
        "Authorization": "Bearer " + exchanged.json()["access_token"],
        "Idempotency-Key": str(uuid4()),
    }
    me = client.get("/v1/me", headers=headers)
    assert me.status_code == 200, "Auth rejected real exchanged user token"
    assert me.json()["user"]["emailVerified"] is True
    assert me.json()["tenants"] == []
    assert (
        client.post(
            "/v1/tenants", headers=headers, json={"name": "Real user tenant", "slug": "real-user"}
        ).status_code
        == 201
    )
    assert client.delete("/v1/sessions/current", headers=headers).status_code == 204
    assert client.get("/v1/me", headers=headers).status_code == 401
    monkeypatch.setenv("SAAS_SESSION_WORKER_CLIENT", "saas-session-worker")
    assert deliver_once(env.pool, settings)
    with env.pool.connection() as conn:
        task = conn.execute(
            "SELECT completed_at FROM private_tasks WHERE kind='session_revoke'"
        ).fetchone()
        assert task["completed_at"] is not None, "Upstream session revocation worker failed"
    refreshed = flow.http.post(
        flow.issuer + "/protocol/openid-connect/token",
        data={
            "grant_type": "refresh_token",
            "client_id": "saas-portal",
            "client_secret": os.environ["SAAS_LOCAL_PORTAL_SECRET"],
            "refresh_token": tokens["refresh_token"],
        },
    )
    assert refreshed.status_code == 400
    flow.tokens(flow.login("local-user", os.environ["SAAS_LOCAL_USER_PASSWORD"]), wrong_pkce=True)


@pytest.fixture
def smtp_capture():
    messages = []

    class Handler:
        async def handle_DATA(self, server, session, envelope):
            messages.append(BytesParser(policy=policy.default).parsebytes(envelope.content))
            return "250 OK"

    controller = Controller(Handler(), hostname="0.0.0.0", port=58025)
    controller.start()
    yield messages
    controller.stop()


def email_link(messages, index):
    deadline = time.monotonic() + 10
    while len(messages) <= index and time.monotonic() < deadline:
        time.sleep(0.1)
    assert len(messages) > index, "Expected local SMTP message"
    part = messages[index].get_body(preferencelist=("plain", "html"))
    text = part.get_content() if part else messages[index].get_content()
    urls = re.findall(r'https?://[^\s<>"\']+', text)
    return next(u for u in urls if "/login-actions/action-token" in u)


def test_open_registration_email_verification_and_password_reset(oidc, smtp_capture):
    flow, client, _ = oidc
    username = "registered-" + uuid4().hex[:12]
    password = secrets.token_urlsafe(32)
    page = flow.start()
    register = next(link for link in Page(page.text).links if "/registration" in link)
    registration = flow.http.get(urljoin(str(page.url), register))
    result = flow.submit(
        registration,
        {
            "username": username,
            "email": username + "@example.com",
            "firstName": "Test",
            "lastName": "User",
            "password": password,
            "password-confirm": password,
        },
    )
    assert result.status_code == 200, "Expected email verification step"
    verification = flow.follow(flow.http.get(email_link(smtp_capture, 0)))
    if verification.status_code == 200:
        confirm = next(
            (
                link
                for link in Page(verification.text).links
                if "/login-actions/action-token" in link
            ),
            None,
        )
        if confirm:
            verification = flow.follow(flow.http.get(urljoin(str(verification.url), confirm)))
    tokens = (
        flow.tokens(verification)
        if verification.status_code in {302, 303}
        else flow.tokens(flow.login(username + "@example.com", password))
    )
    response = client.get("/v1/me", headers={"Authorization": "Bearer " + tokens["access_token"]})
    assert response.status_code == 200
    assert response.json()["user"]["emailVerified"] is True
    page = flow.start()
    reset = next(link for link in Page(page.text).links if "/reset-credentials" in link)
    flow.submit(
        flow.http.get(urljoin(str(page.url), reset)), {"username": username + "@example.com"}
    )
    reset_page = flow.follow(flow.http.get(email_link(smtp_capture, 1)))
    replacement = secrets.token_urlsafe(32)
    changed = flow.submit(
        reset_page, {"password-new": replacement, "password-confirm": replacement}
    )
    assert changed.status_code in {200, 302, 303}
    assert flow.login(username + "@example.com", password).status_code == 200
    assert flow.tokens(flow.login(username + "@example.com", replacement))["access_token"]


def test_authorization_code_is_single_use(oidc):
    flow, _, _ = oidc
    flow.tokens(flow.login("local-user", os.environ["SAAS_LOCAL_USER_PASSWORD"]))
    # Keycloak invalidates tokens after code reuse, so this is deliberately a
    # separate login from the token-exchange success test.
    assert (
        flow.http.post(
            flow.issuer + "/protocol/openid-connect/token", data=flow.exchange_request
        ).status_code
        == 400
    )
