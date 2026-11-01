from contextlib import asynccontextmanager
from typing import Annotated
from uuid import uuid4

import psycopg
from fastapi import Depends, FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg_pool import PoolTimeout
from starlette.exceptions import HTTPException

from saas_auth.app_api import app_router
from saas_auth.app_service import AppService
from saas_auth.config import Settings
from saas_auth.db import make_pool
from saas_auth.errors import ApiError, unavailable
from saas_auth.security import TokenVerifier


def create_app(settings=None):
    settings = settings or Settings.from_env()
    pool = make_pool(settings.database_url)
    users = AppService(pool, settings)
    verifier = TokenVerifier(settings)

    @asynccontextmanager
    async def lifespan(app):
        pool.open()
        try:
            yield
        finally:
            pool.close()

    app = FastAPI(
        title="SaaS user identity and application permissions", version="0.2.0", lifespan=lifespan
    )
    app.state.pool = pool
    app.state.verifier = verifier

    user_bearer = HTTPBearer(auto_error=False, scheme_name="userAccess")

    def authenticate_user(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(user_bearer)],
    ):
        return verifier.verify("Bearer " + credentials.credentials if credentials else None)

    def logout_authenticate(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(user_bearer)],
    ):
        # Only a previously established, matching local session may be revoked or replayed.
        # Local logout must remain available during an IdP outage.
        return verifier.verify(
            "Bearer " + credentials.credentials if credentials else None, check_session=False
        )

    @app.middleware("http")
    async def request_context(request, call_next):
        request.state.request_id = uuid4()
        response = await call_next(request)
        response.headers["X-Request-ID"] = str(request.state.request_id)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ApiError)
    async def api_error(request, exc):
        headers = {"Retry-After": "3"} if exc.status == 503 else {}
        if exc.status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        return JSONResponse(
            {"code": exc.code, "message": exc.message, "requestId": str(request.state.request_id)},
            status_code=exc.status,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return await api_error(request, ApiError(422, "invalid_input", "Invalid request."))

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return await api_error(
            request, ApiError(exc.status_code, "not_found", "Resource not found.")
        )

    for error in (
        psycopg.OperationalError,
        psycopg.errors.QueryCanceled,
        psycopg.errors.LockNotAvailable,
        PoolTimeout,
    ):

        async def database_error(request, exc):
            return await api_error(request, unavailable())

        app.add_exception_handler(error, database_error)

    def response(result):
        headers = {"ETag": result.etag} if result.etag else {}
        if result.status == 204:
            return Response(status_code=204, headers=headers)
        return JSONResponse(result.body, status_code=result.status, headers=headers)

    @app.get("/health/live")
    def live():
        return {"status": "ok"}

    @app.get("/health/ready")
    def ready():
        with pool.connection() as conn:
            # A database reachable before migrations is not ready to serve traffic.
            try:
                if not conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE name='004_app_access_requests.sql'"
                ).fetchone():
                    raise unavailable()
            except psycopg.errors.UndefinedTable:
                raise unavailable() from None
        return {"status": "ready"}

    app.include_router(app_router(users, authenticate_user, logout_authenticate, response))
    return app
