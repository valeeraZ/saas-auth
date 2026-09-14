from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID, uuid4

import psycopg
from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg_pool import PoolTimeout
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException

from saas_auth.config import Settings
from saas_auth.db import make_pool
from saas_auth.errors import ApiError, unavailable
from saas_auth.security import Identity, TokenVerifier
from saas_auth.service import Service
from saas_auth.user_api import user_router
from saas_auth.user_service import UserService


class CreateRole(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    key: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
    description: Annotated[str, Field(max_length=1000)]


def create_app(settings=None):
    settings = settings or Settings.from_env()
    pool = make_pool(settings.database_url)
    service = Service(pool, settings.cursor_secret)
    users = UserService(pool, settings)
    verifier = TokenVerifier(settings)

    @asynccontextmanager
    async def lifespan(app):
        pool.open()
        try:
            yield
        finally:
            pool.close()

    app = FastAPI(title="SaaS Auth service foundation", version="0.1.0", lifespan=lifespan)
    app.state.pool = pool
    app.state.verifier = verifier

    bearer = HTTPBearer(auto_error=False, scheme_name="serviceAccess")

    def authenticate(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        return verifier.verify("Bearer " + credentials.credentials if credentials else None)

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
                    "SELECT 1 FROM schema_migrations WHERE name='002_users_and_invitations.sql'"
                ).fetchone():
                    raise unavailable()
            except psycopg.errors.UndefinedTable:
                raise unavailable() from None
        return {"status": "ready"}

    @app.get("/v1/tenants/{tenantId}", operation_id="getTenant")
    def get_tenant(tenantId: UUID, identity: Identity = Depends(authenticate)):
        return response((users if identity.human else service).snapshot(identity, tenantId))

    @app.get("/v1/tenants/{tenantId}/apps/{appId}/roles", operation_id="listRoles")
    def list_roles(
        tenantId: UUID,
        appId: UUID,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        cursor: Annotated[str | None, Query(max_length=4096)] = None,
        identity: Identity = Depends(authenticate),
    ):
        if identity.human:
            return response(users.list_resources(identity, tenantId, "roles", limit, cursor, appId))
        return response(service.list_roles(identity, tenantId, appId, limit, cursor))

    @app.post(
        "/v1/tenants/{tenantId}/apps/{appId}/roles", operation_id="createRole", status_code=201
    )
    def create_role(
        tenantId: UUID,
        appId: UUID,
        body: CreateRole,
        request: Request,
        idempotency_key: Annotated[str, Header(min_length=16, max_length=128)],
        identity: Identity = Depends(authenticate),
    ):
        return response(
            (users if identity.human else service).write_role(
                identity,
                tenantId,
                appId,
                None,
                body.model_dump(),
                idempotency_key,
                None,
                request.state.request_id,
            )
        )

    @app.delete(
        "/v1/tenants/{tenantId}/apps/{appId}/roles/{roleId}",
        operation_id="deleteRole",
        status_code=204,
    )
    def delete_role(
        tenantId: UUID,
        appId: UUID,
        roleId: UUID,
        request: Request,
        idempotency_key: Annotated[str, Header(min_length=16, max_length=128)],
        if_match: Annotated[str, Header(pattern=r'^"[1-9][0-9]*"$')],
        identity: Identity = Depends(authenticate),
    ):
        return response(
            (users if identity.human else service).write_role(
                identity,
                tenantId,
                appId,
                roleId,
                None,
                idempotency_key,
                if_match,
                request.state.request_id,
            )
        )

    app.include_router(user_router(users, authenticate_user, logout_authenticate, response))
    original_openapi = app.openapi

    def openapi():
        schema = original_openapi()
        for path, methods in schema["paths"].items():
            for operation in methods.values():
                if operation.get("operationId") in {
                    "getTenant",
                    "listRoles",
                    "createRole",
                    "deleteRole",
                }:
                    operation["security"] = [{"serviceAccess": []}, {"userAccess": []}]
        return schema

    app.openapi = openapi
    return app
