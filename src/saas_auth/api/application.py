from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import uuid4

import psycopg
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.exc import TimeoutError as PoolTimeout
from starlette.exceptions import HTTPException
from starlette.middleware.base import RequestResponseEndpoint

from saas_auth.config import Settings
from saas_auth.db import Database
from saas_auth.db.migrations import at_head
from saas_auth.errors import ApiError, unavailable
from saas_auth.identity.security import TokenVerifier

from .dependencies import get_database
from .routes import router
from .schemas import ErrorResponse


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    database = Database(settings.database_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            database.close()

    app = FastAPI(
        title="SaaS user identity and application permissions", version="0.2.0", lifespan=lifespan
    )
    app.state.database = database
    app.state.settings = settings
    app.state.verifier = TokenVerifier(settings)

    @app.middleware("http")
    async def request_context(request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.request_id = uuid4()
        response = await call_next(request)
        response.headers["X-Request-ID"] = str(request.state.request_id)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError) -> JSONResponse:
        headers = {"Retry-After": "3"} if exc.status == 503 else {}
        if exc.status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        return JSONResponse(
            ErrorResponse(
                code=exc.code, message=exc.message, requestId=request.state.request_id
            ).model_dump(mode="json"),
            status_code=exc.status,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return await api_error(request, ApiError(422, "invalid_input", "Invalid request."))

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code, message = {
            404: ("not_found", "Resource not found."),
            405: ("method_not_allowed", "Method not allowed."),
        }.get(exc.status_code, ("http_error", "Request could not be completed."))
        response = await api_error(request, ApiError(exc.status_code, code, message))
        if exc.headers:
            response.headers.update(exc.headers)
        return response

    @app.exception_handler(OperationalError)
    @app.exception_handler(PoolTimeout)
    async def database_error(request: Request, exc: Exception) -> JSONResponse:
        return await api_error(request, unavailable())

    @app.get("/health/live", response_model=None)
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", response_model=None)
    def ready(database: Annotated[Database, Depends(get_database)]) -> dict[str, str]:
        with database.sessions() as session:
            try:
                if not at_head(session.connection()):
                    raise unavailable()
            except ProgrammingError as exc:
                if isinstance(exc.orig, psycopg.errors.UndefinedTable):
                    raise unavailable() from None
                raise
        return {"status": "ready"}

    app.include_router(router)
    return app
