import re
from collections.abc import Callable

import jwt
from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app import sessions
from app.security import decode_access_token


def public[F: Callable](endpoint: F) -> F:
    """Opt an endpoint out of authentication. Put it directly under the route decorator."""
    endpoint.is_public = True
    return endpoint


def find_public_routes(app: FastAPI, routers: list[APIRouter]) -> list[tuple[re.Pattern, set[str]]]:
    routes = [
        (r.path_regex, r.methods)
        for router in routers
        for r in router.routes
        if getattr(r.endpoint, "is_public", False)
    ]
    docs = filter(None, [app.docs_url, app.redoc_url, app.openapi_url, app.swagger_ui_oauth2_redirect_url])
    return routes + [(re.compile(f"^{re.escape(path)}$"), {"GET", "HEAD"}) for path in docs]


class AuthMiddleware(BaseHTTPMiddleware):
    """Every request needs a valid access token unless its route is marked @public."""

    def __init__(self, app, public_routes: list[tuple[re.Pattern, set[str]]]):
        super().__init__(app)
        self.public_routes = public_routes

    async def dispatch(self, request: Request, call_next):
        path, method = request.url.path, request.method
        if any(method in methods and regex.match(path) for regex, methods in self.public_routes):
            return await call_next(request)

        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        try:
            if scheme.lower() != "bearer":
                raise jwt.InvalidTokenError
            claims = decode_access_token(token)
        except jwt.InvalidTokenError:
            return _unauthorized("Not authenticated")

        # Checking the session makes logout and reuse detection apply immediately,
        # instead of waiting for the access token to expire.
        if not await sessions.exists(claims["sid"]):
            return _unauthorized("Session has ended. Please log in again.")

        request.state.user_id = int(claims["sub"])
        request.state.session_id = claims["sid"]
        return await call_next(request)


def _unauthorized(detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
