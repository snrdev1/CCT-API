import secrets
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import get_db
from app.models import User
from app.security import CSRF_COOKIE, CSRF_HEADER

DB = Annotated[AsyncSession, Depends(get_db)]


async def get_current_user(request: Request, db: DB) -> User:
    """AuthMiddleware has already verified the token; this loads the user for endpoints that need it."""
    user_id = getattr(request.state, "user_id", None)
    user = await db.get(User, user_id) if user_id else None
    if user is None:
        raise HTTPException(401, "Not authenticated")
    if not user.is_active:
        raise HTTPException(403, "Account is disabled")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def verify_csrf(request: Request) -> None:
    """For cookie-authenticated endpoints, where the browser attaches the credential on its own."""
    origin = request.headers.get("origin")
    if not origin and (referer := urlsplit(request.headers.get("referer", ""))).netloc:
        origin = f"{referer.scheme}://{referer.netloc}"
    if origin not in settings.CORS_ORIGINS:
        raise HTTPException(403, "Invalid origin")

    cookie, header = request.cookies.get(CSRF_COOKIE), request.headers.get(CSRF_HEADER)
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(403, "CSRF token missing or invalid")
