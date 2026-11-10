import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from anyio import to_thread
from fastapi import Response
from pwdlib import PasswordHash

from app.config import settings

REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

_hasher = PasswordHash.recommended()
# Verified against when the username doesn't exist, so the response time doesn't reveal which usernames are taken.
_DUMMY_HASH = _hasher.hash("dummy-password")


# Argon2 is deliberately slow, so it runs in a worker thread to keep the event loop free.
async def hash_password(password: str) -> str:
    return await to_thread.run_sync(_hasher.hash, password)


async def verify_password(password: str, hashed: str | None) -> tuple[bool, str | None]:
    """Returns (is_valid, upgraded_hash). upgraded_hash is set when the stored hash uses outdated parameters."""
    if hashed is None:
        await to_thread.run_sync(_hasher.verify, password, _DUMMY_HASH)
        return False, None
    return await to_thread.run_sync(_hasher.verify_and_update, password, hashed)


def create_access_token(user_id: int, session_id: str) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "sid": session_id,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(claims, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Raises jwt.InvalidTokenError if the token is forged, expired or not an access token."""
    claims = jwt.decode(
        token,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub", "sid", "type"]},
    )
    if claims["type"] != "access":
        raise jwt.InvalidTokenError("Not an access token")
    return claims


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def set_auth_cookies(response: Response, refresh_token: str) -> None:
    max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    secure, samesite = settings.COOKIE_SECURE, settings.COOKIE_SAMESITE
    # HttpOnly and scoped to /auth: JS can't read it and the browser only sends it to refresh/logout.
    response.set_cookie(
        REFRESH_COOKIE,
        refresh_token,
        max_age,
        path=settings.auth_cookie_path,
        httponly=True,
        secure=secure,
        samesite=samesite,
    )
    # Readable by the frontend, which echoes it back in the X-CSRF-Token header.
    response.set_cookie(CSRF_COOKIE, new_token(), max_age, path="/", secure=secure, samesite=samesite)


def clear_auth_cookies(response: Response) -> None:
    secure, samesite = settings.COOKIE_SECURE, settings.COOKIE_SAMESITE
    response.delete_cookie(
        REFRESH_COOKIE, path=settings.auth_cookie_path, httponly=True, secure=secure, samesite=samesite
    )
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, samesite=samesite)
