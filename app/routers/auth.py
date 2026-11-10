from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app import sessions
from app.config import settings
from app.deps import DB, verify_csrf
from app.middleware import public
from app.models import User
from app.schemas import Token, UserCreate, UserOut
from app.security import (
    REFRESH_COOKIE,
    clear_auth_cookies,
    create_access_token,
    hash_password,
    hash_token,
    new_token,
    set_auth_cookies,
    verify_password,
)

router = APIRouter(prefix=f"{settings.API_PREFIX}/auth", tags=["auth"])

RefreshCookie = Annotated[str | None, Cookie(alias=REFRESH_COOKIE)]
INVALID_REFRESH = "Invalid or expired refresh token"


@router.post("/register", status_code=201)
@public
async def register(data: UserCreate, db: DB) -> UserOut:
    user = User(**data.model_dump(exclude={"password"}), hashed_password=await hash_password(data.password))
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        raise HTTPException(409, "Username or email already registered") from None
    await db.refresh(user)
    return user


@router.post("/login")
@public
async def login(
    request: Request, response: Response, form: Annotated[OAuth2PasswordRequestForm, Depends()], db: DB
) -> Token:
    username = form.username.strip().lower()
    ip = request.client.host if request.client else "unknown"

    if retry_after := await sessions.locked_for(username, ip):
        raise HTTPException(429, "Too many failed login attempts. Try again later.", {"Retry-After": str(retry_after)})

    user = await db.scalar(select(User).where(User.username == username))
    is_valid, upgraded_hash = await verify_password(form.password, user.hashed_password if user else None)
    if not is_valid:
        await sessions.record_failure(username, ip)
        raise HTTPException(401, "Incorrect username or password", {"WWW-Authenticate": "Bearer"})

    await sessions.clear_failures(username, ip)
    if not user.is_active:
        raise HTTPException(403, "Account is disabled")
    if upgraded_hash:
        user.hashed_password = upgraded_hash
        await db.commit()

    session_id, refresh_token = str(uuid4()), new_token()
    await sessions.create(session_id, user.id, hash_token(refresh_token))
    return _issue_tokens(response, user.id, session_id, refresh_token)


# Refresh and logout are public because the access token may already have expired.
# They're protected by the HttpOnly refresh cookie plus the CSRF check instead.
@router.post("/refresh", dependencies=[Depends(verify_csrf)])
@public
async def refresh(response: Response, db: DB, refresh_token: RefreshCookie = None) -> Token:
    if not refresh_token or not (session_id := await sessions.find(hash_token(refresh_token))):
        raise HTTPException(401, INVALID_REFRESH)

    next_refresh_token = new_token()
    status, user_id = await sessions.rotate(session_id, hash_token(refresh_token), hash_token(next_refresh_token))
    if status == "reused":
        raise HTTPException(401, "Refresh token reuse detected. Please log in again.")

    user = await db.get(User, user_id) if user_id and status != "invalid" else None
    if user is None or not user.is_active:
        await sessions.delete(session_id)
        raise HTTPException(401, INVALID_REFRESH)

    # In the grace window, the request that won the race already set the new refresh cookie.
    return _issue_tokens(response, user.id, session_id, next_refresh_token if status == "rotated" else None)


@router.post("/logout", status_code=204, dependencies=[Depends(verify_csrf)])
@public
async def logout(response: Response, refresh_token: RefreshCookie = None) -> None:
    if refresh_token and (session_id := await sessions.find(hash_token(refresh_token))):
        await sessions.delete(session_id)
    clear_auth_cookies(response)


def _issue_tokens(response: Response, user_id: int, session_id: str, refresh_token: str | None) -> Token:
    if refresh_token:
        set_auth_cookies(response, refresh_token)
    return Token(
        access_token=create_access_token(user_id, session_id),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
