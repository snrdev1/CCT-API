from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

from app import models  # noqa: F401  (registers the tables for create_all)
from app.config import settings
from app.db import Base, engine, redis
from app.middleware import AuthMiddleware, find_public_routes, public
from app.routers import auth, users
from app.security import CSRF_HEADER


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Creates missing tables only; it never alters existing ones.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await redis.aclose()
    await engine.dispose()


health = APIRouter(tags=["health"])


@health.get(f"{settings.API_PREFIX}/health")
@public
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


show_docs = settings.ENVIRONMENT != "production"
app = FastAPI(
    title=settings.APP_NAME,
    lifespan=lifespan,
    docs_url="/docs" if show_docs else None,
    openapi_url="/openapi.json" if show_docs else None,
    redoc_url=None,
    # Only adds Swagger's "Authorize" button. AuthMiddleware does the real checking.
    dependencies=[Depends(OAuth2PasswordBearer(f"{settings.API_PREFIX}/auth/login", auto_error=False))],
)

routers = [health, auth.router, users.router]
for router in routers:
    app.include_router(router)

# The last middleware added runs first, so CORS wraps Auth and even 401s carry CORS headers.
app.add_middleware(AuthMiddleware, public_routes=find_public_routes(app, routers))
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", CSRF_HEADER],
)
