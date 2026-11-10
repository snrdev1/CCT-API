from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "CCT-API"
    ENVIRONMENT: Literal["local", "staging", "production"] = "local"
    LOG_LEVEL: str = "INFO"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    API_PREFIX: str = "/api/v1"

    DATABASE_URL: str = "postgresql+asyncpg://cct:cct_dev_password@localhost:5432/cct"
    REDIS_URL: str = "redis://:redis_dev_password@localhost:6379/0"

    JWT_SECRET_KEY: SecretStr = Field(min_length=32)
    JWT_ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_MAX_DAYS: int = 30
    REFRESH_GRACE_SECONDS: int = 10

    CORS_ORIGINS: list[str] = ["http://localhost:5173"]
    COOKIE_SECURE: bool = True
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"

    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    @property
    def auth_cookie_path(self) -> str:
        return f"{self.API_PREFIX}/auth"


settings = Settings()
