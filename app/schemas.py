from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, EmailStr, Field


def _normalize(value: object) -> object:
    return value.strip().lower() if isinstance(value, str) else value


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Annotated[str, BeforeValidator(_normalize), Field(min_length=3, max_length=32, pattern=r"^[a-z0-9_.-]+$")]
    password: Annotated[str, Field(min_length=8, max_length=128)]
    email: Annotated[EmailStr | None, BeforeValidator(_normalize)] = None
    full_name: Annotated[str | None, Field(min_length=1, max_length=100)] = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None
    full_name: str | None
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
