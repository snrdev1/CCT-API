from fastapi import APIRouter

from app.config import settings
from app.deps import CurrentUser
from app.schemas import UserOut

router = APIRouter(prefix=f"{settings.API_PREFIX}/users", tags=["users"])


@router.get("/me")
async def read_me(user: CurrentUser) -> UserOut:
    return user
