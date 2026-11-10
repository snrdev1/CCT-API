"""Create a user from the command line (there is no public sign-up).

    uv run python -m app.create_user <username> [--email EMAIL] [--full-name NAME]

Prompts for the password. When input is piped instead of typed, the first line is the password.
"""

import argparse
import asyncio
import getpass
import sys

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from app.db import Base, SessionLocal, engine
from app.models import User
from app.schemas import UserCreate
from app.security import hash_password


async def create_user(data: UserCreate) -> User:
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with SessionLocal() as db:
            user = User(**data.model_dump(exclude={"password"}), hashed_password=await hash_password(data.password))
            db.add(user)
            await db.commit()
            return user
    finally:
        await engine.dispose()


def read_password() -> str:
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match")
    return password


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a user")
    parser.add_argument("username")
    parser.add_argument("--email")
    parser.add_argument("--full-name")
    args = parser.parse_args()

    try:
        data = UserCreate(username=args.username, password=read_password(), email=args.email, full_name=args.full_name)
    except ValidationError as exc:
        sys.exit("\n".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()))

    try:
        user = asyncio.run(create_user(data))
    except IntegrityError:
        sys.exit("Username or email already exists")
    print(f"Created user '{user.username}' (id {user.id})")


if __name__ == "__main__":
    main()
