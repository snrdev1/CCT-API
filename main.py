import uvicorn

from app.config import settings


def main() -> None:
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.ENVIRONMENT == "local")


if __name__ == "__main__":
    main()
