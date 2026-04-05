from fastapi import FastAPI

from app.api import api_router
from app.core.config import settings
from app.core.database import Base, engine
from app import models  # noqa: F401

app = FastAPI(title=settings.app_name, version=settings.app_version)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": settings.app_name}


app.include_router(api_router)
