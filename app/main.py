from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.core.config import settings
from app.core.database import Base, engine
from app.core.logging import get_logger
from app.services import epss
from app import models  # noqa: F401 — ensures all tables are registered

logger = get_logger(__name__)

app = FastAPI(title=settings.app_name, version=settings.app_version)


def _mode() -> str:
    return "dev" if settings.dev_mode else "production"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://46.101.193.155:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    # Make the running mode unmistakable in the logs — the #1 source of
    # "why did it fall back to dev?" confusion is not knowing which mode is live.
    logger.info(
        "VulBox startup",
        extra={
            "mode": _mode(),
            "epss_scores_loaded": epss.loaded_count(),
            "epss_gate": settings.epss_min,
            "llm_remediation": settings.llm_remediation_enabled,
        },
    )


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "mode": _mode(),
        "epss_scores_loaded": epss.loaded_count(),
    }


app.include_router(api_router)
