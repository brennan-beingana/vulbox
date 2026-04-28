from fastapi import APIRouter

from app.api.auth import router as auth_router
from app.api.ingest import router as ingest_router
from app.api.reports import router as reports_router
from app.api.runs import router as runs_router
from app.api.websocket import router as ws_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(runs_router)
api_router.include_router(ingest_router)
api_router.include_router(reports_router)
api_router.include_router(ws_router)
