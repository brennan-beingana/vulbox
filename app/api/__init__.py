from fastapi import APIRouter

from app.api.findings import router as findings_router
from app.api.ingest import router as ingest_router
from app.api.processing import router as processing_router
from app.api.reports import router as reports_router
from app.api.runs import router as runs_router

api_router = APIRouter()
api_router.include_router(runs_router)
api_router.include_router(findings_router)
api_router.include_router(ingest_router)
api_router.include_router(processing_router)
api_router.include_router(reports_router)
