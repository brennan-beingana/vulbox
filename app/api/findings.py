from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.finding import FindingCreate, FindingResponse
from app.services.finding_service import FindingService

router = APIRouter(prefix="/runs/{run_id}/findings", tags=["findings"])


@router.post("", response_model=FindingResponse)
def create_finding(run_id: int, payload: FindingCreate, db: Session = Depends(get_db)):
    return FindingService.create_finding(db, run_id, payload)


@router.get("", response_model=list[FindingResponse])
def list_findings(run_id: int, db: Session = Depends(get_db)):
    return FindingService.list_findings(db, run_id)
