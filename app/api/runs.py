from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.run import RunCreate, RunResponse, RunUpdate
from app.services.run_service import RunService

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("", response_model=RunResponse)
def create_run(payload: RunCreate, db: Session = Depends(get_db)):
    return RunService.create_run(db, payload)


@router.get("", response_model=list[RunResponse])
def list_runs(db: Session = Depends(get_db)):
    return RunService.list_runs(db)


@router.get("/{run_id}", response_model=RunResponse)
def get_run(run_id: int, db: Session = Depends(get_db)):
    return RunService.get_run(db, run_id)


@router.patch("/{run_id}", response_model=RunResponse)
def update_run(run_id: int, payload: RunUpdate, db: Session = Depends(get_db)):
    return RunService.update_run_status(db, run_id, payload)
