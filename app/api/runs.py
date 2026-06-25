from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.art_test_result import ARTTestResult
from app.models.user import User
from app.schemas.report import ARTTestResultSchema
from app.schemas.run import RunCreate, RunResponse, RunUpdate
from app.services.orchestrator import start_assessment
from app.services.run_service import RunService

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("", response_model=RunResponse)
async def create_run(
    payload: RunCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not payload.consent_granted:
        raise HTTPException(
            status_code=400,
            detail="consent_granted must be true before any adversarial testing (FR-01)",
        )

    run = RunService.create_run(db, payload, submitted_by=current_user.email)
    background_tasks.add_task(start_assessment, run.id)
    return run


@router.get("", response_model=list[RunResponse])
def list_runs(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return RunService.list_runs(db, current_user)


@router.get("/{run_id}", response_model=RunResponse)
def get_run(run_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return RunService.authorize(RunService.get_run(db, run_id), current_user)


@router.patch("/{run_id}", response_model=RunResponse)
def update_run(
    run_id: int,
    payload: RunUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    RunService.authorize(RunService.get_run(db, run_id), current_user)
    return RunService.update_run_status(db, run_id, payload)


@router.delete("/{run_id}", status_code=204)
def delete_run(run_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RunService.authorize(RunService.get_run(db, run_id), current_user)
    RunService.delete_run(db, run_id)


@router.get("/{run_id}/validations", response_model=list[ARTTestResultSchema])
def get_validations(run_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    RunService.authorize(RunService.get_run(db, run_id), current_user)
    return db.query(ARTTestResult).filter(ARTTestResult.run_id == run_id).all()
