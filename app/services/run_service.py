from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.run import Run
from app.schemas.run import RunCreate, RunUpdate


class RunService:
    @staticmethod
    def create_run(db: Session, payload: RunCreate) -> Run:
        run = Run(**payload.model_dump())
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    def list_runs(db: Session) -> list[Run]:
        return db.query(Run).order_by(Run.created_at.desc()).all()

    @staticmethod
    def get_run(db: Session, run_id: int) -> Run:
        run = db.query(Run).filter(Run.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        return run

    @staticmethod
    def update_run_status(db: Session, run_id: int, payload: RunUpdate) -> Run:
        run = RunService.get_run(db, run_id)
        run.status = payload.status
        if payload.status in {"completed", "failed"}:
            run.finished_at = datetime.utcnow()
        db.commit()
        db.refresh(run)
        return run
