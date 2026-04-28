from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.run import AssessmentRun
from app.schemas.run import RunCreate, RunUpdate


class RunService:
    @staticmethod
    def create_run(db: Session, payload: RunCreate, submitted_by: str = "") -> AssessmentRun:
        run = AssessmentRun(
            project_name=payload.project_name,
            repo_url=payload.repo_url,
            branch=payload.branch,
            commit_sha=payload.commit_sha,
            image_name=payload.image_name,
            image_tag=payload.image_tag,
            consent_granted=payload.consent_granted,
            submitted_by=submitted_by,
            status="SUBMITTED",
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    def list_runs(db: Session) -> list[AssessmentRun]:
        return db.query(AssessmentRun).order_by(AssessmentRun.created_at.desc()).all()

    @staticmethod
    def get_run(db: Session, run_id: int) -> AssessmentRun:
        run = db.query(AssessmentRun).filter(AssessmentRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        return run

    @staticmethod
    def update_run_status(db: Session, run_id: int, payload: RunUpdate) -> AssessmentRun:
        run = RunService.get_run(db, run_id)
        run.status = payload.status
        if payload.status in ("COMPLETE", "FAILED"):
            run.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    def delete_run(db: Session, run_id: int) -> None:
        run = RunService.get_run(db, run_id)
        if run.status in ("TESTING", "REBUILDING"):
            raise HTTPException(
                status_code=409,
                detail="Cannot delete a run while testing is active (would leave orphaned containers)",
            )
        db.delete(run)
        db.commit()
