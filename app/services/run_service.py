from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.security import ROLE_ADMIN
from app.models.run import AssessmentRun
from app.schemas.run import RunCreate, RunUpdate


class RunService:
    @staticmethod
    def authorize(run: AssessmentRun, user) -> AssessmentRun:
        """Owner-or-admin gate. Raise 404 (not 403) on a foreign run so a run id
        can't be enumerated by probing for 403s."""
        if user is not None and user.role != ROLE_ADMIN and run.submitted_by != user.email:
            raise HTTPException(status_code=404, detail="Run not found")
        return run

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
            min_severity=payload.min_severity,
            submitted_by=submitted_by,
            status="SUBMITTED",
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    def list_runs(db: Session, user=None) -> list[AssessmentRun]:
        """Admins (and unauthenticated internal callers, user=None) see every
        run; a provider sees only the runs they submitted."""
        query = db.query(AssessmentRun).order_by(AssessmentRun.created_at.desc())
        if user is not None and user.role != ROLE_ADMIN:
            query = query.filter(AssessmentRun.submitted_by == user.email)
        return query.all()

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
