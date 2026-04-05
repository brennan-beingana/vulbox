from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.run import Run
from app.schemas.finding import FindingCreate


class FindingService:
    @staticmethod
    def create_finding(db: Session, run_id: int, payload: FindingCreate) -> Finding:
        run = db.query(Run).filter(Run.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")

        finding = Finding(run_id=run_id, **payload.model_dump())
        db.add(finding)
        db.commit()
        db.refresh(finding)
        return finding

    @staticmethod
    def list_findings(db: Session, run_id: int) -> list[Finding]:
        run = db.query(Run).filter(Run.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")

        return db.query(Finding).filter(Finding.run_id == run_id).all()
