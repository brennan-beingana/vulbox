from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.correlation_service import CorrelationService
from app.services.remediation_service import RemediationService
from app.services.run_service import RunService

router = APIRouter(prefix="/runs/{run_id}", tags=["processing"])


class ProcessResponse:
    def __init__(self, message: str, status: str):
        self.message = message
        self.status = status

    def model_dump(self) -> dict:
        return {"message": self.message, "status": self.status}


@router.post("/correlate")
def correlate_findings(run_id: int, db: Session = Depends(get_db)):
    """Correlate findings across all tools for a run."""
    # Verify run exists
    run = RunService.get_run(db, run_id)
    
    # Run correlation engine
    correlated = CorrelationService.correlate_findings(db, run_id)
    
    return {
        "message": f"Correlated findings into {len(correlated)} groups",
        "status": "success",
        "correlated_count": len(correlated),
    }


@router.post("/remediate")
def generate_remediation(run_id: int, db: Session = Depends(get_db)):
    """Generate remediation guidance for correlated findings."""
    # Verify run exists
    run = RunService.get_run(db, run_id)
    
    # Generate remediations
    remediations = RemediationService.generate_remediations(db, run_id)
    
    return {
        "message": f"Generated {len(remediations)} remediation recommendations",
        "status": "success",
        "remediations_count": len(remediations),
    }


@router.post("/recompute-risk")
def recompute_risk(run_id: int, db: Session = Depends(get_db)):
    """Recompute correlation and risk scores (idempotent)."""
    # Verify run exists
    run = RunService.get_run(db, run_id)
    
    # Recompute correlation
    correlated = CorrelationService.recompute_correlation(db, run_id)
    
    # Regenerate remediations
    remediations = RemediationService.generate_remediations(db, run_id)
    
    return {
        "message": f"Recomputed {len(correlated)} correlations and {len(remediations)} remediations",
        "status": "success",
    }
