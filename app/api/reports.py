from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.correlated_finding import CorrelatedFinding
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.run import Run
from app.schemas.report import (
    CorrelatedFindingResponseSchema,
    RemediationResponseSchema,
    ReportResponse,
)
from app.services.run_service import RunService

router = APIRouter(prefix="/reports", tags=["reporting"])


@router.get("/{run_id}", response_model=ReportResponse)
def get_report(run_id: int, db: Session = Depends(get_db)):
    """Get consolidated security assessment report for a run."""
    # Get run
    run = RunService.get_run(db, run_id)
    
    # Get all correlated findings
    correlated = (
        db.query(CorrelatedFinding)
        .filter(CorrelatedFinding.run_id == run_id)
        .all()
    )
    
    # Get all remediations
    remediations = (
        db.query(Remediation)
        .filter(Remediation.run_id == run_id)
        .all()
    )
    
    # Get total findings
    findings = db.query(Finding).filter(Finding.run_id == run_id).count()
    
    # Build correlated findings response
    correlated_response = []
    for cf in correlated:
        finding = (
            db.query(Finding).filter(Finding.id == cf.main_finding_id).first()
        )
        correlated_response.append(
            CorrelatedFindingResponseSchema(
                id=cf.id,
                main_finding_id=cf.main_finding_id,
                supporting_finding_ids=cf.supporting_finding_ids or [],
                risk_score=cf.risk_score,
                confidence=cf.confidence,
                correlation_reason=cf.correlation_reason,
                is_confirmed=cf.is_confirmed,
                finding_title=finding.title if finding else None,
                finding_severity=finding.severity if finding else None,
            )
        )
    
    # Build remediations response
    remediations_response = [
        RemediationResponseSchema(
            id=r.id,
            summary=r.summary,
            priority_action=r.priority_action,
            why_it_matters=r.why_it_matters,
            example_fix=r.example_fix,
            confidence=r.confidence,
            source=r.source,
        )
        for r in remediations
    ]
    
    return ReportResponse(
        run_id=run.id,
        project_name=run.project_name,
        image_tag=run.image_tag,
        status=run.status,
        findings_count=findings,
        correlated_findings_count=len(correlated),
        remediations_count=len(remediations),
        correlated_findings=correlated_response,
        remediations=remediations_response,
        created_at=run.created_at,
    )
