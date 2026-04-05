from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.atomic import AtomicIngestionPayload, AtomicResponse
from app.schemas.falco import FalcoIngestionPayload, FalcoResponse
from app.schemas.trivy import TrivyIngestionPayload, TrivyResponse
from app.services.parser_service import ParserService
from app.services.run_service import RunService

router = APIRouter(prefix="/runs/{run_id}/ingest", tags=["ingestion"])


@router.post("/trivy", response_model=TrivyResponse)
def ingest_trivy(
    run_id: int, payload: TrivyIngestionPayload, db: Session = Depends(get_db)
):
    """Ingest Trivy static scan results."""
    # Verify run exists
    run = RunService.get_run(db, run_id)
    
    # Parse and store findings
    findings = ParserService.parse_trivy(db, run_id, payload)
    
    return TrivyResponse(
        message=f"Ingested {len(findings)} Trivy findings",
        findings_count=len(findings),
    )


@router.post("/falco", response_model=FalcoResponse)
def ingest_falco(
    run_id: int, payload: FalcoIngestionPayload, db: Session = Depends(get_db)
):
    """Ingest Falco runtime monitoring alerts."""
    # Verify run exists
    run = RunService.get_run(db, run_id)
    
    # Parse and store findings
    findings = ParserService.parse_falco(db, run_id, payload)
    
    return FalcoResponse(
        message=f"Ingested {len(findings)} Falco alerts",
        alerts_count=len(findings),
    )


@router.post("/atomic", response_model=AtomicResponse)
def ingest_atomic(
    run_id: int, payload: AtomicIngestionPayload, db: Session = Depends(get_db)
):
    """Ingest Atomic Red Team validation results."""
    # Verify run exists
    run = RunService.get_run(db, run_id)
    
    # Parse and store findings
    findings = ParserService.parse_atomic(db, run_id, payload)
    
    return AtomicResponse(
        message=f"Ingested {len(findings)} Atomic tests",
        tests_count=len(findings),
    )
