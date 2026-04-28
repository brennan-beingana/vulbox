"""
Ingestion endpoints — dev/demo path only.
When the Orchestrator is active these routes are bypassed; adapters call tool runners directly.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.art_test_result import ARTTestResult
from app.models.falco_alert import FalcoAlert
from app.models.trivy_finding import TrivyFinding
from app.schemas.atomic import AtomicIngestionPayload, AtomicResponse
from app.schemas.falco import FalcoIngestionPayload, FalcoResponse
from app.schemas.trivy import TrivyIngestionPayload, TrivyResponse
from app.services.run_service import RunService

router = APIRouter(prefix="/runs/{run_id}/ingest", tags=["ingestion (dev)"])

_PRIORITY_MAP = {
    "Emergency": "critical", "Alert": "critical", "Critical": "critical",
    "Error": "high", "Warning": "medium", "Notice": "low", "Informational": "low",
}


@router.post("/trivy", response_model=TrivyResponse)
def ingest_trivy(run_id: int, payload: TrivyIngestionPayload, db: Session = Depends(get_db)):
    RunService.get_run(db, run_id)
    findings = []
    for result in payload.results:
        for vuln in result.Vulnerabilities:
            f = TrivyFinding(
                run_id=run_id,
                cve_id=vuln.VulnerabilityID,
                severity=vuln.Severity.lower() if vuln.Severity else "unknown",
                package_name=vuln.PkgName,
                description=vuln.Description[:2000],
                fix_available=bool(vuln.FixedVersion),
            )
            db.add(f)
            findings.append(f)
    db.commit()
    return TrivyResponse(message=f"Ingested {len(findings)} Trivy findings", findings_count=len(findings))


@router.post("/falco", response_model=FalcoResponse)
def ingest_falco(run_id: int, payload: FalcoIngestionPayload, db: Session = Depends(get_db)):
    RunService.get_run(db, run_id)
    alerts = []
    for alert in payload.alerts:
        a = FalcoAlert(
            run_id=run_id,
            rule_triggered=alert.rule,
            severity=_PRIORITY_MAP.get(alert.priority, "medium"),
            syscall_context=alert.output[:500],
            timestamp=datetime.utcnow(),
            detected=True,
        )
        db.add(a)
        alerts.append(a)
    db.commit()
    return FalcoResponse(message=f"Ingested {len(alerts)} Falco alerts", alerts_count=len(alerts))


@router.post("/atomic", response_model=AtomicResponse)
def ingest_atomic(run_id: int, payload: AtomicIngestionPayload, db: Session = Depends(get_db)):
    RunService.get_run(db, run_id)
    results = []
    for test in payload.tests:
        r = ARTTestResult(
            run_id=run_id,
            mitre_test_id=test.technique_id,
            exploited=(test.status == "success"),
            crash_occurred=False,
            executed_at=datetime.utcnow(),
        )
        db.add(r)
        results.append(r)
    db.commit()
    return AtomicResponse(message=f"Ingested {len(results)} Atomic tests", tests_count=len(results))
