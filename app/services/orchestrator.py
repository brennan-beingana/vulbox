"""
Orchestrator — central pipeline controller (SDD §4.6, §4.12.2).

State machine:
  SUBMITTED → BUILDING → SCANNING → TESTING → (REBUILDING → TESTING)* → REPORTING → COMPLETE
  Any BUILDING failure → FAILED (terminal)
"""
import asyncio
from datetime import datetime
from typing import Dict

from sqlalchemy.orm import Session

from app.adapters.art_adapter import ARTAdapter
from app.adapters.falco_adapter import FalcoAdapter
from app.adapters.trivy_adapter import TrivyAdapter
from app.core.logging import get_logger, log_pipeline_event
from app.models.art_test_result import ARTTestResult
from app.models.run import AssessmentRun
from app.models.security_matrix_entry import SecurityMatrixEntry
from app.services.docker_manager import BuildFailedError, DockerManager
from app.services.remediation_service import RemediationService

logger = get_logger(__name__)

# In-memory queues for WebSocket status streaming; keyed by run_id
_status_queues: Dict[int, asyncio.Queue] = {}


def get_status_queue(run_id: int) -> asyncio.Queue:
    if run_id not in _status_queues:
        _status_queues[run_id] = asyncio.Queue()
    return _status_queues[run_id]


def _set_status(db: Session, run: AssessmentRun, status: str) -> None:
    run.status = status
    if status in ("COMPLETE", "FAILED"):
        run.completed_at = datetime.utcnow()
    db.commit()
    log_pipeline_event(logger, "status_transition", run.id, status=status)
    # Push to WebSocket queue if subscribers exist
    if run.id in _status_queues:
        try:
            _status_queues[run.id].put_nowait({"event": "status", "status": status})
        except asyncio.QueueFull:
            pass


def _push_event(run_id: int, event: dict) -> None:
    if run_id in _status_queues:
        try:
            _status_queues[run_id].put_nowait(event)
        except asyncio.QueueFull:
            pass


async def start_assessment(run_id: int, db: Session) -> None:
    """Entry point — called as a FastAPI BackgroundTask from POST /runs."""
    run = db.query(AssessmentRun).filter(AssessmentRun.id == run_id).first()
    if not run:
        logger.error("Run not found", extra={"run_id": run_id})
        return

    image_tag = f"vulbox-run-{run_id}"

    try:
        # Phase 1: Build
        trivy_findings = await _phase_build_and_scan(run, image_tag, db)

        # Phase 2: Deploy sandbox
        container_id = await _phase_deploy_sandbox(run, image_tag, db)

        # Phase 3: Test loop
        await _phase_test_loop(run, image_tag, container_id, trivy_findings, db)

        # Phase 4: Report
        await _phase_report(run, db)

    except BuildFailedError as exc:
        logger.error("Build failed", extra={"run_id": run_id, "error": str(exc)})
        _set_status(db, run, "FAILED")
    except Exception as exc:
        logger.error("Unexpected error in pipeline", extra={"run_id": run_id, "error": str(exc)})
        if run.status == "BUILDING":
            _set_status(db, run, "FAILED")
        # Later-phase failures log but don't set FAILED (assessment continues)


async def _phase_build_and_scan(run: AssessmentRun, image_tag: str, db: Session):
    _set_status(db, run, "BUILDING")
    _push_event(run.id, {"event": "phase", "phase": "BUILDING"})

    repo_path = await asyncio.to_thread(DockerManager.clone_repo, run.repo_url)
    await asyncio.to_thread(DockerManager.build_image, repo_path, image_tag)

    _set_status(db, run, "SCANNING")
    _push_event(run.id, {"event": "phase", "phase": "SCANNING"})

    trivy_findings = await asyncio.to_thread(TrivyAdapter.scan, image_tag, run.id)
    for f in trivy_findings:
        db.add(f)
    db.commit()
    for f in trivy_findings:
        db.refresh(f)

    log_pipeline_event(logger, "scan_complete", run.id, findings=len(trivy_findings))
    _push_event(run.id, {"event": "scan_complete", "findings": len(trivy_findings)})
    return trivy_findings


async def _phase_deploy_sandbox(run: AssessmentRun, image_tag: str, db: Session) -> str:
    _set_status(db, run, "TESTING")
    _push_event(run.id, {"event": "phase", "phase": "TESTING"})

    container_id = await asyncio.to_thread(DockerManager.run_sandbox, image_tag)
    await asyncio.to_thread(FalcoAdapter.attach, container_id)
    return container_id


async def _phase_test_loop(
    run: AssessmentRun, image_tag: str, container_id: str, trivy_findings, db: Session
) -> None:
    queue = await asyncio.to_thread(ARTAdapter.build_queue, trivy_findings)

    for test_id in queue:
        _push_event(run.id, {"event": "test_start", "test_id": test_id})

        test_result: ARTTestResult = await asyncio.to_thread(
            ARTAdapter.execute_test, test_id, run.id
        )

        if test_result.crash_occurred:
            log_pipeline_event(logger, "crash_detected", run.id, test_id=test_id)
            _push_event(run.id, {"event": "crash", "test_id": test_id})
            _set_status(db, run, "REBUILDING")
            container_id = await asyncio.to_thread(
                DockerManager.rebuild_and_restart, container_id, image_tag
            )
            _set_status(db, run, "TESTING")
            db.add(test_result)
            db.commit()
            db.refresh(test_result)
            continue

        # Persist test result
        db.add(test_result)
        db.commit()
        db.refresh(test_result)

        # Collect Falco alerts linked to this test
        alerts = await asyncio.to_thread(
            FalcoAdapter.collect_alerts, run.id, test_result.test_result_id
        )
        for alert in alerts:
            db.add(alert)
        db.commit()

        # Determine risk score
        score = _compute_risk(test_result.exploited, len(alerts) > 0)

        # Build Security Matrix Entry
        finding_id = trivy_findings[0].finding_id if trivy_findings else None
        entry = SecurityMatrixEntry(
            run_id=run.id,
            finding_id=finding_id,
            test_result_id=test_result.test_result_id,
            is_present=True,
            is_exploitable=test_result.exploited,
            is_detectable=len(alerts) > 0,
            mitre_tactic_id=test_id,
            risk_score=score,
        )
        db.add(entry)
        db.commit()

        _push_event(
            run.id,
            {
                "event": "test_complete",
                "test_id": test_id,
                "exploited": test_result.exploited,
                "detected": len(alerts) > 0,
                "risk_score": score,
            },
        )

    await asyncio.to_thread(DockerManager.destroy_sandbox, container_id)
    await asyncio.to_thread(FalcoAdapter.detach)


async def _phase_report(run: AssessmentRun, db: Session) -> None:
    _set_status(db, run, "REPORTING")
    _push_event(run.id, {"event": "phase", "phase": "REPORTING"})

    await asyncio.to_thread(RemediationService.generate_remediations, db, run.id)

    _set_status(db, run, "COMPLETE")
    _push_event(run.id, {"event": "complete"})
    log_pipeline_event(logger, "assessment_complete", run.id)


def _compute_risk(exploited: bool, detected: bool) -> int:
    """Simple three-factor risk score (max 50)."""
    score = 10  # base: vulnerability is present
    if exploited:
        score += 30
    if not detected:
        score += 10  # undetected exploits are highest risk
    return min(50, score)
