"""
Orchestrator — central pipeline controller (SDD §4.6, §4.12.2).

State machine:
  SUBMITTED → BUILDING → SCANNING → TESTING → (REBUILDING → TESTING)* → REPORTING → COMPLETE
  Any pipeline failure → FAILED (terminal). Sandbox + Falco are always torn down.
"""
import asyncio
import os
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.adapters.art_adapter import ARTAdapter
from app.adapters.falco_adapter import FalcoAdapter
from app.adapters.trivy_adapter import TrivyAdapter
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.logging import get_logger, log_pipeline_event
from app.models.art_test_result import ARTTestResult
from app.models.detected_technology import DetectedTechnology
from app.models.run import AssessmentRun
from app.models.security_matrix_entry import SecurityMatrixEntry
from app.models.trivy_finding import TrivyFinding
from app.services.docker_manager import BuildFailedError, DockerManager, SandboxNotRunningError
from app.services.llm_remediation import LLMRemediationService
from app.services.remediation_service import RemediationService
from app.services.run_summary_service import RunSummaryService
from app.services.stack_detector import StackDetector, TechProfile

logger = get_logger(__name__)

MAX_REBUILDS = int(os.getenv("VULBOX_MAX_REBUILDS", "3"))
PIPELINE_TIMEOUT_SECS = int(os.getenv("VULBOX_PIPELINE_TIMEOUT_SECS", "1800"))
EVENT_REPLAY_DEPTH = 200
QUEUE_CLEANUP_GRACE_SECS = int(os.getenv("VULBOX_QUEUE_CLEANUP_GRACE_SECS", "60"))

# Severity → additional risk points (Tier-2 #13).
_SEVERITY_WEIGHT = {
    "critical": 20,
    "high": 15,
    "medium": 10,
    "low": 5,
    "unknown": 0,
}
RISK_SCORE_MAX = 75  # 10 base + 30 exploited + 10 undetected + 20 severity (critical)

# In-memory queues for live WebSocket streaming; keyed by run_id.
_status_queues: Dict[int, asyncio.Queue] = {}
# Ring buffer of recent events per run so a late WS subscriber can backfill.
_event_buffers: Dict[int, Deque[dict]] = {}


def get_status_queue(run_id: int) -> asyncio.Queue:
    if run_id not in _status_queues:
        _status_queues[run_id] = asyncio.Queue()
    return _status_queues[run_id]


def get_event_history(run_id: int) -> List[dict]:
    return list(_event_buffers.get(run_id, ()))


def _record_event(run_id: int, event: dict) -> None:
    buf = _event_buffers.setdefault(run_id, deque(maxlen=EVENT_REPLAY_DEPTH))
    buf.append(event)
    if run_id in _status_queues:
        try:
            _status_queues[run_id].put_nowait(event)
        except asyncio.QueueFull:
            pass


def _set_status(db: Session, run: AssessmentRun, status: str) -> None:
    run.status = status
    if status in ("COMPLETE", "FAILED"):
        run.completed_at = datetime.utcnow()
    db.commit()
    log_pipeline_event(logger, "status_transition", run.id, status=status)
    _record_event(run.id, {"event": "status", "status": status})


def _push_event(run_id: int, event: dict) -> None:
    _record_event(run_id, event)


def _run_dir(run_id: int) -> Path:
    p = settings.project_root / "data" / "runs" / str(run_id)
    (p / "logs").mkdir(parents=True, exist_ok=True)
    return p


async def _cleanup_run_state(run_id: int, grace: int = QUEUE_CLEANUP_GRACE_SECS) -> None:
    """Drop the WS queue + event buffer for a finished run after a grace period.

    The grace gives any WS client that connected during the final phase enough
    time to drain the queue before it disappears.
    """
    try:
        await asyncio.sleep(grace)
    except asyncio.CancelledError:
        return
    _status_queues.pop(run_id, None)
    _event_buffers.pop(run_id, None)


async def start_assessment(run_id: int) -> None:
    """Entry point — fired as a BackgroundTask from POST /runs.

    Opens its own DB session (request-scoped sessions are closed by the time
    the task runs). Always reaches a terminal status and cleans up sandbox +
    Falco, even on timeout or unexpected exception.
    """
    db: Session = SessionLocal()
    image_tag = f"vulbox-run-{run_id}"
    container_id: Optional[str] = None
    falco_attached = False
    failure_reason: Optional[str] = None
    run: Optional[AssessmentRun] = None

    try:
        run = db.query(AssessmentRun).filter(AssessmentRun.id == run_id).first()
        if not run:
            logger.error("Run not found", extra={"run_id": run_id})
            return

        _run_dir(run_id)  # ensure log dir exists

        async def _pipeline() -> None:
            nonlocal container_id, falco_attached
            trivy_findings, repo_path, tech_profile = await _phase_build_and_scan(
                run, image_tag, db
            )
            sandbox_cfg = await asyncio.to_thread(DockerManager.load_sandbox_config, repo_path)
            container_id = await _phase_deploy_sandbox(
                run, image_tag, db, run_id, sandbox_cfg
            )
            falco_attached = True
            await _phase_test_loop(
                run, image_tag, container_id, trivy_findings, db, sandbox_cfg, tech_profile
            )
            await _phase_report(run, db)

        await asyncio.wait_for(_pipeline(), timeout=PIPELINE_TIMEOUT_SECS)

    except asyncio.TimeoutError:
        failure_reason = f"pipeline exceeded {PIPELINE_TIMEOUT_SECS}s timeout"
        logger.error(failure_reason, extra={"run_id": run_id})
    except BuildFailedError as exc:
        failure_reason = f"build failed: {exc}"
        logger.error(failure_reason, extra={"run_id": run_id})
    except SandboxNotRunningError as exc:
        failure_reason = f"sandbox failed to stay running: {exc}"
        logger.error(failure_reason, extra={"run_id": run_id})
    except Exception as exc:  # noqa: BLE001 — top-level guard
        failure_reason = f"{type(exc).__name__}: {exc}"
        logger.exception("Unexpected error in pipeline", extra={"run_id": run_id})
    finally:
        # Tear down sandbox + Falco even on exceptions.
        if falco_attached:
            try:
                await asyncio.to_thread(FalcoAdapter.detach, run_id)
            except Exception:
                logger.exception("Falco detach failed", extra={"run_id": run_id})
        if container_id:
            try:
                await asyncio.to_thread(DockerManager.destroy_sandbox, container_id)
            except Exception:
                logger.exception("Sandbox destroy failed", extra={"run_id": run_id})

        # A failed flush (e.g. a schema mismatch mid-pipeline) leaves the
        # session in a rolled-back-pending state; without clearing it the
        # status write below raises and the run is stranded non-terminal
        # (the "stuck in SCANNING" symptom). Roll back first so the terminal
        # status can always be committed.
        try:
            db.rollback()
        except Exception:
            logger.exception("Session rollback failed", extra={"run_id": run_id})

        # Resolve to a terminal status no matter what.
        try:
            if run is not None and run.status not in ("COMPLETE", "FAILED"):
                if failure_reason:
                    _push_event(run_id, {"event": "error", "reason": failure_reason})
                    try:
                        (_run_dir(run_id) / "logs" / "failure.log").write_text(failure_reason)
                    except Exception:
                        pass
                    _set_status(db, run, "FAILED")
                else:
                    _set_status(db, run, "COMPLETE")
        except Exception:
            logger.exception("Failed to write terminal status", extra={"run_id": run_id})
        db.close()
        # Schedule queue cleanup so memory doesn't grow per run.
        asyncio.create_task(_cleanup_run_state(run_id))


async def _phase_build_and_scan(
    run: AssessmentRun, image_tag: str, db: Session
) -> Tuple[List[TrivyFinding], Optional[Path], TechProfile]:
    _set_status(db, run, "BUILDING")
    _push_event(run.id, {"event": "phase", "phase": "BUILDING"})

    repo_path = await asyncio.to_thread(DockerManager.clone_repo, run.repo_url, run.id)
    await asyncio.to_thread(DockerManager.build_image, repo_path, image_tag, run.id)

    # Fingerprint the tech stack from the repo's Dockerfile + manifests so the
    # test loop can queue stack-relevant attacks. Best-effort: detect() never
    # raises, and an empty profile degrades the queue to its reactive behavior.
    tech_profile = await asyncio.to_thread(StackDetector.detect, repo_path)
    for tech in tech_profile.techs:
        db.add(
            DetectedTechnology(
                run_id=run.id,
                name=tech.name,
                version=tech.version,
                source=tech.source,
                confidence=tech.confidence,
            )
        )
    db.commit()
    log_pipeline_event(logger, "stack_detected", run.id, tags=sorted(tech_profile.tags()))
    _push_event(run.id, {"event": "stack_detected", "tags": sorted(tech_profile.tags())})

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
    return trivy_findings, repo_path, tech_profile


async def _phase_deploy_sandbox(
    run: AssessmentRun,
    image_tag: str,
    db: Session,
    run_id: int,
    sandbox_cfg: Dict[str, Any],
) -> str:
    _set_status(db, run, "TESTING")
    _push_event(run.id, {"event": "phase", "phase": "TESTING"})

    container_id = await asyncio.to_thread(
        DockerManager.run_sandbox, image_tag, run_id, sandbox_cfg
    )
    # Fail fast if the image's entrypoint exited immediately — testing a dead
    # container produces meaningless results.
    await asyncio.to_thread(DockerManager.assert_running, container_id)
    await asyncio.to_thread(FalcoAdapter.attach, container_id, run_id)
    return container_id


async def _phase_test_loop(
    run: AssessmentRun,
    image_tag: str,
    container_id: str,
    trivy_findings: List[TrivyFinding],
    db: Session,
    sandbox_cfg: Dict[str, Any],
    tech_profile: Optional[TechProfile] = None,
) -> None:
    queue: List[Tuple[str, List[int]]] = await asyncio.to_thread(
        ARTAdapter.build_queue, trivy_findings, tech_profile
    )
    findings_by_id: Dict[int, TrivyFinding] = {f.finding_id: f for f in trivy_findings}
    rebuilds = 0

    for test_id, motivating_finding_ids in queue:
        _push_event(run.id, {"event": "test_start", "test_id": test_id})

        test_result: ARTTestResult = await asyncio.to_thread(
            ARTAdapter.execute_test, test_id, run.id, container_id
        )

        if test_result.crash_occurred:
            log_pipeline_event(logger, "crash_detected", run.id, test_id=test_id)
            _push_event(run.id, {"event": "crash", "test_id": test_id})
            db.add(test_result)
            db.commit()
            db.refresh(test_result)

            rebuilds += 1
            if rebuilds > MAX_REBUILDS:
                raise RuntimeError(
                    f"exceeded MAX_REBUILDS={MAX_REBUILDS} after test {test_id}"
                )
            _set_status(db, run, "REBUILDING")
            container_id = await asyncio.to_thread(
                DockerManager.rebuild_and_restart,
                container_id,
                image_tag,
                run.id,
                sandbox_cfg,
            )
            await asyncio.to_thread(DockerManager.assert_running, container_id)
            _set_status(db, run, "TESTING")
            continue

        db.add(test_result)
        db.commit()
        db.refresh(test_result)

        alerts = await asyncio.to_thread(
            FalcoAdapter.collect_alerts, run.id, test_result.test_result_id
        )
        for alert in alerts:
            db.add(alert)
        db.commit()

        detected = len(alerts) > 0
        # Fan-out: one SecurityMatrixEntry per motivating CVE, all sharing this
        # test_result_id, so every detected CVE that mapped to the technique
        # gets its own exploitability row. Proactive/fallback techniques (and
        # techniques whose CVEs were all gated out by EPSS) carry no motivating
        # finding — record a single entry with finding_id=None.
        finding_ids = motivating_finding_ids or [None]
        max_score = 0
        for fid in finding_ids:
            severity = findings_by_id[fid].severity if fid in findings_by_id else None
            score = _compute_risk(test_result.exploited, detected, severity)
            max_score = max(max_score, score)
            db.add(
                SecurityMatrixEntry(
                    run_id=run.id,
                    finding_id=fid,
                    test_result_id=test_result.test_result_id,
                    is_present=True,
                    is_exploitable=test_result.exploited,
                    is_detectable=detected,
                    mitre_tactic_id=test_id,
                    risk_score=score,
                )
            )
        db.commit()

        _push_event(
            run.id,
            {
                "event": "test_complete",
                "test_id": test_id,
                "exploited": test_result.exploited,
                "detected": detected,
                "risk_score": max_score,
                "motivating_cves": len([f for f in finding_ids if f is not None]),
            },
        )


async def _phase_report(run: AssessmentRun, db: Session) -> None:
    _set_status(db, run, "REPORTING")
    _push_event(run.id, {"event": "phase", "phase": "REPORTING"})

    # LLM remediation falls back to RemediationService internally if the API
    # key is missing or the call fails, so this single path covers both modes.
    if LLMRemediationService.is_enabled():
        await asyncio.to_thread(LLMRemediationService.generate_remediations, db, run.id)
    else:
        await asyncio.to_thread(RemediationService.generate_remediations, db, run.id)

    # Run-level executive summary (Gemini call, or templated fallback).
    await asyncio.to_thread(RunSummaryService.generate_summary, db, run.id)

    _set_status(db, run, "COMPLETE")
    _push_event(run.id, {"event": "complete"})
    log_pipeline_event(logger, "assessment_complete", run.id)


def _compute_risk(exploited: bool, detected: bool, severity: Optional[str] = None) -> int:
    """Four-factor risk score.

    base 10 (present) + 30 (exploited) + 10 (undetected) + severity weight
    (critical=20, high=15, medium=10, low=5, unknown/None=0). Capped at
    RISK_SCORE_MAX (75).
    """
    score = 10  # base: vulnerability is present
    if exploited:
        score += 30
    if not detected:
        score += 10  # undetected exploits are highest risk
    if severity:
        score += _SEVERITY_WEIGHT.get(severity.lower(), 0)
    return min(RISK_SCORE_MAX, score)
