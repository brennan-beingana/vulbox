import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from app.core.config import settings
from app.core.logging import get_logger
from app.models.falco_alert import FalcoAlert

logger = get_logger(__name__)

_DEV_FIXTURE = settings.project_root / "data" / "sample_outputs" / "falco-fixture.json"


def _falco_enabled() -> bool:
    # Opt-out toggle so production-mode runs on hosts without Falco (CI runners,
    # dev laptops without kernel-module access) still complete instead of
    # crashing in attach(). is_detectable becomes uniformly False on those
    # runs — the Security Matrix still has signal from Trivy + ART.
    return os.getenv("VULBOX_FALCO_ENABLED", "true").lower() == "true"

_PRIORITY_MAP = {
    "Emergency": "critical",
    "Alert": "critical",
    "Critical": "critical",
    "Error": "high",
    "Warning": "medium",
    "Notice": "low",
    "Informational": "low",
}

# Per-run Falco subprocesses, keyed by run_id, so concurrent runs don't collide.
_falco_procs: Dict[int, subprocess.Popen] = {}
# Per-run sandbox container id, so collect_alerts can attribute host-wide Falco
# events to the container under test (see _read_live_alerts).
_falco_containers: Dict[int, str] = {}

# Seconds to wait after launch before confirming Falco is still alive. Falco
# needs a moment to load its driver + rules; if it has exited by then it never
# captured a syscall and detection for this run is silently dead.
_FALCO_STARTUP_SETTLE_SECS = 2.0


def _run_log_path(run_id: int) -> Path:
    p = settings.project_root / "data" / "runs" / str(run_id) / "falco.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


class FalcoAdapter:
    @staticmethod
    def attach(container_id: str, run_id: int) -> None:
        """Start a per-run Falco that writes JSON events to data/runs/{id}/falco.json.

        No-op in dev mode.
        """
        if settings.dev_mode:
            logger.info(
                "FalcoAdapter dev mode: skipping attach",
                extra={"container_id": container_id, "run_id": run_id},
            )
            return

        if not _falco_enabled():
            logger.info(
                "FalcoAdapter disabled via VULBOX_FALCO_ENABLED=false; skipping attach",
                extra={"container_id": container_id, "run_id": run_id},
            )
            return

        events_file = _run_log_path(run_id)
        stderr_path = events_file.parent / "falco.stderr.log"
        # JSON output is enabled purely via `-o json_output=true`; Falco has no
        # `--json` flag and exits non-zero ("Option 'json' does not exist") if one
        # is passed, before it ever opens the output file. `falco -o` overrides
        # config. Falco watches host-wide; per-run isolation is achieved at
        # collect-time by filtering for the sandbox container.id.
        cmd = [
            "falco",
            "-o", "json_output=true",
            "-o", "json_include_output_property=true",
            "-o", f"file_output.filename={events_file}",
            "-o", "file_output.enabled=true",
        ]
        # Stderr → file, not PIPE: Falco logs continuously, and an unread PIPE
        # buffer fills and deadlocks the process. The file also captures the
        # reason on an early exit.
        stderr_f = open(stderr_path, "wb")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=stderr_f)
        finally:
            stderr_f.close()  # child has its own dup of the fd

        # Confirm Falco survived startup. A dead process here means it captured
        # nothing, so every finding would silently read as undetectable — log
        # that loudly rather than completing the run with a blank detection
        # dimension (the symptom we were debugging).
        import time
        time.sleep(_FALCO_STARTUP_SETTLE_SECS)
        if proc.poll() is not None:
            try:
                err_tail = stderr_path.read_text()[-1000:]
            except Exception:
                err_tail = "<stderr unavailable>"
            logger.error(
                "Falco exited at startup; detection disabled for this run",
                extra={"run_id": run_id, "exit_code": proc.returncode, "stderr": err_tail},
            )
            return

        _falco_procs[run_id] = proc
        _falco_containers[run_id] = container_id
        logger.info(
            "Falco attached",
            extra={"container_id": container_id, "run_id": run_id, "pid": proc.pid},
        )

    @staticmethod
    def detach(run_id: int) -> None:
        """Stop this run's Falco sidecar (no-op in dev mode or if not attached)."""
        _falco_containers.pop(run_id, None)
        proc: Optional[subprocess.Popen] = _falco_procs.pop(run_id, None)
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            logger.exception("Falco detach error", extra={"run_id": run_id})

    @staticmethod
    def collect_alerts(
        run_id: int, test_result_id: int, window_seconds: int = 30
    ) -> List[FalcoAlert]:
        """Collect Falco alerts that fired during a test window.

        Dev mode: read from fixture, link every alert to test_result_id.
        Production: read this run's JSON file, take entries within the last
        window_seconds.
        """
        if settings.dev_mode:
            raw = json.loads(_DEV_FIXTURE.read_text())
            alerts_data = raw.get("alerts", [])
        elif not _falco_enabled():
            alerts_data = []
        else:
            alerts_data = FalcoAdapter._read_live_alerts(run_id, window_seconds)

        alerts: List[FalcoAlert] = []
        for item in alerts_data:
            alerts.append(
                FalcoAlert(
                    run_id=run_id,
                    test_result_id=test_result_id,
                    rule_triggered=item.get("rule", "unknown"),
                    severity=_PRIORITY_MAP.get(item.get("priority", ""), "medium"),
                    syscall_context=str(item.get("output", ""))[:500],
                    timestamp=datetime.utcnow(),
                    detected=True,
                )
            )
        return alerts

    @staticmethod
    def _read_live_alerts(run_id: int, window_seconds: int) -> list:
        falco_log = _run_log_path(run_id)
        if not falco_log.exists():
            return []
        cutoff = datetime.utcnow().timestamp() - window_seconds
        our_cid = _falco_containers.get(run_id)
        results = []
        for line in falco_log.read_text().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = obj.get("ts") or obj.get("time") or 0
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    ts = 0
            if ts < cutoff:
                continue
            # Falco runs host-wide; attribute only events from the sandbox under
            # test. Match by container.id prefix because Falco reports the short
            # 12-char id while `docker run` hands us the full 64-char one. Events
            # with no container.id (host-scope rules) can't be attributed, so we
            # keep them rather than silently dropping a real detection.
            if our_cid:
                event_cid = (obj.get("output_fields") or {}).get("container.id")
                if event_cid and not (
                    our_cid.startswith(event_cid) or event_cid.startswith(our_cid)
                ):
                    continue
            results.append(obj)
        return results
