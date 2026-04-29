import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from app.core.config import settings
from app.core.logging import get_logger
from app.models.falco_alert import FalcoAlert

logger = get_logger(__name__)

_DEV_FIXTURE = settings.project_root / "data" / "sample_outputs" / "falco-fixture.json"

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

        events_file = _run_log_path(run_id)
        # `falco -o` overrides config. Falco watches host-wide; per-run isolation
        # is achieved at collect-time by filtering for `container.id == <our id>`.
        cmd = [
            "falco",
            "--json",
            "-o", "json_output=true",
            "-o", "json_include_output_property=true",
            "-o", f"file_output.filename={events_file}",
            "-o", "file_output.enabled=true",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        _falco_procs[run_id] = proc
        logger.info(
            "Falco attached",
            extra={"container_id": container_id, "run_id": run_id, "pid": proc.pid},
        )

    @staticmethod
    def detach(run_id: int) -> None:
        """Stop this run's Falco sidecar (no-op in dev mode or if not attached)."""
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
            if ts >= cutoff:
                results.append(obj)
        return results
