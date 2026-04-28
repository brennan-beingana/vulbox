import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from app.core.config import settings
from app.core.logging import get_logger
from app.models.falco_alert import FalcoAlert

logger = get_logger(__name__)

_DEV_FIXTURE = Path("data/sample_outputs/falco-fixture.json")

_PRIORITY_MAP = {
    "Emergency": "critical",
    "Alert": "critical",
    "Critical": "critical",
    "Error": "high",
    "Warning": "medium",
    "Notice": "low",
    "Informational": "low",
}

_falco_proc: Optional[subprocess.Popen] = None


class FalcoAdapter:
    @staticmethod
    def attach(container_id: str) -> None:
        """Start Falco watching the given container (no-op in dev mode)."""
        if settings.dev_mode:
            logger.info("FalcoAdapter dev mode: skipping attach", extra={"container_id": container_id})
            return
        global _falco_proc
        _falco_proc = subprocess.Popen(
            ["falco", "--cri", "/run/containerd/containerd.sock", "-p", container_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logger.info("Falco attached", extra={"container_id": container_id, "pid": _falco_proc.pid})

    @staticmethod
    def detach() -> None:
        """Stop Falco sidecar process (no-op in dev mode)."""
        global _falco_proc
        if _falco_proc:
            _falco_proc.terminate()
            _falco_proc = None

    @staticmethod
    def collect_alerts(run_id: int, test_result_id: int, window_seconds: int = 30) -> List[FalcoAlert]:
        """
        Collect Falco alerts that fired during a test window.
        In dev mode, reads from fixture and links every alert to test_result_id.
        """
        if settings.dev_mode:
            raw = json.loads(_DEV_FIXTURE.read_text())
            alerts_data = raw.get("alerts", [])
        else:
            alerts_data = FalcoAdapter._read_live_alerts(window_seconds)

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
    def _read_live_alerts(window_seconds: int) -> list:
        """Read Falco JSON output file for alerts from the last window_seconds."""
        falco_log = Path("/var/log/falco/events.json")
        if not falco_log.exists():
            return []
        lines = falco_log.read_text().splitlines()
        cutoff = datetime.utcnow().timestamp() - window_seconds
        results = []
        for line in lines:
            try:
                obj = json.loads(line)
                if obj.get("ts", 0) >= cutoff:
                    results.append(obj)
            except json.JSONDecodeError:
                pass
        return results
