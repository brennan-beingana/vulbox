import json
import os
import re
import subprocess
from datetime import datetime, timezone
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

# Seconds to wait after launch before confirming Falco is still alive AND before
# the first ART test runs. Falco needs several seconds to compile+load its BPF
# driver; until then it captures no syscalls, so a test that fires too early is
# invisible. Sleeping here serves double duty: it lets the driver come up before
# the orchestrator starts the test loop, and if Falco has instead exited (e.g. a
# rules parse error) poll() catches it and detection is reported dead loudly
# rather than silently reading every finding as undetectable.
_FALCO_STARTUP_SETTLE_SECS = 6.0

# Bundled VulBox rules tuned to the exact syscalls scanners/atomic_runner.sh
# produces. The stock ruleset did not fire on the docker-exec'd ART activity
# (no container metadata attached → container-scoped rules never matched), so
# Falco wrote no output file at all. These guarantee a match on the techniques
# we actually run. See the file header for the design rationale.
_VULBOX_RULES = settings.project_root / "deploy" / "falco" / "vulbox_rules.yaml"

# Stock Falco rules locations, probed in order. Loading these explicitly keeps
# the default coverage when we override rules_files on the command line with -r.
_STOCK_RULES_CANDIDATES = (
    "/etc/falco/falco_rules.yaml",
    "/etc/falco/falco_rules.local.yaml",
    "/etc/falco/rules.d",
)


def _rules_args() -> List[str]:
    """Build the `-r <path>` arguments: stock rules (whichever exist) + ours.

    Passing `-r` on the command line overrides the `rules_files` list in
    falco.yaml, so we re-add the stock paths to preserve default coverage and
    then append the bundled VulBox rules. If no stock rules are present we still
    load ours, so VulBox detection works on a host with a bare Falco install.
    """
    args: List[str] = []
    for path in _STOCK_RULES_CANDIDATES:
        if os.path.exists(path):
            args += ["-r", path]
    if _VULBOX_RULES.exists():
        args += ["-r", str(_VULBOX_RULES)]
    else:
        logger.warning(
            "VulBox Falco rules file missing; relying on stock rules only",
            extra={"expected_path": str(_VULBOX_RULES)},
        )
    return args


def _run_log_path(run_id: int) -> Path:
    p = settings.project_root / "data" / "runs" / str(run_id) / "falco.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _event_epoch(obj: dict) -> Optional[float]:
    """Best-effort epoch-seconds for a Falco event.

    Falco emits `time` as an ISO string with **nanosecond** precision
    (9 fractional digits). `datetime.fromisoformat` on Python < 3.11 rejects
    more than 6 fractional digits, so on the 3.10 deploy host every event
    raised ValueError and was treated as ts=0 — i.e. "infinitely old" — which
    silently filtered out the entire detection dimension. We therefore prefer
    the unambiguous integer nanosecond epoch (`output_fields["evt.time"]`) and
    only fall back to parsing the string (with the fraction trimmed to 6 digits).
    Returns None when no timestamp can be recovered — callers must NOT treat
    that as old (that was the original trap).
    """
    nanos = (obj.get("output_fields") or {}).get("evt.time")
    if isinstance(nanos, (int, float)):
        return nanos / 1e9

    raw = obj.get("ts") or obj.get("time")
    if isinstance(raw, (int, float)):
        # Some builds put a nanosecond epoch in top-level "ts".
        return raw / 1e9 if raw > 1e12 else float(raw)
    if isinstance(raw, str):
        s = raw.replace("Z", "+00:00")
        # Trim fractional seconds to 6 digits for fromisoformat on Python 3.10.
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)
        try:
            return datetime.fromisoformat(s).timestamp()
        except ValueError:
            return None
    return None


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
        # Load stock rules (if present) plus the bundled VulBox rules so a match
        # is guaranteed on the ART techniques we run — otherwise file_output
        # never creates falco.json and detection is silently empty.
        cmd += _rules_args()
        # Stderr → file, not PIPE: Falco logs continuously, and an unread PIPE
        # buffer fills and deadlocks the process. The file also captures the
        # reason on an early exit.
        stderr_f = open(stderr_path, "wb")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=stderr_f)
        finally:
            stderr_f.close()  # child has its own dup of the fd

        # Wait out the driver-load window, then confirm Falco survived startup.
        # A dead process here means it captured nothing (e.g. a rules parse
        # error), so every finding would silently read as undetectable — log that
        # loudly rather than completing the run with a blank detection dimension
        # (the symptom we were debugging).
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
        # Timezone-aware UTC: datetime.utcnow().timestamp() interprets the naive
        # value as *local* time, skewing the window on non-UTC hosts.
        cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
        our_cid = _falco_containers.get(run_id)
        results = []
        for line in falco_log.read_text().splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = _event_epoch(obj)
            # Only exclude on time when we actually have a timestamp; an
            # unparseable one must not silently drop a real detection (the bug
            # that zeroed the whole detection dimension on the 3.10 host).
            if ts is not None and ts < cutoff:
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
