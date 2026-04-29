import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from app.core.config import settings
from app.core.logging import get_logger
from app.models.art_test_result import ARTTestResult
from app.models.trivy_finding import TrivyFinding

logger = get_logger(__name__)

_DEV_FIXTURE = settings.project_root / "data" / "sample_outputs" / "atomic-fixture.json"

# Known CVE → MITRE technique mappings used to prioritise tests.
_CVE_TECHNIQUE_MAP = {
    "CVE-2021-4034": "T1068",   # Polkit privilege escalation
    "CVE-2022-0847": "T1068",   # Dirty Pipe
    "CVE-2019-5736": "T1611",   # Container escape
    "CVE-2020-15257": "T1611",  # Containerd shim escape
    "CVE-2021-44228": "T1059",  # Log4Shell
}

# Generic techniques to run when no CVE-specific matches exist.
_FALLBACK_TECHNIQUES = ["T1059.004", "T1543.002", "T1611"]


class ARTAdapter:
    @staticmethod
    def build_queue(
        trivy_findings: List[TrivyFinding],
    ) -> List[Tuple[str, Optional[int]]]:
        """Return ordered list of (technique_id, motivating_finding_id|None).

        CVE-driven tests appear first and carry the finding_id of the CVE that
        motivated them, so the SecurityMatrixEntry can be correctly correlated
        downstream. Fallback techniques carry None.
        """
        if settings.dev_mode:
            raw = json.loads(_DEV_FIXTURE.read_text())
            seen: set = set()
            queue: List[Tuple[str, Optional[int]]] = []
            # Pair each fixture technique with the first finding (if any) that
            # maps to it via _CVE_TECHNIQUE_MAP — keeps dev mode meaningful.
            cve_to_finding = {f.cve_id: f.finding_id for f in trivy_findings}
            for t in raw.get("tests", []):
                tid = t["technique_id"]
                if tid in seen:
                    continue
                seen.add(tid)
                motivating_fid: Optional[int] = None
                for cve, technique in _CVE_TECHNIQUE_MAP.items():
                    if technique == tid and cve in cve_to_finding:
                        motivating_fid = cve_to_finding[cve]
                        break
                queue.append((tid, motivating_fid))
            return queue

        priority: List[Tuple[str, Optional[int]]] = []
        seen_techniques: set = set()
        for finding in trivy_findings:
            technique = _CVE_TECHNIQUE_MAP.get(finding.cve_id)
            if technique and technique not in seen_techniques:
                priority.append((technique, finding.finding_id))
                seen_techniques.add(technique)

        for technique in _FALLBACK_TECHNIQUES:
            if technique not in seen_techniques:
                priority.append((technique, None))
                seen_techniques.add(technique)

        return priority

    @staticmethod
    def execute_test(test_id: str, run_id: int) -> ARTTestResult:
        """Execute a single ART test and return an ARTTestResult (not yet persisted)."""
        if settings.dev_mode:
            return ARTAdapter._fixture_result(test_id, run_id)
        return ARTAdapter._run_atomic(test_id, run_id)

    @staticmethod
    def _fixture_result(test_id: str, run_id: int) -> ARTTestResult:
        raw = json.loads(_DEV_FIXTURE.read_text())
        for test in raw.get("tests", []):
            if test["technique_id"] == test_id:
                status = test.get("status", "unknown")
                return ARTTestResult(
                    run_id=run_id,
                    mitre_test_id=test_id,
                    exploited=(status == "success"),
                    crash_occurred=False,
                    executed_at=datetime.utcnow(),
                )
        return ARTTestResult(
            run_id=run_id,
            mitre_test_id=test_id,
            exploited=False,
            crash_occurred=False,
            executed_at=datetime.utcnow(),
        )

    @staticmethod
    def _run_atomic(test_id: str, run_id: int) -> ARTTestResult:
        log_path = (
            settings.project_root / "data" / "runs" / str(run_id) / "logs" / f"art-{test_id}.log"
        )
        log_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["bash", "scanners/atomic_runner.sh", test_id],
            capture_output=True,
            text=True,
            timeout=120,
            env={"ATOMIC_CONSENT": "true"},
        )
        try:
            log_path.write_text(
                f"$ atomic_runner.sh {test_id}\n"
                f"--- exit: {result.returncode} ---\n"
                f"--- stdout ---\n{result.stdout}\n"
                f"--- stderr ---\n{result.stderr}\n"
            )
        except Exception:
            logger.exception("Failed to persist ART log", extra={"run_id": run_id})

        exploited = result.returncode == 0
        crash_occurred = result.returncode == 2  # convention: exit 2 = crash
        logger.info(
            "ART test executed",
            extra={"run_id": run_id, "test_id": test_id, "rc": result.returncode},
        )
        return ARTTestResult(
            run_id=run_id,
            mitre_test_id=test_id,
            exploited=exploited,
            crash_occurred=crash_occurred,
            executed_at=datetime.utcnow(),
        )
