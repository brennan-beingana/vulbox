import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List

from app.core.config import settings
from app.core.logging import get_logger
from app.models.art_test_result import ARTTestResult
from app.models.trivy_finding import TrivyFinding

logger = get_logger(__name__)

_DEV_FIXTURE = Path("data/sample_outputs/atomic-fixture.json")

# Known CVE → MITRE technique mappings used to prioritise tests
_CVE_TECHNIQUE_MAP = {
    "CVE-2021-4034": "T1068",   # Polkit privilege escalation
    "CVE-2022-0847": "T1068",   # Dirty Pipe
    "CVE-2019-5736": "T1611",   # Container escape
    "CVE-2020-15257": "T1611",  # Containerd shim escape
}


class ARTAdapter:
    @staticmethod
    def build_queue(trivy_findings: List[TrivyFinding]) -> List[str]:
        """
        Return ordered list of MITRE test IDs.
        CVE-related tests (matching cve_id to known ART technique mappings) sorted first.
        """
        if settings.dev_mode:
            raw = json.loads(_DEV_FIXTURE.read_text())
            all_tests = [t["technique_id"] for t in raw.get("tests", [])]
            # Dedup preserving order
            seen: set = set()
            return [t for t in all_tests if not (t in seen or seen.add(t))]  # type: ignore[func-returns-value]

        priority: List[str] = []
        fallback: List[str] = []
        cve_ids = {f.cve_id for f in trivy_findings}
        for cve, technique in _CVE_TECHNIQUE_MAP.items():
            if cve in cve_ids and technique not in priority:
                priority.append(technique)

        # Add generic techniques
        for technique in ["T1059.004", "T1543.002", "T1611"]:
            if technique not in priority:
                fallback.append(technique)

        return priority + fallback

    @staticmethod
    def execute_test(test_id: str, run_id: int) -> ARTTestResult:
        """
        Execute a single ART test and return an ARTTestResult (not yet persisted).
        In dev mode, reads status from the fixture file.
        """
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
        # Not in fixture — treat as non-exploited
        return ARTTestResult(
            run_id=run_id,
            mitre_test_id=test_id,
            exploited=False,
            crash_occurred=False,
            executed_at=datetime.utcnow(),
        )

    @staticmethod
    def _run_atomic(test_id: str, run_id: int) -> ARTTestResult:
        result = subprocess.run(
            ["bash", "scanners/atomic_runner.sh", test_id],
            capture_output=True,
            text=True,
            timeout=120,
            env={"ATOMIC_CONSENT": "true"},
        )
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
