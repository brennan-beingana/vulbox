import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from app.core.config import settings
from app.core.logging import get_logger
from app.models.art_test_result import ARTTestResult
from app.models.trivy_finding import TrivyFinding

logger = get_logger(__name__)

_DEV_FIXTURE = settings.project_root / "data" / "sample_outputs" / "atomic-fixture.json"
_TECHNIQUE_MAP_PATH = settings.project_root / "data" / "cve_technique_map.yml"

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _load_technique_map() -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    """Parse data/cve_technique_map.yml into (cve→technique, fallbacks).

    Missing/malformed file falls back to a tiny built-in seed so the adapter
    still produces a sensible queue. Logged at warning level so a misnamed
    file is visible.
    """
    seed_cve: Dict[str, str] = {
        "CVE-2021-4034": "T1068",
        "CVE-2022-0847": "T1068",
        "CVE-2019-5736": "T1611",
        "CVE-2020-15257": "T1611",
        "CVE-2021-44228": "T1059",
    }
    seed_fb: List[Dict[str, Any]] = [
        {"technique": "T1082", "match": {"always": True}},
        {"technique": "T1059.004", "match": {"always": True}},
        {"technique": "T1543.002", "match": {"always": True}},
        {"technique": "T1611", "match": {"always": True}},
    ]
    if not _TECHNIQUE_MAP_PATH.is_file():
        logger.warning("CVE map not found; using built-in seed", extra={"path": str(_TECHNIQUE_MAP_PATH)})
        return seed_cve, seed_fb
    try:
        data = yaml.safe_load(_TECHNIQUE_MAP_PATH.read_text()) or {}
    except yaml.YAMLError as exc:
        logger.warning("Invalid cve_technique_map.yml; using seed", extra={"err": str(exc)})
        return seed_cve, seed_fb

    cve_map: Dict[str, str] = {}
    for entry in data.get("mappings", []) or []:
        cve = entry.get("cve")
        tech = entry.get("technique")
        if cve and tech:
            cve_map[cve] = tech
    fallbacks = [fb for fb in (data.get("fallbacks", []) or []) if fb.get("technique")]
    if not cve_map and not fallbacks:
        logger.warning("Empty CVE map; using seed")
        return seed_cve, seed_fb
    return cve_map, fallbacks


_CVE_TECHNIQUE_MAP, _FALLBACK_RULES = _load_technique_map()


def _fallback_matches(rule: Dict[str, Any], findings: List[TrivyFinding]) -> bool:
    """Return True if the rule's match preconditions are satisfied by findings."""
    match = rule.get("match") or {}
    if match.get("always"):
        return True

    sev_min = match.get("severity_min")
    if sev_min:
        threshold = _SEVERITY_RANK.get(str(sev_min).lower(), 0)
        if not any(_SEVERITY_RANK.get((f.severity or "").lower(), 0) >= threshold for f in findings):
            return False

    keywords = [k.lower() for k in (match.get("keywords") or [])]
    if keywords:
        haystack = " ".join(
            f"{(f.package_name or '').lower()} {(f.description or '').lower()}" for f in findings
        )
        if not any(k in haystack for k in keywords):
            return False

    return True


class ARTAdapter:
    @staticmethod
    def build_queue(
        trivy_findings: List[TrivyFinding],
    ) -> List[Tuple[str, Optional[int]]]:
        """Return ordered list of (technique_id, motivating_finding_id|None).

        CVE-driven tests appear first and carry the finding_id of the CVE that
        motivated them. Heuristic fallbacks then fill the queue based on what
        the Trivy findings actually look like (severity profile + package
        keywords), so two images with different vulnerability profiles get
        different test queues.
        """
        if settings.dev_mode:
            raw = json.loads(_DEV_FIXTURE.read_text())
            seen: set = set()
            queue: List[Tuple[str, Optional[int]]] = []
            cve_to_finding = {f.cve_id: f.finding_id for f in trivy_findings}
            for t in raw.get("tests", []):
                tid = t["technique_id"]
                if tid in seen:
                    continue
                seen.add(tid)
                motivating_fid: Optional[int] = None
                technique_for_cve = _CVE_TECHNIQUE_MAP
                for cve, technique in technique_for_cve.items():
                    if technique == tid and cve in cve_to_finding:
                        motivating_fid = cve_to_finding[cve]
                        break
                queue.append((tid, motivating_fid))
            return queue

        priority: List[Tuple[str, Optional[int]]] = []
        seen_techniques: set = set()

        # CVE-driven tests first.
        for finding in trivy_findings:
            technique = _CVE_TECHNIQUE_MAP.get(finding.cve_id)
            if technique and technique not in seen_techniques:
                priority.append((technique, finding.finding_id))
                seen_techniques.add(technique)

        # Heuristic fallbacks — fired by signal, not a fixed list.
        for rule in _FALLBACK_RULES:
            tech = rule["technique"]
            if tech in seen_techniques:
                continue
            if _fallback_matches(rule, trivy_findings):
                priority.append((tech, None))
                seen_techniques.add(tech)

        return priority

    @staticmethod
    def execute_test(
        test_id: str, run_id: int, container_id: Optional[str] = None
    ) -> ARTTestResult:
        """Execute a single ART test and return an ARTTestResult (not yet persisted).

        ``container_id`` is the live sandbox to exec into. Optional for back-compat
        and dev mode (which reads fixtures and never spawns a container).
        """
        if settings.dev_mode:
            return ARTAdapter._fixture_result(test_id, run_id)
        return ARTAdapter._run_atomic(test_id, run_id, container_id)

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
    def _run_atomic(
        test_id: str, run_id: int, container_id: Optional[str] = None
    ) -> ARTTestResult:
        log_path = (
            settings.project_root / "data" / "runs" / str(run_id) / "logs" / f"art-{test_id}.log"
        )
        log_path.parent.mkdir(parents=True, exist_ok=True)

        runner = settings.project_root / "scanners" / "atomic_runner.sh"
        env = {
            "ATOMIC_CONSENT": "true",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
        if container_id:
            env["VULBOX_SANDBOX_CONTAINER"] = container_id

        result = subprocess.run(
            ["bash", str(runner), test_id],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
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
