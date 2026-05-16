import json
import subprocess
import sys
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
_CURATED_MAP_PATH = settings.project_root / "data" / "cve_technique_map.yml"
_GENERATED_MAP_PATH = settings.project_root / "data" / "cve_technique_map.generated.yml"

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _ingest_mappings(
    path: Path,
    into: Dict[str, str],
    meta: Dict[str, Dict[str, Any]],
    *,
    override: bool,
) -> int:
    """Load mappings from ``path`` into the ``into`` and ``meta`` dicts.

    ``into`` is the CVE→technique lookup the queue builder consults. ``meta``
    carries side-channel flags (``kev``, ``ransomware``, ``provenance``) used
    by ``build_queue`` to prioritize actively-exploited vulnerabilities ahead
    of the long tail.

    If ``override`` is False, the first technique seen for a CVE wins (within
    a file, the build script orders entries so the primary impact appears
    first). If True, later entries overwrite — used for the curated layer to
    beat the generated bulk on conflict.
    """
    if not path.is_file():
        return 0
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        logger.warning("Invalid CVE map", extra={"path": str(path), "err": str(exc)})
        return 0
    added = 0
    for entry in data.get("mappings", []) or []:
        cve = entry.get("cve")
        tech = entry.get("technique")
        if not (cve and tech):
            continue
        if override or cve not in into:
            into[cve] = tech
            added += 1
        # Metadata flags merge regardless of override — they're additive
        # (KEV-true never goes false on the same CVE).
        m = meta.setdefault(cve, {})
        if entry.get("kev"):
            m["kev"] = True
        if entry.get("ransomware"):
            m["ransomware"] = True
        if entry.get("provenance") and "provenance" not in m:
            m["provenance"] = entry["provenance"]
    return added


def _load_technique_map() -> Tuple[
    Dict[str, str], Dict[str, Dict[str, Any]], List[Dict[str, Any]]
]:
    """Merge generated + curated maps and side-channel CVE metadata.

    Resolution order:
      1. ``cve_technique_map.generated.yml`` — bulk auto-generated layer.
      2. ``cve_technique_map.yml`` — curated layer; wins on conflict and
         additionally supplies the heuristic fallback rules.

    Returns (cve→technique, cve→metadata, fallbacks). Metadata carries
    ``kev`` and ``ransomware`` flags consumed by ``build_queue`` for
    priority ordering. If both files are missing/empty, a built-in seed
    keeps the adapter usable so failed deploys don't blank out the queue.
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

    cve_map: Dict[str, str] = {}
    cve_meta: Dict[str, Dict[str, Any]] = {}
    gen_count = _ingest_mappings(
        _GENERATED_MAP_PATH, cve_map, cve_meta, override=False
    )
    cur_count = _ingest_mappings(
        _CURATED_MAP_PATH, cve_map, cve_meta, override=True
    )

    fallbacks: List[Dict[str, Any]] = []
    if _CURATED_MAP_PATH.is_file():
        try:
            data = yaml.safe_load(_CURATED_MAP_PATH.read_text()) or {}
            fallbacks = [
                fb for fb in (data.get("fallbacks", []) or []) if fb.get("technique")
            ]
        except yaml.YAMLError:
            pass  # already logged in _ingest_mappings

    if not cve_map and not fallbacks:
        logger.warning("No CVE map data; using built-in seed")
        return seed_cve, {}, seed_fb

    kev_count = sum(1 for m in cve_meta.values() if m.get("kev"))
    ransomware_count = sum(1 for m in cve_meta.values() if m.get("ransomware"))
    logger.info(
        "CVE map loaded",
        extra={
            "generated_entries": gen_count,
            "curated_entries": cur_count,
            "total_cves": len(cve_map),
            "kev_flagged": kev_count,
            "ransomware_flagged": ransomware_count,
            "fallbacks": len(fallbacks),
        },
    )
    return cve_map, cve_meta, fallbacks


_CVE_TECHNIQUE_MAP, _CVE_METADATA, _FALLBACK_RULES = _load_technique_map()


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

        # Collect CVE-driven matches with priority signals, then emit in order:
        # ransomware-linked first, then KEV-listed, then everything else.
        # Stable sort within each bucket preserves the order findings arrived.
        cve_driven: List[Tuple[int, str, Optional[int]]] = []
        for idx, finding in enumerate(trivy_findings):
            technique = _CVE_TECHNIQUE_MAP.get(finding.cve_id)
            if not technique:
                continue
            meta = _CVE_METADATA.get(finding.cve_id, {})
            # Lower tuple = higher priority.
            rank = (
                0 if meta.get("ransomware") else 1,
                0 if meta.get("kev") else 1,
                idx,
            )
            cve_driven.append((rank, technique, finding.finding_id))

        cve_driven.sort(key=lambda x: x[0])
        for _, technique, fid in cve_driven:
            if technique in seen_techniques:
                continue
            priority.append((technique, fid))
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

        # Python runner first — covers the vendored ART catalog, and falls
        # through to scanners/atomic_runner.sh for techniques the catalog
        # can't serve (container-escape, systemd-write, etc.).
        runner = settings.project_root / "scanners" / "atomic_runner.py"
        env = {
            "ATOMIC_CONSENT": "true",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONPATH": str(settings.project_root),
        }
        if container_id:
            env["VULBOX_SANDBOX_CONTAINER"] = container_id

        result = subprocess.run(
            [sys.executable, str(runner), test_id],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        try:
            log_path.write_text(
                f"$ atomic_runner.py {test_id}\n"
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
