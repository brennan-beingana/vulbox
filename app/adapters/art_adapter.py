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
from app.services.stack_detector import TechProfile
from app.services.tech_profiles import techniques_for

logger = get_logger(__name__)

_DEV_FIXTURE = settings.project_root / "data" / "sample_outputs" / "atomic-fixture.json"
_CURATED_MAP_PATH = settings.project_root / "data" / "cve_technique_map.yml"
_GENERATED_MAP_PATH = settings.project_root / "data" / "cve_technique_map.generated.yml"
_CWE_BRIDGE_PATH = settings.project_root / "data" / "cwe_technique_map.yml"

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _load_cwe_bridge(path: Path) -> Dict[str, List[str]]:
    """Load the CWE→technique bridge into ``{CWE-XX: [technique, ...]}``.

    This is the scan-time fallback consulted by ``build_queue`` when a finding's
    CVE isn't in the CVE→technique map: bridging the finding's CweIDs keeps the
    CVE in play (provenance ``cwe-bridge``) instead of dropping it. A CWE may map
    to several techniques (distinct rows), so values are ordered lists.
    """
    if not path.is_file():
        logger.warning("CWE bridge missing", extra={"path": str(path)})
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        logger.warning("Invalid CWE bridge", extra={"path": str(path), "err": str(exc)})
        return {}
    bridge: Dict[str, List[str]] = {}
    for entry in data.get("mappings", []) or []:
        cwe = (entry.get("cwe") or "").strip()
        tech = (entry.get("technique") or "").strip()
        if cwe and tech and tech not in bridge.setdefault(cwe, []):
            bridge[cwe].append(tech)
    logger.info("CWE bridge loaded", extra={"cwes": len(bridge)})
    return bridge


def _bridge_techniques(cwe_ids: str) -> List[str]:
    """Map a comma-joined CweIDs string to deduped bridge techniques (order-preserving)."""
    out: List[str] = []
    for cwe in (cwe_ids or "").split(","):
        cwe = cwe.strip()
        if not cwe:
            continue
        for tech in _CWE_TECHNIQUE_MAP.get(cwe, []):
            if tech not in out:
                out.append(tech)
    return out


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
        if entry.get("technology") and "technology" not in m:
            m["technology"] = entry["technology"]
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
_CWE_TECHNIQUE_MAP: Dict[str, List[str]] = _load_cwe_bridge(_CWE_BRIDGE_PATH)


def _passes_epss_gate(finding: TrivyFinding, meta: Dict[str, Any]) -> bool:
    """Whether a motivating CVE earns its own fan-out matrix row.

    With ``VULBOX_EPSS_MIN`` at its default 0.0 the gate is off and every
    motivating CVE passes. When raised, only CVEs whose EPSS score meets the
    threshold are attributed per-CVE — except KEV/ransomware-flagged CVEs,
    which are always included regardless of score.
    """
    threshold = settings.epss_min
    if threshold <= 0.0:
        return True
    if meta.get("kev") or meta.get("ransomware"):
        return True
    return (finding.epss_score or 0.0) >= threshold


def _passes_severity_gate(finding: TrivyFinding, min_severity: Optional[str]) -> bool:
    """Whether a motivating CVE clears the user-selected severity floor.

    ``min_severity`` (from the run's ``min_severity``) caps report size by
    only attributing per-CVE fan-out rows to findings at/above the chosen
    level. ``low``/None disables the gate (everything passes). The technique
    itself still runs regardless — this only governs matrix attribution.
    """
    floor = _SEVERITY_RANK.get((min_severity or "low").lower(), 0)
    # "low"/None/unknown floor → gate off: every finding passes (incl. unknown
    # severity), matching the slider's "test every finding" promise.
    if floor <= _SEVERITY_RANK["low"]:
        return True
    return _SEVERITY_RANK.get((finding.severity or "unknown").lower(), 0) >= floor


def _dedupe_findings_by_cve(findings: List[TrivyFinding]) -> List[int]:
    """Collapse package-level findings to one finding_id per CVE.

    Trivy emits one finding per (CVE × affected package), so a single CVE that
    touches N packages (e.g. CVE-2022-1304 across libc-bin/libc6/e2fsprogs/…)
    produces N near-identical findings. Fanning all of them out gave N duplicate
    SecurityMatrixEntry rows — and N duplicate remediations — with one identical
    exploitability verdict. We keep the highest-severity finding per CVE (severity
    is normally uniform per CVE within an image; highest is the safe choice) and
    preserve first-seen order, which is the caller's priority order.
    """
    best: Dict[str, TrivyFinding] = {}
    order: List[str] = []
    for f in findings:
        cur = best.get(f.cve_id)
        if cur is None:
            best[f.cve_id] = f
            order.append(f.cve_id)
        elif _SEVERITY_RANK.get((f.severity or "unknown").lower(), 0) > _SEVERITY_RANK.get(
            (cur.severity or "unknown").lower(), 0
        ):
            best[f.cve_id] = f
    return [best[c].finding_id for c in order]


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
        tech_profile: Optional[TechProfile] = None,
        min_severity: Optional[str] = None,
    ) -> List[Tuple[str, List[int]]]:
        """Return ordered list of (technique_id, [motivating_finding_id, ...]).

        Each technique runs once; the list of finding_ids is every Trivy
        finding that motivated it (fan-out), so the orchestrator can attribute
        one exploitability row per CVE sharing the test. Proactive/fallback
        techniques carry an empty list (no motivating CVE).

        Priority, highest first:
          1. CVE-driven matches — a technique resolved from a Trivy-confirmed
             CVE, either via the CVE→technique map or, when that misses, by
             bridging the finding's CweIDs. Ranked by stack-relevance,
             ransomware, KEV, then EPSS (higher first).
          2. Stack-aware proactive bucket — techniques relevant to the detected
             stack, queued even with no CVE. Confirmed-present beats inferred.
          3. Heuristic keyword fallbacks — fired by severity/keyword signal.

        tech_profile None/empty → queue degrades to CVE+fallback behavior.
        (Bucket 2 is skipped in dev mode, which replays a fixture.)
        """
        if settings.dev_mode:
            raw = json.loads(_DEV_FIXTURE.read_text())
            seen: set = set()
            queue: List[Tuple[str, List[int]]] = []
            for t in raw.get("tests", []):
                tid = t["technique_id"]
                if tid in seen:
                    continue
                seen.add(tid)
                # Fan-out: every finding whose CVE (or CWE bridge) resolves to
                # this technique and clears the EPSS gate motivates the test.
                # Deduped to one finding per CVE so a CVE spanning many packages
                # doesn't produce duplicate matrix rows.
                matching = [
                    f
                    for f in trivy_findings
                    if tid in ARTAdapter._techniques_for_finding(f)
                    and _passes_severity_gate(f, min_severity)
                    and _passes_epss_gate(f, _CVE_METADATA.get(f.cve_id, {}))
                ]
                queue.append((tid, _dedupe_findings_by_cve(matching)))
            return queue

        priority: List[Tuple[str, List[int]]] = []
        seen_techniques: set = set()

        # Collect CVE-driven matches with priority signals. A finding may yield
        # several techniques (CWE bridge); each (technique, finding) pair is
        # ranked independently, then grouped so each technique runs once with
        # all its motivating findings. Lower rank tuple = higher priority.
        profile_tags = tech_profile.tags() if tech_profile else set()
        records: List[Tuple[tuple, str, TrivyFinding]] = []
        for idx, finding in enumerate(trivy_findings):
            techniques = ARTAdapter._techniques_for_finding(finding)
            if not techniques:
                continue
            meta = _CVE_METADATA.get(finding.cve_id, {})
            if not _passes_severity_gate(finding, min_severity):
                continue
            if not _passes_epss_gate(finding, meta):
                continue
            # A CVE whose tagged technology matches the detected stack is the
            # strongest signal — confirmed-present *and* stack-relevant.
            stack_relevant = bool(profile_tags & set(meta.get("technology") or []))
            rank = (
                0 if stack_relevant else 1,
                0 if meta.get("ransomware") else 1,
                0 if meta.get("kev") else 1,
                -(finding.epss_score or 0.0),  # higher EPSS = tested sooner
                idx,
            )
            for technique in techniques:
                records.append((rank, technique, finding))

        records.sort(key=lambda x: x[0])
        # Group by technique (preserving rank order), then collapse to one
        # finding per CVE so a CVE spanning many packages yields a single row.
        grouped: Dict[str, List[TrivyFinding]] = {}
        for _, technique, finding in records:
            grouped.setdefault(technique, []).append(finding)
        for technique, group_findings in grouped.items():
            priority.append((technique, _dedupe_findings_by_cve(group_findings)))
            seen_techniques.add(technique)

        # Stack-aware proactive bucket — techniques relevant to the detected
        # stack, even when no CVE flagged them. No motivating finding.
        if tech_profile is not None and not tech_profile.is_empty():
            for technique in techniques_for(tech_profile.tags()):
                if technique in seen_techniques:
                    continue
                priority.append((technique, []))
                seen_techniques.add(technique)

        # Heuristic fallbacks — fired by signal, not a fixed list.
        for rule in _FALLBACK_RULES:
            tech = rule["technique"]
            if tech in seen_techniques:
                continue
            if _fallback_matches(rule, trivy_findings):
                priority.append((tech, []))
                seen_techniques.add(tech)

        return priority

    @staticmethod
    def _techniques_for_finding(finding: TrivyFinding) -> List[str]:
        """Resolve a finding to ART techniques.

        The CVE→technique map is authoritative; on a miss, fall back to bridging
        the finding's CweIDs. Returns [] when neither resolves (the finding is
        dropped from the CVE-driven bucket but may still be covered by the
        proactive/fallback buckets).
        """
        technique = _CVE_TECHNIQUE_MAP.get(finding.cve_id)
        if technique:
            return [technique]
        return _bridge_techniques(finding.cwe_ids)

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
