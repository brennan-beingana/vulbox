#!/usr/bin/env python3
"""Sprint 6 — Layer 2 ground-truth validation harness.

Pulls/builds each image in ``tests/ground_truth/manifest.yml``, runs the
static-analysis half of the pipeline against it (Trivy + ARTAdapter.build_queue),
compares results against the manifest's expectations, and writes a markdown
report to ``docs/validation_report.md``.

Beyond raw finding/queue counts, the harness now reports the exploitability-
coverage signals introduced with CWE bridging + EPSS:
  * **coverage** — distinct detected CVEs that reach a tested technique
    (``tested / detected``), the headline "more detected CVEs get a verdict".
  * **provenance** — of the tested CVEs, how many resolved via the direct
    CVE→technique map vs. the coarser CWE bridge.
  * **EPSS** — how many findings carry an EPSS score and the max, so the
    ranking/gating inputs are visible per image.

Requires Docker daemon access and the ``trivy`` CLI on PATH.

Usage::

    # Smoke check + report (no Falco, no sandbox spawn — just trivy & queue)
    python scripts/validate_e2e.py

    # Use a custom corpus
    python scripts/validate_e2e.py --corpus path/to/manifest.yml

    # Only re-generate the report from the most recent run
    python scripts/validate_e2e.py --report-only

The harness intentionally stops short of executing ART tests against a live
sandbox — that adds significant flake (image-build failures, network
quirks, Falco lifecycle) and is better triggered manually via
``scripts/demo.py``. The static-analysis side is what most validation
questions hinge on, and it's the part that runs deterministically in CI.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Force production mode so adapters call real Trivy, not the fixture.
os.environ.setdefault("VULBOX_DEV_MODE", "false")

from app.adapters import art_adapter as ART  # noqa: E402
from app.adapters.trivy_adapter import TrivyAdapter  # noqa: E402
from app.models.trivy_finding import TrivyFinding  # noqa: E402

DEFAULT_MANIFEST = PROJECT_ROOT / "tests" / "ground_truth" / "manifest.yml"
DEFAULT_REPORT = PROJECT_ROOT / "docs" / "validation_report.md"
RESULTS_PATH = PROJECT_ROOT / "data" / "validation" / "results.json"


@dataclass
class CaseResult:
    name: str
    image: str
    description: str
    source: str
    pulled: bool = False
    error: Optional[str] = None
    findings_total: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    queue: List[str] = field(default_factory=list)
    queue_kev_count: int = 0
    # Exploitability-coverage signals (CWE bridge + EPSS).
    detected_cves: int = 0
    tested_cves: int = 0
    cve_map_matches: int = 0      # tested CVEs resolved via the CVE→technique map
    cwe_bridge_matches: int = 0   # tested CVEs resolved only via the CWE bridge
    epss_scored: int = 0          # findings carrying an EPSS score
    epss_max: float = 0.0
    cves: List[str] = field(default_factory=list)  # distinct detected CVE ids
    expectations_pass: List[str] = field(default_factory=list)
    expectations_fail: List[str] = field(default_factory=list)
    duration_secs: float = 0.0

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        if self.expectations_fail:
            return "FAIL"
        return "PASS"


def _bin_present(name: str) -> bool:
    return shutil.which(name) is not None


def _materialize_image(case: dict) -> None:
    source = case.get("source", "registry")
    if source == "registry":
        subprocess.run(
            ["docker", "pull", case["image"]], check=True, capture_output=True, text=True
        )
    elif source == "dockerfile":
        dockerfile = PROJECT_ROOT / case["dockerfile_path"]
        if not dockerfile.is_file():
            raise FileNotFoundError(f"missing dockerfile: {dockerfile}")
        subprocess.run(
            ["docker", "build", "-t", case["image"], "-f", str(dockerfile), str(dockerfile.parent)],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        raise ValueError(f"unknown source: {source!r}")


def _coverage_signals(findings: List[TrivyFinding], queue: list) -> Dict[str, Any]:
    """Derive exploitability-coverage signals from findings + the built queue.

    ``queue`` is ``ARTAdapter.build_queue`` output: ``[(technique, [fid, ...])]``.
    A CVE is "tested" if any of its findings landed in a technique's fan-out
    list. Provenance splits tested CVEs into CVE-map (direct) vs CWE-bridge
    (fallback) — the bridge is the coverage lever, so seeing its share matters.
    """
    by_id = {f.finding_id: f for f in findings}
    tested_fids: set = set()
    for _technique, fids in queue:
        tested_fids.update(fids)
    tested_cves = {by_id[fid].cve_id for fid in tested_fids if fid in by_id}
    detected_cves = {f.cve_id for f in findings}
    cve_map_matches = sum(1 for c in tested_cves if c in ART._CVE_TECHNIQUE_MAP)
    scored = [f.epss_score for f in findings if f.epss_score is not None]
    return {
        "detected_cves": len(detected_cves),
        "tested_cves": len(tested_cves),
        "cve_map_matches": cve_map_matches,
        "cwe_bridge_matches": len(tested_cves) - cve_map_matches,
        "epss_scored": len(scored),
        "epss_max": round(max(scored), 5) if scored else 0.0,
        "cves": sorted(detected_cves),
    }


def _evaluate_case(case: dict) -> CaseResult:
    name = case["name"]
    image = case["image"]
    desc = (case.get("description") or "").strip()
    source = case.get("source", "registry")
    result = CaseResult(name=name, image=image, description=desc, source=source)
    started = time.time()

    try:
        _materialize_image(case)
        result.pulled = True

        findings: List[TrivyFinding] = TrivyAdapter.scan(image, run_id=0)
        result.findings_total = len(findings)
        for f in findings:
            sev = (f.severity or "unknown").lower()
            result.findings_by_severity[sev] = result.findings_by_severity.get(sev, 0) + 1

        # Scanned findings aren't persisted here, so finding_id is None for all
        # of them — assign synthetic ids so build_queue's per-CVE fan-out (and
        # the coverage signals derived from it) attribute correctly.
        for idx, f in enumerate(findings):
            f.finding_id = idx

        queue = ART.ARTAdapter.build_queue(findings)
        result.queue = [tid for tid, _ in queue]
        result.queue_kev_count = sum(
            1
            for f in findings
            if ART._CVE_METADATA.get(f.cve_id, {}).get("kev")
        )

        sig = _coverage_signals(findings, queue)
        result.detected_cves = sig["detected_cves"]
        result.tested_cves = sig["tested_cves"]
        result.cve_map_matches = sig["cve_map_matches"]
        result.cwe_bridge_matches = sig["cwe_bridge_matches"]
        result.epss_scored = sig["epss_scored"]
        result.epss_max = sig["epss_max"]
        result.cves = sig["cves"]

        _check_expectations(result, case.get("expectations") or {})
    except subprocess.CalledProcessError as exc:
        result.error = f"docker error: {exc.stderr[:500] if exc.stderr else exc}"
    except Exception as exc:  # noqa: BLE001 — surface everything
        result.error = f"{type(exc).__name__}: {exc}"

    result.duration_secs = round(time.time() - started, 2)
    return result


def _check_expectations(result: CaseResult, exps: dict) -> None:
    findings = exps.get("findings") or {}
    if "min_total" in findings:
        v = findings["min_total"]
        if result.findings_total >= v:
            result.expectations_pass.append(f"findings >= {v} ({result.findings_total})")
        else:
            result.expectations_fail.append(
                f"findings >= {v} expected; got {result.findings_total}"
            )
    if "max_total" in findings:
        v = findings["max_total"]
        if result.findings_total <= v:
            result.expectations_pass.append(f"findings <= {v} ({result.findings_total})")
        else:
            result.expectations_fail.append(
                f"findings <= {v} expected; got {result.findings_total}"
            )
    if "min_critical" in findings:
        v = findings["min_critical"]
        got = result.findings_by_severity.get("critical", 0)
        (result.expectations_pass if got >= v else result.expectations_fail).append(
            f"critical >= {v}; got {got}"
        )
    if "must_contain_cve" in findings:
        cve_set = set(result.cves)
        for cve in findings["must_contain_cve"]:
            (result.expectations_pass if cve in cve_set else result.expectations_fail).append(
                f"findings must contain {cve}"
            )

    # ---- coverage expectations (CWE bridge + EPSS lift) ----
    coverage = exps.get("coverage") or {}
    if "min_ratio" in coverage and result.detected_cves:
        ratio = result.tested_cves / result.detected_cves
        v = coverage["min_ratio"]
        (result.expectations_pass if ratio >= v else result.expectations_fail).append(
            f"coverage ratio >= {v} ({ratio:.2f}: {result.tested_cves}/{result.detected_cves})"
        )
    if "min_tested" in coverage:
        v = coverage["min_tested"]
        (result.expectations_pass if result.tested_cves >= v else result.expectations_fail).append(
            f"tested CVEs >= {v} ({result.tested_cves})"
        )
    if "min_bridge" in coverage:
        v = coverage["min_bridge"]
        (result.expectations_pass if result.cwe_bridge_matches >= v else result.expectations_fail).append(
            f"CWE-bridge-tested CVEs >= {v} ({result.cwe_bridge_matches})"
        )

    queue = exps.get("queue") or {}
    qset = set(result.queue)
    for tid in queue.get("must_include", []):
        (result.expectations_pass if tid in qset else result.expectations_fail).append(
            f"queue must include {tid}"
        )
    for tid in queue.get("must_not_include", []):
        (result.expectations_fail if tid in qset else result.expectations_pass).append(
            f"queue must NOT include {tid}"
        )


def _check_prereqs() -> List[str]:
    missing: List[str] = []
    if not _bin_present("docker"):
        missing.append("docker")
    if not _bin_present("trivy"):
        missing.append("trivy")
    if _bin_present("docker"):
        probe = subprocess.run(
            ["docker", "info"], capture_output=True, text=True
        )
        if probe.returncode != 0:
            missing.append("docker daemon (CLI present, daemon unreachable)")
    return missing


def _load_results() -> Optional[dict]:
    if not RESULTS_PATH.is_file():
        return None
    try:
        return json.loads(RESULTS_PATH.read_text())
    except json.JSONDecodeError:
        return None


def _persist_results(results: List[CaseResult]) -> None:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "cases": [asdict(r) for r in results],
            },
            indent=2,
        )
    )


def _write_report(results_payload: Optional[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    parts: List[str] = []
    parts.append("# VulBox Validation Report")
    parts.append("")
    parts.append(f"_Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}_")
    parts.append("")

    # ---- Static-coverage section (always present) ------------------------
    parts.append("## Static coverage")
    parts.append("")
    parts.append(_static_table())
    parts.append("")

    # ---- Catalog summary -------------------------------------------------
    parts.append("## Catalog (Atomic Red Team)")
    parts.append("")
    parts.append(_catalog_summary())
    parts.append("")

    # ---- E2E results -----------------------------------------------------
    parts.append("## Ground-truth E2E corpus")
    parts.append("")
    if not results_payload:
        parts.append(
            "_No results yet. Run `python scripts/validate_e2e.py` on a host "
            "with Docker + Trivy to populate this section._"
        )
        parts.append("")
    else:
        parts.append(f"_Last run: {results_payload['generated_at']}_")
        parts.append("")
        parts.append(_e2e_table(results_payload["cases"]))
        parts.append("")
        parts.append("### Case detail")
        parts.append("")
        for case in results_payload["cases"]:
            parts.append(_case_block(case))
            parts.append("")

    out_path.write_text("\n".join(parts) + "\n")


def _static_table() -> str:
    curated = yaml.safe_load((PROJECT_ROOT / "data/cve_technique_map.yml").read_text()) or {}
    generated = yaml.safe_load(
        (PROJECT_ROOT / "data/cve_technique_map.generated.yml").read_text()
    ) or {}
    cwe_bridge = yaml.safe_load(
        (PROJECT_ROOT / "data/cwe_technique_map.yml").read_text()
    ) or {}
    cur_maps = [m for m in (curated.get("mappings") or []) if m.get("technique")]
    gen_maps = [m for m in (generated.get("mappings") or []) if m.get("technique")]
    return "\n".join(
        [
            "| Layer | Entries | Notes |",
            "|---|---:|---|",
            f"| Curated CVE→technique | {len(cur_maps)} | hand-picked, wins on conflict |",
            f"| Generated CVE→technique | {len(gen_maps)} | from attack_to_cve + KEV+CWE bridge |",
            f"| CWE→technique bridge | {len(cwe_bridge.get('mappings') or [])} | curated; expands KEV coverage |",
            f"| Total unique CVEs in map | {len(ART._CVE_TECHNIQUE_MAP)} | after merge |",
            f"| KEV-flagged CVEs in map | {sum(1 for m in ART._CVE_METADATA.values() if m.get('kev'))} | priority-ordered in build_queue |",
            f"| Fallback rules | {len(ART._FALLBACK_RULES)} | signal-driven, image-shape aware |",
        ]
    )


def _catalog_summary() -> str:
    from scanners.atomic_catalog import CATALOG

    tids = CATALOG.technique_ids()
    total = sum(len(CATALOG.get_tests(t)) for t in tids)
    rows = ["| Technique | Linux tests | Default test |", "|---|---:|---|"]
    for tid in tids:
        tests = CATALOG.get_tests(tid)
        sh = [t for t in tests if t.executor == "sh"]
        pick = sh[0] if sh else tests[0]
        rows.append(f"| {tid} | {len(tests)} | {pick.name[:60]} |")
    return (
        f"Source SHA: `{CATALOG.source_sha}`\n\n"
        f"{len(tids)} techniques, {total} Linux atomic tests vendored.\n\n"
        + "\n".join(rows)
    )


def _e2e_table(cases: List[dict]) -> str:
    rows = ["| Case | Image | Status | Findings | Coverage (tested/detected) | via CWE-bridge | EPSS max | Queue | Time |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|"]
    for c in cases:
        status = "PASS" if not c["expectations_fail"] and not c["error"] else (
            "ERROR" if c["error"] else "FAIL"
        )
        det = c.get("detected_cves", 0)
        tested = c.get("tested_cves", 0)
        cov = f"{tested}/{det}" + (f" ({tested / det:.0%})" if det else "")
        rows.append(
            f"| {c['name']} | `{c['image']}` | {status} | {c['findings_total']} | "
            f"{cov} | {c.get('cwe_bridge_matches', 0)} | {c.get('epss_max', 0.0)} | "
            f"{len(c['queue'])} | {c['duration_secs']}s |"
        )
    return "\n".join(rows)


def _case_block(case: dict) -> str:
    lines = [f"#### `{case['name']}` — `{case['image']}`", ""]
    if case.get("description"):
        lines.append(case["description"])
        lines.append("")
    if case.get("error"):
        lines.append(f"**Error:** `{case['error']}`")
        return "\n".join(lines)
    sev = case.get("findings_by_severity") or {}
    lines.append(
        "Severity breakdown: "
        + ", ".join(f"{k}={v}" for k, v in sorted(sev.items())) if sev else "no findings"
    )
    lines.append("")
    det = case.get("detected_cves", 0)
    tested = case.get("tested_cves", 0)
    cov_pct = f" ({tested / det:.0%})" if det else ""
    lines.append(
        f"Exploitability coverage: **{tested} of {det}** detected CVEs tested{cov_pct} "
        f"— {case.get('cve_map_matches', 0)} via CVE-map, "
        f"{case.get('cwe_bridge_matches', 0)} via CWE-bridge. "
        f"EPSS: {case.get('epss_scored', 0)} scored, max {case.get('epss_max', 0.0)}."
    )
    lines.append("")
    if case["queue"]:
        lines.append("Queue order:")
        lines.append("")
        lines.append("```")
        lines.append(", ".join(case["queue"][:30]))
        if len(case["queue"]) > 30:
            lines.append(f"... ({len(case['queue']) - 30} more)")
        lines.append("```")
        lines.append("")
    if case["expectations_pass"]:
        lines.append("✓ Expectations met:")
        for p in case["expectations_pass"]:
            lines.append(f"  - {p}")
        lines.append("")
    if case["expectations_fail"]:
        lines.append("✗ Expectations failed:")
        for p in case["expectations_fail"]:
            lines.append(f"  - {p}")
        lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--corpus", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--output", default=str(DEFAULT_REPORT))
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Skip E2E execution; rebuild the report from the last results.",
    )
    args = parser.parse_args(argv)

    out_path = Path(args.output)

    if args.report_only:
        payload = _load_results()
        _write_report(payload, out_path)
        print(f"Wrote {out_path.relative_to(PROJECT_ROOT)} from cached results.")
        return 0

    missing = _check_prereqs()
    if missing:
        print(f"Missing prerequisites: {', '.join(missing)}", file=sys.stderr)
        print(
            "Static report can still be regenerated with --report-only.",
            file=sys.stderr,
        )
        # Still rewrite the report from current static state so the file is
        # in sync with code even when Docker is unavailable.
        _write_report(_load_results(), out_path)
        return 2

    manifest = yaml.safe_load(Path(args.corpus).read_text()) or {}
    cases = manifest.get("cases") or []
    if not cases:
        print(f"No cases in {args.corpus}", file=sys.stderr)
        return 1

    results: List[CaseResult] = []
    for case in cases:
        print(f"==> {case['name']} ({case['image']}) ...", flush=True)
        r = _evaluate_case(case)
        results.append(r)
        print(
            f"    status={r.status} findings={r.findings_total} "
            f"coverage={r.tested_cves}/{r.detected_cves} bridge={r.cwe_bridge_matches} "
            f"epss_max={r.epss_max} queue={len(r.queue)} kev={r.queue_kev_count} "
            f"duration={r.duration_secs}s"
        )

    _persist_results(results)
    _write_report(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "cases": [asdict(r) for r in results],
        },
        out_path,
    )

    print()
    fails = [r for r in results if r.status != "PASS"]
    print(f"Summary: {len(results) - len(fails)} pass, {len(fails)} fail/error")
    print(f"Report: {out_path.relative_to(PROJECT_ROOT)}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
