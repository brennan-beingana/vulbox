#!/usr/bin/env python3
"""Full-pipeline validation harness over a curated vulhub corpus.

Where ``scripts/validate_e2e.py`` runs only the *static* half (Trivy + ART
queue building) against registry images, this harness drives VulBox's **whole**
pipeline — build → Trivy → sandbox → ART → Falco → report — against a curated
set of real vulhub vulnerable apps, one per distinct stack (Java / PHP / Node /
Ruby / C / Go). It's the "run the project across a broad range of apps" check.

How it works (no product code is touched):
  1. Clone vulhub once at a pinned commit into a local cache (``data/sources/vulhub``).
  2. For each env in ``tests/ground_truth/vulhub_manifest.yml``: copy that env's
     subdir into a throwaway git repo, inject ``.vulbox.yml`` (sandbox relaxation
     from the manifest), then POST a run through an in-process FastAPI TestClient
     running in **production mode** — so real Docker/Trivy/Falco are exercised.
  3. Poll to terminal, pull ``/reports/{id}``, and record findings / coverage /
     exploitability / detectability / duration per env.
  4. Write ``docs/vulhub_validation_report.md``.

Most vulhub envs aren't a fit (multi-container, or pull prebuilt images with no
local Dockerfile); see the manifest header for why these ~10 were chosen.

Requirements: Docker daemon reachable + ``trivy`` on PATH. Falco is optional —
without it the detectability column is reported as "n/a" instead of asserted.
Runs against a **dedicated** SQLite DB (``data/vulhub_findings.db``) so it never
touches your real ``data/findings.db``.

Usage::

    python scripts/validate_vulhub.py                 # all envs
    python scripts/validate_vulhub.py --only node-cve-2017-14849,rsync-common
    python scripts/validate_vulhub.py --refresh       # re-pull the vulhub cache
    python scripts/validate_vulhub.py --keep-images   # don't docker rmi between envs
    python scripts/validate_vulhub.py --report-only    # rebuild report from cache
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
from typing import Dict, List, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_MANIFEST = PROJECT_ROOT / "tests" / "ground_truth" / "vulhub_manifest.yml"
DEFAULT_REPORT = PROJECT_ROOT / "docs" / "vulhub_validation_report.md"
RESULTS_PATH = PROJECT_ROOT / "data" / "validation" / "vulhub_results.json"
VULHUB_CACHE = PROJECT_ROOT / "data" / "sources" / "vulhub"
VULHUB_REPO = "https://github.com/vulhub/vulhub"
# Pin for determinism; bump deliberately. `--refresh` re-pulls to this ref.
VULHUB_REF = "master"

# Dedicated DB + production mode, set BEFORE app import (mirrors tests/e2e/conftest).
os.environ["VULBOX_DEV_MODE"] = "false"
# Falco drives the detectability dimension. FalcoAdapter reads VULBOX_FALCO_ENABLED
# straight from the process env (default "true"), so auto-enable it when the falco
# binary is present (e.g. on the VM) and leave it off on a host without falco so
# `attach` doesn't fail the pipeline. An explicit VULBOX_FALCO_ENABLED always wins.
if "VULBOX_FALCO_ENABLED" not in os.environ:
    os.environ["VULBOX_FALCO_ENABLED"] = "true" if shutil.which("falco") else "false"
os.environ["DATABASE_URL"] = f"sqlite:///{PROJECT_ROOT / 'data' / 'vulhub_findings.db'}"

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "vulbox-vulhub",
    "GIT_AUTHOR_EMAIL": "vulhub@vulbox.local",
    "GIT_COMMITTER_NAME": "vulbox-vulhub",
    "GIT_COMMITTER_EMAIL": "vulhub@vulbox.local",
}


@dataclass
class EnvResult:
    name: str
    subpath: str
    stack: str
    status: str = "PENDING"      # final AssessmentRun status
    build_ok: bool = False
    findings_total: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    detected_cves: int = 0
    tested_cves: int = 0
    exploitable: int = 0
    detectable: int = 0
    matrix_entries: int = 0
    techs: List[str] = field(default_factory=list)
    falco_available: bool = False
    note: str = ""
    failure_reason: str = ""
    expectations_pass: List[str] = field(default_factory=list)
    expectations_fail: List[str] = field(default_factory=list)
    duration_secs: float = 0.0

    @property
    def verdict(self) -> str:
        if self.status != "COMPLETE":
            return "ERROR"
        if self.expectations_fail:
            return "FAIL"
        return "PASS"


def _bin(name: str) -> bool:
    return shutil.which(name) is not None


def _check_prereqs() -> List[str]:
    missing: List[str] = []
    if not _bin("docker"):
        missing.append("docker")
    elif subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        missing.append("docker daemon (CLI present, daemon unreachable — start Docker)")
    if not _bin("trivy"):
        missing.append("trivy")
    if not _bin("git"):
        missing.append("git")
    return missing


def _ensure_vulhub(refresh: bool) -> None:
    if refresh and VULHUB_CACHE.exists():
        shutil.rmtree(VULHUB_CACHE)
    if VULHUB_CACHE.exists():
        print(f"    vulhub cache present: {VULHUB_CACHE.relative_to(PROJECT_ROOT)}")
        return
    VULHUB_CACHE.parent.mkdir(parents=True, exist_ok=True)
    print(f"    cloning vulhub ({VULHUB_REF}) -> {VULHUB_CACHE.relative_to(PROJECT_ROOT)} ...")
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", VULHUB_REF, VULHUB_REPO, str(VULHUB_CACHE)],
        check=True, capture_output=True, text=True,
    )


def _materialize_env(case: dict, defaults: dict, dest: Path) -> Path:
    """Copy the vulhub env subdir into ``dest``, inject .vulbox.yml, git-init it."""
    src = VULHUB_CACHE / case["subpath"]
    if not (src / "Dockerfile").is_file():
        raise FileNotFoundError(f"no Dockerfile in {case['subpath']} (cache stale? --refresh)")
    shutil.copytree(src, dest, dirs_exist_ok=True)

    sandbox = {**(defaults.get("sandbox") or {}), **(case.get("sandbox") or {})}
    (dest / ".vulbox.yml").write_text(yaml.safe_dump({"sandbox": sandbox}, sort_keys=False))

    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=dest, check=True, env=_GIT_ENV)
    subprocess.run(["git", "add", "."], cwd=dest, check=True, env=_GIT_ENV)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", case["name"]],
        cwd=dest, check=True, env=_GIT_ENV,
    )
    return dest


def _run_one(client, case: dict, defaults: dict, falco_available: bool, work: Path) -> EnvResult:
    r = EnvResult(
        name=case["name"], subpath=case["subpath"], stack=case.get("stack", ""),
        note=(case.get("note") or "").strip(), falco_available=falco_available,
    )
    started = time.time()
    try:
        repo = _materialize_env(case, defaults, work / case["name"])
        repo_url = f"file://{repo}"

        resp = client.post(
            "/runs",
            json={"project_name": case["name"], "repo_url": repo_url, "consent_granted": True},
            timeout=None,  # create may block until the background pipeline finishes
        )
        if resp.status_code >= 400:
            r.status = "ERROR"
            r.failure_reason = f"create_run {resp.status_code}: {resp.text[:300]}"
            return r
        run_id = resp.json()["id"]

        final = _poll(client, run_id)
        r.status = final.get("status", "UNKNOWN")
        r.failure_reason = (final.get("error_message") or final.get("failure_reason") or "")[:500]

        report = client.get(f"/reports/{run_id}", timeout=60).json()
        r.build_ok = r.status in ("COMPLETE",) or (report.get("trivy_findings_count", 0) > 0)
        r.findings_total = report.get("trivy_findings_count", 0)
        r.techs = sorted({t["name"] for t in report.get("detected_technologies", [])})
        matrix = report.get("security_matrix", []) or []
        r.matrix_entries = len(matrix)
        r.exploitable = sum(1 for e in matrix if e.get("is_exploitable"))
        r.detectable = sum(1 for e in matrix if e.get("is_detectable"))
        cov = report.get("coverage") or {}
        r.detected_cves = cov.get("detected_cves", 0)
        r.tested_cves = cov.get("tested_cves", 0)
        for e in matrix:
            sev = (e.get("severity") or "unknown").lower()
            r.findings_by_severity[sev] = r.findings_by_severity.get(sev, 0) + 1

        _check_expectations(r, case.get("expectations") or {})
    except Exception as exc:  # noqa: BLE001 — surface everything per-env
        r.status = r.status if r.status != "PENDING" else "ERROR"
        r.failure_reason = r.failure_reason or f"{type(exc).__name__}: {exc}"
    r.duration_secs = round(time.time() - started, 1)
    return r


def _poll(client, run_id: int, timeout: int = 2000, interval: float = 3.0) -> dict:
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        last = client.get(f"/runs/{run_id}", timeout=30).json()
        if last.get("status") in ("COMPLETE", "FAILED"):
            return last
        time.sleep(interval)
    return last or {"status": "TIMEOUT"}


def _check_expectations(r: EnvResult, exps: dict) -> None:
    findings = exps.get("findings") or {}
    if "min_total" in findings:
        v = findings["min_total"]
        (r.expectations_pass if r.findings_total >= v else r.expectations_fail).append(
            f"findings >= {v} (got {r.findings_total})"
        )
    coverage = exps.get("coverage") or {}
    if "min_tested" in coverage:
        v = coverage["min_tested"]
        (r.expectations_pass if r.tested_cves >= v else r.expectations_fail).append(
            f"tested CVEs >= {v} (got {r.tested_cves})"
        )
    if r.status != "COMPLETE":
        r.expectations_fail.append(f"pipeline reached COMPLETE (got {r.status})")


def _docker_prune_images() -> None:
    """Drop vulbox build images + dangling layers so the disk doesn't balloon."""
    ids = subprocess.run(
        ["docker", "images", "--filter", "reference=vulbox-*", "-q"],
        capture_output=True, text=True,
    ).stdout.split()
    if ids:
        subprocess.run(["docker", "rmi", "-f", *ids], capture_output=True)
    subprocess.run(["docker", "image", "prune", "-f"], capture_output=True)


# --------------------------------------------------------------------------- #
# Report rendering
# --------------------------------------------------------------------------- #
def _write_report(payload: Optional[dict], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    p: List[str] = ["# VulBox — vulhub Full-Pipeline Validation", ""]
    p.append(f"_Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}_")
    p.append("")
    if not payload:
        p.append("_No results yet. Run `python scripts/validate_vulhub.py` on a host "
                 "with Docker + Trivy._")
        out.write_text("\n".join(p) + "\n")
        return

    cases = payload["cases"]
    falco = any(c.get("falco_available") for c in cases)
    p.append(f"_Last run: {payload['generated_at']}_ — "
             f"Falco {'present (detectability asserted)' if falco else 'absent (detectability n/a)'}")
    p.append("")
    n_pass = sum(1 for c in cases if not c["expectations_fail"] and c["status"] == "COMPLETE")
    p.append(f"**{n_pass}/{len(cases)} envs passed.**")
    p.append("")
    p.append("| Env | Stack | Verdict | Status | Findings | Coverage | Exploitable | Detectable | Time |")
    p.append("|---|---|---|---|---:|---:|---:|---:|---:|")
    for c in cases:
        verdict = ("PASS" if not c["expectations_fail"] and c["status"] == "COMPLETE"
                   else ("FAIL" if c["status"] == "COMPLETE" else "ERROR"))
        det = c["detected_cves"]
        cov = f"{c['tested_cves']}/{det}" + (f" ({c['tested_cves']/det:.0%})" if det else "")
        detectable = c["detectable"] if c["falco_available"] else "n/a"
        p.append(
            f"| {c['name']} | {c['stack']} | {verdict} | {c['status']} | {c['findings_total']} | "
            f"{cov} | {c['exploitable']} | {detectable} | {c['duration_secs']}s |"
        )
    p.append("")
    p.append("## Detail")
    p.append("")
    for c in cases:
        p.append(f"### `{c['name']}` — {c['stack']}  (`{c['subpath']}`)")
        p.append("")
        if c.get("note"):
            p.append(f"> {c['note']}")
            p.append("")
        if c["techs"]:
            p.append(f"Detected technologies: {', '.join(c['techs'])}")
            p.append("")
        if c["failure_reason"]:
            p.append(f"**Failure:** `{c['failure_reason']}`")
            p.append("")
        for ok in c["expectations_pass"]:
            p.append(f"- ✓ {ok}")
        for bad in c["expectations_fail"]:
            p.append(f"- ✗ {bad}")
        p.append("")
    out.write_text("\n".join(p) + "\n")


def _persist(results: List[EnvResult]) -> dict:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cases": [asdict(r) for r in results],
    }
    RESULTS_PATH.write_text(json.dumps(payload, indent=2))
    return payload


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--output", default=str(DEFAULT_REPORT))
    ap.add_argument("--only", help="comma-separated env names to run")
    ap.add_argument("--refresh", action="store_true", help="re-pull the vulhub cache")
    ap.add_argument("--keep-images", action="store_true", help="don't docker rmi between envs")
    ap.add_argument("--report-only", action="store_true", help="rebuild report from cache")
    args = ap.parse_args(argv)

    out = Path(args.output)
    if args.report_only:
        payload = json.loads(RESULTS_PATH.read_text()) if RESULTS_PATH.is_file() else None
        _write_report(payload, out)
        print(f"Wrote {out.relative_to(PROJECT_ROOT)} from cached results.")
        return 0

    missing = _check_prereqs()
    if missing:
        print(f"Missing prerequisites: {', '.join(missing)}", file=sys.stderr)
        print("Re-run after fixing, or use --report-only to rebuild the report.", file=sys.stderr)
        return 2

    manifest = yaml.safe_load(Path(args.manifest).read_text()) or {}
    defaults = manifest.get("defaults") or {}
    cases = manifest.get("cases") or []
    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        cases = [c for c in cases if c["name"] in wanted]
    if not cases:
        print("No cases selected.", file=sys.stderr)
        return 1

    print("==> preparing vulhub corpus")
    _ensure_vulhub(args.refresh)

    falco_available = _bin("falco") and os.getenv("VULBOX_FALCO_ENABLED", "false").lower() == "true"

    # Fresh DB so prior runs don't bleed in (dedicated file, not findings.db).
    db_file = PROJECT_ROOT / "data" / "vulhub_findings.db"
    if db_file.exists():
        db_file.unlink()

    from fastapi.testclient import TestClient
    from app.core import config as config_module
    from app.core.config import Settings
    config_module.settings = Settings()  # rebuild with prod mode + dedicated DB
    from app.main import app

    import tempfile
    results: List[EnvResult] = []
    with TestClient(app) as client:
        with tempfile.TemporaryDirectory(prefix="vulhub-work-") as tmp:
            work = Path(tmp)
            for case in cases:
                print(f"==> {case['name']} ({case['subpath']}) ...", flush=True)
                r = _run_one(client, case, defaults, falco_available, work)
                results.append(r)
                print(f"    verdict={r.verdict} status={r.status} findings={r.findings_total} "
                      f"coverage={r.tested_cves}/{r.detected_cves} exploit={r.exploitable} "
                      f"detect={r.detectable if r.falco_available else 'n/a'} "
                      f"{r.duration_secs}s"
                      + (f"  [{r.failure_reason}]" if r.failure_reason else ""))
                if not args.keep_images:
                    _docker_prune_images()

    payload = _persist(results)
    _write_report(payload, out)

    fails = [r for r in results if r.verdict != "PASS"]
    print()
    print(f"Summary: {len(results) - len(fails)} pass, {len(fails)} fail/error")
    print(f"Report: {out.relative_to(PROJECT_ROOT)}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
