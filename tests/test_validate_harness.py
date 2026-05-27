"""Unit test for the coverage-signal helper in scripts/validate_e2e.py.

Docker-free: exercises only the pure aggregation over findings + a synthetic
queue, so it runs in the normal suite without pulling images.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

from app.adapters import art_adapter as ART
from app.models.trivy_finding import TrivyFinding

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_e2e.py"


def _load_harness():
    if "validate_e2e" in sys.modules:
        return sys.modules["validate_e2e"]
    spec = importlib.util.spec_from_file_location("validate_e2e", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so the @dataclass can resolve string annotations
    # (the module uses `from __future__ import annotations`).
    sys.modules["validate_e2e"] = mod
    spec.loader.exec_module(mod)
    return mod


def _f(cve, fid, epss=None):
    return TrivyFinding(run_id=0, cve_id=cve, severity="high", finding_id=fid, epss_score=epss)


def test_coverage_signals_splits_provenance_and_epss(monkeypatch):
    harness = _load_harness()
    # CVE-A resolves via the CVE map; CVE-B only via the bridge; CVE-C is
    # detected but never tested (not in the queue's fan-out lists).
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-A", "T1190")
    findings = [
        _f("CVE-A", 0, epss=0.9),
        _f("CVE-B", 1, epss=0.2),
        _f("CVE-C", 2, epss=None),
    ]
    queue = [("T1190", [0, 1]), ("T1082", [])]  # T1082 = proactive/fallback, no CVE

    sig = harness._coverage_signals(findings, queue)
    assert sig["detected_cves"] == 3
    assert sig["tested_cves"] == 2          # A + B
    assert sig["cve_map_matches"] == 1      # A
    assert sig["cwe_bridge_matches"] == 1   # B
    assert sig["epss_scored"] == 2          # A, B (C is None)
    assert sig["epss_max"] == 0.9
    assert sig["cves"] == ["CVE-A", "CVE-B", "CVE-C"]


def test_coverage_signals_empty_queue():
    harness = _load_harness()
    findings = [_f("CVE-A", 0)]
    sig = harness._coverage_signals(findings, [])
    assert sig["detected_cves"] == 1
    assert sig["tested_cves"] == 0
