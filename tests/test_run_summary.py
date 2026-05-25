"""Tests for the executive-summary service (templated fallback + gating)."""
import json
import os
import types
from unittest.mock import patch

os.environ["VULBOX_DEV_MODE"] = "true"

from app.services.run_summary_service import (
    RunSummaryService,
    _compute_stats,
    _templated_summary,
)


def _entry(**kw):
    base = dict(
        entry_id=1, run_id=1, finding_id=None, test_result_id=None,
        is_present=True, is_exploitable=False, is_detectable=False,
        mitre_tactic_id="T1059", risk_score=10,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_compute_stats_counts_exploitable_and_undetected():
    entries = [
        _entry(is_exploitable=True, is_detectable=False, risk_score=60),
        _entry(is_exploitable=True, is_detectable=True, risk_score=40),
        _entry(is_exploitable=False, risk_score=10),
    ]
    # finding_id is None on all, so db is never queried — pass None safely.
    stats = _compute_stats(None, entries)
    assert stats["total"] == 3
    assert stats["exploitable"] == 2
    assert stats["undetected"] == 1
    assert stats["max_risk"] == 60
    assert len(stats["top_lines"]) == 3


def test_templated_summary_no_findings():
    stats = _compute_stats(None, [])
    s = _templated_summary(run_id=7, s=stats)
    assert s.run_id == 7
    assert s.generated_by == "static"
    assert "No security-matrix findings" in s.headline
    assert json.loads(s.top_priorities)  # non-empty list


def test_templated_summary_critical_when_undetected():
    stats = _compute_stats(None, [_entry(is_exploitable=True, is_detectable=False, risk_score=60)])
    s = _templated_summary(run_id=1, s=stats)
    assert s.confidence == "critical"
    assert "undetected" in s.overall_posture.lower()


def test_is_enabled_requires_all_three_flags():
    with patch("app.services.run_summary_service.settings") as fake:
        fake.llm_remediation_enabled = True
        fake.llm_exec_summary_enabled = True
        fake.gemini_api_key = "AIza..."
        assert RunSummaryService.is_enabled() is True

        fake.llm_exec_summary_enabled = False
        assert RunSummaryService.is_enabled() is False
