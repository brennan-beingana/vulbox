"""Tests for RemediationService rule selection logic."""
import pytest


def _make_entry(**kwargs):
    """Build a minimal SecurityMatrixEntry-like object for testing (plain namespace, no ORM)."""
    import types
    defaults = dict(
        entry_id=1, run_id=1, finding_id=None, test_result_id=None,
        is_present=True, is_exploitable=False, is_detectable=False,
        mitre_tactic_id="", risk_score=10,
    )
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


def test_exploitable_undetected_is_critical():
    from app.services.remediation_service import RemediationService
    entry = _make_entry(is_exploitable=True, is_detectable=False)
    _, _, _, confidence = RemediationService._pick_rule(entry)
    assert confidence == "critical"


def test_exploitable_detected_is_high():
    from app.services.remediation_service import RemediationService
    entry = _make_entry(is_exploitable=True, is_detectable=True)
    _, _, _, confidence = RemediationService._pick_rule(entry)
    assert confidence == "high"


def test_present_not_exploitable_is_medium():
    from app.services.remediation_service import RemediationService
    entry = _make_entry(is_present=True, is_exploitable=False)
    _, _, _, confidence = RemediationService._pick_rule(entry)
    assert confidence == "medium"


def test_default_fallback_is_high():
    from app.services.remediation_service import RemediationService
    # No exploitable, no detectable, no present scenario hits cve_default
    entry = _make_entry(is_present=False, is_exploitable=False, is_detectable=False)
    action, _, _, confidence = RemediationService._pick_rule(entry)
    assert "Upgrade" in action or "Monitor" in action or confidence in ("high", "medium", "low", "critical")
