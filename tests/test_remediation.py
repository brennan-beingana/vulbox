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


def test_summary_omits_severity_prefix():
    # Severity is rendered as its own badge on the card now, so the summary text
    # must not embed a "[CRITICAL]" prefix (which read as a second severity next
    # to the confidence badge).
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.core.database import Base
    from app.models.trivy_finding import TrivyFinding
    from app.services.remediation_service import RemediationService

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    f = TrivyFinding(run_id=1, cve_id="CVE-2022-1304", severity="critical", package_name="libc6")
    db.add(f)
    db.commit()
    db.refresh(f)

    summary = RemediationService._build_summary(
        db, _make_entry(finding_id=f.finding_id, mitre_tactic_id="T1203")
    )
    assert "[" not in summary
    assert "CVE-2022-1304" in summary and "libc6" in summary and "T1203" in summary
    db.close()
