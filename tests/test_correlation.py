"""Tests for SecurityMatrixEntry creation logic in the orchestrator."""
import pytest

from app.services.orchestrator import RISK_SCORE_MAX, _compute_risk


def test_risk_exploited_undetected():
    score = _compute_risk(exploited=True, detected=False)
    assert score == 50  # 10 base + 30 exploited + 10 undetected


def test_risk_exploited_detected():
    score = _compute_risk(exploited=True, detected=True)
    assert score == 40  # 10 base + 30 exploited (no undetected penalty)


def test_risk_present_only():
    score = _compute_risk(exploited=False, detected=False)
    assert score == 20  # 10 base + 10 undetected


def test_risk_present_detected():
    score = _compute_risk(exploited=False, detected=True)
    assert score == 10  # 10 base only


def test_risk_capped_at_50():
    # Should never exceed 50
    score = _compute_risk(exploited=True, detected=False)
    assert score <= 50


@pytest.mark.parametrize("exploited,detected,expected", [
    (True, False, 50),
    (True, True, 40),
    (False, False, 20),
    (False, True, 10),
])
def test_risk_matrix_cases(exploited, detected, expected):
    assert _compute_risk(exploited, detected) == expected


# Tier-2 #13: severity-weighted risk score


@pytest.mark.parametrize("severity,bonus", [
    ("critical", 20),
    ("CRITICAL", 20),  # case-insensitive
    ("high", 15),
    ("medium", 10),
    ("low", 5),
    ("unknown", 0),
    (None, 0),
])
def test_severity_weight_added(severity, bonus):
    base = _compute_risk(exploited=False, detected=True)  # base 10
    weighted = _compute_risk(exploited=False, detected=True, severity=severity)
    assert weighted == base + bonus


def test_critical_exploited_undetected_caps_at_max():
    score = _compute_risk(exploited=True, detected=False, severity="critical")
    # 10 + 30 + 10 + 20 = 70, well under 75 cap
    assert score == 70
    assert score <= RISK_SCORE_MAX


def test_unknown_severity_does_not_negative():
    score = _compute_risk(exploited=False, detected=True, severity="bogus-value")
    assert score == 10  # falls through severity map, no bonus
