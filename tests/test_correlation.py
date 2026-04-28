"""Tests for SecurityMatrixEntry creation logic in the orchestrator."""
import pytest

from app.services.orchestrator import _compute_risk


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
