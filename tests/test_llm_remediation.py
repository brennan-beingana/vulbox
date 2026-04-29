"""Tests for the LLM remediation service (without making real API calls)."""
import os
from unittest.mock import patch

os.environ["VULBOX_DEV_MODE"] = "true"

from app.services.llm_remediation import (
    LLMRemediationService,
    _Evidence,
    _parse_json_response,
)


def _ev(**overrides):
    base = dict(
        technique="T1059.004",
        exploited=True,
        detected=False,
        risk_score=50,
        cves=["CVE-2021-44228"],
        cve_severities=["critical"],
        falco_rules=[],
        art_log_excerpt="uid=0(root) ...",
    )
    base.update(overrides)
    return _Evidence(**base)


def test_parse_json_strict_object():
    raw = '{"priority_action":"a","why_it_matters":"b","example_fix":"c","confidence":"high","references":[]}'
    out = _parse_json_response(raw)
    assert out and out["priority_action"] == "a"


def test_parse_json_strips_markdown_fence():
    raw = '```json\n{"priority_action":"a","why_it_matters":"b","example_fix":"c"}\n```'
    out = _parse_json_response(raw)
    assert out and out["example_fix"] == "c"


def test_parse_json_extracts_first_object_from_chatter():
    raw = 'Sure! Here you go:\n{"priority_action":"a","why_it_matters":"b","example_fix":"c"}\nLet me know if...'
    out = _parse_json_response(raw)
    assert out and out["why_it_matters"] == "b"


def test_parse_json_rejects_missing_fields():
    raw = '{"priority_action":"a"}'  # missing required keys
    assert _parse_json_response(raw) is None


def test_parse_json_rejects_non_object():
    assert _parse_json_response('"just a string"') is None
    assert _parse_json_response("[1,2,3]") is None
    assert _parse_json_response("") is None


def test_cache_key_stable_across_whitespace():
    a = _ev(art_log_excerpt="line1\nline2  line3").cache_key()
    b = _ev(art_log_excerpt="line1 line2 line3").cache_key()
    assert a == b


def test_cache_key_changes_on_technique():
    assert _ev(technique="T1059").cache_key() != _ev(technique="T1611").cache_key()


def test_is_enabled_off_when_no_api_key():
    with patch("app.services.llm_remediation.settings") as fake:
        fake.llm_remediation_enabled = True
        fake.openai_api_key = ""
        assert LLMRemediationService.is_enabled() is False


def test_is_enabled_off_when_flag_off():
    with patch("app.services.llm_remediation.settings") as fake:
        fake.llm_remediation_enabled = False
        fake.openai_api_key = "sk-..."
        assert LLMRemediationService.is_enabled() is False


def test_is_enabled_on_when_both_set():
    with patch("app.services.llm_remediation.settings") as fake:
        fake.llm_remediation_enabled = True
        fake.openai_api_key = "sk-..."
        assert LLMRemediationService.is_enabled() is True
