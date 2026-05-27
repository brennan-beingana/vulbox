"""Report-layer enrichment: matrix CVE/EPSS/provenance + coverage stat (E5)."""
from types import SimpleNamespace as NS

from app.adapters import art_adapter as ART
from app.api.reports import _coverage, _matrix_schema


def _entry(entry_id, finding_id):
    return NS(
        entry_id=entry_id, finding_id=finding_id, test_result_id=1,
        is_present=True, is_exploitable=True, is_detectable=False,
        mitre_tactic_id="T1190", risk_score=50,
    )


def test_matrix_schema_enriches_cve_and_epss():
    finding = NS(finding_id=1, cve_id="CVE-2021-44228", epss_score=0.9)
    schema = _matrix_schema(_entry(1, 1), {1: finding})
    assert schema.cve_id == "CVE-2021-44228"
    assert schema.epss_score == 0.9


def test_match_source_distinguishes_cve_map_vs_bridge(monkeypatch):
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-MAPPED", "T1190")
    mapped = NS(finding_id=1, cve_id="CVE-MAPPED", epss_score=None)
    bridged = NS(finding_id=2, cve_id="CVE-NOTMAPPED-XYZ", epss_score=None)
    assert _matrix_schema(_entry(1, 1), {1: mapped}).match_source == "cve-map"
    assert _matrix_schema(_entry(2, 2), {2: bridged}).match_source == "cwe-bridge"


def test_match_source_none_for_proactive_entry():
    # finding_id None → no motivating CVE, no provenance.
    schema = _matrix_schema(_entry(3, None), {})
    assert schema.cve_id is None
    assert schema.match_source is None


def test_coverage_counts_distinct_cves():
    findings = [
        NS(finding_id=1, cve_id="CVE-A"),
        NS(finding_id=2, cve_id="CVE-B"),
        NS(finding_id=3, cve_id="CVE-C"),  # detected but never tested
    ]
    matrix = [_entry(1, 1), _entry(2, 2), _entry(3, None)]
    cov = _coverage(findings, matrix)
    assert cov.detected_cves == 3
    assert cov.tested_cves == 2
