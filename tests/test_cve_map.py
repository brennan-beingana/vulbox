"""Tests for the externalized CVE→technique map and signal-driven fallbacks."""
import pytest

from app.adapters import art_adapter as ART
from app.core.config import settings
from app.models.trivy_finding import TrivyFinding


@pytest.fixture(autouse=True)
def _force_prod_mode(monkeypatch):
    """All cases here exercise the production code path; settings is a singleton."""
    monkeypatch.setattr(settings, "dev_mode", False)


def _f(cve, severity="medium", pkg="", desc="", cwe_ids="", epss_score=None, finding_id=None):
    return TrivyFinding(
        run_id=1,
        cve_id=cve,
        severity=severity,
        package_name=pkg,
        description=desc,
        cwe_ids=cwe_ids,
        epss_score=epss_score,
        finding_id=finding_id,
    )


def test_yaml_map_loaded():
    # The shipped YAML has dozens of mappings — confirm we got at least 30.
    assert len(ART._CVE_TECHNIQUE_MAP) >= 30
    # Spot-check known entries.
    assert ART._CVE_TECHNIQUE_MAP.get("CVE-2021-4034") == "T1068"
    assert ART._CVE_TECHNIQUE_MAP.get("CVE-2021-44228") == "T1059"
    assert ART._CVE_TECHNIQUE_MAP.get("CVE-2019-5736") == "T1611"


def test_fallback_rules_loaded():
    techs = {fb["technique"] for fb in ART._FALLBACK_RULES}
    # Always-on discovery + at least the keyword-driven ones.
    assert "T1082" in techs
    assert "T1059.004" in techs
    assert "T1190" in techs


def test_cve_match_takes_priority():
    findings = [
        _f("CVE-2021-4034", severity="critical", pkg="polkit"),
        _f("CVE-9999-9999", severity="low", pkg="random"),  # unmapped
    ]
    queue = ART.ARTAdapter.build_queue(findings)
    techniques = [t for t, _ in queue]
    # CVE-driven T1068 should appear before any fallback technique.
    assert "T1068" in techniques
    assert techniques.index("T1068") == 0  # CVE matches always lead the queue


def test_fallbacks_signal_driven_web_image():
    # Image with a PHP web stack should pull T1190 from the web-stack keyword rule.
    findings = [_f("CVE-2099-0001", severity="medium", pkg="apache2", desc="HTTP server")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings)]
    assert "T1190" in techs


def test_fallbacks_signal_driven_kernel_image():
    # Kernel-package + high severity should trigger T1068.
    findings = [_f("CVE-2099-0002", severity="high", pkg="linux-kernel", desc="memory bug")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings)]
    assert "T1068" in techs


def test_fallbacks_distroless_minimal():
    # No keywords match and severity is low — only the always-on T1082 should fire.
    findings = [_f("CVE-2099-0003", severity="low", pkg="rare-pkg", desc="x")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings)]
    assert "T1082" in techs
    # And the privesc/escape ones should NOT fire.
    assert "T1068" not in techs
    assert "T1611" not in techs


def test_severity_min_gates_privesc():
    # Same kernel keyword but severity=low → T1068 should NOT fire (gated by high).
    findings = [_f("CVE-2099-0004", severity="low", pkg="linux-kernel")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings)]
    assert "T1068" not in techs


def test_two_different_images_get_different_queues():
    # The whole point of the rewrite: distinct vulnerability profiles → distinct queues.
    php_image = [_f("CVE-2021-44228", severity="critical", pkg="log4j")]
    kernel_image = [_f("CVE-2022-0847", severity="critical", pkg="linux-kernel")]
    php_q = {t for t, _ in ART.ARTAdapter.build_queue(php_image)}
    kernel_q = {t for t, _ in ART.ARTAdapter.build_queue(kernel_image)}
    # CVE-driven differ; otherwise the test below is meaningless.
    assert php_q != kernel_q


def test_kev_flagged_cve_precedes_non_kev(monkeypatch):
    """KEV-listed CVEs must outrank non-KEV CVE-driven matches.

    Construct two findings that map to distinct techniques: one tagged KEV,
    the other not. The KEV one must appear first regardless of input order.
    """
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-TEST-KEV", {"kev": True})
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-TEST-PLAIN", {})
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-TEST-KEV", "T1190")
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-TEST-PLAIN", "T1003")

    # Plain CVE appears first in the findings list — without prioritization
    # it would come out first. The KEV flag should flip the order.
    findings = [_f("CVE-TEST-PLAIN"), _f("CVE-TEST-KEV")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings)]
    assert techs.index("T1190") < techs.index("T1003")


def test_ransomware_flagged_cve_precedes_kev_only(monkeypatch):
    """Ransomware-linked CVEs outrank plain KEV entries."""
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-TEST-RANSOM", {"kev": True, "ransomware": True})
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-TEST-KEV", {"kev": True})
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-TEST-RANSOM", "T1486")
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-TEST-KEV", "T1190")

    findings = [_f("CVE-TEST-KEV"), _f("CVE-TEST-RANSOM")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings)]
    assert techs.index("T1486") < techs.index("T1190")


# --- Stack-aware proactive bucket (Component 4) ---

def _profile(*tags):
    from app.services.stack_detector import DetectedTech, TechProfile

    return TechProfile(
        techs=[DetectedTech(name=t, version=None, source="test", confidence=1.0) for t in tags]
    )


def test_tech_profile_none_reproduces_prior_queue():
    findings = [_f("CVE-2099-0003", severity="low", pkg="rare-pkg", desc="x")]
    assert ART.ARTAdapter.build_queue(findings) == ART.ARTAdapter.build_queue(findings, None)


def test_empty_profile_changes_nothing():
    findings = [_f("CVE-2099-0003", severity="low", pkg="rare-pkg", desc="x")]
    base = ART.ARTAdapter.build_queue(findings)
    with_empty = ART.ARTAdapter.build_queue(findings, _profile())  # no techs
    assert base == with_empty


def test_profile_injects_proactive_techniques():
    # Minimal finding (no keywords, low severity) — proactive bucket supplies
    # the FastAPI techniques that nothing else would queue.
    findings = [_f("CVE-2099-0003", severity="low", pkg="rare-pkg", desc="x")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings, _profile("python", "fastapi"))]
    assert "T1190" in techs
    assert "T1505.003" in techs
    assert "T1059.006" in techs


def test_proactive_sits_after_cve_and_before_fallback():
    # CVE-driven T1068 leads; uvicorn proactive T1190 must precede the always-on
    # T1082 fallback (uvicorn profile has only T1190, not T1082).
    findings = [_f("CVE-2021-4034", severity="critical", pkg="polkit")]
    queue = [t for t, _ in ART.ARTAdapter.build_queue(findings, _profile("uvicorn"))]
    assert queue.index("T1068") < queue.index("T1190") < queue.index("T1082")


def test_proactive_bucket_dedups_against_other_buckets():
    findings = [_f("CVE-2099-0003", severity="low", pkg="rare-pkg", desc="x")]
    queue = [t for t, _ in ART.ARTAdapter.build_queue(findings, _profile("python", "fastapi"))]
    assert len(queue) == len(set(queue))


# --- CVE technology tagging + stack-relevant priority (Component 2) ---

def test_generated_map_carries_technology_metadata():
    # Spring4Shell is tagged java/java-spring by build_cve_map.py.
    assert "java-spring" in ART._CVE_METADATA.get("CVE-2022-22965", {}).get("technology", [])


def test_stack_relevant_cve_leads_queue(monkeypatch):
    # A plain (non-KEV) java-spring CVE should outrank a ransomware+KEV CVE that
    # has nothing to do with the detected stack, when the stack is java-spring.
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-STACK", {"technology": ["java", "java-spring"]})
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-RANSOM", {"kev": True, "ransomware": True})
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-STACK", "T1190")
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-RANSOM", "T1486")

    findings = [_f("CVE-RANSOM"), _f("CVE-STACK")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings, _profile("java", "java-spring"))]
    assert techs.index("T1190") < techs.index("T1486")


def test_stack_relevance_ignored_without_profile(monkeypatch):
    # Same CVEs, no profile: ransomware ordering wins as before.
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-STACK", {"technology": ["java", "java-spring"]})
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-RANSOM", {"kev": True, "ransomware": True})
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-STACK", "T1190")
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-RANSOM", "T1486")

    findings = [_f("CVE-RANSOM"), _f("CVE-STACK")]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings)]
    assert techs.index("T1486") < techs.index("T1190")


# --- Scan-time CWE bridging (E2) ---

def test_cwe_bridge_loaded():
    assert len(ART._CWE_TECHNIQUE_MAP) >= 60  # expanded to ~80 CWEs
    assert "T1059.004" in ART._CWE_TECHNIQUE_MAP.get("CWE-78", [])
    assert "T1203" in ART._CWE_TECHNIQUE_MAP.get("CWE-787", [])


def test_unmapped_cve_with_cwe_yields_technique():
    # CVE not in the CVE→technique map, but its CWE bridges to a technique.
    # Before the bridge this finding would be dropped from the CVE-driven bucket.
    f = _f("CVE-9999-0001", cwe_ids="CWE-78", finding_id=7)
    assert ART._CVE_TECHNIQUE_MAP.get("CVE-9999-0001") is None
    queue = dict(ART.ARTAdapter.build_queue([f]))
    assert queue.get("T1059.004") == [7]


def test_cve_map_wins_over_cwe_bridge(monkeypatch):
    # When a CVE is in the map, the map technique is used and the CWE ignored.
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-MAPPED", "T1068")
    f = _f("CVE-MAPPED", cwe_ids="CWE-78", finding_id=3)  # CWE-78 → T1059.004
    techs = [t for t, _ in ART.ARTAdapter.build_queue([f])]
    assert "T1068" in techs
    assert "T1059.004" not in techs


# --- Fan-out attribution (E3) ---

def test_fanout_groups_findings_under_one_technique(monkeypatch):
    # Two distinct CVEs mapping to the same technique → ONE queue entry that
    # carries BOTH motivating finding_ids.
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-A", "T1190")
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-B", "T1190")
    findings = [_f("CVE-A", finding_id=1), _f("CVE-B", finding_id=2)]
    queue = dict(ART.ARTAdapter.build_queue(findings))
    assert sorted(queue["T1190"]) == [1, 2]


def test_proactive_and_fallback_carry_empty_finding_list():
    findings = [_f("CVE-2099-0003", severity="low", pkg="rare-pkg", desc="x")]
    queue = ART.ARTAdapter.build_queue(findings)
    # The always-on T1082 fallback fires with no motivating CVE → empty list.
    assert ("T1082", []) in queue


# --- EPSS ranking + gate (E4) ---

def test_epss_orders_within_same_priority(monkeypatch):
    # Two plain (non-KEV) CVEs, distinct techniques, differing EPSS. The higher
    # EPSS one is tested first.
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-LOWP", "T1003")
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-HIGHP", "T1190")
    findings = [
        _f("CVE-LOWP", epss_score=0.01, finding_id=1),
        _f("CVE-HIGHP", epss_score=0.90, finding_id=2),
    ]
    techs = [t for t, _ in ART.ARTAdapter.build_queue(findings)]
    assert techs.index("T1190") < techs.index("T1003")


def test_epss_gate_excludes_low_score(monkeypatch):
    monkeypatch.setattr(settings, "epss_min", 0.5)
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-LOW", "T1190")
    f = _f("CVE-LOW", epss_score=0.01, finding_id=9)
    queue = dict(ART.ARTAdapter.build_queue([f]))
    # Below the gate and not KEV/ransomware → no CVE-driven row for it.
    assert "T1190" not in queue


def test_epss_gate_includes_high_score(monkeypatch):
    monkeypatch.setattr(settings, "epss_min", 0.5)
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-HIGH", "T1190")
    f = _f("CVE-HIGH", epss_score=0.80, finding_id=9)
    queue = dict(ART.ARTAdapter.build_queue([f]))
    assert queue.get("T1190") == [9]


def test_epss_gate_keeps_kev_regardless(monkeypatch):
    monkeypatch.setattr(settings, "epss_min", 0.9)
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-KEVLOW", "T1190")
    monkeypatch.setitem(ART._CVE_METADATA, "CVE-KEVLOW", {"kev": True})
    f = _f("CVE-KEVLOW", epss_score=0.01, finding_id=4)  # below gate, but KEV
    queue = dict(ART.ARTAdapter.build_queue([f]))
    assert queue.get("T1190") == [4]


def test_gate_off_by_default_includes_unscored(monkeypatch):
    # Default epss_min=0.0 → gate off, even an unscored (None) CVE is attributed.
    monkeypatch.setattr(settings, "epss_min", 0.0)
    monkeypatch.setitem(ART._CVE_TECHNIQUE_MAP, "CVE-NOSCORE", "T1190")
    f = _f("CVE-NOSCORE", epss_score=None, finding_id=5)
    queue = dict(ART.ARTAdapter.build_queue([f]))
    assert queue.get("T1190") == [5]
