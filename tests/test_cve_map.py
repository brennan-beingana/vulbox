"""Tests for the externalized CVE→technique map and signal-driven fallbacks."""
import pytest

from app.adapters import art_adapter as ART
from app.core.config import settings
from app.models.trivy_finding import TrivyFinding


@pytest.fixture(autouse=True)
def _force_prod_mode(monkeypatch):
    """All cases here exercise the production code path; settings is a singleton."""
    monkeypatch.setattr(settings, "dev_mode", False)


def _f(cve, severity="medium", pkg="", desc=""):
    return TrivyFinding(
        run_id=1, cve_id=cve, severity=severity, package_name=pkg, description=desc
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
