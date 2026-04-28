"""Unit tests for TrivyAdapter, FalcoAdapter, ARTAdapter using fixture files."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

# Force dev mode for all tests
import os
os.environ["VULBOX_DEV_MODE"] = "true"


def test_trivy_adapter_parses_fixture():
    from app.adapters.trivy_adapter import TrivyAdapter

    findings = TrivyAdapter.scan("test-image:latest", run_id=1)
    assert len(findings) > 0
    for f in findings:
        assert f.cve_id
        assert f.severity in ("critical", "high", "medium", "low", "unknown")
        assert f.run_id == 1


def test_trivy_adapter_is_not_blocking():
    from app.adapters.trivy_adapter import TrivyAdapter
    assert TrivyAdapter.is_blocking() is False


def test_falco_adapter_collects_alerts():
    from app.adapters.falco_adapter import FalcoAdapter

    alerts = FalcoAdapter.collect_alerts(run_id=1, test_result_id=42)
    assert len(alerts) > 0
    for a in alerts:
        assert a.run_id == 1
        assert a.test_result_id == 42
        assert a.rule_triggered
        assert a.detected is True


def test_art_adapter_builds_queue():
    from app.adapters.art_adapter import ARTAdapter
    from app.models.trivy_finding import TrivyFinding

    findings = [TrivyFinding(run_id=1, cve_id="CVE-2021-4034", severity="critical", package_name="pkexec")]
    queue = ARTAdapter.build_queue(findings)
    assert len(queue) > 0
    assert all(isinstance(t, str) for t in queue)


def test_art_adapter_executes_test_from_fixture():
    from app.adapters.art_adapter import ARTAdapter

    result = ARTAdapter.execute_test("T1059.004", run_id=1)
    assert result.run_id == 1
    assert result.mitre_test_id == "T1059.004"
    assert isinstance(result.exploited, bool)
    assert result.crash_occurred is False
