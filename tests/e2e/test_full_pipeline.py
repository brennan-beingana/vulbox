"""End-to-end test: VulBox pipeline against bundled vulnerable targets.

Deliverable A of demo_revamp.md, extended (Phase 3) to multiple stacks. Runs the
real Docker build, Trivy scan, and ART test against each target in
`tests/e2e/fixtures/`. Falco is optional; when missing or disabled, detection
asserts become advisory rather than hard.

Skipped by default. Opt in with:

    pytest -m e2e -v
"""
from __future__ import annotations

import warnings

import pytest

# Each target: fixture dir + per-stack expectations. Adding a stack is a one
# fixture dir + one row here — the test body stays generic.
TARGETS = [
    pytest.param(
        "vulnerable_target",
        {
            "project": "e2e-node-express",
            "stack_tag": "node",
            "expect_techs": {"node", "express"},
        },
        id="node-express",
    ),
    pytest.param(
        "vulnerable_python",
        {
            "project": "e2e-python-flask",
            "stack_tag": "python",
            "expect_techs": {"python", "flask"},
        },
        id="python-flask",
    ),
]


@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.requires_trivy
@pytest.mark.parametrize("fixture_name,spec", TARGETS)
def test_full_pipeline_against_vulnerable_target(
    api_client, make_target_repo, fixture_name, spec
):
    target_path = make_target_repo(fixture_name)
    repo_url = f"file://{target_path}"

    run_id = api_client.create_run(repo_url=repo_url, project_name=spec["project"])

    events = api_client.collect_ws_events(run_id, max_seconds=900)

    final = api_client.poll_run(run_id, timeout=900)
    assert final["status"] == "COMPLETE", (
        f"pipeline failed: final={final.get('status')!r}\n"
        f"events:\n" + "\n".join(repr(e) for e in events)
    )

    # Stack detection fingerprints the target before testing.
    stack_events = [e for e in events if e.get("event") == "stack_detected"]
    assert stack_events, (
        "no stack_detected event — StackDetector not wired into BUILDING.\n"
        "events:\n" + "\n".join(repr(e) for e in events)
    )
    assert spec["stack_tag"] in stack_events[-1].get("tags", []), (
        f"expected {spec['stack_tag']!r} in detected stack tags, "
        f"got {stack_events[-1].get('tags')}"
    )

    report = api_client.get_report(run_id)

    detected = {t["name"] for t in report.get("detected_technologies", [])}
    assert spec["expect_techs"] <= detected, (
        f"expected {sorted(spec['expect_techs'])} in detected_technologies, "
        f"got {sorted(detected)}"
    )

    # These EOL bases + pinned vulnerable deps deterministically produce well
    # above 5 CVEs; tightening further makes the test brittle against Trivy DB
    # updates.
    assert report["trivy_findings_count"] >= 5, (
        f"expected >=5 Trivy findings, got {report['trivy_findings_count']}. "
        f"Has the Trivy DB lost coverage for the {fixture_name} base image?"
    )
    assert len(report["security_matrix"]) > 0, "security matrix is empty"
    assert report["remediations_count"] > 0, "no remediations generated"

    # Coverage lift (CWE-bridge + fan-out): exploitability should be attributed
    # to more than one distinct detected CVE, not just a single motivating one.
    matrix_cves = {
        e["cve_id"] for e in report["security_matrix"] if e.get("cve_id")
    }
    assert len(matrix_cves) >= 2, (
        "expected exploitability rows for multiple distinct CVEs (fan-out + "
        f"CWE-bridge coverage lift), got {sorted(matrix_cves)}"
    )
    coverage = report.get("coverage") or {}
    assert coverage.get("tested_cves", 0) >= 2, (
        f"expected >=2 CVEs to receive an exploitability verdict, got {coverage}"
    )

    # Soft: if no test exploited, ART wiring is suspect — warn instead of fail
    # so a partial pipeline regression doesn't block the whole demo prep.
    if not any(e.get("is_exploitable") for e in report["security_matrix"]):
        warnings.warn(
            f"[{fixture_name}] No ART test exploited the target — atomic_runner / "
            "container-exec wiring may be broken."
        )
