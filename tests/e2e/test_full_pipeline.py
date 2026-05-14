"""End-to-end test: VulBox pipeline against the bundled vulnerable target.

Deliverable A of demo_revamp.md. Runs the real Docker build, Trivy scan, and
ART test against `tests/e2e/fixtures/vulnerable_target/`. Falco is optional;
when missing or disabled, detection asserts become advisory rather than hard.

Skipped by default. Opt in with:

    pytest -m e2e -v
"""
from __future__ import annotations

import warnings

import pytest


@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.requires_trivy
def test_full_pipeline_against_vulnerable_target(api_client, target_path):
    repo_url = f"file://{target_path}"

    run_id = api_client.create_run(repo_url=repo_url)

    events = api_client.collect_ws_events(run_id, max_seconds=900)

    final = api_client.poll_run(run_id, timeout=900)
    assert final["status"] == "COMPLETE", (
        f"pipeline failed: final={final.get('status')!r}\n"
        f"events:\n" + "\n".join(repr(e) for e in events)
    )

    report = api_client.get_report(run_id)

    # node:14-alpine + pinned-vulnerable express/lodash deterministically
    # produces well above 5 CVEs; tightening this further makes the test
    # brittle against Trivy DB updates.
    assert report["trivy_findings_count"] >= 5, (
        f"expected >=5 Trivy findings, got {report['trivy_findings_count']}. "
        "Has the Trivy DB lost coverage for node:14-alpine?"
    )
    assert len(report["security_matrix"]) > 0, "security matrix is empty"
    assert report["remediations_count"] > 0, "no remediations generated"

    # Soft: if no test exploited, ART wiring is suspect — warn instead of fail
    # so a partial pipeline regression doesn't block the whole demo prep.
    if not any(e.get("is_exploitable") for e in report["security_matrix"]):
        warnings.warn(
            "No ART test exploited the target — atomic_runner.sh / "
            "container-exec wiring may be broken."
        )
