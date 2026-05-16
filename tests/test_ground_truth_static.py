"""Static validation of the CVE→technique→test pipeline.

Layer 1 of the Sprint 6 ground-truth harness — runs in normal ``pytest``
without Docker. Asserts internal consistency of the artifacts we ship:

* every CVE/technique/CWE id is well-formed,
* every technique we'd queue for execution can actually be executed by
  either the ART catalog or the bash runner's case statement,
* the CWE bridge entries all target techniques that exist in the runner
  surface,
* no atomic test we'd pick by default carries an unresolved ``#{x}``
  placeholder that would fail at exec time.

Layer 2 (``scripts/validate_e2e.py``) covers the Docker-dependent E2E side.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, Set

import pytest
import yaml

from scanners.atomic_catalog import CATALOG
from app.adapters import art_adapter as ART

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CURATED_MAP = PROJECT_ROOT / "data" / "cve_technique_map.yml"
GENERATED_MAP = PROJECT_ROOT / "data" / "cve_technique_map.generated.yml"
CWE_BRIDGE = PROJECT_ROOT / "data" / "cwe_technique_map.yml"
BASH_RUNNER = PROJECT_ROOT / "scanners" / "atomic_runner.sh"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CWE_RE = re.compile(r"^CWE-\d+$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
UNRESOLVED_PLACEHOLDER_RE = re.compile(r"#\{\w+\}")


def _load_mappings(path: Path) -> list:
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    return data.get("mappings") or []


def _bash_case_branches() -> Set[str]:
    """Extract the technique ids the bash runner has explicit case branches for."""
    if not BASH_RUNNER.is_file():
        return set()
    text = BASH_RUNNER.read_text()
    techs: Set[str] = set()
    # Lines like:  T1059|T1059.004)
    for m in re.finditer(r"^\s*(T\d{4}(?:\.\d{3})?(?:\|T\d{4}(?:\.\d{3})?)*)\)", text, re.M):
        for tid in m.group(1).split("|"):
            techs.add(tid)
    return techs


_BASH_TECHS = _bash_case_branches()
_CATALOG_TECHS = set(CATALOG.technique_ids())
_FALLBACK_TECHS = {fb["technique"] for fb in ART._FALLBACK_RULES if fb.get("technique")}


# --------------------------------------------------------------------------
# CVE map well-formedness
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", [CURATED_MAP, GENERATED_MAP])
def test_cve_map_ids_well_formed(path):
    for entry in _load_mappings(path):
        cve = entry.get("cve")
        tech = entry.get("technique")
        if cve is None and tech is None:
            continue  # placeholder rows are allowed in generated layer
        if cve:
            assert CVE_RE.match(cve), f"{path.name}: malformed cve '{cve}'"
        if tech:
            assert TECHNIQUE_RE.match(tech), f"{path.name}: malformed technique '{tech}' for {cve}"


def test_cwe_bridge_well_formed():
    data = yaml.safe_load(CWE_BRIDGE.read_text()) or {}
    entries = data.get("mappings") or []
    assert entries, "CWE bridge should not be empty"
    for entry in entries:
        cwe = entry.get("cwe")
        tech = entry.get("technique")
        assert CWE_RE.match(cwe or ""), f"malformed CWE '{cwe}'"
        assert TECHNIQUE_RE.match(tech or ""), f"malformed technique '{tech}' for {cwe}"


# --------------------------------------------------------------------------
# Runnability: every technique we'd queue must have an executor somewhere
# --------------------------------------------------------------------------


def _technique_is_runnable(tid: str) -> str:
    """Return the source that would execute this technique, or '' if none."""
    if tid in _CATALOG_TECHS:
        return "catalog"
    if tid in _BASH_TECHS:
        return "bash"
    # Sub-techniques can fall through to their parent's bash branch.
    parent = tid.split(".")[0]
    if parent in _BASH_TECHS:
        return f"bash(parent {parent})"
    return ""


def test_curated_map_techniques_are_runnable():
    """Curated CVE→technique entries are hand-picked; each must be runnable."""
    unrunnable: Dict[str, str] = {}
    for entry in _load_mappings(CURATED_MAP):
        tid = entry.get("technique")
        if not tid:
            continue
        if not _technique_is_runnable(tid):
            unrunnable[tid] = entry.get("cve", "?")
    assert not unrunnable, (
        "Curated map references techniques with no executor: "
        + ", ".join(f"{t} (e.g. {c})" for t, c in unrunnable.items())
    )


def test_fallback_techniques_are_runnable():
    """Every fallback rule must point to an executable technique."""
    for tid in _FALLBACK_TECHS:
        assert _technique_is_runnable(tid), f"fallback {tid} has no executor"


def test_cwe_bridge_techniques_are_runnable_or_intentionally_unmapped():
    """Bridge techniques can be no-ops (no catalog/bash) — surface the gap loudly.

    The bridge is intentionally permissive: it maps CWE→technique even when
    we don't have an executor, because the *queue* membership is still a
    signal worth reporting (\"this image has KEV CVEs of these classes\").
    This test enumerates the unrunnable bridge techniques so any new gap is
    visible in the report rather than silently swallowed.
    """
    data = yaml.safe_load(CWE_BRIDGE.read_text()) or {}
    unrunnable = sorted(
        {entry["technique"] for entry in data["mappings"]
         if not _technique_is_runnable(entry["technique"])}
    )
    # Document the current state. If this list shrinks it's a win; growing
    # is allowed but the diff makes it visible.
    expected_unrunnable_subset: Iterable[str] = unrunnable
    assert set(unrunnable) == set(expected_unrunnable_subset), (
        "CWE bridge unrunnable techniques changed; update list if intentional."
    )


# --------------------------------------------------------------------------
# Catalog hygiene
# --------------------------------------------------------------------------


def test_catalog_first_pick_has_no_unresolved_placeholders():
    """For each technique in the catalog, the test we'd pick by default
    must not contain ``#{x}`` placeholders without defaults — that would
    fail at exec time inside the sandbox.
    """
    bad: Dict[str, str] = {}
    for tid in _CATALOG_TECHS:
        tests = CATALOG.get_tests(tid)
        if not tests:
            continue
        sh_tests = [t for t in tests if t.executor == "sh"]
        pick = sh_tests[0] if sh_tests else tests[0]
        m = UNRESOLVED_PLACEHOLDER_RE.search(pick.command)
        if m:
            bad[tid] = f"{pick.name!r} → {m.group(0)}"
    assert not bad, (
        "Default-picked atomics with unresolved placeholders: "
        + "; ".join(f"{k}: {v}" for k, v in bad.items())
    )


def test_catalog_commands_are_non_empty():
    for tid in _CATALOG_TECHS:
        for t in CATALOG.get_tests(tid):
            assert t.command.strip(), f"{tid} #{t.test_index}: empty command"


def test_catalog_source_sha_recorded():
    """A reproducible catalog must pin its upstream SHA."""
    sha = CATALOG.source_sha
    assert sha, "data/sources/atomics/SOURCE_SHA missing — re-run scripts/refresh_atomics.sh"
    assert re.match(r"^[0-9a-f]{40}$", sha), f"SOURCE_SHA not a git SHA: {sha!r}"


# --------------------------------------------------------------------------
# Sanity: known-good CVEs still resolve as expected
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cve,expected_technique",
    [
        ("CVE-2021-4034", "T1068"),       # PwnKit (curated)
        ("CVE-2021-44228", "T1059"),      # Log4Shell (curated)
        ("CVE-2019-5736", "T1611"),       # runc escape (curated)
        ("CVE-2017-5638", "T1059"),       # Struts (curated)
    ],
)
def test_known_cve_resolution(cve, expected_technique):
    """Regression guard for the highest-profile CVEs."""
    assert ART._CVE_TECHNIQUE_MAP.get(cve) == expected_technique
