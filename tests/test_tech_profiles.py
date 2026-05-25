"""Unit tests for the tech attack profile catalog + loader."""
import os
import re
from pathlib import Path

os.environ["VULBOX_DEV_MODE"] = "true"

from app.core.config import settings  # noqa: E402
from app.services.tech_profiles import (  # noqa: E402
    load_tech_profiles,
    techniques_for,
)

_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _executable_techniques() -> set:
    """Techniques VulBox can actually run: vendored atomics ∪ bash-runner probes."""
    root = settings.project_root
    vendored = {
        p.name
        for p in (root / "data" / "sources" / "atomics").iterdir()
        if p.is_dir() and p.name.startswith("T")
    }
    bash_runner = set(
        _TECHNIQUE_RE.findall((root / "scanners" / "atomic_runner.sh").read_text())
    )
    return vendored | bash_runner


def test_loader_returns_nonempty_mapping():
    profiles = load_tech_profiles()
    assert profiles
    assert "fastapi" in profiles
    assert "T1190" in profiles["fastapi"]


def test_every_profile_technique_is_executable():
    """The catalog must never reference a technique we can't run."""
    executable = _executable_techniques()
    profiles = load_tech_profiles()
    orphans = {
        tid
        for ids in profiles.values()
        for tid in ids
        if tid not in executable
    }
    assert not orphans, f"profiles reference non-executable techniques: {sorted(orphans)}"


def test_technique_ids_are_well_formed():
    for ids in load_tech_profiles().values():
        for tid in ids:
            assert _TECHNIQUE_RE.fullmatch(tid), f"malformed technique id: {tid}"


def test_techniques_for_aggregates_base_and_framework():
    # A FastAPI app detected as {python, fastapi, uvicorn} should pull from all three.
    techniques = techniques_for({"python", "fastapi", "uvicorn"})
    assert "T1190" in techniques       # from fastapi/uvicorn
    assert "T1059.006" in techniques   # python execution
    assert "T1505.003" in techniques   # web shell


def test_techniques_for_dedups():
    techniques = techniques_for({"python", "fastapi"})
    assert len(techniques) == len(set(techniques))


def test_techniques_for_base_precedes_framework():
    # python base techniques are listed before fastapi in the catalog, so a
    # python-only technique should appear before a fastapi-only one.
    techniques = techniques_for({"python", "fastapi"})
    assert techniques.index("T1083") < techniques.index("T1505.003")


def test_techniques_for_unknown_tags_returns_empty():
    assert techniques_for({"cobol", "haskell"}) == []


def test_techniques_for_empty_tags_returns_empty():
    assert techniques_for(set()) == []
