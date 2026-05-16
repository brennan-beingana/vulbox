"""Tests for the ART YAML catalog and the Python runner's selection logic."""
from pathlib import Path

import pytest
import yaml

from scanners.atomic_catalog import CATALOG, AtomicCatalog, AtomicTest


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def test_module_singleton_loads_vendored_yamls():
    """The shipped catalog should expose at least the techniques we know are present."""
    ids = CATALOG.technique_ids()
    # Spot-check a few we verified upstream during Sprint 2 setup.
    assert "T1059.004" in ids
    assert "T1083" in ids
    assert "T1552.001" in ids


def test_get_tests_filters_to_linux_only():
    """Loader must exclude Windows/macOS-only atomic_tests from the catalog."""
    tests = CATALOG.get_tests("T1059.004")
    assert tests, "expected at least one Linux atomic for T1059.004"
    for t in tests:
        assert "linux" in t.supported_platforms


def test_executor_filter():
    tests = CATALOG.get_tests("T1552.001", executor="sh")
    for t in tests:
        assert t.executor == "sh"


def test_unknown_technique_returns_empty():
    assert CATALOG.get_tests("T9999") == []
    assert not CATALOG.has_linux_atomic("T9999")


def test_input_argument_substitution(tmp_path):
    """``#{name}`` placeholders should resolve to the input_arguments default."""
    yaml_path = tmp_path / "atomics" / "T9001" / "T9001.yaml"
    _write_yaml(
        yaml_path,
        {
            "attack_technique": "T9001",
            "display_name": "fake",
            "atomic_tests": [
                {
                    "name": "Echo placeholder",
                    "supported_platforms": ["linux"],
                    "input_arguments": {
                        "msg": {"description": "greeting", "type": "string", "default": "hello"}
                    },
                    "executor": {
                        "name": "sh",
                        "command": 'echo "#{msg}"',
                    },
                }
            ],
        },
    )
    catalog = AtomicCatalog(tmp_path / "atomics")
    tests = catalog.get_tests("T9001")
    assert len(tests) == 1
    assert tests[0].command == 'echo "hello"'


def test_unresolved_placeholder_is_left_in_place(tmp_path):
    """Missing defaults should not silently produce broken commands."""
    yaml_path = tmp_path / "atomics" / "T9002" / "T9002.yaml"
    _write_yaml(
        yaml_path,
        {
            "attack_technique": "T9002",
            "atomic_tests": [
                {
                    "name": "Missing default",
                    "supported_platforms": ["linux"],
                    "input_arguments": {"target": {"description": "x", "type": "string"}},
                    "executor": {"name": "sh", "command": "ls #{target}"},
                }
            ],
        },
    )
    catalog = AtomicCatalog(tmp_path / "atomics")
    tests = catalog.get_tests("T9002")
    # Placeholder remains, telling the runner this test isn't unattended-safe.
    assert "#{target}" in tests[0].command


def test_malformed_yaml_does_not_break_catalog(tmp_path, capsys):
    good = tmp_path / "atomics" / "T9003" / "T9003.yaml"
    bad = tmp_path / "atomics" / "T9004" / "T9004.yaml"
    _write_yaml(
        good,
        {
            "attack_technique": "T9003",
            "atomic_tests": [
                {
                    "name": "ok",
                    "supported_platforms": ["linux"],
                    "executor": {"name": "sh", "command": "true"},
                }
            ],
        },
    )
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("attack_technique: [unclosed")

    catalog = AtomicCatalog(tmp_path / "atomics")
    # Good one still loads.
    assert "T9003" in catalog.technique_ids()
    # Bad one is skipped with a stderr note.
    err = capsys.readouterr().err
    assert "T9004" in err


def test_runner_selects_sh_over_bash(tmp_path, monkeypatch):
    """Runner should prefer sh when both executor variants exist."""
    from scanners import atomic_runner

    # Build a synthetic catalog inline.
    fake = AtomicCatalog(tmp_path / "atomics-empty")  # empty by design
    fake._by_technique["T9005"] = [
        AtomicTest(
            technique_id="T9005",
            test_index=1,
            name="bash test",
            executor="bash",
            command="echo bash",
            cleanup_command=None,
            supported_platforms=["linux"],
        ),
        AtomicTest(
            technique_id="T9005",
            test_index=2,
            name="sh test",
            executor="sh",
            command="echo sh",
            cleanup_command=None,
            supported_platforms=["linux"],
        ),
    ]
    monkeypatch.setattr(atomic_runner, "CATALOG", fake)
    chosen = atomic_runner._select_test("T9005", prefer_executor=None, test_index=None)
    assert chosen is not None
    assert chosen.executor == "sh"


def test_runner_select_by_index(tmp_path, monkeypatch):
    from scanners import atomic_runner

    fake = AtomicCatalog(tmp_path / "atomics-empty")
    fake._by_technique["T9006"] = [
        AtomicTest("T9006", 1, "first", "sh", "echo 1", None),
        AtomicTest("T9006", 2, "second", "sh", "echo 2", None),
    ]
    monkeypatch.setattr(atomic_runner, "CATALOG", fake)
    chosen = atomic_runner._select_test("T9006", prefer_executor=None, test_index=2)
    assert chosen is not None
    assert chosen.test_index == 2
