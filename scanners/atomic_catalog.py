"""Parse vendored Atomic Red Team YAMLs into a queryable catalog.

The atomics tree under ``data/sources/atomics/`` mirrors the upstream
redcanaryco/atomic-red-team layout: one ``Txxxx/Txxxx.yaml`` file per
technique, each containing one or more ``atomic_tests`` definitions.

This module loads those YAMLs and exposes them as :class:`AtomicTest`
objects. The runner in :mod:`scanners.atomic_runner` consumes the result to
build ``docker exec`` commands that target our sandbox container.

The catalog is *read-only* and stateless — it eagerly walks the directory
once at module import to fail loudly on a missing or malformed file, then
serves queries from in-memory dicts.

Why we parse rather than depend on `atomic-operator`:

* ``atomic-operator`` is CLI-shaped; its executor model assumes the calling
  host *is* the target. Our target is a hostile sandbox container, so we
  run the test commands ourselves via ``docker exec``.
* Reading the YAMLs is a small parser (everything we need is one level
  deep) and avoids carrying a pip dependency for what's essentially data.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

# Linux executors we know how to run inside a docker container.
_LINUX_EXECUTORS = {"sh", "bash"}

# ``{{name}}`` placeholders substituted from ``input_arguments`` defaults.
_ARG_PATTERN = re.compile(r"#\{(\w+)\}")


@dataclass(frozen=True)
class AtomicTest:
    """One executable test within a technique's atomic_tests list."""

    technique_id: str
    test_index: int  # 1-based index into the YAML's atomic_tests list
    name: str
    executor: str  # "sh" | "bash"
    command: str  # ready-to-exec, with #{x} placeholders resolved
    cleanup_command: Optional[str]
    supported_platforms: List[str] = field(default_factory=list)
    elevation_required: bool = False


class AtomicCatalog:
    """In-memory catalog of Linux-runnable atomic tests."""

    def __init__(self, atomics_root: Path):
        self._root = atomics_root
        self._by_technique: Dict[str, List[AtomicTest]] = {}
        if atomics_root.is_dir():
            self._load()

    @property
    def source_sha(self) -> Optional[str]:
        sha_file = self._root / "SOURCE_SHA"
        if not sha_file.is_file():
            return None
        return sha_file.read_text().split()[0]

    def technique_ids(self) -> List[str]:
        return sorted(self._by_technique.keys())

    def get_tests(
        self, technique_id: str, *, executor: Optional[str] = None
    ) -> List[AtomicTest]:
        """Return all Linux atomic tests for ``technique_id``.

        ``executor`` (``"sh"`` or ``"bash"``) filters further; default
        returns both. If the technique has no Linux atomics in the
        vendored tree, the returned list is empty — callers should fall
        back to the container-native bash runner.
        """
        tests = self._by_technique.get(technique_id, [])
        if executor:
            tests = [t for t in tests if t.executor == executor]
        return tests

    def has_linux_atomic(self, technique_id: str) -> bool:
        return bool(self._by_technique.get(technique_id))

    # ---- loading ---------------------------------------------------------

    def _load(self) -> None:
        for yaml_path in sorted(self._root.glob("T*/*.yaml")):
            try:
                self._ingest_file(yaml_path)
            except (yaml.YAMLError, KeyError, TypeError) as exc:
                # One malformed YAML shouldn't disable the whole catalog;
                # log to stderr and keep going.
                import sys
                print(
                    f"[atomic_catalog] skipping {yaml_path.name}: {exc}",
                    file=sys.stderr,
                )

    def _ingest_file(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text()) or {}
        tid = data.get("attack_technique")
        tests_raw = data.get("atomic_tests") or []
        if not tid or not tests_raw:
            return

        out: List[AtomicTest] = []
        for idx, t in enumerate(tests_raw, start=1):
            plats = t.get("supported_platforms") or []
            if "linux" not in plats:
                continue
            executor_block = t.get("executor") or {}
            exec_name = executor_block.get("name")
            if exec_name not in _LINUX_EXECUTORS:
                continue
            raw_command = executor_block.get("command")
            if not raw_command:
                continue

            resolved_cmd = _substitute_args(raw_command, t.get("input_arguments") or {})
            cleanup_raw = executor_block.get("cleanup_command")
            cleanup_resolved = (
                _substitute_args(cleanup_raw, t.get("input_arguments") or {})
                if cleanup_raw
                else None
            )

            out.append(
                AtomicTest(
                    technique_id=tid,
                    test_index=idx,
                    name=str(t.get("name", "")).strip(),
                    executor=exec_name,
                    command=resolved_cmd.strip(),
                    cleanup_command=cleanup_resolved.strip() if cleanup_resolved else None,
                    supported_platforms=list(plats),
                    elevation_required=bool(t.get("executor", {}).get("elevation_required", False)),
                )
            )

        if out:
            self._by_technique[tid] = out


def _substitute_args(template: str, input_arguments: dict) -> str:
    """Replace ``#{name}`` placeholders with each argument's ``default``.

    If an argument has no default, the placeholder is left in place — the
    runner will surface that as a test that cannot run unattended (a fair
    outcome rather than executing a half-resolved command).
    """
    def _repl(m: re.Match) -> str:
        name = m.group(1)
        spec = input_arguments.get(name) or {}
        default = spec.get("default")
        return str(default) if default is not None else m.group(0)

    return _ARG_PATTERN.sub(_repl, template)


# Module-level singleton — loads at import.
_DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "data" / "sources" / "atomics"
CATALOG = AtomicCatalog(_DEFAULT_ROOT)
