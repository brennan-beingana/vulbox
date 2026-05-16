"""Execute a single ATT&CK technique against the sandbox container.

Replaces the case-statement in ``scanners/atomic_runner.sh`` for techniques
where the vendored Atomic Red Team catalog has a Linux-supported test.
Techniques without a usable atomic (container-escape, systemd-write, etc.)
defer to the original bash runner, which still hosts the hand-written
probes designed for our sandbox model.

Exit conventions (consumed by ``app.adapters.art_adapter.ARTAdapter._run_atomic``):

* ``0``  technique exploited (image is vulnerable)
* ``1``  technique failed / not applicable / no Linux atomic available
* ``2``  sandbox container crashed mid-test (orchestrator rebuilds)

Required environment:

* ``VULBOX_SANDBOX_CONTAINER``  container id/name to ``docker exec`` into
* ``ATOMIC_CONSENT=true``       consent gate (FR-01)

Optional:

* ``ATOMIC_BASH_FALLBACK=/path/to/atomic_runner.sh`` — invoked when the
  catalog yields no usable test. Defaults to the sibling shell script.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Optional

from scanners.atomic_catalog import CATALOG, AtomicTest

DEFAULT_BASH_FALLBACK = Path(__file__).resolve().parent / "atomic_runner.sh"


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Execute one ATT&CK technique via docker exec.")
    parser.add_argument("technique_id", help="MITRE technique id, e.g. T1059.004")
    parser.add_argument(
        "--prefer-executor",
        choices=("sh", "bash"),
        help="Force a specific executor when multiple Linux tests exist.",
    )
    parser.add_argument(
        "--test-index",
        type=int,
        help="Run a specific 1-based atomic test index. Default: first usable.",
    )
    args = parser.parse_args(argv)

    if os.environ.get("ATOMIC_CONSENT") != "true":
        print("Atomic validation blocked: set ATOMIC_CONSENT=true to proceed.")
        return 1

    container = os.environ.get("VULBOX_SANDBOX_CONTAINER", "")
    if not container:
        print("VULBOX_SANDBOX_CONTAINER not set; cannot exec. Treating as non-exploitable.")
        return 1

    state = _container_state(container)
    if state != "running":
        print(f"Sandbox container state={state} — crash.")
        return 2

    test = _select_test(args.technique_id, args.prefer_executor, args.test_index)
    if test is None:
        return _delegate_to_bash(args.technique_id)

    rc = _exec_atomic(container, test)

    # Re-check container after the test. If we broke it, return crash so the
    # orchestrator rebuilds before the next technique.
    after = _container_state(container)
    if after != "running":
        print(f">>> Sandbox state after test: {after} — crash")
        return 2

    return rc


def _select_test(
    technique_id: str, prefer_executor: Optional[str], test_index: Optional[int]
) -> Optional[AtomicTest]:
    tests = CATALOG.get_tests(technique_id, executor=prefer_executor)
    if not tests:
        return None
    if test_index:
        for t in tests:
            if t.test_index == test_index:
                return t
        return None
    # Default selection: first sh test if any, else first bash test. Shell
    # ("sh") is more universal across minimal images than bash.
    sh_tests = [t for t in tests if t.executor == "sh"]
    return sh_tests[0] if sh_tests else tests[0]


def _container_state(container: str) -> str:
    res = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}}", container],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return "missing"
    return res.stdout.strip() or "missing"


def _exec_atomic(container: str, test: AtomicTest) -> int:
    """Run the atomic's command inside the container via ``docker exec``.

    The command is wrapped in ``sh -c`` (or ``bash -c``) so multi-line
    pipelines and shell features work the same way they did when the test
    was authored. Output is streamed to our stdout/stderr for the log file.
    """
    shell = "/bin/bash" if test.executor == "bash" else "/bin/sh"
    print(f">>> [{test.technique_id} #{test.test_index}] {test.name}")
    print(f">>> executor: {test.executor}  command:")
    for line in test.command.splitlines():
        print(f"      {line}")

    proc = subprocess.run(
        ["docker", "exec", container, shell, "-c", test.command],
        capture_output=True,
        text=True,
    )
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)

    if proc.returncode == 0:
        print(">>> RESULT: success")
        return 0
    print(f">>> RESULT: failure (rc={proc.returncode})")
    return 1


def _delegate_to_bash(technique_id: str) -> int:
    """No atomic available → fall through to the legacy bash probes."""
    runner = Path(os.environ.get("ATOMIC_BASH_FALLBACK") or DEFAULT_BASH_FALLBACK)
    if not runner.is_file():
        print(f">>> No catalog test for {technique_id} and no bash fallback at {runner}")
        return 1
    print(f">>> [{technique_id}] no Linux atomic available; deferring to {runner.name}")
    res = subprocess.run(
        ["bash", str(runner), technique_id],
        env={**os.environ},
    )
    return res.returncode


if __name__ == "__main__":
    # Allow direct execution: python scanners/atomic_runner.py T1059.004
    # When called via `python scanners/atomic_runner.py` from project root,
    # ensure imports resolve.
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    sys.exit(main())
