# vulnerable_python — VulBox E2E fixture

**Intentionally vulnerable. Do not deploy.** A buildable single-Dockerfile
Python/Flask target used by `tests/e2e/test_full_pipeline.py` to exercise the
full pipeline (build → Trivy → sandbox → ART → report) against a non-Node stack.

Why it produces deterministic results:
- **`python:3.6-slim` base image** — end-of-life, ships a known set of Debian
  base-image CVEs.
- **Pinned EOL Flask/Werkzeug stack** (`requirements.txt`) — adds Python-package
  findings and makes `StackDetector` emit `python` + `flask`.

The app (`app.py`) is a long-running Flask server so the sandbox stays up for
the ART phase. It is the second target in the parametrized e2e suite, alongside
`vulnerable_target/` (node/express).
