# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

VulBox is an automated application security assessment prototype. It builds a target repository into a Docker image, scans it with Trivy, runs it in an isolated sandbox under Falco monitoring, executes Atomic Red Team tests, and produces a three-dimensional Security Matrix (Presence × Exploitability × Detectability). A FastAPI REST API, a WebSocket status stream, and a React dashboard expose all results.

## Commands

### Backend
```bash
# Activate virtualenv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Drop and recreate DB after schema changes
rm -f data/findings.db

# Start API (hot-reload)
uvicorn app.main:app --reload
# API: http://127.0.0.1:8000
# Docs: http://127.0.0.1:8000/docs
```

### Configuration & running modes
Config is `pydantic-settings` (`app/core/config.py`), resolved highest-priority-first: **process env → `<repo>/.env` → in-code default**. `.env` is gitignored; copy `.env.example` and edit. This is what persists production mode across restarts — set `VULBOX_DEV_MODE=false` in `.env` rather than exporting it per shell.

- Verify the live mode: `GET /health` returns `{"mode": "dev"|"production", "epss_scores_loaded": N}`, and a `VulBox startup` log line echoes it on boot.
- Durable launch: `scripts/serve.sh` (loads `.env`, runs uvicorn from the venv) or, reboot-safe, the systemd unit in `deploy/vulbox.service` (`systemctl enable --now vulbox`; logs via `journalctl -u vulbox`). Bare `nohup uvicorn …` works but does not survive reboot.
- `docker/docker-compose.yml` no longer hardcodes dev mode — `VULBOX_DEV_MODE` is overridable from the host env (defaults to dev for the demo).

### Tests
```bash
source venv/bin/activate
pytest tests/
```

**Test scope (important):** the pytest suite covers unit-level logic only — fixture parsers, correlation, risk-score arithmetic, remediation rendering, CVE-map loading, and LLM prompt construction (mocked client). It does **not** exercise the real Docker build, Trivy CLI, Falco ingestion, Atomic Red Team execution, or any end-to-end pipeline against a real repository. A green run proves parsing/scoring is internally consistent; it does not prove VulBox successfully assesses real targets. End-to-end validation must be done manually via `scripts/demo.py` (dev-mode) or a full-mode run on a host with Docker + Trivy + Falco installed.

### Frontend
```bash
cd frontend
npm install
npm run dev
# Dev server: http://localhost:5173
```

### Docker Compose
```bash
# Standard (dev mode, no Falco):
cd docker && docker compose up

# Full mode (with Falco sidecar):
cd docker && docker compose --profile full up
```

### End-to-end demo
```bash
# With the API running:
python scripts/demo.py
```
The demo authenticates, creates a run, ingests fixture files, polls for completion, and prints the Security Matrix and remediation report.

## Architecture

### Pipeline state machine
```
SUBMITTED → BUILDING → SCANNING → TESTING → (REBUILDING → TESTING)* → REPORTING → COMPLETE
                  ↘ FAILED (only reachable from BUILDING)
```

### Request flow
```
POST /runs              → validate consent → create AssessmentRun → fire Orchestrator as BackgroundTask
GET  /runs/{id}         → poll status
WS   /ws/runs/{id}/status → real-time pipeline events (JSON stream)
GET  /reports/{id}      → full Security Matrix + remediations
GET  /reports/{id}/export?format=json|csv|pdf → downloadable report
GET  /runs/{id}/validations → ARTTestResult rows for the run
```

### Layer map
| Layer | Location | Responsibility |
|---|---|---|
| API routes | `app/api/` | HTTP I/O, delegates to services/orchestrator |
| Orchestrator | `app/services/orchestrator.py` | Central pipeline controller (async state machine) |
| Adapters | `app/adapters/` | Thin wrappers around Trivy, Falco, ART |
| Services | `app/services/` | Business logic (run CRUD, remediation) |
| DockerManager | `app/services/docker_manager.py` | Clone, build, sandbox, rebuild |
| Models | `app/models/` | SQLAlchemy ORM table definitions |
| Schemas | `app/schemas/` | Pydantic request/response shapes |
| Core | `app/core/` | DB, config, structured logging, JWT security |

### Key data model
- **AssessmentRun** (`assessment_runs`) — top-level container; status ∈ {SUBMITTED, BUILDING, SCANNING, TESTING, REBUILDING, REPORTING, COMPLETE, FAILED}; `consent_granted` must be true before any ART tests
- **TrivyFinding** (`trivy_findings`) — per-CVE static scan result; `fix_available` flag; `cwe_ids` (comma-joined CWEs from Trivy, drives the scan-time CWE bridge) and `epss_score` (0–1 exploitation probability, enriched from the EPSS snapshot)
- **ARTTestResult** (`art_test_results`) — per-technique ART result; `exploited` and `crash_occurred` booleans
- **FalcoAlert** (`falco_alerts`) — runtime alert; `test_result_id` FK links detection to the specific test that triggered it
- **SecurityMatrixEntry** (`security_matrix_entries`) — three-dimensional output: `is_present`, `is_exploitable`, `is_detectable`, `risk_score` (0–75)
- **Remediation** (`remediations`) — one actionable fix per SecurityMatrixEntry; `matrix_entry_id` FK; `generated_by` ∈ {static, llm}, `source` (e.g. "gemini" / "rule-based"), `references`
- **RunSummary** (`run_summaries`) — one run-level executive summary per run; `top_priorities` is JSON-encoded list[str]; `generated_by` ∈ {static, llm}
- **User** (`users`) — JWT auth user; `role` ∈ {provider, admin}

### Risk scoring (`app/services/orchestrator.py → _compute_risk`)
Base 10 (present) + 30 if exploited + 10 if undetected + severity weight (critical 20 / high 15 / medium 10 / low 5 / unknown 0). Capped at 75 (`RISK_SCORE_MAX`).

### Adapters (`app/adapters/`)
- In **dev mode** (`VULBOX_DEV_MODE=true`): all adapters read from `data/sample_outputs/` fixture files, no Docker/Trivy/Falco processes launched.
- In **production mode**: `TrivyAdapter` calls `trivy` CLI, `FalcoAdapter` starts Falco sidecar, `ARTAdapter` calls `scanners/atomic_runner.sh`.
- `TrivyAdapter.is_blocking()` always returns `False` (Non-Blocking Rule §4.12.2).
- `ARTAdapter.build_queue` returns `List[(technique, [finding_id, ...])]` — **fan-out**: each technique runs once but every motivating CVE sharing it gets its own `SecurityMatrixEntry` (one exploitability verdict per CVE, not just one per technique). Proactive/fallback techniques carry an empty list.
- **CWE bridging** (`data/cwe_technique_map.yml`, ~80 CWEs): when a finding's CVE isn't in the CVE→technique map, the adapter bridges the finding's `cwe_ids` to technique(s) so the CVE still gets tested. This is the main coverage lever — more detected CVEs reach an exploitability verdict.
- **EPSS** (`app/services/epss.py`): the queue rank tuple is `(stack_relevant, ransomware, kev, -epss, idx)` so actively-predicted-exploitable CVEs are tested first. `VULBOX_EPSS_MIN` (default `0.0` = off) gates per-CVE fan-out: when raised, only CVEs at/above the threshold are attributed (KEV/ransomware always included), bounding matrix size on large scans while the technique still runs.
- **Severity gate** (`AssessmentRun.min_severity`, set per-run from the New Run slider; default `high`): a second per-CVE fan-out gate alongside EPSS. Only findings at/above the chosen severity (`critical`/`high`/`medium`/`low`) get their own matrix row; `low` disables the gate (tests everything, incl. unknown severity). The technique still runs regardless — this only governs matrix attribution, which is the main lever on report size. `_passes_severity_gate` in `art_adapter.py`.
- **Report ordering**: `GET /reports/{id}` and the CSV/PDF export sort the security matrix and remediation cards critical→low (severity band, then risk score). `LLMRemediationService` also processes entries highest-risk-first so critical findings get the real Gemini call before any rate-limit/backup failover. The Report screen adds client-side severity + min-risk filters over both the matrix table and remediation cards.

### EPSS snapshot
Vendored at `data/sources/epss.csv.gz` (FIRST.org daily CSV, `cve,epss,percentile`, ~335k rows). Loaded once at import by `app/services/epss.py`; a missing/corrupt file degrades to no scores (never crashes). Snapshots age — refresh with `python scripts/fetch_epss.py` (same explicit-refresh pattern as `data/sources/kev.json`). The report exposes a coverage stat: "exploitability tested for N of M detected CVEs".

### Validation harness
`python scripts/validate_e2e.py` (Docker + Trivy required) runs the static half of the pipeline against the image corpus in `tests/ground_truth/manifest.yml` and writes `docs/validation_report.md`. Besides finding/queue counts it now reports the coverage signals: tested/detected CVE ratio, CVE-map vs CWE-bridge provenance split, and EPSS max per image. Manifest `expectations` support `findings.must_contain_cve` and a `coverage` block (`min_ratio`, `min_tested`, `min_bridge`). `--report-only` rebuilds the report from cached results without Docker.

### Multi-stack e2e (vulhub-style)
- **Tier A (static, in the manifest):** the corpus includes one EOL base/app image per tech profile (python / node / java-tomcat / php / ruby) on top of the alpine/debian control cases. Run via `validate_e2e.py`. vulhub's compose stacks aren't driven directly (multi-container); we scan the stable images they're built on so Trivy stays deterministic.
- **Tier B (full dynamic, gated):** `tests/e2e/test_full_pipeline.py` is parametrized over buildable single-Dockerfile targets in `tests/e2e/fixtures/` (`vulnerable_target` = node/express, `vulnerable_python` = python/flask). Each runs the whole pipeline (build → Trivy → sandbox → ART → report) and asserts stack detection + the per-CVE coverage lift. Add a stack = one fixture dir + one row in `TARGETS`. Opt in with `pytest -m e2e` (auto-skips without Docker/Trivy/Falco).

### LLM remediation (Google Gemini)
- `LLMRemediationService` (`app/services/llm_remediation.py`) generates one remediation per SecurityMatrixEntry; entries with `risk_score ≥ VULBOX_LLM_MIN_RISK_SCORE` get a Gemini call, the rest use the static `RemediationService` rule. `RunSummaryService` adds one run-level executive summary.
- `GeminiProvider` (`app/services/llm_provider.py`) owns the **primary → backup** failover: one API key, `gemini-2.5-flash` serves every call, `gemini-2.5-flash-lite` is the failover on API error / 429 `RESOURCE_EXHAUSTED` / timeout. Returns parsed JSON or `None`; never raises.
- **Any failure → static fallback.** Missing key/SDK, both models erroring, or malformed JSON all fall back to the rule-based path, so the report always populates. Responses are cached on disk under `data/llm_cache/`.
- ART runner output is untrusted (hostile container); it's wrapped in `<evidence>` tags and the response is schema-validated.
- Env vars: `VULBOX_LLM_REMEDIATION` (enable, default false), `GEMINI_API_KEY`, `VULBOX_LLM_MODEL_PRIMARY`, `VULBOX_LLM_MODEL_BACKUP`, `VULBOX_LLM_MIN_RISK_SCORE`, `VULBOX_LLM_TIMEOUT_SECS`, `VULBOX_LLM_MAX_TOKENS`, `VULBOX_LLM_EXEC_SUMMARY` (default true).

### Authentication
- JWT via `python-jose` (HS256). Secret from `VULBOX_SECRET_KEY` env var.
- `POST /auth/register`, `POST /auth/login`, `GET /auth/me`
- Token passed as `Authorization: Bearer <token>` header.

### Database
SQLite at `data/findings.db`. Tables auto-created on startup via `Base.metadata.create_all`. No migrations framework — drop and recreate for schema changes.

### Frontend (4 screens)
| Screen | Path | Description |
|---|---|---|
| Login | `/login` | Email + password, stores JWT in localStorage |
| Register | `/register` | Create provider account |
| New Run | `/` | Submit repo URL + consent checkbox |
| Live Status | `/runs/:id/status` | WebSocket-driven phase progress + event log |
| Report | `/runs/:id/report` | Security Matrix table + remediations + PDF/CSV export |

## Vendored sources (`data/sources/`)
- `kev.json` — CISA Known Exploited Vulnerabilities (refresh per `scripts/build_cve_map.py` docstring).
- `attack_to_cve.csv` — Center for Threat-Informed Defense CVE→ATT&CK mappings.
- `epss.csv.gz` — FIRST.org EPSS daily snapshot (refresh with `scripts/fetch_epss.py`).
- `atomics/` — vendored Atomic Red Team catalog.

## Sample fixtures
`data/sample_outputs/` contains representative JSON outputs:
- `trivy-fixture.json` — Trivy image scan report
- `falco-fixture.json` — Falco alert stream
- `atomic-fixture.json` — Atomic Red Team test results

## Directory layout
```
app/
  adapters/     trivy_adapter.py  falco_adapter.py  art_adapter.py
  api/          runs.py  reports.py  ingest.py  auth.py  websocket.py
  core/         config.py  database.py  logging.py  security.py
  models/       run.py  trivy_finding.py  art_test_result.py
                falco_alert.py  security_matrix_entry.py  remediation.py  user.py
  schemas/      run.py  report.py  trivy.py  falco.py  atomic.py
  services/     orchestrator.py  docker_manager.py  run_service.py  remediation_service.py
                llm_remediation.py  llm_provider.py  run_summary_service.py
ci/             github-actions.yml  gitlab-ci-sample.yml
docker/         Dockerfile.app  Dockerfile.target-app  docker-compose.yml
frontend/src/
  pages/        Login.jsx  Register.jsx  NewRun.jsx  RunStatus.jsx  Report.jsx
tests/          test_parsers.py  test_correlation.py  test_remediation.py
data/sample_outputs/  trivy-fixture.json  falco-fixture.json  atomic-fixture.json
scanners/       trivy_runner.sh  atomic_runner.sh
scripts/        demo.py
```

## CI
`ci/github-actions.yml` triggers `POST /runs` against the deployed API and polls until COMPLETE. Trivy still runs as part of the VulBox pipeline (not as a standalone step). A GitLab equivalent is in `ci/gitlab-ci-sample.yml`.
