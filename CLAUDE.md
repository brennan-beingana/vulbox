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

### Tests
```bash
source venv/bin/activate
pytest tests/
```

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
- **TrivyFinding** (`trivy_findings`) — per-CVE static scan result; `fix_available` flag
- **ARTTestResult** (`art_test_results`) — per-technique ART result; `exploited` and `crash_occurred` booleans
- **FalcoAlert** (`falco_alerts`) — runtime alert; `test_result_id` FK links detection to the specific test that triggered it
- **SecurityMatrixEntry** (`security_matrix_entries`) — three-dimensional output: `is_present`, `is_exploitable`, `is_detectable`, `risk_score` (0–50)
- **Remediation** (`remediations`) — one actionable fix per SecurityMatrixEntry; `matrix_entry_id` FK
- **User** (`users`) — JWT auth user; `role` ∈ {provider, admin}

### Risk scoring (`app/services/orchestrator.py → _compute_risk`)
Base 10 (present) + 30 if exploited + 10 if undetected. Capped at 50.

### Adapters (`app/adapters/`)
- In **dev mode** (`VULBOX_DEV_MODE=true`): all adapters read from `data/sample_outputs/` fixture files, no Docker/Trivy/Falco processes launched.
- In **production mode**: `TrivyAdapter` calls `trivy` CLI, `FalcoAdapter` starts Falco sidecar, `ARTAdapter` calls `scanners/atomic_runner.sh`.
- `TrivyAdapter.is_blocking()` always returns `False` (Non-Blocking Rule §4.12.2).

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
