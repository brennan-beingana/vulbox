# VulBox

Automated application security assessment prototype combining static scanning, runtime signals, and validation outcomes.

## Implemented now
- FastAPI backend with async orchestrator (`SUBMITTED → BUILDING → SCANNING → TESTING → REPORTING → COMPLETE`) and SQLite persistence.
- JWT auth scaffolding (`/auth/register`, `/auth/login`, `/auth/me`). **Note:** data-plane routes are not yet auth-gated — see `docs/PROGRESS_REPORT.md` §5.1.
- Trivy / Falco / Atomic Red Team adapters with dev-mode fixture replay.
- CVE → MITRE map: **1,465 unique CVEs** (55 curated + 2017 generated), **1,060 KEV-flagged**, 17 ART techniques with **88 vendored Linux atomic tests** (`data/sources/atomics/`, pinned SHA).
- LLM remediation service (OpenAI) with static-rule fallback and prompt-cache-friendly inputs.
- WebSocket pipeline-event stream with 200-event replay buffer.
- React dashboard: Login / Register / Dashboard / RunStatus / Report / Reports / Profile / Guides.
- Ground-truth validation harness (`scripts/validate_e2e.py` + `tests/ground_truth/manifest.yml`). Infrastructure ready; not yet executed on a Docker host.
- GitHub Actions workflows (`.github/workflows/ci.yml`, `security-assessment.yml`) and a demo runbook (`docs/DEMO_RUNBOOK.md`).

## Project layout
- app/: backend application code
- frontend/: React dashboard
- scanners/: helper scripts for tool execution
- docker/: compose setup
- docs/: architecture and implementation references
- tests/: test suite placeholder

## Run locally
### Backend
1. Create and activate a Python virtual environment.
2. Install requirements:
   pip install -r requirements.txt
3. Start API:
   uvicorn app.main:app --reload

### Frontend
1. Open a second terminal.
2. Install dependencies and run dev server:
   cd frontend
   npm install
   npm run dev

## Run with Docker Compose
From the docker directory:
  docker compose up

## Test scope

The pytest suite (`tests/`) covers unit-level logic only:
- Fixture parsers (Trivy, Falco, Atomic JSON shapes)
- Correlation engine and risk-score arithmetic
- Remediation rendering and CVE-map loading
- LLM remediation prompt construction (mocked client)

The suite does **not** exercise:
- Docker image build or sandbox runtime
- Real Trivy CLI invocation
- Falco event ingestion from a live kernel
- Atomic Red Team test execution
- End-to-end pipeline against a real repository

A green test run is evidence the parsing and scoring code is internally consistent. It is **not** evidence that VulBox successfully assesses real targets. Validation against real repositories must be done manually via `scripts/demo.py` (dev-mode, fixture-driven) or a full-mode run on the deployment VM with Docker, Trivy, and Falco installed.

## Next milestones (toward consumer-ready)
1. Apply `Depends(get_current_user)` to every route in `runs.py`, `reports.py`, `ingest.py`, and the WebSocket. Add `user_id` FK on `AssessmentRun` and scope queries.
2. Run `scripts/validate_e2e.py` on a Docker-enabled host so `docs/validation_report.md` carries real numbers, not "No results yet."
3. Build the LLM golden-set (~15 hand-written `evidence → expected remediation` pairs) and an output-quality harness.
4. `.vulbox.yml` v1 schema (techniques to skip, sensitive paths, network allow-list) and a "Configure run" frontend step.
5. Add Alembic migrations, an `error_message` column on `AssessmentRun`, and replace the hardcoded frontend API URL with `VITE_API_BASE_URL`.

See `docs/JOURNEY.md` for a narrative of what has been built so far, what fallbacks are in place, and what is still missing. `docs/PROGRESS_REPORT.md` is the long-form audit.
