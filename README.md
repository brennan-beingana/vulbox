# VulBox

Automated application security assessment prototype combining static scanning, runtime signals, and validation outcomes.

## Implemented now
- FastAPI backend skeleton with SQLite persistence.
- Core run and finding routes.
- React dashboard shell.
- Docker Compose startup for backend and frontend.
- Starter CI workflow for Trivy artifact generation.

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

## Next milestones
1. Tool-specific ingestion endpoints (Trivy/Falco/Atomic)
2. Correlation and risk scoring engine
3. Remediation generator and reporting endpoints
4. End-to-end tests and demo fixture pipeline
