# Implementation Reference

## What is implemented in this first slice
- FastAPI app bootstrap with startup table creation.
- SQLite persistence for runs and findings.
- Run APIs: create, list, get, and status update.
- Finding APIs: create and list findings for a run.
- React dashboard shell with backend health check.
- Docker Compose for local API + frontend startup.
- CI workflow starter for image build + Trivy artifact.
- Scanner script placeholders for Trivy and Atomic.

## Current API routes
- GET /health
- POST /runs
- GET /runs
- GET /runs/{run_id}
- PATCH /runs/{run_id}
- POST /runs/{run_id}/findings
- GET /runs/{run_id}/findings

## Immediate next tasks
1. Add ingestion-specific routes for Trivy, Falco, and Atomic payload formats.
2. Add normalized parser layer for each tool output.
3. Add correlation and risk scoring services.
4. Add remediation generation service and report endpoints.
5. Add automated tests for services and API behavior.

## Notes
- Database file path: data/findings.db
- Atomic validation remains consent-gated by environment variable.
- LLM-based remediation is intentionally deferred to later phase.
