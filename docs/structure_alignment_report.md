# Repository Structure Alignment Evaluation

## Summary
The current implementation has **foundation-grade coverage** (40% of full spec) with a working backend skeleton and frontend shell. Major gaps exist in tool-specific parsers, correlation/remediation services, and the data models for validations. Alignment with the design doc is **partial but directional**.

---

## Specification vs. Implementation

### ✅ IMPLEMENTED (MATCHES SPEC)
| Component | Location | Status |
|-----------|----------|--------|
| main.py | `/app/main.py` | ✅ Present |
| findings.py | `/app/api/findings.py` | ✅ Present |
| runs.py | `/app/api/runs.py` | ✅ Present |
| config.py | `/app/core/config.py` | ✅ Present |
| database.py | `/app/core/database.py` | ✅ Implemented (bonus) |
| run.py | `/app/models/run.py` | ✅ Present |
| finding.py | `/app/models/finding.py` | ✅ Present |
| finding_service.py | `/app/services/finding_service.py` | ✅ Implemented (bonus) |
| run_service.py | `/app/services/run_service.py` | ✅ Implemented (bonus) |
| api/__init__.py | `/app/api/__init__.py` | ✅ Implemented (bonus: router aggregation) |
| trivy_runner.sh | `/scanners/trivy_runner.sh` | ✅ Placeholder present |
| atomic_runner.sh | `/scanners/atomic_runner.sh` | ✅ Placeholder present |
| docker-compose.yml | `/docker/docker-compose.yml` | ✅ Present |
| GitHub Actions stub | `.github/workflows/security-assessment.yml` | ✅ Present |
| README.md | `/README.md` | ✅ Present |

**Count: 14 of ~30 expected items** ✅

---

### ⚠️ MISSING - HIGH PRIORITY (Core Functionality)

| Component | Expected Location | Reason | Impact |
|-----------|-------------------|--------|--------|
| reports.py | `/app/api/reports.py` | Not created | Blocks reporting endpoints |
| parser_service.py | `/app/services/parser_service.py` | Not created | Cannot normalize Trivy/Falco/Atomic outputs |
| correlation_service.py | `/app/services/correlation_service.py` | Not created | Cannot merge findings by metadata or compute risk scores |
| remediation_service.py | `/app/services/remediation_service.py` | Not created | Cannot generate prioritized remediation |
| validation.py | `/app/models/validation.py` | Not created | Cannot store Atomic test outcomes |
| trivy.py, falco.py, atomic.py | `/app/schemas/{tool}.py` | Not created | No tool-specific payload validation |
| ui/templates/ | `/app/ui/templates/` | Not created | Dashboard rendering not possible with FastAPI templates |

**Count: 7 missing critical files**

---

### ⚠️ MISSING - MEDIUM PRIORITY (Infrastructure)

| Component | Expected Location | Reason | Impact |
|-----------|-------------------|--------|--------|
| logging.py | `/app/core/logging.py` | Not created | No structured logging for observability |
| security.py | `/app/core/security.py` | Not created | No auth/context isolation placeholders |
| falco_config/ | `/scanners/falco_config/` | Not created | Falco config/rules not staged |
| ci/ folder | `/ci/` | Not created (using .github/ instead) | Alternative CI paths not provided |
| Dockerfile.app | `/docker/Dockerfile.app` | Not created | Backend container image not defined |
| Dockerfile.target-app | `/docker/Dockerfile.target-app` | Not created | Test target image not defined |
| data/sample_outputs/ | `/data/sample_outputs/` | Directory not created | No fixture data for replay scenarios |
| test_*.py | `/tests/test_*.py` | Not created | No test suite |

**Count: 8 missing infrastructure/optional files**

---

### 🔄 DEVIATION FROM SPEC

| Item | Spec | Current | Rationale |
|------|------|---------|-----------|
| Dashboard | FastAPI templates (Jinja) | React frontend | More modern UX pattern, aligns with student project polish |
| Models | Partial schema | Full SQLAlchemy ORM | Better for SQLite operations and migrations |
| Services | Not specified in detail | Added `*_service.py` base | Enables testability and separation |
| CI location | `/ci/` folder | `.github/workflows/` | Standard GitHub Actions convention |
| docs/ folder | Not in spec | Added | Helpful for future reference docs |
| .gitignore | Not in spec | Added | Standard practice |

---

## Alignment Score

| Category | Coverage | Notes |
|----------|----------|-------|
| API Layer | 60% | Core CRUD + ingestion stubs present; no reports/processing endpoints |
| Data Models | 50% | Run + Finding OK; missing Validation, CorrelatedFinding, Remediation models |
| Service Layer | 30% | Basic run/finding services exist; missing parsers, correlation, remediation |
| Storage | 100% | Database config + table creation working |
| CI/CD | 20% | Starter workflow only; no actual Trivy/Falco integration |
| Frontend | 80% | React shell works; no run creation/results forms |
| Testing | 0% | No test suite yet |
| Documentation | 80% | README + inline comments; missing API docs |

**Overall Alignment: ~50% of full spec coverage**

---

## Recommended Next Steps (Priority Order)

### Phase 2A: Complete Data Layer (1-2 hours)
1. Add `validation.py` model for Atomic outcomes
2. Add `correlated_findings.py` model for merged results
3. Add `remediations.py` model for recommendations
4. Create migrations or ensure auto-creation at startup

### Phase 2B: Add Parser and Schema Layer (2-3 hours)
1. Create `/app/schemas/trivy.py` with Trivy JSON payload schema
2. Create `/app/schemas/falco.py` with Falco alert schema
3. Create `/app/schemas/atomic.py` with Atomic result schema
4. Create `/app/services/parser_service.py` with normalization logic for each tool

### Phase 2C: Implement Correlation and Remediation (3-4 hours)
1. Create `/app/services/correlation_service.py` with merge logic and scoring
2. Create `/app/services/remediation_service.py` with rule-based generator
3. Add report generation endpoint in `/app/api/reports.py`

### Phase 2D: Add Ingestion Endpoints (1-2 hours)
1. Add `/runs/{run_id}/ingest/trivy` endpoint
2. Add `/runs/{run_id}/ingest/falco` endpoint
3. Add `/runs/{run_id}/ingest/atomic` endpoint
4. Add `/runs/{run_id}/correlate` and `/runs/{run_id}/remediate` triggers

### Phase 3: Infrastructure (1-2 hours)
1. Add Dockerfiles for app and target containers
2. Add sample Falco config to `/scanners/falco_config/`
3. Create `/data/sample_outputs/` with fixture JSONs
4. Add `/app/core/logging.py` and `/app/core/security.py` stubs

### Phase 4: Testing (2-3 hours)
1. Add `tests/test_parsers.py` for tool normalization
2. Add `tests/test_correlation.py` for merge and scoring logic
3. Add `tests/test_remediation.py` for rule generation
4. Add `tests/test_api.py` for HTTP routes

---

## Verdict

**Status: Structurally Sound, Functionally Incomplete**

The repository **IS aligned conceptually** with the design doc's structure and intent. The foundation (config, models, API routes, database) is in place and follows FastAPI best practices. However, the **core business logic is missing**: parsers, correlation engine, remediation generator, and reporting endpoints. These are not optional—they're the heart of the system.

**Recommendation**: Continue to Phase 2 (parser/correlation/remediation layers) without restructuring. The current foundation supports the full spec without refactoring.
