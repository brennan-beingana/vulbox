# System Design Reference Document
## Automated Application Security Assessment Tool

### 1. Purpose of the System
This system is a low-cost, student-friendly security assessment pipeline for containerized applications. Its purpose is to detect, validate, correlate, and report vulnerabilities using a combination of static image scanning, runtime monitoring, and controlled exploit validation.

The design supports a practical one-month prototype while still demonstrating the core ideas in the research proposal: CI/CD-integrated security testing, correlation of findings, false-positive reduction, and actionable remediation guidance.

### 2. Problem Statement
Modern containerized development moves quickly, but security checks are often fragmented. Static scanners can find vulnerabilities, runtime tools can observe suspicious behavior, and exploit validation can confirm whether an issue is actually exploitable. However, when these tools are used separately, developers receive many disconnected alerts and cannot easily tell what is urgent, confirmed, or safe to ignore.

This system addresses that gap by combining build-time scanning, runtime monitoring, validation, and remediation into one workflow.

### 3. Design Objectives
The system is designed to:
- detect vulnerabilities in container images,
- monitor runtime behavior of deployed containers,
- validate selected findings in a safe sandbox,
- correlate findings from different tools using shared metadata,
- generate prioritized remediation guidance,
- provide a simple dashboard for users to start and review runs.

### 4. Scope of the Prototype
The prototype focuses on containerized applications only. It does not aim to support enterprise-scale distributed systems.

In scope:
- Docker-based applications,
- CI/CD-integrated scanning,
- Trivy-based image scanning,
- Falco runtime monitoring,
- Atomic Red Team validation for selected cases,
- SQLite-based result storage,
- FastAPI backend and minimal dashboard.

Out of scope:
- enterprise Kubernetes rollouts,
- distributed production clusters,
- non-containerized systems,
- large-scale commercial SIEM or ELK deployments.

### 5. High-Level Architecture
The system is organized into three main layers:

#### 5.1 CI / Collection Layer
This layer builds the application image and runs static scanning.
- GitHub Actions triggers the workflow.
- Docker builds the target image.
- Trivy scans the image and exports structured output.

#### 5.2 Validation Layer
This layer deploys the built image into an isolated test environment.
- Falco monitors runtime behavior.
- Atomic Red Team runs only selected tests and only with explicit consent.
- The environment should be isolated and network-restricted during validation.

#### 5.3 Correlation and Reporting Layer
This layer consolidates all results into one dataset.
- FastAPI receives Trivy, Falco, and Atomic outputs.
- The backend normalizes and stores findings in SQLite.
- Correlation uses commit SHA, image tag, container ID, and timestamps.
- Remediation is produced as a prioritized report for the user.

### 6. User Interaction Model
The system should include a dashboard where the user can:
1. create a new assessment run,
2. provide the code source or repository link,
3. configure scanning and validation options,
4. monitor the progress of the run,
5. view correlated findings and remediation guidance.

Recommended dashboard screens:
- New Assessment Run
- Run Configuration
- Live Status
- Results and Remediation

### 7. Recommended Technology Stack
The preferred stack is intentionally simple and lightweight:

- Backend: FastAPI + Python
- API server: Uvicorn
- Storage: SQLite
- ORM: SQLAlchemy or plain sqlite3
- Data validation: Pydantic
- Automation scripts: Python + Bash
- Container runtime: Docker + Docker Compose
- Static scanning: Trivy
- Runtime monitoring: Falco
- Validation: Atomic Red Team
- Testing: pytest
- CI/CD: GitHub Actions
- Optional dashboard: simple FastAPI-rendered templates or Jinja

This stack is suitable for a student project because it is affordable, portable, and easy to explain in a report or viva.

### 8. System Flow
The operational flow of the system is:

1. Developer submits code or repository details through the dashboard.
2. FastAPI creates a run record.
3. GitHub Actions builds the Docker image.
4. Trivy scans the image and saves findings.
5. The image is deployed to an isolated test environment.
6. Falco monitors the running container for suspicious activity.
7. Atomic Red Team runs a small number of selected validations, if consent is provided.
8. FastAPI ingests all outputs and stores them in SQLite.
9. The correlation service groups related findings using shared metadata.
10. The remediation service generates prioritized guidance.
11. The dashboard displays the final report.

### 9. Backend Service Design

#### 9.1 Main Responsibilities
The FastAPI backend is the brain of the system. It should:
- receive results from scanners and validators,
- normalize all tool outputs into a common format,
- store runs and findings,
- correlate findings across tools,
- generate remediation guidance,
- serve data to the dashboard.

#### 9.2 Internal Layers
The backend is best split into four layers:

**API Layer**
- Handles dashboard requests and CI job submissions.
- Exposes endpoints for runs, ingestion, reports, and remediation.

**Service Layer**
- Parses raw tool output.
- Correlates findings.
- Produces remediation results.

**Storage Layer**
- Persists runs, findings, validations, correlations, and remediation outputs in SQLite.

**Integration Layer**
- Connects to GitHub Actions, Trivy, Falco, Atomic Red Team, and optionally an LLM.

### 10. Recommended API Route Map

#### 10.1 Run Management
- `POST /runs` — create a new assessment run
- `GET /runs` — list all runs
- `GET /runs/{run_id}` — show run status and metadata
- `PATCH /runs/{run_id}` — update run settings or status
- `DELETE /runs/{run_id}` — remove a run if required

#### 10.2 Ingestion
- `POST /runs/{run_id}/ingest/trivy` — ingest Trivy JSON output
- `POST /runs/{run_id}/ingest/falco` — ingest Falco alerts
- `POST /runs/{run_id}/ingest/atomic` — ingest Atomic Red Team results

#### 10.3 Processing
- `POST /runs/{run_id}/correlate` — merge findings into correlated records
- `POST /runs/{run_id}/remediate` — generate remediation guidance
- `POST /runs/{run_id}/recompute-risk` — recalculate priority scores if needed

#### 10.4 Reporting
- `GET /reports/{run_id}` — return the final consolidated report
- `GET /reports/{run_id}/export` — export report as JSON, CSV, or PDF
- `GET /runs/{run_id}/findings` — list normalized findings
- `GET /runs/{run_id}/validations` — list validation outcomes

### 11. Data Model

#### 11.1 Runs Table
Stores one record per assessment run.

Key fields:
- `id`
- `project_name`
- `repo_url`
- `branch`
- `commit_sha`
- `image_name`
- `image_tag`
- `source_type`
- `status`
- `started_at`
- `finished_at`
- `triggered_by`
- `llm_remediation_enabled`

#### 11.2 Findings Table
Stores one record for each normalized tool finding.

Key fields:
- `id`
- `run_id`
- `source_tool`
- `severity`
- `title`
- `description`
- `rule_or_cve_id`
- `asset_type`
- `evidence_json`
- `created_at`

#### 11.3 Validations Table
Stores Atomic Red Team test outcomes.

Key fields:
- `id`
- `run_id`
- `test_name`
- `mitre_technique`
- `result`
- `consent_given`
- `sandboxed`
- `notes`
- `executed_at`

#### 11.4 Correlated Findings Table
Stores merged findings after correlation.

Key fields:
- `id`
- `run_id`
- `main_finding_id`
- `supporting_finding_ids`
- `risk_score`
- `confidence`
- `correlation_reason`
- `is_confirmed`
- `created_at`

#### 11.5 Remediations Table
Stores generated remediation suggestions.

Key fields:
- `id`
- `run_id`
- `correlated_finding_id`
- `summary`
- `priority_action`
- `why_it_matters`
- `example_fix`
- `confidence`
- `source`
- `created_at`

### 12. Normalized Finding Format
All tool results should be converted into one shared internal format before storage and correlation.

Common fields:
- run identifier
- source tool
- severity
- title
- description
- evidence
- asset type
- timestamp

Example:
- Trivy findings become package/CVE records.
- Falco alerts become runtime behavior records.
- Atomic results become validation records tied to a test and technique.

### 13. Correlation Logic
The correlation layer should merge findings based on:
- `run_id`
- `commit_sha`
- `image_tag`
- `container_id`
- timestamps and execution window

A simple scoring model is enough for the prototype:
- Critical = 40
- High = 30
- Medium = 20
- Low = 10
- add points when Falco confirms suspicious behavior
- add points when Atomic validation succeeds
- add points when multiple tools report the same issue
- subtract points when evidence is weak or unconfirmed

This gives a practical way to prioritize findings without adding machine learning complexity.

### 14. Remediation Design

#### 14.1 Remediation Strategy
The remediation service should be rule-based first. It should generate short, clear recommendations such as:
- upgrade a vulnerable package,
- remove interactive shell access,
- reduce container privileges,
- use a non-root user,
- pin a safer base image version,
- review a Falco rule match.

#### 14.2 Remediation Output Fields
Each remediation record should contain:
- summary
- priority action
- why it matters
- example fix
- confidence
- source of recommendation

#### 14.3 Optional LLM Enhancement
The correlated findings can be formatted as structured JSON and sent to an external LLM using a fixed prompt. The LLM should refine the wording of the remediation, not replace the backend’s evidence-based scoring.
Send a compact JSON object like this:
{
 "run_id": "run_001",
 "asset": "app-image:latest",
 "correlated_findings": [
   {
     "source": ["trivy", "falco"],
     "severity": "HIGH",
     "title": "OpenSSL vulnerability confirmed by runtime behavior",
     "evidence": {
       "cve_id": "CVE-XXXX-YYYY",
       "falco_rule": "Terminal shell in container",
       "fixed_version": "1.1.1w"
     }
   }
 ],
 "constraints": {
   "audience": "student developer",
   "tone": "clear and concise",
   "output_format": "json"
 }
}

The LLM should return:
- summary
- priority action
- why it matters
- example fix
- confidence

### 15. Suggested Project Directory Structure

```text
project-root/
├─ app/
│  ├─ main.py
│  ├─ api/
│  │  ├─ findings.py
│  │  ├─ runs.py
│  │  └─ reports.py
│  ├─ core/
│  │  ├─ config.py
│  │  ├─ logging.py
│  │  └─ security.py
│  ├─ models/
│  │  ├─ run.py
│  │  ├─ finding.py
│  │  └─ validation.py
│  ├─ schemas/
│  │  ├─ trivy.py
│  │  ├─ falco.py
│  │  └─ atomic.py
│  ├─ services/
│  │  ├─ parser_service.py
│  │  ├─ correlation_service.py
│  │  └─ remediation_service.py
│  └─ ui/
│     └─ templates/
├─ scanners/
│  ├─ trivy_runner.sh
│  ├─ falco_config/
│  └─ atomic_runner.sh
├─ ci/
│  ├─ github-actions.yml
│  └─ gitlab-ci-sample.yml
├─ docker/
│  ├─ Dockerfile.app
│  ├─ Dockerfile.target-app
│  └─ docker-compose.yml
├─ data/
│  ├─ findings.db
│  └─ sample_outputs/
├─ tests/
│  ├─ test_parsers.py
│  ├─ test_correlation.py
│  └─ test_remediation.py
└─ README.md
```

### 16. Implementation Plan
A practical four-week implementation plan is:

#### Week 1: Setup and Skeleton
- create the repository structure,
- define the FastAPI skeleton,
- create SQLite tables,
- implement sample JSON ingestion,
- prepare Docker Compose.

#### Week 2: Static Scanning
- build the GitHub Actions workflow,
- run Trivy during CI,
- export scan JSON,
- parse and store scan results.

#### Week 3: Runtime Monitoring and Correlation
- deploy the target container to an isolated environment,
- run Falco monitoring,
- ingest runtime alerts,
- correlate scan and runtime findings.

#### Week 4: Validation, Remediation, and Demo
- add a small Atomic Red Team validation path,
- require consent and sandbox restrictions,
- generate remediation guidance,
- complete a simple dashboard,
- prepare demo artifacts and documentation.

### 17. Final Deliverables
The completed prototype should demonstrate:
- a working CI pipeline,
- static scanning,
- runtime alerts,
- basic correlation,
- at least one validation path,
- prioritized remediation output,
- reproducible logs and artifacts.

### 18. Summary
This system design combines build-time scanning, runtime monitoring, controlled validation, and remediation into one practical pipeline. It is intentionally lightweight, uses common open-source tools, and is suitable for a student project with limited time and resources. The architecture is strong enough to explain clearly in a system design report and simple enough to implement within one month.

