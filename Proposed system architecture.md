Proposed system architecture​
##### **Recommended architecture for a one-month student build** **1.1 Three-Layer Architecture**


**1) CI / collection layer​**
GitHub Actions builds the Docker image, runs Trivy scans, and stores artifacts. This matches
your proposal’s emphasis on Docker-based builds and ready-to-use CI templates. You can add
a minimal GitLab CI example later, but GitHub Actions should be the main pipeline first.


**2) Validation layer​**
After the image is built and scanned, deploy it into a small isolated test environment, then run
Falco for runtime monitoring and a small set of Atomic Red Team tests only on selected cases
with consent and network isolation. This directly matches your functional requirements for
runtime alerts, correlation, and safe exploit validation.


**3) Correlation + reporting layer​**
A **FastAPI** service receives JSON outputs from Trivy, Falco, and Atomic tests, stores them in
**SQLite**, correlates them by image name, commit SHA, timestamp, and container ID, then
produces a simple prioritized report. This is enough to satisfy your correlation and remediation
requirements without needing a heavy ELK stack. Your proposal explicitly allows a simple
SQLite store as an alternative to ELK.

##### **1.2 Priority Order**


**Must-have for your grade and demo**


1.​ **Docker image build + Trivy scan** for each commit.
2.​ **Falco runtime alert capture** in the test environment.
3.​ **A correlation script/service** that links scan output and runtime alerts using the same

image/commit metadata.
4.​ **A simple remediation generator** that turns findings into short, prioritized fixes.
5.​ **A GitHub Actions workflow** that runs everything automatically.


**Good but optional if time remains​**
6. **A minimal GitLab CI YAML example** .​
7. **Atomic Red Team sandbox validation** for 1–3 selected cases only.​
8. **A basic web dashboard** for browsing results.

##### **1.3 Tech Stack**


Use the simplest stack that still looks professional:


●​ **Backend:** FastAPI + Python
●​ **API server:** Uvicorn


●​ **Storage:** SQLite
●​ **ORM:** SQLAlchemy or plain sqlite3 if you want less overhead
●​ **Data validation:** Pydantic
●​ **Automation scripts:** Python + Bash
●​ **Container runtime:** Docker + Docker Compose
●​ **Scanning:** Trivy first; add Clair only if you finish early
●​ **Runtime monitoring:** Falco
●​ **Validation tests:** Atomic Red Team
●​ **Testing:** pytest
●​ **CI/CD:** GitHub Actions
●​ **Optional dashboard:** very small FastAPI-rendered HTML pages or Jinja templates


I would **not** make ELK, Kubernetes, or a complex Node.js backend your core implementation for
this one-month version. Your documents already show resource constraints, and the literature
review also notes that enterprise-grade approaches can be complex and resource-intensive,
while your target is a low-cost, student-friendly prototype.

##### **1.4 Suggested system flow**


This flow aligns with your proposal’s architecture: build in CI, scan the image, deploy to an
isolated environment, monitor runtime, run controlled validation, then merge all outputs into a
unified report.

##### **1.4.1 Implementation Steps**


**Week 1: skeleton and environment​**
Set up the repo, directory structure, Docker Compose, and the FastAPI skeleton. Create folders
like app/, pipelines/, scans/, reports/, and tests/ . Add a SQLite database and a table
for findings. At the end of this week, your backend should already accept a sample JSON file
and save it.​
This is your foundation for the reporting layer, which your proposal says should be lightweight
and CI-integrated.


**Week 2: build + static scan​**
Create the GitHub Actions workflow that:​
builds the Docker image, runs **Trivy**, exports JSON, and uploads the scan artifact.​
Then write a parser that converts Trivy output into your database schema.​
This covers one full functional requirement early: static scanning with structured vulnerability
reports.


**Week 3: runtime monitoring + correlation​**
Run the target container in a local isolated environment and configure **Falco** to watch for a few
high-value behaviors. Collect its JSON/YAML alerts, then correlate them with Trivy findings
using shared metadata like image tag, commit hash, and timestamp.​


Your proposal specifically says the system should link static and runtime signals to lower false
positives, and your survey results show this is one of the key user pain points.


**Week 4: validation + remediation + demo​**
Add a very small Atomic Red Team validation step for only a few selected cases, and make it
optional behind a consent flag. Then generate a report with severity, evidence, confidence, and
a short fix. Finish with a small dashboard or API endpoint plus a polished demo workflow.​
This addresses your requirements for safe exploit validation and action-oriented remediation
guidance.

##### **1.4.2 Final Project Deliverables**


For your defense, this should be enough to show:


●​ a working CI pipeline,
●​ static scanning,
●​ runtime alerts,
●​ basic correlation,
●​ at least one validation path,
●​ prioritized remediation output,
●​ reproducible artifacts and logs.


That is already very close to your listed requirements, because your proposal’s functional
requirements are centered on exactly those components.

### **System Architecture**

Use a **thin, student-friendly prototype** : a **FastAPI/Python backend** with a **minimal web**
**UI/REST API**, **Docker/Docker Compose**, **Trivy** for image scanning, **Falco** for runtime
monitoring, **Atomic Red Team** for a few sandboxed validation tests, and **GitHub Actions** as the
main automation layer. That matches your stated functional requirements for static scanning,
runtime alerts, correlation, safe validation, remediation output, and CI templates, while staying
within the non-functional limits of low overhead, portability, and sandbox safety.


This flow is the simplest version of what your proposal already describes: build in CI, scan the
container image, deploy in an isolated environment, capture Falco alerts, run targeted Atomic
tests, then merge everything into one correlated dataset and report layer. Your documents also
explicitly allow a **simple SQLite store** instead of a heavier ELK stack, which is the right choice
for a one-month build.


For the user flow, I would implement four dashboard screens:


1.​ **New Assessment Run** : enter repo URL / upload code / select branch or image tag.
2.​ **Run Configuration** : choose scanner options, sandbox choice, and Atomic consent.
3.​ **Live Status** : show build, scan, runtime monitoring, and validation progress.
4.​ **Results & Remediation** : show correlated findings, severity, evidence, and fixes.

#### **Entire Project Architecture and Repo Structure**


project-root/
├─ app/
│ ├─ main.py
│ ├─ api/


│ │ ├─ findings.py
│ │ ├─ runs.py
│ │ └─ reports.py
│ ├─ core/
│ │ ├─ config.py
│ │ ├─ logging.py
│ │ └─ security.py
│ ├─ models/
│ │ ├─ run.py
│ │ ├─ finding.py
│ │ └─ validation.py
│ ├─ schemas/
│ │ ├─ trivy.py
│ │ ├─ falco.py
│ │ └─ atomic.py
│ ├─ services/
│ │ ├─ parser_service.py
│ │ ├─ correlation_service.py
│ │ └─ remediation_service.py
│ └─ ui/
│   └─ templates/ (optional minimal HTML)
├─ scanners/
│ ├─ trivy_runner.sh
│ ├─ falco_config/
│ └─ atomic_runner.sh
├─ ci/
│ ├─ github-actions.yml
│ └─ gitlab-ci-sample.yml
├─ docker/
│ ├─ Dockerfile.app
│ ├─ Dockerfile.target-app
│ └─ docker-compose.yml
├─ data/
│ ├─ findings.db
│ └─ sample_outputs/
├─ tests/
│ ├─ test_parsers.py
│ ├─ test_correlation.py
│ └─ test_remediation.py
└─ README.md


## **FastAPI ingestion and remediation service**

Below is a practical way to structure the **FastAPI ingestion and remediation service** so it is
easy to build in a month, matches your proposal, and still looks solid in a final-year defense.
Your proposal says the backend can be a **FastAPI/Python service with a minimal web**
**UI/REST API**, backed by **SQLite or ELK**, and that it should merge **Trivy/Clair scan outputs,**
**Falco alerts, and Atomic Red Team results** into a unified dataset for correlated reporting. It
also says the system should produce **prioritized, human-readable remediation reports** and
support **GitHub Actions / GitLab CI templates** .

# **1) What this service should do**


Think of the FastAPI service as the **brain and data hub** of the project.


It should have four jobs:


1.​ **Ingest** outputs from Trivy, Falco, and Atomic Red Team in machine-readable form.
2.​ **Normalize** those outputs into one shared format.
3.​ **Correlate** findings using CI metadata like commit SHA, image tag, timestamps, and

container ID to reduce noise.
4.​ **Generate remediation** that is short, prioritized, and easy to act on.


That matches your requirements almost exactly: static scans, runtime alerts, linking signals with
CI metadata, sandboxed validation, and action-oriented fixes.

# **2) Recommended internal structure** **1) FastAPI service structure**


Split the backend into four layers:


**API layer​**
Receives requests from the dashboard and from CI jobs.


**Service layer​**
Does parsing, correlation, and remediation generation.


**Storage layer​**
Persists runs, findings, validations, and remediation outputs in SQLite.


**Integration layer​**
Talks to GitHub Actions, Trivy, Falco, Atomic Red Team, and optionally the LLM.​


This matches your document’s design direction: a lightweight FastAPI/Python backend that
combines scan outputs, runtime alerts, and validation results into a structured store for analysis
and reporting.

# **2) Recommended route map**

##### **Core run management**


**Route** **Purpose**


POST /runs Create a new assessment run from the
dashboard


GET /runs List past runs


GET /runs/{run_id} Show run details and status



PATCH

/runs/{run_id}


DELETE

/runs/{run_id}

##### **Ingestion**



Update run settings or status


Remove a run record if needed



**Route** **Purpose**


POST

/runs/{run_id}/ingest/trivy


POST

/runs/{run_id}/ingest/falco


POST

/runs/{run_id}/ingest/atomic

##### **Processing**



Accept Trivy JSON output


Accept Falco alerts


Accept Atomic Red Team results



**Route** **Purpose**


POST /runs/{run_id}/correlate Merge findings into one correlated
dataset


POST /runs/{run_id}/remediate Generate remediation guidance



POST

/runs/{run_id}/recompute-risk

##### **Reporting**



Recalculate priority scores if needed



**Route** **Purpose**


GET /reports/{run_id} Return the final consolidated report


GET

/reports/{run_id}/export


GET

/runs/{run_id}/findings


GET

/runs/{run_id}/validations



Download JSON/CSV/PDF report


List all normalized findings


List validation test outcomes



This route map directly supports the requirements for structured vulnerability reports, runtime
alerts, CI metadata linkage, sandboxed validation, and action-oriented remediation guidance.

# **3) What POST /runs should accept**


This is the most important endpoint because it connects the dashboard to the pipeline.


Example request:


{


"project_name": "final-year-demo",


"source_type": "git",


"repo_url": "https://github.com/user/app",


"branch": "main",


"commit_sha": "abc123",


"image_name": "app-image",


"image_tag": "latest",


"run_trivy": true,


"run_falco": true,


"run_atomic": false,


"atomic_consent": false,


"llm_remediation": true


}


The backend should create a run_id, store the metadata, and either trigger GitHub Actions or
enqueue a local job. That aligns with your proposal’s CI/CD orientation and the survey finding
that Docker + GitHub Actions is the most natural fit for your users.

# **4) Database tables you should use**

##### **runs**


One row per security assessment run.


Fields:


●​ id

●​ project_name

●​ repo_url

●​ branch

●​ commit_sha

●​ image_name

●​ image_tag

●​ source_type

●​ status

●​ started_at

●​ finished_at

●​ triggered_by

●​ llm_remediation_enabled

##### **findings**


One row per normalized issue from any tool.


Fields:


●​ id


●​ run_id

●​ source_tool ( trivy, falco, atomic )

●​ severity

●​ title

●​ description

●​ rule_or_cve_id

●​ asset_type

●​ evidence_json

●​ created_at

##### **validations**


One row per Atomic validation.


Fields:


●​ id

●​ run_id

●​ test_name

●​ mitre_technique

●​ result

●​ consent_given

●​ sandboxed

●​ notes

●​ executed_at

##### **correlated_findings**


One row per merged issue after correlation.


Fields:


●​ id

●​ run_id

●​ main_finding_id

●​ supporting_finding_ids

●​ risk_score

●​ confidence

●​ correlation_reason

●​ is_confirmed

●​ created_at


##### **remediations**

One row per fix suggestion.


Fields:


●​ id

●​ run_id

●​ correlated_finding_id

●​ summary

●​ priority_action

●​ why_it_matters

●​ example_fix

●​ confidence

●​ source ( rules_engine, llm )

●​ created_at


This schema fits your proposal’s requirement to merge CI logs, Trivy/Clair reports, Falco alerts,
and Atomic outcomes into a central structured store for later reporting and evaluation.

# **4) Normalized ingestion format**


Every tool should be converted into one common internal shape.


Example internal finding object:


{
"run_id": "run_2026_03_27_01",
"source_tool": "trivy",
"severity": "HIGH",
"title": "OpenSSL vulnerability in image layer",
"description": "Package openssl has a known CVE",
"evidence": {
"cve_id": "CVE-XXXX-YYYY",
"package": "openssl",
"installed_version": "1.1.1",
"fixed_version": "1.1.1w"
},
"asset_type": "image",
"timestamp": "2026-03-27T10:30:00Z"
}


For Falco:


{
"source_tool": "falco",
"severity": "CRITICAL",
"title": "Shell spawned in container",
"description": "Unexpected shell execution detected",
"evidence": {
"rule_name": "Terminal shell in container",
"container_id": "abc123",
"process": "/bin/sh"
}
}


For Atomic Red Team:


{
"source_tool": "atomic",
"severity": "MEDIUM",
"title": "Validation succeeded for suspicious behavior",
"description": "Controlled test reproduced the behavior",
"evidence": {
"test_name": "container-escape-check",
"mitre_technique": "T1611"
}
}


This matches your proposal’s idea of collecting scan outputs, Falco alerts, and structured
validation results into a central store.

# **5) How the service should operate, end to end**

##### **Step 1: A CI run starts**


GitHub Actions builds the Docker image and stores metadata like commit SHA, branch, and
image tag. Your proposal already states the pipeline should be driven by GitHub Actions or
GitLab CI.

##### **Step 2: Trivy scan runs**


Trivy produces JSON. A small parser sends that JSON to /ingest/trivy .​
The service validates the payload, converts each vulnerability into a normalized finding, and
inserts it into SQLite. Your proposal identifies Trivy as the main static scanner for this pipeline.


##### **Step 3: Runtime test environment starts**

The built container is deployed into an isolated environment. Falco watches system calls and
emits alerts as YAML or JSON. The service accepts these via /ingest/falco . Your proposal
explicitly says Falco should run in the test environment and that exploit validation must be
sandboxed and isolated.

##### **Step 4: Atomic validation runs only if allowed**


If the user has consented, the service triggers selected Atomic Red Team tests in the sandbox.
Results go to /ingest/atomic .​
This should be **optional**, because your requirements say exploit validation must run with
explicit consent and no outbound network access.

##### **Step 5: Correlation happens**


The service groups findings by:


●​ same run_id

●​ same commit_sha

●​ same image_tag
●​ same container/session time window


This is the critical part of the whole project. Your documents say the system should merge static
and runtime data to reduce false positives and identify genuine vulnerabilities.

##### **Step 6: Remediation is generated**


The remediation service ranks items by severity, exploit evidence, and runtime confirmation. It
then emits concise guidance such as:


●​ upgrade package X
●​ remove risky shell access
●​ tighten container privileges
●​ pin base image version
●​ review Falco rule match


Your proposal says remediation must be clear, concise, and usable quickly, with prioritized fixes
and sample commands or snippets.

# **6) Correlation logic: how to make it intelligent without** **overengineering**


Use a simple scoring model.

##### **Example priority score**


Start with severity points:


●​ Critical = 40
●​ High = 30
●​ Medium = 20
●​ Low = 10


Then add:


●​ +20 if Falco confirmed runtime suspicious behavior
●​ +15 if Atomic validation succeeded
●​ +10 if the issue appears in multiple tools
●​ +5 if the issue affects a package with a known fix


Then subtract:


●​ -10 if only static and unconfirmed
●​ -5 if evidence is weak or ambiguous


This gives you a practical correlation engine without machine learning. That is a good fit
because your literature review says static tools alone create noise, while runtime tools add
context, and hybrid systems reduce false positives.

# **7) Remediation service: how it should be structured**


Keep remediation rule-based, not AI-heavy.

##### **Inputs**


●​ normalized findings
●​ tool source
●​ severity
●​ package/CVE or Falco rule
●​ validation result
●​ image base metadata

##### **Outputs**


Each remediation should contain:


●​ headline


●​ why_it_matters

●​ recommended_fix

●​ example_command

●​ confidence

●​ priority

##### **Example mapping**


If Trivy finds a CVE in a package:


●​ recommendation: upgrade package version
●​ example fix: apt-get update && apt-get install -y

<package>=<fixed_version>


If Falco detects shell spawning:


●​ recommendation: remove interactive shell from runtime image, reduce container
privileges, use non-root user


If Atomic validates exploitation:


●​ recommendation: treat as confirmed, move to top of queue, include evidence from both
scan and runtime test


This directly supports your proposal’s goal of producing evidence-backed, human-readable
remediation reports.

# **8) How the LLM step should be wired**


Do **not** send raw logs.


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


Then ask the LLM to return:


●​ summary

●​ priority_action

●​ why_it_matters

●​ example_fix

●​ confidence


This keeps the response structured and easy to display in the dashboard. It also helps you
defend the design because your system still uses evidence-backed correlation before any
language model is involved.

# **9) Suggested FastAPI module breakdown**


app/


├─ main.py
├─ api/
│ ├─ runs.py
│ ├─ ingest.py
│ ├─ reports.py
│ └─ remediation.py
├─ schemas/
│ ├─ run.py
│ ├─ trivy.py
│ ├─ falco.py
│ └─ atomic.py
├─ services/
│ ├─ run_service.py
│ ├─ parser_service.py
│ ├─ correlation_service.py
│ ├─ remediation_service.py
│ └─ llm_service.py
├─ db/
│ ├─ models.py
│ └─ session.py
└─ utils/
├─ scoring.py
└─ formatters.py


This structure is small enough for a student project but still clean enough to explain in a viva.

# **10) What each endpoint should do**

##### **POST /ingest/trivy**


Accept Trivy JSON, validate it, extract CVEs, save findings, update run status.

##### **POST /ingest/falco**


Accept Falco alert JSON/YAML converted to JSON, store rule name, severity, container ID, and
timestamp.

##### **POST /ingest/atomic**


Accept validation result, store test name, pass/fail, and sandbox/consent status.

##### **GET /reports/{run_id}**


Return a single consolidated report:


●​ summary counts
●​ confirmed issues
●​ unconfirmed issues
●​ runtime-confirmed issues
●​ remediation priorities

##### **POST /remediate/{run_id}**


Generate or refresh remediation guidance for that run.


This directly supports the project’s requirement to generate prioritized reports and combine
outputs from multiple sources.

# **11) How to keep it safe and defensible**


Your proposal is very clear that exploit validation must only run:


●​ with explicit consent,
●​ in isolated sandbox environments,
●​ with restricted outbound access.


So build the service with these guardrails:


●​ require consent_given=true before Atomic ingestion or execution
●​ refuse Atomic job creation if sandbox flag is false
●​ mark validation as not_run if conditions are missing
●​ log all test runs with timestamp and operator identity


That will help you defend the safety of the system during presentation.

# **12) A realistic operating sequence for your backend**


A practical sequence is:


1.​ CI job sends run_id + image metadata to FastAPI.
2.​ Trivy scan output is ingested.
3.​ Falco alerts are ingested.
4.​ Atomic validation results are ingested only if permitted.
5.​ Correlation service computes a final risk score.
6.​ Remediation service generates plain-language fixes.
7.​ Report is returned through the API or minimal dashboard.


That is already enough to satisfy most of your functional requirements while staying within your
resource limits. Your proposal explicitly positions the prototype as a low-cost toolchain for
containerized applications, not an enterprise-scale platform.

# **13) What to build first in code**


Build it in this order:


1.​ runs table and /runs endpoint
2.​ ingestion endpoints
3.​ parser service
4.​ correlation service
5.​ deterministic remediation service
6.​ dashboard views
7.​ optional LLM layer
8.​ export/reporting


That order gets you a working system quickly and helps you show incremental progress during
supervision.


One important scope note: your proposal allows a minimal dashboard and a lightweight
backend, so do not overbuild the UI. A few forms, a status page, and a results page are enough
for this project.


