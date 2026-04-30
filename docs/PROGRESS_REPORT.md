# VulBox — Development Progress Report

**Status snapshot:** 2026-04-30
**Author:** Engineering team
**Audience:** Project supervisor / stakeholders / next maintainer
**Project root:** `/home/bbei/Desktop/vulbox`

---

## 1. Executive Summary

VulBox has matured from concept into a **functioning prototype** that successfully orchestrates the full vision described in the SDD: build → scan → adversarial test → correlate → report. The async state machine, WebSocket event streaming, JWT authentication, three adapters (Trivy, Falco, ART), an LLM remediation service, a CVE-to-MITRE mapping layer, and a redesigned 8-screen React dashboard are all implemented and the 50-test suite passes cleanly.

However, the prototype is **demo-grade, not production-grade**. End-to-end correctness has only been proven against three small fixture files; the production code paths that drive real Docker, Trivy, Falco, and ART subprocesses exist but have **no integration test coverage**. The product also has three architectural gaps that would be blockers for any external user: (a) most REST endpoints have **no authentication enforcement**, (b) the data model has **no user scoping** (all runs are visible to all users), and (c) assessment runs are **not configurable per target application** beyond branch and image tag. Combined with a thin technique map (12 MITRE techniques, 55 CVEs) and an LLM remediation service that has not been validated on real exploit evidence, VulBox is currently best described as **"vertically complete in the demo path, horizontally thin everywhere else."**

This document inventories what is real, what is fragile, and what is missing — and proposes a prioritised roadmap to take VulBox from prototype to a tool a security engineer would actually trust on an unfamiliar repository.

---

## 2. Maturity Snapshot

| Capability | Implementation | Verified end-to-end? | Production-ready? |
|---|---|---|---|
| Async pipeline state machine | Real (`orchestrator.py`) | Yes (dev mode only) | No — no real-target integration test |
| Docker clone / build / sandbox | Stubbed in dev, real CLI in prod | Dev only | No — prod path untested |
| Trivy scan adapter | Fixture in dev, `trivy image` CLI in prod | Dev only | No — prod path untested |
| Falco runtime monitor | Fixture in dev, real subprocess in prod | Dev only | No — process leaks on crash |
| Atomic Red Team runner | Real bash script, 13 techniques | No (script not yet run inside CI) | No — script invocation untested |
| Risk scoring (`Presence × Exploitability × Detectability`) | Real formula, capped 0–75 | Yes | Yes |
| CVE → MITRE technique map | YAML file, 55 CVEs, 12 techniques | Yes (8 unit tests) | **Coverage too thin** |
| LLM remediation service | OpenAI client + static fallback | Cache + JSON parse tested | **Output quality not validated** |
| Static remediation rules | 4 hard-coded `(exploited, detectable)` rules | Yes | Acceptable as fallback |
| WebSocket event streaming | Per-run queue + 200-event replay | Yes | Yes |
| JWT auth (`/auth/*`) | Real, HS256, password hashing | Yes | Yes |
| Authorization on data routes | **Missing on 12 of 14 endpoints** | n/a | **Critical gap** |
| User scoping on runs/reports | **Missing — no `user_id` FK on `AssessmentRun`** | n/a | **Critical gap** |
| Per-app run configuration | Limited to `branch` + `image_tag` | n/a | **Missing** |
| React frontend (8 screens) | Login, Register, Dashboard, RunStatus, Report, Reports, Profile, Guides | Yes (clean Vite build) | Yes |
| PDF export | `weasyprint` HTML→PDF, falls back to 501 if not installed | Partial | Soft-failing |
| CI pipeline | `ci/github-actions.yml`, `ci/gitlab-ci-sample.yml` (sample) | Not actually run on a real repo | No |
| Test suite | 50 tests, fixture-driven, all green | Unit-level only | **No integration tests** |

**Headline number:** of the 12 distinct capabilities VulBox claims, **5 are demo-only** (no real subprocess work has been verified), **3 are critical security gaps** (auth, scoping, audit), and **4 are production-quality** (state machine, scoring, WebSocket, JWT primitives).

---

## 3. What's Genuinely Working

It is worth being honest about what has been delivered, because the foundations are real:

### 3.1 The orchestrator is a real async state machine
`app/services/orchestrator.py` drives the SDD-prescribed flow `SUBMITTED → BUILDING → SCANNING → TESTING → (REBUILDING → TESTING)* → REPORTING → COMPLETE` with real `await` boundaries, real exception handling, a 1800-second timeout, a max-rebuilds-of-3 self-healing loop, and a `try/finally` cleanup guarantee. It is not a placeholder.

### 3.2 The risk score formula is implemented and tested
`base 10 + 30 (exploited) + 10 (undetected) + severity_weight (5–20)`, capped at 75. Ten unit tests cover edge cases. The Security Matrix's three-dimensional output (`is_present`, `is_exploitable`, `is_detectable`) is computed correctly from upstream adapter output.

### 3.3 The WebSocket layer is production-quality
`app/api/websocket.py` maintains per-run event queues and a 200-event replay buffer, so a client connecting late still gets the full history. Heartbeats prevent idle-disconnects. This is the strongest single piece of code in the project.

### 3.4 The frontend is now professional-looking
The April 2026 redesign delivers a fixed sidebar layout (Dashboard / Reports / Guides / Profile / Sign Out), a stat-card-driven dashboard, a phase-stepper run-status page, a coloured risk-chip security matrix, and three new pages (Reports, Profile, Guides). The build is clean (16 KB CSS, 242 KB JS gzipped to 78 KB).

### 3.5 The CVE-to-MITRE mapping is data-driven, not hard-coded
`data/cve_technique_map.yml` (208 lines, 55 CVEs, 12 techniques) is loaded at startup and externalised — adding a new CVE doesn't require a code change. Eight unit tests guard the loader and signal-driven fallback rules.

### 3.6 The LLM remediation service has the right scaffolding
`app/services/llm_remediation.py` calls OpenAI with prompt-cache-friendly inputs, sandboxes untrusted evidence, parses JSON with markdown-fence stripping, falls back to static rules on any error, and caches results by `(technique, CVEs, log_hash)`. The plumbing is sound — the **content quality has not been validated on real evidence**.

---

## 4. The Critical Gaps You Identified — Detailed Assessment

### 4.1 End-to-end proven orchestration on random containerised apps

**Current reality:** the entire demonstrated end-to-end flow uses three hand-crafted fixture files (`trivy-fixture.json`, `falco-fixture.json`, `atomic-fixture.json`) containing **three findings each**. The orchestrator has never been observed completing a run against an arbitrary GitHub repository. `docker_manager.py` lines 66–187 contain the real `subprocess.run("git clone …")`, `docker build …`, `docker run …` invocations, but nothing in the test suite or CI exercises them.

**Concretely missing:**
- A test corpus of 5–10 deliberately diverse target repositories (a Flask app, a Node Express app, a Go binary, a Java Spring Boot service, a static-site generator, a deliberately vulnerable app like Juice Shop).
- An integration test that, in a CI environment with Docker available, actually clones each target, builds it, runs Trivy, executes at least one ART technique, and asserts the resulting `AssessmentRun.status == COMPLETE`.
- Robustness handling for the "this Dockerfile doesn't exist", "this repo's image won't start", "the entrypoint dies in 200ms" cases. Currently the orchestrator catches these but has no targeted recovery — it just transitions to FAILED with a generic message.
- A timing budget: how long does a real run take on a small/medium/large target? No data exists.

**Severity:** This is the single biggest obstacle to claiming VulBox is "an automated security assessment tool". Until it has been run successfully against a target nobody on the team has hand-crafted fixtures for, the system is unproven.

### 4.2 Valuable report generation using the LLM remediation service

**Current reality:** the LLM service exists and is wired in, but its output has not been judged for **practical value**. There is no validation suite that takes a real `(SecurityMatrixEntry, list[TrivyFinding], list[FalcoAlert])` triple and asks: "did the LLM produce a remediation a human engineer would act on?" The eight unit tests cover JSON parsing and cache key stability — not output quality.

**Specific quality concerns:**
- The prompt is constructed once and has not been iterated on against real evidence; it has likely never been A/B tested against alternatives.
- Evidence is sandboxed (good — prevents prompt injection) but the sandboxed format may also strip useful context (e.g. the actual file path, the actual config snippet that introduced the vulnerability). No tests verify that meaningful context survives.
- The static-fallback rules (4 of them, keyed only on `(exploited, detectable)`) are extremely coarse and produce identical text for very different findings. When the LLM fails or returns malformed JSON, every Critical finding gets the same message.
- The `example_fix` field is currently a single short string. Real remediations need multiple numbered steps, before/after snippets, or pointer to an upstream patch.
- No mechanism exists for the LLM to say "I don't have enough information — defer to a human." Every run gets a remediation per matrix entry whether or not one is warranted.

**Concretely missing:**
- A **golden-set validation harness**: 10–20 canonical findings (each: one CVE + one ART result + one Falco alert + one expected remediation written by hand) and a script that runs the LLM against each and scores `(precision, recall, "would-act-on-it"-rate)`.
- Prompt versioning + iteration loop. Currently one prompt, one shot.
- Multi-turn refinement: feed the model its own draft + the original evidence and ask for a higher-quality second pass. Cost is modest with prompt caching.
- A "low-confidence" path that emits the static fallback *and* flags the entry for human review rather than silently degrading.

**Severity:** This is the difference between VulBox being a triage tool (humans still write the actual fixes) and a productivity tool (engineers paste the fix into a PR). Today it is the former.

### 4.3 More populated technique map and more efficient execution

**Current reality:** the technique map covers **12 distinct MITRE ATT&CK techniques** (`T1003, T1059, T1059.004, T1068, T1082, T1190, T1210, T1543.002, T1552.001, T1557, T1574, T1611`) and **55 CVEs**. The ART runner script implements all 13 referenced techniques as real bash test bodies (not stubs). For comparison, MITRE ATT&CK has ~600 techniques, and a credible coverage target for a containerised-app scanner is 50–80 of the most relevant ones.

**Coverage gaps:**
- **Initial Access (TA0001):** only T1190 represented. No phishing, supply-chain, drive-by, or external service exploitation techniques modelled — though several are container-relevant (T1078 valid accounts, T1195 supply chain).
- **Persistence (TA0003):** only T1543.002 (systemd). Nothing on T1136 (account manipulation), T1505 (server software components), T1546 (event-triggered execution), all relevant in a long-lived container.
- **Defence Evasion (TA0005):** completely absent. T1027 (obfuscated files), T1140 (deobfuscate), T1562 (impair defences), T1218 (signed binary proxy execution) are all common in real attacks against containerised apps and would each test Falco's detection coverage in a useful way.
- **Discovery (TA0007):** only T1082 (system info) and T1552.001 (creds in files). T1018 (remote system), T1083 (file/directory), T1087 (account discovery) missing.
- **Lateral Movement (TA0008):** only T1210. T1021 (remote services), T1570 (lateral tool transfer), T1080 (taint shared content) all unrepresented.
- **Exfiltration (TA0010):** absent entirely — T1041 (over C2), T1567 (web service), T1048 (alt protocol).

The execution path is also serial: `_phase_test_loop()` runs ART techniques one at a time. For a target image with 30+ findings, this becomes the dominant phase wall-clock-wise.

**Concretely missing:**
- A roadmap and acceptance criteria for "level-2 coverage": a target of, say, 40 techniques across all 14 tactics, with at least one technique per tactic.
- A way for ART techniques to declare prerequisites (e.g. "needs root", "needs internet — skip in sandbox") so that the runner can short-circuit irrelevant tests rather than executing and failing.
- Parallel execution of independent ART techniques when the host has spare cores. Mostly a thread-pool concern; the orchestrator already has the right shape for it.
- A heuristic that, given a Trivy scan result, prioritises which ART techniques to run first (CVE-driven prioritisation already exists in the YAML; it is not used to *order* the test queue, only to compose it).

**Severity:** The current technique set is enough to demonstrate the matrix concept on a few CVEs but not enough to give a meaningful "security posture" on a real target. The right framing is: today VulBox can detect the obvious; tomorrow it needs to detect the unobvious.

### 4.4 Personalised settings on assessment runs tailored for each app

**Current reality:** an assessment run is configured by exactly four fields (`project_name, repo_url, branch, image_tag, consent_granted`). There is **no per-target configuration** for:

- Which techniques to run (always all of them)
- Which CVE severities to flag (always all)
- The base image expected vs detected
- Sensitive paths the target legitimately reads (so Falco doesn't false-positive on them)
- Network egress allow-list — currently the sandbox is `--network none` always; some apps legitimately need DNS+443 to a single host for licence checks etc.
- Build args / build secrets (private repositories with private package registries are unbuildable today)
- Resource limits (currently fixed; a memory-hungry build OOMs and looks like a target failure)
- Test time-budget per technique

**Concretely missing:**
- A `.vulbox.yml` schema *with full validation*. The DockerManager already accepts a `.vulbox.yml` file but has no schema, no documented fields, no consent-aware allow-list. This needs to become a first-class part of the product.
- An override layer in the database: an `AssessmentRunConfig` table keyed by `run_id`, containing all the above. The frontend would gain a "Configure run" step between "submit repo" and "consent + start".
- A "profile" concept: the user defines `profile: webapp-flask` once with sensible defaults for all of the above, and subsequent runs reuse it.
- A "dry-run preview" that, given a `.vulbox.yml`, lists which techniques will fire and which will be skipped, before consent is granted.

**Severity:** Without per-app configuration, VulBox's false-positive rate on real targets will be unworkable. A Flask app's normal startup behaviour will fire half a dozen Falco rules; the user has no way to silence them, so the matrix will report them as "detectable findings" forever.

---

## 5. Additional Critical Gaps (Audit-Identified)

### 5.1 Authentication is essentially absent on the data plane

Twelve of fourteen REST endpoints (and the WebSocket) accept any caller and return any data. Specifically `GET /runs`, `GET /runs/{id}`, `GET /runs/{id}/validations`, `GET /reports/{id}`, `GET /reports/{id}/export`, `WS /ws/runs/{id}/status`, and the three `POST /runs/{id}/ingest/*` dev-mode endpoints all skip the JWT check. Only `GET /auth/me` enforces it. This is not a hypothetical — the new Reports page calls `GET /runs` without scoping, so any logged-in user sees every run from every other user, and an *unauthenticated* attacker on the same network can do the same.

### 5.2 No user scoping in the data model

`AssessmentRun` has no `user_id` foreign key. There is no concept of "my runs". The `User` model exists for login only; it never appears in any query. This is a one-migration fix in principle, but every router needs a `Depends(get_current_user)` and a `.filter(AssessmentRun.user_id == current_user.id)` applied along with it.

### 5.3 Falco subprocesses can orphan

`falco_adapter.py` stores per-run `Popen` handles in a module-level dict. If the API process crashes between `attach()` and `collect_alerts()`, the Falco subprocess survives — and on the next API start, nothing reaps it. On a long-running deployment this leaks privileged processes.

### 5.4 No database migrations

SQLite with `Base.metadata.create_all` and "rm `findings.db` for schema changes". This is fine for a prototype but unworkable in production: any schema migration loses every run, every report, every user account. Alembic is one `pip install alembic && alembic init` away and should be done before anyone outside the team uses VulBox.

### 5.5 PDF export silently degrades to 501

If `weasyprint` is not installed, the export endpoint returns HTTP 501 instead of a PDF. The frontend's "Export PDF" button has no handling for this — it opens a new tab with a 501 page. Either bundle weasyprint as a hard dependency (with the `libpango`/`libcairo` system packages) or remove the button until the dependency is actually present.

### 5.6 Errors are not surfaced to the frontend

When the orchestrator transitions to FAILED, the frontend shows "Assessment failed during the BUILDING phase. Check server logs for details." The user has no way to see the actual error message. There is no `error_message` column on `AssessmentRun`. This makes troubleshooting at minimum a two-person job (one user, one engineer with SSH access).

### 5.7 No audit log

Who deleted run #42? Who created the admin account? Who exported the security report for project X? There is no answer. For a security tool, this is a basic requirement — both for compliance and for incident investigation.

### 5.8 Hardcoded API URL in the frontend

`src/api.js` and `src/pages/Report.jsx` both hardcode `http://46.101.193.155:8000`. This couples every frontend build to a single VM. Should be a Vite environment variable (`VITE_API_BASE_URL`) read at build time, with a sensible default.

### 5.9 CI is sample-only

`ci/github-actions.yml` describes a workflow but it has never been run against a real PR. There is no green-build badge. The first time someone tries to use VulBox in a PR pipeline they will discover the CI integration is aspirational.

---

## 6. Pitfalls and Risks

### 6.1 The "passing tests" trap

The 50-test suite is genuinely useful for detecting regressions in fixture parsing, score arithmetic, and CVE-map loading. It is **not** evidence that the system works end to end. Any future maintainer reading the README and seeing "all tests pass" may reasonably believe VulBox has been verified against real repositories — it has not. This documentation gap should be closed (the README and CLAUDE.md should both say so explicitly).

### 6.2 Adversarial testing without consent enforcement at runtime

The consent check exists only at `POST /runs`. The orchestrator does not re-check `AssessmentRun.consent_granted` before invoking `atomic_runner.sh`. If a future bug allows a run to be created without the consent flag (e.g. via direct DB write, or a new endpoint that bypasses the schema), real exploit code will execute. This is a defence-in-depth issue: the guard should be re-asserted at every privilege boundary.

### 6.3 The LLM service is untrusted but treated as trustworthy

The remediation service prompt-injects evidence carefully, but the *output* is currently inserted directly into the report and rendered as text in the React UI. If a malicious target manages to influence the LLM's output (e.g. via a CVE description containing crafted text), the remediation field could carry HTML that the React renderer escapes — but also Markdown-ish content that humans copy-paste into their codebase. There is no "this remediation is LLM-generated, treat with care" disclaimer in the UI.

### 6.4 Single-point-of-failure on the OpenAI key

`VULBOX_OPENAI_API_KEY` is a single env var, no rotation, no rate limiting, no per-user quota. A bug or hostile target that triggers many high-token calls is a billing event. Add a token-budget per run (e.g. 30k tokens max) and a hard cap.

### 6.5 SQLite under concurrent writes

The orchestrator and the WebSocket layer both write to the same SQLite file. Under concurrent runs, SQLite serialises writes with file-level locking; on a modest VM this is invisible, but on a multi-tenant deployment it will cause noticeable latency. The migration target should be Postgres before concurrency becomes interesting.

### 6.6 Nothing prevents a malicious target from filling the disk

A target repository can contain a 50 GB Dockerfile, an infinite-output build step, or a runtime that writes to `/data` (which the prod compose mounts on the host). There is no quota or `--storage-opt size=` enforcement. A single malicious submission can DoS the host.

---

## 7. Missing Structure

### 7.1 No clear product boundary
The system reads as "the SDD, implemented" rather than "a tool with a defined scope". Decisions like "should we support Java?" or "do we handle multi-stage Dockerfiles?" or "what happens to a run after 30 days?" are not answered anywhere. A short `docs/SCOPE.md` listing supported and unsupported targets would prevent feature creep and clarify the testing surface.

### 7.2 No data-retention policy
Reports, run records, ART results, and Falco alerts all accumulate indefinitely. There is no archival path, no deletion policy, no anonymisation step. For any production deployment this becomes a compliance question very quickly.

### 7.3 No observability layer
There are structured logs (`app/core/logging.py`) but no metrics (`runs_total`, `run_duration_seconds`, `findings_per_run`, `llm_call_failures_total`) and no tracing across the async phases. Debugging a slow or stuck pipeline today means reading log lines.

### 7.4 No threat model document
A security tool should have a written threat model: what we defend, what we don't defend, what we trust, what we treat as adversarial. Without it, every code review is freelance and every reviewer applies different assumptions.

### 7.5 Documentation is scattered
`CLAUDE.md`, `DEPLOYMENT.md`, `README.md`, `docs/implementation_reference.md`, `docs/structure_alignment_report.md`, `docs/structure_checklist.md`, `system_design_reference_document.md`, `Proposed system architecture.md`, `e2eplan.md`, `evaluation.md`, and `changes_plan.md` all describe overlapping aspects of the project. New contributors have no obvious entry point. A single `docs/README.md` index pointing to "what to read for X" would help a lot.

---

## 8. Recommended Roadmap

The priorities below are listed in **value-per-week-of-work** order — the first two weeks of effort buy the most credibility per unit time.

### Sprint 1 (1–2 weeks): close the security gaps that block any external use

1. Add `Depends(get_current_user)` to every route in `runs.py`, `reports.py`, `ingest.py`, and the WebSocket handler.
2. Add `user_id` FK on `AssessmentRun`. Backfill existing rows to a "system" user. Filter every query.
3. Re-assert `consent_granted` at the top of `_phase_test_loop()`.
4. Add `error_message` to `AssessmentRun` and surface it on the Run Status page.
5. Replace the hardcoded API URL with `VITE_API_BASE_URL`.
6. Add Alembic and write the first migration.

### Sprint 2 (2–3 weeks): prove the end-to-end claim

1. Pick 5 target repositories of varying stack (Flask, Express, Spring Boot, Go, vulnerable-by-design like Juice Shop). Wire them into a `tests/integration/` suite that runs in CI on a Docker-enabled runner.
2. For each target: assert the orchestrator reaches COMPLETE, the matrix has ≥ N entries, the report exports as JSON without error, and the run finishes inside a stated time budget.
3. Document the time-and-resource budget in a new `docs/PERFORMANCE.md`.

### Sprint 3 (2–3 weeks): make the report worth reading

1. Build the LLM golden-set: 15 hand-written `(evidence → expected remediation)` pairs.
2. Validation harness that runs the LLM against each, scores against expected output, and produces a quality dashboard.
3. Iterate the prompt until the harness reports ≥ 70% "would-act-on-it" rate.
4. Add a "low-confidence" path that emits the static fallback and flags the entry for human review.

### Sprint 4 (3–4 weeks): expand technique coverage and add per-app config

1. Extend the CVE→technique YAML to ~30 techniques across 10 tactics.
2. Implement `T1027`, `T1041`, `T1140`, `T1078`, `T1562` ART tests as new entries in `atomic_runner.sh`.
3. Define the `.vulbox.yml` v1 schema (techniques to skip, sensitive paths to allow, network allow-list, build args, resource limits) and validate it on submission.
4. Add the "Configure run" step in the frontend before consent.
5. Parallelise independent ART techniques in the orchestrator.

### Sprint 5 (ongoing): production hardening

- Audit log table and middleware.
- Per-user / per-run quotas and rate limits.
- Metrics + tracing.
- Migrate to Postgres for any multi-user deployment.
- Docker storage and CPU/RAM quotas on the sandbox.

---

## 9. Risks to the Roadmap

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Adding auth breaks the existing demo flow | High | Medium | Keep a `--dev-no-auth` flag for the demo until end-to-end tests pass with auth on |
| Real-target integration tests are flaky on shared CI runners | High | High | Pin Docker image digests; record-replay HTTP for OpenAI; allocate a dedicated runner |
| LLM golden-set is judged subjectively | Medium | Medium | Two reviewers per case, keep the dataset versioned, treat the score as a trend not an absolute |
| Per-app config schema drifts from `.vulbox.yml` adoption | Medium | High | Version the schema (`v1: …`) from day one; refuse unknown versions |
| Postgres migration introduces silent type coercion bugs | Low | High | Run the full test suite against both backends in CI for at least one release |

---

## 10. Conclusion

VulBox is **further along than a typical academic prototype** — the orchestrator is real, the WebSocket is production-grade, the frontend is clean, and the data model captures the right concepts. It is also **further from "ready for users" than the demo suggests** — three of its fourteen REST endpoints have no auth, runs have no concept of ownership, the technique catalogue is shallow, and the LLM-generated remediations have not been validated against real exploit evidence.

The shortest credible path to "a tool worth using on an unfamiliar repository" is the five-sprint roadmap in §8. Roughly two months of focused engineering would close the security gaps, prove the end-to-end claim against external targets, and bring the report quality to the point where an engineer might actually paste an LLM remediation into a PR.

Until then, VulBox is best framed as **what it actually is**: a working proof-of-concept that demonstrates the SDD's three-dimensional Security Matrix is a viable architecture, with a clean frontend that helps a reviewer see how the parts fit together. Calling it more than that today would be over-claiming; calling it less would be selling short the real engineering that has gone in.

---

## Appendix A — Concrete Numbers

| Metric | Value |
|---|---|
| MITRE techniques in the runner script | 13 |
| MITRE techniques in CVE map | 12 |
| CVEs in CVE map | 55 |
| Tactics covered (out of 14) | 7 |
| Fixture findings (Trivy / Falco / ART) | 3 / 3 / 3 |
| Tests passing | 50 / 50 |
| Tests that exercise real subprocesses | 0 |
| REST endpoints with auth enforcement | 1 of 14 |
| Hardcoded URLs in frontend | 2 (`api.js`, `Report.jsx`) |
| Static remediation rules | 4 |
| Risk score range | 10–75 |
| Pipeline timeout | 1800 s |
| Max self-healing rebuilds | 3 |
| WebSocket replay buffer | 200 events |

## Appendix B — Files of Interest

| File | Why it matters |
|---|---|
| `app/services/orchestrator.py` | The core of the system; all phase logic lives here |
| `app/services/docker_manager.py` | Real CLI invocations vs dev stubs split lines 66–187 |
| `app/services/llm_remediation.py` | The remediation pipeline; prompt iteration target |
| `app/adapters/art_adapter.py` | Where the technique queue is built |
| `data/cve_technique_map.yml` | The map to expand for technique coverage |
| `scanners/atomic_runner.sh` | The 13 real technique tests |
| `app/api/runs.py` & `reports.py` | Where auth needs to be added |
| `tests/` | What is and isn't being verified |
| `docker/docker-compose.yml` | Production deployment target |

---

*End of report.*
