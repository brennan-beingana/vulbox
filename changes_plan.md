 Step-by-Step Restructuring Plan

  ---
  Step 1 — Align the data model to the ERD (§4.10)
                                                                                                                                 
  The current Finding table conflates three distinct entity types. Split it properly.
                                                                                                                                 
  1a. Rename/extend Run → AssessmentRun                                                                                          
  - Rename table to assessment_runs, rename model to AssessmentRun                                                               
  - Add fields: consent_granted: bool (enforce before any ART test), submitted_by: str, completed_at: datetime                   
  - Change status enum to the 7 SDD states: SUBMITTED, BUILDING, SCANNING, TESTING, REBUILDING, REPORTING, COMPLETE, FAILED
                                                                                                                                 
  1b. Rename/specialise Finding → TrivyFinding                                                                                   
  - Rename table to trivy_findings                                                                                               
  - Fields: finding_id, run_id, cve_id, severity, package_name, description, fix_available: bool                                 
  - Remove Falco/Atomic rows from this table entirely                                                                            
                                                                                                                                 
  1c. Replace Validation → ARTTestResult                                                                                         
  - Rename table to art_test_results                                                                                             
  - Fields: test_result_id, run_id, mitre_test_id, exploited: bool, crash_occurred: bool, executed_at                            
  - These two booleans are the primary data points for Exploitability in the Security Matrix         
                                                                                                                                 
  1d. Replace Falco rows in Finding → FalcoAlert                                                                                 
  - New table falco_alerts                                                                                                       
  - Fields: alert_id, run_id, test_result_id (FK to art_test_results — this is the key linkage), rule_triggered, severity,       
  syscall_context, timestamp, detected: bool                                                                                     
  - Linking to test_result_id (not just run_id) is what makes Detectability measurable per-test                                  
   
  1e. Replace CorrelatedFinding → SecurityMatrixEntry                                                                            
  - New table security_matrix_entries
  - Fields: entry_id, run_id, finding_id (FK to trivy_findings), test_result_id (FK to art_test_results), is_present: bool,      
  is_exploitable: bool, is_detectable: bool, mitre_tactic_id, risk_score                                                   
  - This is the three-dimensional output the SDD describes in §4.13                                                              
                                                                   
  1f. Keep Remediation table — it isn't in the ERD but is specified in §14.2. Link it to SecurityMatrixEntry instead of          
  CorrelatedFinding.                                                                                                             
                                                                                                                                 
  Delete: app/models/correlated_finding.py, the Validation model, and the general Finding model. Update app/models/__init__.py   
  accordingly.    
                                                                                                                                 
  ---             
  Step 2 — Add app/core/logging.py and app/core/security.py
                                                           
  2a. app/core/logging.py
  - Structured JSON logger using Python's logging module                                                                         
  - All pipeline events (phase transitions, crashes, rebuild triggers) write to it                                               
  - This is needed before writing the Orchestrator so every action is traceable                                                  
                                                                                                                                 
  2b. app/core/security.py                                                                                                       
  - JWT token creation and verification using python-jose                                                                        
  - get_current_user() FastAPI dependency                                                                                        
  - Role constants: ROLE_PROVIDER = "provider", ROLE_ADMIN = "admin"
  - Add python-jose[cryptography] and passlib[bcrypt] to requirements.txt                                                        
                                                                                                                                 
  ---                                                                                                                            
  Step 3 — Build the Orchestrator (app/services/orchestrator.py)                                                                 
                                                                                                                                 
  This is the most important addition. The Orchestrator is the central controller (§4.6, §4.12.2) that drives the whole pipeline
  asynchronously.                                                                                                                
                  
  3a. Implement the state machine                                                                                                
  - set_status(db, run_id, state) — single function that transitions AssessmentRun.status and writes a log entry. Valid
  transitions must match the state diagram: FAILED is only reachable from BUILDING.                                              
                                                                                   
  3b. Implement start_assessment(run_id, db)                                                                                     
  - Entry point. Called as a FastAPI BackgroundTask from POST /runs.                                                             
  - Drives: clone_and_build → run_phase1_scan → deploy_to_sandbox → run_phase3_loop → generate_report                            
  - Wrapped in a try/except: any unhandled exception sets status to FAILED only if still in BUILDING; later failures log but     
  continue                                                                                                                       
                                                                                                                                 
  3c. Implement clone_and_build(run_id, repo_url, db)                                                                            
  - Sets status → BUILDING                                                                                                       
  - Calls DockerManager.clone_repo(repo_url) then DockerManager.build_image()
  - On failure: set status → FAILED and return (this is the only terminal failure path)                                          
                                                                                                                                 
  3d. Implement run_phase1_scan(run_id, image_tag, db)                                                                           
  - Sets status → SCANNING                                                                                                       
  - Calls TrivyAdapter.scan(image_tag) → returns list of TrivyFinding objects                                                    
  - Stores all findings. Non-blocking Rule: always proceeds regardless of findings count or severity                             
  - Returns findings list for queue-building in Phase 3                                             
                                                       
  3e. Implement deploy_to_sandbox(run_id, image_tag, db)                                                                         
  - Sets status → TESTING                                                                                                        
  - Calls DockerManager.run_sandbox(image_tag) with network isolation                                                            
  - Calls FalcoAdapter.attach(container_id)                                                                                      
  - Waits for Falco to confirm it is active before proceeding
                                                                                                                                 
  3f. Implement run_phase3_loop(run_id, trivy_findings, db)                                                                      
  - Calls ARTAdapter.build_queue(trivy_findings) — CVE-related tests go first                                                    
  - For each test in queue:                                                                                                      
    a. Call ARTAdapter.execute_test(test_id) → get TestResult                                                                    
    b. If crash_occurred: log crash event, call DockerManager.rebuild_and_restart(), set status → REBUILDING then back to        
  TESTING, continue to next test (Self-Healing Pipeline)                                                                 
    c. If no crash: call FalcoAdapter.collect_alerts(test_result_id) → store FalcoAlert rows linked to this test_result_id       
    d. Store ARTTestResult row                                                                                            
    e. Create SecurityMatrixEntry with is_present=True, is_exploitable=result.exploited, is_detectable=(len(alerts) > 0)         
                                                                                                                                 
  3g. Implement generate_report(run_id, db)                                                                                      
  - Sets status → REPORTING                                                                                                      
  - Calls RemediationService.generate_remediations(db, run_id) for each SecurityMatrixEntry                                      
  - Sets status → COMPLETE
                                                                                                                                 
  ---
  Step 4 — Write the three tool adapters (app/adapters/)                                                                         
                                                                                                                                 
  Create app/adapters/__init__.py and three adapter modules.
                                                                                                                                 
  4a. app/adapters/trivy_adapter.py — TrivyAdapter
  - scan(image_ref: str) -> list[TrivyFinding]                                                                                   
  - Invokes scanners/trivy_runner.sh via subprocess.run()                                                                        
  - Parses the JSON output (same schema as existing trivy-fixture.json)
  - is_blocking() -> bool always returns False (enforces Non-Blocking Rule as a code constraint, §4.12.2)                        
                                                                                                                                 
  4b. app/adapters/falco_adapter.py — FalcoAdapter                                                                               
  - attach(container_id: str) — starts Falco as a sidecar process watching the container                                         
  - detach() — stops Falco process                                                                                               
  - collect_alerts(test_result_id: int, window_seconds: int) -> list[FalcoAlert] — reads Falco's output file for alerts that     
  fired during the test execution window and links them to test_result_id                                                        
  - In dev/test mode: reads from data/sample_outputs/falco-fixture.json  

  4c. app/adapters/art_adapter.py — ARTAdapter                                                                                   
  - build_queue(trivy_findings: list[TrivyFinding]) -> list[str] — returns ordered test IDs; CVE-related tests (matching cve_id
  to known ART technique mappings) sorted to front                                                                               
  - execute_test(test_id: str) -> ARTTestResult — invokes scanners/atomic_runner.sh, captures exploited and crash_occurred from
  exit code / output                                                                                                             
  - In dev/test mode: reads from data/sample_outputs/atomic-fixture.json                                                         
   
  ---                                                                                                                            
  Step 5 — Build DockerManager (app/services/docker_manager.py)
                                                                                                                                 
  5a. clone_repo(repo_url: str) -> Path — git clone to a temp directory
                                                                                                                                 
  5b. build_image(repo_path: Path, tag: str) -> str — docker build -t {tag} {repo_path}; raises BuildFailedError on non-zero exit
                                                                                                                                 
  5c. run_sandbox(image_tag: str) -> str — docker run on an isolated network (--network none or a dedicated bridge with iptables 
  blocking outbound), returns container_id
                                                                                                                                 
  5d. rebuild_and_restart(container_id: str, image_tag: str) -> str — stop/remove old container, docker run fresh instance,      
  return new container_id; this is the technical implementation of the Self-Healing Pipeline
                                                                                                                                 
  5e. destroy_sandbox(container_id: str) — stop and remove the sandbox container after the test loop exits                       
   
  Add docker Python SDK (docker package) to requirements.txt.                                                                    
                  
  ---                                                                                                                            
  Step 6 — Update the API layer
                               
  6a. Update POST /runs
  - Accept repo_url and consent_granted: bool in the request body                                                                
  - Validate that consent_granted == True (reject with 400 if not — FR-01)
  - Store submitted_by from JWT token once auth is added                                                                         
  - Fire orchestrator.start_assessment(run_id) as a BackgroundTasks task                                                         
  - Return run_id immediately (≤3 seconds, NFR-02)                                                                               
                                                                                                                                 
  6b. Add DELETE /runs/{run_id} (§10.1)                                                                                          
  - Allowed only if status is not TESTING or REBUILDING (would leave orphaned containers)                                        
                                                                                                                                 
  6c. Add GET /runs/{run_id}/validations (§10.4)                                                                                 
  - Returns all ARTTestResult rows for the run                                                                                   
                                                                                                                                 
  6d. Add GET /reports/{run_id}/export (§10.3)
  - Query param format: json (default), csv, pdf                                                                                 
  - JSON: return existing report schema                                                                                          
  - CSV: serialize SecurityMatrixEntry rows using Python csv module
  - PDF: use reportlab or weasyprint to render the Security Matrix; add to requirements.txt                                      
                                                                                                                                 
  6e. Add WebSocket endpoint WS /ws/runs/{run_id}/status                                                                         
  - The Orchestrator writes status events to an in-memory asyncio queue keyed by run_id                                          
  - The WebSocket handler reads from the queue and pushes to the connected client                                                
  - The frontend uses this for the Live Status screen                            
                                                                                                                                 
  6f. Update app/api/ingest.py                                                                                                   
  - The ingestion endpoints become internal-only (called by the Orchestrator/adapters, not by external CI jobs pushing JSON)     
  - Keep them for the demo/fixture path but add a note they're bypassed when the Orchestrator is active                          
                                                                                                                                 
  ---                                                                                                                            
  Step 7 — Add JWT authentication and RBAC (FR-11, NFR-01)                                                                       
                                                                                                                                 
  7a. Add User model (app/models/user.py)                                                                                        
  - Fields: id, email, hashed_password, role (provider | admin), created_at                                                      
                                                                                                                                 
  7b. Add auth router (app/api/auth.py)
  - POST /auth/register — hash password with bcrypt, store user                                                                  
  - POST /auth/login — verify password, return JWT access token                                                                  
  - GET /auth/me — return current user info                    
                                                                                                                                 
  7c. Protect routes with Depends(get_current_user)
  - All /runs, /reports routes require a valid token                                                                             
  - Admin-only routes (e.g. DELETE /runs/{run_id}) check current_user.role == "admin"
                                                                                                                                 
  ---                                                                                                                            
  Step 8 — Build the React frontend (§4.6, §6)                                                                                   
                                                                                                                                 
  Replace the stub App.jsx with four proper screens.                                                                             
                                                                                                                                 
  8a. Install routing and HTTP library                                                                                           
  - Add react-router-dom and axios to frontend/package.json
                                                                                                                                 
  8b. Screen 1 — Auth UI (src/pages/Login.jsx, src/pages/Register.jsx)
  - Simple form: email + password                                                                                                
  - Stores JWT in localStorage; redirects to Submission Form on success
                                                                                                                                 
  8c. Screen 2 — Submission Form (src/pages/NewRun.jsx)                                                                          
  - Input: GitHub repository URL                                                                                                 
  - Consent checkbox with plain-language explanation of what adversarial testing means (NFR-04)                                  
  - Submit → POST /runs → shows run ID and navigates to Live Status                                                              
                                                                                                                                 
  8d. Screen 3 — Live Status (src/pages/RunStatus.jsx)                                                                           
  - Connects to WS /ws/runs/{run_id}/status                                                                                      
  - Displays current phase (BUILDING → SCANNING → TESTING → REPORTING → COMPLETE)                                                
  - Shows test-by-test progress during Phase 3 as WebSocket events arrive                                                        
  - Shows crash/rebuild events as they happen                                                                                    
                                                                                                                                 
  8e. Screen 4 — Report Dashboard (src/pages/Report.jsx)                                                                         
  - Fetches GET /reports/{run_id}                                                                                                
  - Renders the Security Matrix as a table: one row per vulnerability, columns for Presence ✓/✗, Exploitability ✓/✗,
  Detectability ✓/✗, Risk Score, MITRE Tactic                                                                                    
  - "Export PDF" button → GET /reports/{run_id}/export?format=pdf                                                                
   
  ---                                                                                                                            
  Step 9 — Add CI templates and update the GitHub Actions workflow
                                                                                                                                 
  9a. Create ci/ directory with github-actions.yml
  - Moves CI logic out of .github/workflows/ and into ci/ as the SDD directory structure specifies (§15)                         
  - The workflow should: trigger the Orchestrator via POST /runs rather than running Trivy standalone                            
                                                                                                     
  9b. Add ci/gitlab-ci-sample.yml (FR-12)                                                                                        
  - Minimal GitLab CI equivalent so providers on GitLab can use the same tool                                                    
                                                                                                                                 
  9c. Add docker/Dockerfile.app — containerise the FastAPI backend                                                               
  9d. Add docker/Dockerfile.target-app — a sample intentionally-vulnerable app for demo purposes                                 
  9e. Update docker/docker-compose.yml — add a falco service and a sandbox network with internal: true                           
                                                                                                                                 
  ---                                                                                                                            
  Step 10 — Write the test suite                                                                                                 
                                                                                                                                 
  10a. tests/test_parsers.py
  - Unit-test TrivyAdapter.scan() using the fixture file (mock subprocess)                                                       
  - Unit-test FalcoAdapter.collect_alerts() using the fixture file                                                               
  - Unit-test ARTAdapter.execute_test() using the fixture file
                                                                                                                                 
  10b. tests/test_correlation.py
  - Test SecurityMatrixEntry creation: given a TrivyFinding, an ARTTestResult with exploited=True, and a FalcoAlert, assert      
  is_present=True, is_exploitable=True, is_detectable=True                                                                       
  - Test the negative case: ARTTestResult with exploited=False, zero Falco alerts
  - Test the self-healing path: crash_occurred=True increments rebuild count, test continues                                     
                                                                                                                                 
  10c. tests/test_remediation.py                                                                                                 
  - Test that a SecurityMatrixEntry with is_exploitable=True produces a confidence="critical" remediation                        
  - Test that is_present=True, is_exploitable=False produces a lower-priority remediation                                        
  - Test the rule lookup paths in RemediationService                                                                             
                                                                                                                                 
  Add pytest and httpx (for FastAPI test client) to requirements.txt.                                                            
                                                                                                                                 
  ---                                                                                                                            
  Step 11 — Update CLAUDE.md
                                                                                                                                 
  After all the above is done, update CLAUDE.md to reflect:
  - the new directory layout (app/adapters/, ci/)                                                                                
  - new commands (pytest, export endpoint)                                                                                       
  - the Orchestrator flow replacing the manual demo script
                                                                                                                                 
  ---             
  Summary of what changes vs what stays                                                                                          
                                                                                                                                 
  ┌──────────────────────────────────┬──────────────────────────────────────────┐
  │            Component             │                  Action                  │                                                
  ├──────────────────────────────────┼──────────────────────────────────────────┤
  │ app/models/run.py                │ Extend (7 states, consent, submitted_by) │                                                
  ├──────────────────────────────────┼──────────────────────────────────────────┤
  │ app/models/finding.py            │ Replace with trivy_finding.py            │                                                
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/models/validation.py         │ Replace with art_test_result.py          │                                                
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/models/correlated_finding.py │ Replace with security_matrix_entry.py    │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/models/remediation.py        │ Keep, re-link to SecurityMatrixEntry     │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/models/user.py               │ New                                      │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/models/falco_alert.py        │ New                                      │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/services/orchestrator.py     │ New (most important)                     │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/services/docker_manager.py   │ New                                      │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/adapters/                    │ New directory (3 adapters)               │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/core/security.py             │ New                                      │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/core/logging.py              │ New                                      │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/api/runs.py                  │ Update (BackgroundTask, DELETE)          │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/api/ingest.py                │ Demote to internal/dev-only              │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/api/processing.py            │ Remove (Orchestrator absorbs this)       │
  ├──────────────────────────────────┼──────────────────────────────────────────┤
  │ app/api/reports.py               │ Update (export endpoint, matrix schema)  │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/api/auth.py                  │ New                                      │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ app/api/websocket.py             │ New                                      │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ frontend/src/                    │ Full rewrite (4 screens + auth)          │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ ci/                              │ New directory                            │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ docker/                          │ Add Dockerfiles + sandbox network        │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ tests/                           │ 3 test files (currently empty)           │
  ├──────────────────────────────────┼──────────────────────────────────────────┤                                                
  │ scripts/demo.py                  │ Update to match new API flow             │
  └──────────────────────────────────┴──────────────────────────────────────────┘                                                