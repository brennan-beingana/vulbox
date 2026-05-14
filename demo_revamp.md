● Here's a detailed plan for Tier 3, scoped specifically to "must work flawlessly for a project demo." I've split it into
  three deliverables — automated, CI, and manual runbook — because a demo needs all three.
                                                                                                                           
  Tier 3 Plan: Real End-to-End Coverage for Demo-Grade Confidence                                                          
                                                                                                                           
  What "production grade" means for this demo                                                                              
                                                                                                                         
  For your demo to land, three things must be unshakeably true:                                                            
                                                                                                                         
  1. The pipeline actually works against a real repository — not just fixtures. Someone in the audience asking "is this    
  real?" has to be answerable with a live run.
  2. Every test/run is reproducible — same result on your laptop, the VM, and the demo machine. No flakes. No "it worked on
   my machine."                                                                                                            
  3. The system fails visibly, not silently — if Trivy isn't installed, if Docker is down, if the test target repo is
  unreachable, the failure has to be loud and self-explanatory, not "tests passed but nothing actually happened."          
                                                                                                                         
  Tier 3 builds toward all three.                                                                                          
                                                                                                                         
  ---
  Deliverable A — Automated E2E test (pytest -m e2e)
                                                                                                                           
  Goal: a single command that builds a real Docker image, runs Trivy and Falco against it, executes one ART test, computes
  a Security Matrix, and asserts the result is sane.                                                                       
                                                                                                                         
  Test target (committed in repo, not external):                                                                           
                                                                                                                         
  Create tests/e2e/fixtures/vulnerable_target/ containing:                                                                 
  - Dockerfile — FROM node:14-alpine (intentionally outdated → Trivy finds known CVEs deterministically)
  - package.json — pinned to lodash@4.17.20 (known prototype-pollution CVE) and express@4.16.0 (known CVEs)                
  - app.js — minimal Express server with a deliberately exploitable endpoint (e.g., eval(req.query.cmd)) so an ART test can
   actually trigger it                                                                                                     
  - README.md — explicitly labels the directory as "INTENTIONALLY VULNERABLE — for VulBox E2E tests only"                  
                                                                                                                           
  This makes the test deterministic: the same Trivy DB version + the same Dockerfile = the same finding count. No external 
  repo, no network race, no "the upstream changed."                                                                        
                                                                                                                           
  Test file: tests/e2e/test_full_pipeline.py                                                                               
                                                                                                                         
  Single test, structured roughly:                                                                                         
                                                                                                                         
  @pytest.mark.e2e
  @pytest.mark.requires_docker                                                                                             
  @pytest.mark.requires_trivy
  def test_full_pipeline_against_vulnerable_target(api_client, target_path):                                               
      run_id = api_client.create_run(repo_url=f"file://{target_path}", consent_granted=True)                               
                                                                                                                           
      # 2. Stream WebSocket events to a buffer (with timeout)                                                              
      events = collect_ws_events(run_id, max_seconds=600)                                                                  
                                                                                                                           
      # 3. Poll until COMPLETE or FAILED                                                                                   
      final = api_client.poll_run(run_id, timeout=600)                                                                     
      assert final.status == "COMPLETE", f"Pipeline failed: {events}"                                                      
                                                                                                                           
      # 4. Fetch the report                                                                                                
      report = api_client.get_report(run_id)
                                                                                                                           
      # 5. Hard assertions on shape                                                                                        
      assert report.trivy_findings_count >= 5  # known-vulnerable image, must find something
      assert len(report.security_matrix) > 0                                                                               
      assert report.remediations_count > 0                                                                                 
                                          
      # 6. Soft assertions on content (warnings, not failures)                                                             
      if not any(e.is_exploitable for e in report.security_matrix):                                                      
          warnings.warn("No exploit succeeded — ART runner may not be wired correctly")                                    
                                                                                                                           
  Markers in pytest.ini:                                                                                                   
  [pytest]                                                                                                                 
  markers =                                                                                                                
      e2e: full-pipeline tests requiring Docker + Trivy (skipped by default)                                               
      requires_docker: needs a running Docker daemon                                                                       
      requires_trivy: needs `trivy` CLI on PATH     
      requires_falco: needs Falco running with JSON output configured                                                      
  addopts = -m "not e2e"                                                                                                 
                                                                                                                           
  Conftest fixtures (tests/e2e/conftest.py):                                                                               
                                                                                                                           
  - api_client — boots the FastAPI app via TestClient, registers a test user, returns an authenticated wrapper. Tears down 
  the SQLite DB after each test.                                                                                         
  - target_path — yields the absolute path to tests/e2e/fixtures/vulnerable_target/. Asserts the Dockerfile exists.        
  - collect_ws_events(run_id, max_seconds) — opens the WebSocket, accumulates events with a hard timeout, returns the list.
   Critical for debugging when the assertion at step 3 fails.                                                              
  - Pre-flight check at session start: verifies docker info and trivy --version succeed; if not, skips all e2e tests with a
   single clear message.                                                                                                   
                                                                                                                         
  Why this design holds up under scrutiny:                                                                                 
                                                                                                                         
  - The vulnerable target is committed → no network flakes                                                                 
  - WebSocket events are captured → when something fails, the failure message includes the exact phase + event log
  - Markers gate execution → pytest tests/ keeps passing for casual contributors; pytest -m e2e is the explicit "I have    
  Docker, run the real thing" gesture                                                                                      
  - Pre-flight checks fail fast with helpful errors → "Docker daemon not reachable" beats "TimeoutError after 600s"        
                                                                                                                           
  ---                                                                                                                    
  Deliverable B — CI integration (GitHub Actions)                                                                          
                                                                                                                         
  Goal: every PR runs unit tests; every merge to main runs E2E tests; results are visible as a green/red badge in README.
                                                                                                                           
  File: .github/workflows/ci.yml (replaces or complements current ci/github-actions.yml)                                   
                                                                                                                           
  Two jobs:                                                                                                                
                                                                                                                         
  Job 1: unit — fast, runs on every PR                                                                                     
  - Ubuntu runner, Python 3.11
  - pip install -r requirements.txt                                                                                        
  - pytest tests/ -v (excludes e2e by default via addopts)                                                               
  - Coverage report uploaded as artifact                                                                                   
                                                                                                                           
  Job 2: e2e — slow, runs on push to main and on PRs labeled run-e2e                                                       
  - Ubuntu runner with Docker pre-installed (GitHub-hosted runners have it)                                                
  - Install Trivy from the official deb repo (pinned version, e.g., 0.50.4)                                                
  - trivy image --download-db-only (cached between runs)                                                                   
  - Skip Falco for now (kernel access is brittle in GHA — see "Falco caveat" below)                                        
  - pytest -m "e2e and not requires_falco" -v                                                                              
  - Upload the run's full report JSON as an artifact named e2e-run-{run_id}.json                                           
                                                                                                                           
  Falco caveat: GitHub-hosted runners don't allow loading kernel modules. Falco-dependent tests must run on a self-hosted  
  runner (your VM). Either:                                                                                                
  - Skip them in GHA (use -m "e2e and not requires_falco")                                                                 
  - Add a third e2e-full job tagged runs-on: [self-hosted, vm-46-101-193-155] that runs them on your VM                  
                                                                                                       
  For the demo, skip Falco in CI, but include a Falco-enabled run in the manual runbook (Deliverable C).                   
                                                                                                                           
  README badge:                                                                                                            
  ![CI](https://github.com/brennan-beingana/vulbox/actions/workflows/ci.yml/badge.svg)                                     
                                                                                                                           
  This is what gives "all tests pass" actual weight: the badge means someone other than your laptop ran the pipeline       
  successfully against a real Docker image. That's the line that closes the trap.                                          
                                                                                                                           
  ---                                                                                                                      
  Deliverable C — Manual demo runbook (docs/DEMO_RUNBOOK.md)                                                             
                                                                                                                           
  Goal: a checklist your future-self can follow 30 minutes before the demo to verify everything works on the actual demo
  machine.                                                                                                                 
                                                                                                                         
  Section structure:                                                                                                       
                                                                                                                         
  1. T-24 hours: pre-flight on demo machine                                                                                
  # Verify all tools
  docker --version          # >= 24                                                                                        
  trivy --version           # >= 0.50                                                                                      
  falco --version           # >= 0.38 (optional — note if missing)
  node --version            # >= 18                                                                                        
                                                                                                                         
  # Pre-pull all images (slow on conference wifi)                                                                          
  docker pull node:14-alpine                                                                                               
  docker pull falcosecurity/falco:0.38.0                                                                                   
                                                                                                                           
  # Pre-download Trivy DB (5-10 min on first run)                                                                          
  trivy image --download-db-only                 
                                                                                                                           
  # Verify backend starts                                                                                                
  cd vulbox && source venv/bin/activate                                                                                    
  uvicorn app.main:app --port 8000 &   
  sleep 3                                                                                                                  
  curl -f http://localhost:8000/health || echo "BACKEND DOWN"                                                              
  
  2. T-1 hour: smoke test                                                                                                  
                                                                                                                         
  Run the automated E2E suite against the local backend:                                                                   
  VULBOX_DEV_MODE=false pytest -m e2e -v --tb=short                                                                      
                                                                                                                           
  Expected output: 1 test passes in 2-5 minutes. If it fails, do not demo — debug or fall back to dev mode.                
                                                                                                                           
  3. T-15 min: load demo state                                                                                             
                                                                                                                           
  Pre-populate a few completed runs in the DB so the Reports page isn't empty when the demo starts:                        
  python scripts/seed_demo_data.py  # ← new script, see Deliverable D                                                    
                                                                                                                           
  4. The demo flow itself (script the user reads from)                                                                     
                                                                                                                           
  Numbered steps with what to say + what to click + the expected screen state at each step. Includes "if X fails, fall back
   to Y" branches:                                                                                                         
  - Login screen → click Register → create demo account → ✅ if you see the dashboard                                      
  - Dashboard → submit https://github.com/OWASP/NodeGoat (or the bundled vulnerable_target) → ✅ if redirected to          
  /runs/N/status                                                                                                 
  - Status screen → narrate the phase stepper as it advances → ✅ if BUILDING → SCANNING → TESTING within 90 seconds       
  - (If TESTING takes too long during demo) → switch to a pre-completed run from the Reports page                        
  - Report → walk through the Security Matrix → ✅ if you can point at a single cell and explain Present × Exploitable ×   
  Detectable                                                                                                               
  - Export → download CSV → open in terminal to show the raw data                                                          
                                                                                                                           
  5. Recovery scripts for anything that breaks live:                                                                       
  - scripts/demo_reset.sh — kills any running container, drops the DB, restarts the API                                    
  - scripts/demo_replay.sh — re-streams a known-good run's WebSocket events for backup                                     
                                                                                                                           
  This is the single most important deliverable for demo-grade confidence. The automated test proves it can work; the      
  runbook proves it will work on the day.                                                                                  
                                                                                                                           
  ---                                                                                                                      
  Deliverable D — Demo seed data + recovery (scripts/)                                                                   
                                                                                                                           
  Two small scripts that make the difference between a demo and a disaster:
                                                                                                                           
  scripts/seed_demo_data.py — creates 3-4 representative completed runs in the DB so the Reports page looks alive on first 
  load. Uses fixture JSON, not real pipeline runs.                                                                         
                                                                                                                           
  scripts/demo_reset.sh — one command to return to a known-good state: kill orphan containers, drop DB, re-seed, restart   
  API. Run it in a tmux pane during the demo.
                                                                                                                           
  ---                                                                                                                    
  What I'd flag as risks for the demo
                                                                                                                           
  ┌──────────────────────────────────────┬─────────────────────┬──────────────────────────────────────────────────────┐ 
  │                 Risk                 │     Likelihood      │                      Mitigation                      │    
  ├──────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────────┤  
  │                                      │ High (kernel        │ Demo with --profile full only if pre-tested;         │ 
  │ Falco fails to load on demo machine  │ modules are         │ otherwise demo dev mode + show a screenshot of a     │ 
  │                                      │ brittle)            │ Falco-enabled run                                    │    
  ├──────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────────┤ 
  │ Trivy DB download blocks the first   │ Medium              │ Pre-download in pre-flight; add a fixture-mode       │    
  │ scan                                 │                     │ fallback                                             │  
  ├──────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────────┤    
  │ Docker hub rate-limits during demo   │ Medium              │ Pre-pull all images; use a cached registry if        │    
  │                                      │                     │ available                                            │ 
  ├──────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────────┤    
  │ Live ART test fails to exploit       │                     │ Use the bundled vulnerable target with eval() —      │    
  │ (target hardened differently than    │ Medium              │ guaranteed to exploit                                │
  │ expected)                            │                     │                                                      │    
  ├──────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────────┤  
  │ WebSocket disconnects mid-demo       │ Low                 │ The status page already handles disconnects; show    │
  │                                      │                     │ "Reports" view as backup                             │    
  ├──────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────────┤
  │ Demo runs >5 min and audience loses  │ High                │ Cap real runs to 90s in the runbook; have a          │    
  │ interest                             │                     │ pre-completed run open in another tab                │    
  └──────────────────────────────────────┴─────────────────────┴──────────────────────────────────────────────────────┘
                                                                                                                           
  ---                                                                                                                    
  Files this plan creates / modifies
                                                                                                                           
  ┌───────────────────────────────────────────────────┬──────┬──────────────────────────────────┐
  │                       File                        │ Type │             Purpose              │                          
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                        
  │ tests/e2e/fixtures/vulnerable_target/Dockerfile   │ new  │ Deterministic vulnerable target  │
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤
  │ tests/e2e/fixtures/vulnerable_target/package.json │ new  │ Pinned vulnerable deps           │                          
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ tests/e2e/fixtures/vulnerable_target/app.js       │ new  │ Exploitable endpoint             │                          
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ tests/e2e/fixtures/vulnerable_target/README.md    │ new  │ "Intentionally vulnerable" label │                        
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ tests/e2e/test_full_pipeline.py                   │ new  │ The actual E2E test              │                        
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ tests/e2e/conftest.py                             │ new  │ Fixtures + pre-flight            │                        
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ pytest.ini                                        │ new  │ Markers + default exclude        │
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ .github/workflows/ci.yml                          │ new  │ Two-job CI (unit + e2e)          │                        
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ docs/DEMO_RUNBOOK.md                              │ new  │ Step-by-step demo script         │                        
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ scripts/seed_demo_data.py                         │ new  │ Pre-populate DB                  │                        
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ scripts/demo_reset.sh                             │ new  │ Recovery one-liner               │
  ├───────────────────────────────────────────────────┼──────┼──────────────────────────────────┤                          
  │ README.md                                         │ edit │ Add CI badge + link to runbook   │                        
  └───────────────────────────────────────────────────┴──────┴──────────────────────────────────┘                          
                                                                                                                         
  ---                                                                                                                      
  Recommended execution order (for your timeline)                                                                        
                                                 
  1. Day 1 — Build the bundled vulnerable target + write the E2E test locally. Get it green on your laptop. (~3 hrs)
  2. Day 2 — Wire up CI. Get the green badge. (~2 hrs)                                                                     
  3. Day 3 — Write DEMO_RUNBOOK.md. Run the runbook cold on the actual demo machine — find every gap. Fix gaps. (~3 hrs)   
  4. T-1 day — Run the runbook again, end to end, on the demo machine. Time it. Record yourself doing it as a backup video.
  5. T-0 — Demo with the runbook in a sticky note on a second monitor.                                                     
                                                                                                                           
  ---                                                  