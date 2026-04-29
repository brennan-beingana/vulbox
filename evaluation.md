● I've reviewed the orchestrator (app/services/orchestrator.py), DockerManager, the three adapters, and the wiring through POST 
  /runs + BackgroundTasks. Here's an honest evaluation, with the changes that would make it actually reliable in production, and 
  a concrete way to drive an E2E test against the live pipeline while watching system events.       
                                                                                                                                 
  Orchestration evaluation                                                                                                       
                                                                                                                                 
  The state machine and event push pattern are clean, but several issues will break or silently corrupt production runs. Ranked  
  by severity:                                                                                                                   
                                                                                                                                 
  Correctness / reliability bugs

  1. Request-scoped DB session leaks into BackgroundTask — runs.py:27 passes db (yielded by Depends(get_db)) into                
  start_assessment. The session is closed when the response returns; the orchestrator then writes to a dead session. This is the
  single highest-impact bug.                                                                                                     
  2. Falco process is module-global (falco_adapter.py:25) — _falco_proc and attach()/detach() are singletons. Two concurrent runs
   collide. Same for data/falco/events.json reads with no per-run filtering.                                                     
  3. falco --cri ... -p <container_id> (falco_adapter.py:37) — -p is not a valid Falco flag. Production attach will fail
  immediately. Falco watches host-wide; you need container.id filtering in rules + per-run log slicing.                          
  4. Sandbox container started with --network none --read-only (docker_manager.py:60) — most target images won't start (no
  writable /tmp, no port, no DB). Pipeline goes BUILDING → TESTING → orchestrator dies on first test.                            
  5. finding_id = trivy_findings[0].finding_id if trivy_findings else None (orchestrator.py:163) — every matrix row is correlated
   to the first CVE, regardless of what was tested. The Presence/Exploitability/Detectability matrix is mathematically wrong from
   row 2 onward.  
  6. No bound on the REBUILDING loop — a test that always crashes spins forever. No max-rebuild counter, no global pipeline      
  timeout.                                                                                                                       
  7. Late-phase exceptions log and exit silently (orchestrator.py:87) — comment says "assessment continues," but the function
  returns. The run is stuck in TESTING/REPORTING with no terminal status, no completed_at.                                       
  8. No try/finally around sandbox lifecycle — a TESTING-phase exception leaks the container and the Falco subprocess.
  9. WS subscribers that connect after orchestrator started miss earlier events — get_status_queue is lazy, no replay buffer, no 
  last-known status backfill.                                                                                                    
  10. _status_queues dict is never cleaned up — slow leak. After thousands of runs, the API process holds dead queues.           
  11. FastAPI BackgroundTasks is wrong for multi-minute jobs — they run in the request task group; if uvicorn restarts mid-run   
  (deploy, OOM, signal) the run is silently abandoned with no recovery on next boot.                                             
  12. Fixture paths are relative (Path("data/sample_outputs/...")) — break if the process is launched from anywhere but the repo 
  root (e.g., a systemd unit with a different CWD).                                                                              
                  
  Practical / operability gaps                                                                                                   
                  
  - No persistence of stdout/stderr from git clone, docker build, trivy, atomic_runner.sh — when something fails, there is       
  nothing to look at.
  - Risk score is binary-flag arithmetic; CVE severity (CRITICAL vs. LOW) is ignored.                                            
  - _CVE_TECHNIQUE_MAP has 4 entries and a 3-technique fallback — every run produces ~3 matrix rows regardless of repo size.     
  - No idempotency on POST /runs. Two clicks → two parallel runs against the same repo, same image tag — docker build -t         
  vulbox-run-{id} collides only on layer cache, but _falco_proc collides hard.                                                   
  - No authn check inside the orchestrator path — if a row is created, the orchestrator runs unconditionally; consent is checked 
  at the route only.                                                                                                             
                  
  Prioritized changes (smallest patch with the most reliability)                                                                 
                  
  I'd group these into three tiers. The Tier 1 changes are the minimum to call this "reliable enough for a thesis demo on a real 
  VM."            
                                                                                                                                 
  Tier 1 — must fix before production E2E:

  ┌─────┬─────────────────────────────────────────────────────────────────────────────────────────┬──────────────────────────┐   
  │  #  │                                         Change                                          │          Where           │
  ├─────┼─────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤   
  │ 1   │ Open a fresh SessionLocal() inside start_assessment; close in finally. Don't accept db  │ orchestrator.py:58,      │
  │     │ as a parameter.                                                                         │ runs.py:27               │
  ├─────┼─────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤   
  │ 2   │ Wrap the entire pipeline in try/finally that always calls DockerManager.destroy_sandbox │ orchestrator.py:67–88    │
  │     │  and FalcoAdapter.detach and sets a terminal status (COMPLETE or FAILED).               │                          │   
  ├─────┼─────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤
  │ 3   │ Add MAX_REBUILDS = 3 counter; on exceeding, mark run FAILED with a reason.              │ orchestrator.py:121      │   
  ├─────┼─────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤   
  │ 4   │ Add a global per-run wall-clock timeout (e.g., 30 min) via asyncio.wait_for.            │ orchestrator.py:67       │
  ├─────┼─────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤   
  │ 5   │ Correlate matrix entries to the CVE that motivated the test (use _CVE_TECHNIQUE_MAP     │ orchestrator.py:163      │
  │     │ reversed, or store the CVE→technique link when building the queue).                     │                          │   
  ├─────┼─────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤
  │     │ Replace BackgroundTasks with a real worker: either asyncio.create_task held in a        │                          │   
  │ 6   │ registry plus a startup-time "resume orphaned runs" sweep, or pull in arq/rq/Celery.    │ runs.py:27, app/main.py  │   
  │     │ Even a 30-line custom worker is fine.                                                   │                          │
  ├─────┼─────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤   
  │     │ Make Falco per-run: write events with --json --file-output data/falco/run-<id>.json,    │                          │
  │ 7   │ filter by container.id == <our id>, and read only that file in collect_alerts. Drop the │ falco_adapter.py         │   
  │     │  global _falco_proc.                                                                    │                          │
  ├─────┼─────────────────────────────────────────────────────────────────────────────────────────┼──────────────────────────┤   
  │ 8   │ Capture stdout/stderr of every subprocess call into data/runs/<id>/logs/ and expose GET │ docker_manager.py, all   │
  │     │  /runs/{id}/logs.                                                                       │ adapters                 │   
  └─────┴─────────────────────────────────────────────────────────────────────────────────────────┴──────────────────────────┘
                                                                                                                                 
  Tier 2 — needed for a multi-run demo on the VM:

  9. Resolve fixture paths against settings.project_root so CWD doesn't matter.                                                  
  10. WS replay: keep last N events per run in a ring buffer; on connect, send buffer then live stream.
  11. Cleanup _status_queues[run_id] after COMPLETE/FAILED + 60 s grace.                                                         
  12. Sandbox config per-image: read an optional .vulbox.yml in the cloned repo for ports, tmpfs, command overrides instead of   
  hardcoding --network none --read-only.                                                                                         
  13. Risk score should weight Trivy severity (critical=20, high=15, medium=10, low=5) on top of the                             
  present/exploitable/detectable triad.                                                                                          
                  
  Tier 3 — nice to have:                                                                                                         
                  
  14. Idempotent POST /runs via a client idempotency_key header.                                                                 
  15. Move CVE→technique map to a YAML file under data/mappings/ so it can grow without code change.
                                                                                                                                 
  Practical end-to-end test on the production VM                                                                                 
                                                                                                                                 
  This assumes the VM already has Docker, Falco, Trivy, and the API running under a process supervisor (systemd/docker-compose). 
  Goal: drive a real run against a deliberately vulnerable image, watch the matrix populate, and verify each subsystem's events.
                                                                                                                                 
  Test target     

  Use a known-vulnerable image rather than a real customer repo. Two good choices:                                               
   
  - vulhub/log4j-cve-2021-44228 — has a real RCE (T1059), Trivy will flag it, ART has matching atomics, Falco's default ruleset  
  detects the spawned shell.
  - appsecco/dvna (Damn Vulnerable Node App) — multiple CVEs, app actually starts so the sandbox-run path is exercised.          
                                                                                                                                 
  Pre-flight (5 min, on the VM)                                                                                                  
                                                                                                                                 
  # Verify each subsystem alone before pointing the orchestrator at them                                                         
  docker run --rm aquasec/trivy:latest image --format json vulhub/log4j-cve-2021-44228 | jq '.Results | length'                  
  sudo falco --list | head           # rules loaded                                                                              
  docker ps --format '{{.Names}}'    # api, frontend, falco containers up                                                        
  curl -fsS http://<vm-ip>:8000/health                                                                                           
                                                                                                                                 
  If any of these fail, fix before driving the orchestrator.                                                                     
                                                                                                                                 
  Drive the run                                                                                                                  
                  
  TOKEN=$(curl -s -X POST http://<vm-ip>:8000/auth/login \
    -H 'content-type: application/json' \                                                                                        
    -d '{"email":"demo@vulbox.local","password":"demo-password-123"}' | jq -r .access_token)
                                                                                                                                 
  RUN_ID=$(curl -s -X POST http://<vm-ip>:8000/runs \                                                                            
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \                                                      
    -d '{"project_name":"log4shell-e2e","repo_url":"https://github.com/vulhub/vulhub.git",                                       
         "branch":"master","commit_sha":"HEAD","image_name":"vulhub/log4j-cve-2021-44228",                                       
         "image_tag":"latest","consent_granted":true}' | jq -r .id)                                                              
  echo "run_id=$RUN_ID"                                                                                                          
                                                                                                                                 
  Watch four event streams in parallel (four terminals or tmux)                                                                  
                  
  1. Pipeline events (WebSocket):                                                                                                
  websocat ws://<vm-ip>:8000/ws/runs/$RUN_ID/status
  2. API + orchestrator logs:                                                                                                    
  docker logs -f vulbox-api 2>&1 | grep -E "run_id=$RUN_ID|ERROR"
  3. Falco syscall alerts (the actual detectability signal):                                                                     
  tail -F data/falco/events.json | jq 'select(.output_fields["container.id"] | startswith("'$SANDBOX_ID'"))'                     
  4. Sandbox container resource use (catches hangs, OOM, fork bombs):                                                            
  docker stats $(docker ps -q --filter "ancestor=vulbox-run-$RUN_ID")                                                            
                                                                                                                                 
  Validation checklist (what "passing" looks like)                                                                               
                                                                                                                                 
  For each phase, you should see a specific signal — not just a status string. If a signal is missing, you've found a real bug,  
  not a flaky test:
                                                                                                                                 
  ┌──────────┬──────────────────────────────────────────────────┬────────────────────────────────────────────────────────────┐   
  │  Phase   │                 Expected signal                  │                 If missing → likely cause                  │
  ├──────────┼──────────────────────────────────────────────────┼────────────────────────────────────────────────────────────┤   
  │ BUILDING │ docker images | grep vulbox-run-$RUN_ID returns  │ clone or build failed; check                               │
  │          │ a row                                            │ data/runs/$RUN_ID/logs/build.log (after Tier-1 #8)         │
  ├─────────────┼────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤    
  │ SCANNING    │ GET /runs/$RUN_ID returns Trivy findings ≥ 1   │ Trivy CLI not on PATH, or image not pullable from VM     │ 
  │             │ with cve_id=CVE-2021-44228                     │                                                          │    
  ├─────────────┼─────────────────────────────────────────────────────┼──────────────────────────────────────────────────────┤
  │ TESTING     │ New container in docker ps; Falco events.json grows │ sandbox flags too restrictive (Tier-1 #4 / Tier-2    │   
  │             │                                                     │ #12); image won't start                              │   
  ├─────────────┼─────────────────────────────────────────────────────┼──────────────────────────────────────────────────────┤
  │ TESTING     │ At least one falco_alert row with non-null          │ Falco attach broken (Tier-1 #7); rules not           │   
  │ (Falco)     │ test_result_id                                      │ container-scoped                                     │   
  ├─────────────┼─────────────────────────────────────────────────────┼──────────────────────────────────────────────────────┤
  │ REPORTING   │ GET /reports/$RUN_ID returns security_matrix with   │ matrix-correlation bug (Tier-1 #5)                   │   
  │             │ rows whose finding_id differs across rows           │                                                      │   
  ├─────────────┼─────────────────────────────────────────────────────┼──────────────────────────────────────────────────────┤
  │ COMPLETE    │ completed_at is set; sandbox container removed; no  │ missing finally (Tier-1 #2)                          │   
  │             │ leaked Falco process                                │                                                      │   
  └─────────────┴─────────────────────────────────────────────────────┴──────────────────────────────────────────────────────┘
                                                                                                                                 
  Failure-injection runs (do these after the happy path passes)                                                                  
   
  The reliability claims only mean something if abnormal cases also reach a terminal status. Run each and confirm the run ends as
   FAILED with a reason and that no resources leak (docker ps -a, pgrep falco):
                                                                                                                                 
  1. Submit repo_url=https://github.com/does/not/exist.git → expect FAILED from BUILDING within 120 s.                           
  2. Submit a repo with a Dockerfile that RUN exit 1 → expect FAILED from BUILDING.
  3. Submit an image whose entrypoint is sleep 99999 and no port → expect ART tests to run with no exploitation; sandbox cleaned 
  up; COMPLETE.                                                                                                                  
  4. Kill the API container during TESTING (docker kill vulbox-api) and restart it → after Tier-1 #6, the run should resume or be
   marked FAILED on boot, not stay TESTING forever.                                                                              
  5. Submit two runs back-to-back against the same image → both must reach COMPLETE, both must have distinct Falco alert sets
  (validates Tier-1 #7).                                                                                                         
                  
  Post-run forensic check                                                                                                        
                  
  sqlite3 data/findings.db "                                                                                                     
    SELECT r.id, r.status, r.completed_at,
           (SELECT count(*) FROM trivy_findings WHERE run_id=r.id) AS trivy,                                                     
           (SELECT count(*) FROM art_test_results WHERE run_id=r.id) AS art,
           (SELECT count(*) FROM falco_alerts WHERE run_id=r.id) AS falco,                                                       
           (SELECT count(*) FROM security_matrix_entries WHERE run_id=r.id) AS matrix                                            
    FROM assessment_runs r WHERE id=$RUN_ID;"                                                                                    
  docker ps -a --filter "ancestor=vulbox-run-$RUN_ID"   # should be empty                                                        
  pgrep -af falco                                       # should be only the sidecar, not orphans                                
                                                                                                                                 
  If matrix ≠ art or any leaked container/process exists, the run is "green" on the API but actually broken — exactly the kind of
   failure today's silent-exception path hides.                                                                                  
                                                                                                                                 
  ---             

  1. Submit repo_url=https://github.com/does/not/exist.git → expect FAILED from BUILDING within 120 s.
  2. Submit a repo with a Dockerfile that RUN exit 1 → expect FAILED from BUILDING.
  3. Submit an image whose entrypoint is sleep 99999 and no port → expect ART tests to run with no exploitation; sandbox cleaned
  up; COMPLETE.
  4. Kill the API container during TESTING (docker kill vulbox-api) and restart it → after Tier-1 #6, the run should resume or be
   marked FAILED on boot, not stay TESTING forever.
  5. Submit two runs back-to-back against the same image → both must reach COMPLETE, both must have distinct Falco alert sets
  (validates Tier-1 #7).

  Post-run forensic check

  sqlite3 data/findings.db "
    SELECT r.id, r.status, r.completed_at,
           (SELECT count(*) FROM trivy_findings WHERE run_id=r.id) AS trivy,
           (SELECT count(*) FROM art_test_results WHERE run_id=r.id) AS art,
           (SELECT count(*) FROM falco_alerts WHERE run_id=r.id) AS falco,
           (SELECT count(*) FROM security_matrix_entries WHERE run_id=r.id) AS matrix
    FROM assessment_runs r WHERE id=$RUN_ID;"
  docker ps -a --filter "ancestor=vulbox-run-$RUN_ID"   # should be empty
  pgrep -af falco                                       # should be only the sidecar, not orphans

  If matrix ≠ art or any leaked container/process exists, the run is "green" on the API but actually broken — exactly the kind of
   failure today's silent-exception path hides.
