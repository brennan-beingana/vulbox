● Here's an end-to-end runbook for driving a real assessment against your VM, updated for the Tier-1/Tier-2 paths. Don't follow  
  evaluation.md literally — three commands in it (Falco log path, watch streams) are now stale.                                
                                                                                                                                 
  Step 0 — Pick your deployment shape (5 min decision)                                                                           
                                                                                                                                 
  Option A — API on the host directly (uvicorn). Simplest. Easiest to debug because Trivy, Falco, Docker, and uvicorn all share  
  $PATH and process tree. Recommended for first run.                                                                             
                                                                                                                                 
  Option B — API in docker-compose. What docker/docker-compose.yml ships. Requires additional changes I haven't made (mount      
  /var/run/docker.sock into the api container, install trivy+git in Dockerfile.app, set VULBOX_DEV_MODE=false). Skip this for now
   — fix Option A first.                                                                                                         
                                                            
  The rest of this guide assumes Option A on the VM at 46.101.193.155.                                                           
  
  Step 1 — Pre-flight on the VM                                                                                                  
                                                            
  Run each of these. Stop and fix anything that fails before going further.                                                      
  
  # 1. Required binaries on PATH                                                                                                 
  which docker trivy falco git jq curl websocat sqlite3                                                                          
  # missing websocat? sudo apt install websocat   (or use wscat)                                                                 
                                                                                                                                 
  # 2. Docker reachable as the user running uvicorn                                                                              
  docker info >/dev/null && echo OK                                                                                              
                                                                                                                                 
  # 3. Falco runs as root and uses eBPF or kernel module — confirm it can start                                                  
  sudo falco --version && sudo falco --list rules | head -3                                                                      
                                                                                                                                 
  # 4. Trivy DB updated (first run is slow; pre-warm now)                                                                        
  trivy image --download-db-only                                                                                                 
                                                                                                                                 
  # 5. Production mode is ON. The default in app/core/config.py is dev_mode=true.                                                
  export VULBOX_DEV_MODE=false
  export VULBOX_SECRET_KEY="$(openssl rand -hex 32)"   # don't ship the default                                                  
  export VULBOX_PIPELINE_TIMEOUT_SECS=1800                                                                                       
  export VULBOX_MAX_REBUILDS=3                                                                                                   
                                                                                                                                 
  # 6. Install the new Tier-2 dep                                                                                                
  cd ~/Desktop/vulbox && source venv/bin/activate && pip install -r requirements.txt                                             
                                                                                                                                 
  # 7. Reset DB if schema drifted (no migrations framework)                                                                      
  rm -f data/findings.db                                                                                                         
                                                                                                                                 
  # 8. Falco itself needs root to attach syscalls. uvicorn does NOT need root —                                                  
  #    but the FalcoAdapter spawns falco via subprocess. Two options:
  #    (a) run uvicorn as root (quickest, security-bad)                                                                          
  #    (b) give the uvicorn user passwordless sudo for /usr/bin/falco                                                            
  #    Pick one. For thesis-demo, (a) is fine.                                                                                   
                                                                                                                                 
  # 9. Start the API                                                                                                             
  sudo -E uvicorn app.main:app --host 0.0.0.0 --port 8000 &                                                                      
  curl -fsS http://46.101.193.155:8000/health                                                                                    
                                                            
  If /health returns {"status":"ok",...} you're ready.                                                                           
                                                            
  Step 2 — Pick a target repo (1 min decision)                                                                                   
                                                            
  Your orchestrator clones a repo and builds it, not pulls a pre-built image. The image_name/image_tag fields in the request are 
  stored as metadata only; the actual built tag is vulbox-run-<id>.
                                                                                                                                 
  So you need a repo with a Dockerfile in its root that builds in well under 30 min. Three good options:                         
  
  ┌────────────────────────────────────────────────────────┬──────────────────────────────────────────────────────────────────┐  
  │                          Repo                          │                               Why                                │
  ├────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤  
  │ https://github.com/digininja/DVWA.git                  │ Dockerfile in root, ~3 min build, dozens of CVEs Trivy will flag │
  ├────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤  
  │ https://github.com/appsecco/dvna.git                   │ Damn Vulnerable Node App, builds fast, runs                      │  
  ├────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤  
  │ A small fork of yours containing one vulhub Dockerfile │ Best for log4shell-targeted runs                                 │  
  └────────────────────────────────────────────────────────┴──────────────────────────────────────────────────────────────────┘  
                                                            
  I'll use DVWA below.                                                                                                           
                                                            
  Step 3 — Drive a happy-path run                                                                                                
  
  Open 5 terminals before clicking go.                                                                                           
                                                            
  Terminal 1 — Submit the run:                                                                                                   
                                                            
    -H 'content-type: application/json' \                        
    -d '{"email":"demo@vulbox.local","password":"demo-password-123"}' | jq -r .access_token)                                     
  # (register the demo user once if needed: POST /auth/register with role=admin)                                                 
                                                                                                                                 
  RUN_ID=$(curl -s -X POST http://46.101.193.155:8000/runs \                                                                     
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \                                                      
    -d '{"project_name":"dvwa-e2e","repo_url":"https://github.com/digininja/DVWA.git",                                           
         "branch":"master","commit_sha":"HEAD","image_name":"dvwa","image_tag":"latest",                                         
         "consent_granted":true}' | jq -r .id)                                                                                   
  echo "run_id=$RUN_ID"                                                                                                          
                                                                                                                                 
  Terminal 2 — Pipeline events (the WS replay buffer means you can connect after the orchestrator started):                      
  websocat ws://46.101.193.155:8000/ws/runs/$RUN_ID/status                                                                       
                                                            
  Terminal 3 — Tail the per-phase subprocess logs (NEW location, Tier-1 #8):                                                     
  tail -F data/runs/$RUN_ID/logs/clone.log \                                                                                     
          data/runs/$RUN_ID/logs/build.log \                                                                                     
          data/runs/$RUN_ID/logs/sandbox-start.log \                                                                             
          data/runs/$RUN_ID/logs/failure.log 2>/dev/null                                                                         
                                                                                                                                 
  Terminal 4 — Falco events for THIS run only (NEW location, Tier-1 #7). Old data/falco/events.json is gone:                     
  tail -F data/runs/$RUN_ID/falco.json | jq .                                                                                    
                                                                                                                                 
  Terminal 5 — Sandbox container resource use:                                                                                   
  watch -n2 "docker ps --filter label=vulbox.run_id=$RUN_ID --format \
    'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}'"                                                                        
                                                                                                                                 
  Step 4 — Validation checklist                                                                                                  
                                                                                                                                 
  Walk through these as the run progresses. The key change vs. evaluation.md: terminal-state guarantees mean every column should 
  always resolve, never hang.                               
                                                                                                                                 
  ┌──────────┬─────────────────────────────────────────────────────────────┬─────────────────────────────────────────────────┐   
  │  Phase   │                       Expected signal                       │                  If missing →                   │
  ├──────────┼─────────────────────────────────────────────────────────────┼─────────────────────────────────────────────────┤   
  │ BUILDING │ docker images | grep vulbox-run-$RUN_ID returns a row;      │ Check clone.log first, then build.log stderr    │
  │           │ data/runs/$RUN_ID/logs/build.log ends with exit: 0         │                                                │ 
  ├───────────┼────────────────────────────────────────────────────────────┼────────────────────────────────────────────────┤    
  │           │ curl -sH "authorization: Bearer $TOKEN" .../runs/$RUN_ID   │                                                │ 
  │ SCANNING   │ shows status SCANNING then TESTING; /reports/$RUN_ID will  │ Trivy not on PATH or DB not initialised        │   
  │            │ list trivy findings ≥ 1                                    │                                                │
  ├────────────┼────────────────────────────────────────────────────────────┼────────────────────────────────────────────────┤   
  │            │                                                           │ .vulbox.yml absent → defaults to --network     │    
  │ TESTING    │ docker ps --filter label=vulbox.run_id=$RUN_ID shows a    │ none --read-only (image must boot under        │ 
  │            │ running container; data/runs/$RUN_ID/falco.json grows     │ those). For DVWA expect this to fail — see     │    
  │            │                                                           │ "Common pitfalls" #2 below                     │ 
  ├────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────┤ 
  │ TESTING    │ At least one row in falco_alerts with non-null            │ Falco needs root or eBPF probe — see           │ 
  │ (Falco)    │ test_result_id                                            │ Pre-flight #8                                  │    
  ├────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────┤ 
  │ REPORTING  │ security_matrix rows where finding_id differs across rows │ Means Tier-1 #5 actually landed                │    
  │            │  (NOT all the same)                                       │                                                │    
  ├────────────┼───────────────────────────────────────────────────────────┼────────────────────────────────────────────────┤ 
  │ COMPLETE / │ completed_at is set; sandbox container removed; no orphan │ If still TESTING after 30 min → wall-clock     │    
  │  FAILED    │  falco proc                                               │ timeout fires and run flips to FAILED          │    
  │            │                                                           │ automatically                                  │
  └────────────┴───────────────────────────────────────────────────────────┴────────────────────────────────────────────────┘    
                                                            
  Risk score range now goes 0 → 75 (severity-weighted). A critical CVE that's exploited and undetected will sit at 70.           
  
  Step 5 — Failure-injection runs (this is what proves Tier 1 worked)                                                            
                                                            
  Run each, confirm the run reaches a terminal status, and confirm no resources leak. After each, run the forensic check at the  
  end of this section.                                      
                                                                                                                                 
  5.1 — Bad repo URL (validates BuildFailedError → FAILED path):                                                                 
  curl -s -X POST http://46.101.193.155:8000/runs -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \                                                                                        
    -d '{"project_name":"bad","repo_url":"https://github.com/does/not/exist.git",                                                
         "image_name":"x","image_tag":"latest","consent_granted":true}' | jq .id 
  # Expect: status FAILED within 120s, data/runs/<id>/logs/clone.log shows the git error,                                        
  # data/runs/<id>/logs/failure.log contains "build failed: git clone failed: ..."                                               
                                                                                                                                 
  5.2 — Dockerfile that exits 1. Push a tiny repo containing only:                                                               
  FROM alpine                                                                                                                    
  RUN exit 1                                                                                                                     
  Submit it. Expect FAILED, build.log shows exit: 1, no orphan image.                                                            
                                                                     
  5.3 — Image that boots and idles (validates happy path under default --network none --read-only). Push a repo with:            
  FROM alpine                                                                                                                    
  ENTRYPOINT ["sleep","99999"]                                                                                                   
  Expect: BUILDING → SCANNING (zero findings) → TESTING (ART tests run, none exploited because there's nothing to exploit) →     
  COMPLETE. Sandbox container destroyed at end.                                                                                  
                                                                                                                                 
  5.4 — Two parallel runs against the same image (validates Tier-1 #7 per-run Falco):                                            
  R1=$(./submit.sh dvwa-1); R2=$(./submit.sh dvwa-2)                                                                             
  # Wait for both to reach COMPLETE, then:                  
  ls data/runs/$R1/falco.json data/runs/$R2/falco.json   # both must exist, distinct contents                                    
  sqlite3 data/findings.db \                                                                                                     
    "SELECT run_id, count(*) FROM falco_alerts WHERE run_id IN ($R1,$R2) GROUP BY run_id;"                                       
  # both rows must be non-zero, and the alert sets must differ                                                                   
                                                                                                                                 
  5.5 — Kill the API mid-run (NOTE: known limitation):                                                                           
  kill -9 $(pgrep -f 'uvicorn app.main:app')                                                                                     
  # restart                                                                                                                      
  sudo -E uvicorn app.main:app --host 0.0.0.0 --port 8000 &                                                                      
  Current state: the run will sit in TESTING forever — orphan-resume on startup is Tier-3 work (unimplemented). Either skip this 
  case, or treat its failure as the motivation to implement that next. If you want it now, say the word.                        
                                                                                                                                 
  Step 6 — Forensic check (run after each happy + failure case)
                                                                                                                                 
  RID=$RUN_ID  # or any run id                              
                                                                                                                                 
  # DB consistency                                          
  sqlite3 data/findings.db <<SQL                                                                                                 
  SELECT r.id, r.status, r.completed_at,                                                                                         
         (SELECT count(*) FROM trivy_findings        WHERE run_id=r.id) AS trivy,
         (SELECT count(*) FROM art_test_results      WHERE run_id=r.id) AS art,                                                  
         (SELECT count(*) FROM falco_alerts          WHERE run_id=r.id) AS falco,                                                
         (SELECT count(*) FROM security_matrix_entries WHERE run_id=r.id) AS matrix,                                             
         (SELECT count(DISTINCT finding_id) FROM security_matrix_entries WHERE run_id=r.id) AS distinct_cves                     
  FROM assessment_runs r WHERE id=$RID;                                                                                          
  SQL                                                                                                                            
                                                                                                                                 
  # No leaked containers from this run                                                                                           
  docker ps -a --filter label=vulbox.run_id=$RID            
                                                                                                                                 
  # No leaked falco process for this run (after the 60s cleanup grace)                                                           
  pgrep -af falco
                                                                                                                                 
  # Per-run on-disk artefacts                               
  ls -la data/runs/$RID/ data/runs/$RID/logs/
                                                                                                                                 
  Pass criteria:
  - status is COMPLETE or FAILED. Not anything else.                                                                             
  - completed_at is non-null.                                                                                                    
  - For COMPLETE runs: matrix ≈ art (each successful test produces one matrix row; crashes don't), and distinct_cves > 1 if
  multiple CVEs map to multiple techniques.                                                                                      
  - docker ps -a returns zero rows.                                                                                              
  - pgrep -af falco shows no orphans tagged with our run ID.                                                                     
  - data/runs/$RID/logs/ contains clone.log, build.log, sandbox-start.log for production runs.                                   
                                                                                                                                 

  Common pitfalls you will hit on first try

  1. VULBOX_DEV_MODE is true by default. If you forget to set it, the orchestrator skips Trivy/Falco/Docker entirely and reads
  fixtures. The run completes "successfully" but proves nothing. Always confirm with: curl http://localhost:8000/health and
  submit one run; if data/runs/$RID/logs/ is empty, you're in dev mode.
  2. DVWA needs a writable filesystem and a port. Default sandbox config (--network none --read-only) will likely break it
  (apache can't write /var/log/apache2). Drop a .vulbox.yml in the repo before submission:
  sandbox:
    network: bridge
    read_only: false
    ports: ["8080:80"]
  2. But — --network bridge means the container has internet access, which violates the original isolation premise. For a thesis
  demo I'd push DVWA to a private fork, add the .vulbox.yml, and submit that fork's URL. Document the trade-off in your writeup.
  3. falco not running as root. Symptoms: empty data/runs/$RID/falco.json, zero alerts, every matrix row says is_detectable:
  false. Fix in pre-flight #8.
  4. Trivy DB out of date. First scan in production is silent for ~60s while it downloads. Pre-warm with trivy image
  --download-db-only.
  5. WS connects too early and shows nothing. That's fine now (Tier-1 replay buffer fixes the late case). If WS is silent on
  connect, the orchestrator hasn't started yet — wait one second.

  What to capture for your thesis

  After a clean DVWA run, screenshot or cat:
  - GET /reports/$RUN_ID (the matrix + remediations JSON)
  - data/runs/$RUN_ID/logs/build.log (proof of real Docker activity)
  - data/runs/$RUN_ID/falco.json head (proof of real syscall capture)
  - Forensic check output (proof of clean teardown)

  These are the artefacts that distinguish "demo on fixtures" from "real pipeline against a vulnerable target."