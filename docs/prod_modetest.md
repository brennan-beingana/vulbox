 VulBox: prod-mode persistence + multi-stack e2e — plan

  Context that shapes everything

  - Your launch is nohup uvicorn … &. That has two consequences: (a) env vars must already be in the shell's environment at the moment you
  run the command, and (b) it does not survive a reboot. So "set it once and forget" needs either a file-backed config or a service manager
   — a shell export won't cut it.
  - Settings (app/core/config.py) reads env vars at import, has no .env loader, and docker/docker-compose.yml hardcodes
  VULBOX_DEV_MODE=true. The compose hardcode is irrelevant to you (you're not using compose) but should still be fixed so the two launch
  paths don't disagree.

  ---
  Phase 1 — Make production mode persistent

  Goal: prod mode (and the other knobs) survive restarts and reboots without remembering to export anything.

  1A. File-backed config (recommended core change)
  - Add pydantic-settings to requirements.txt; change Settings(BaseModel) → BaseSettings with model_config = 
  SettingsConfigDict(env_file=".env", extra="ignore"). Keep every field as-is — it stays backward compatible (real env vars still override
  the file).
  - Add a gitignored .env on the VM and a committed .env.example documenting all VULBOX_* keys (VULBOX_DEV_MODE=false, VULBOX_SECRET_KEY=…,
   VULBOX_EPSS_MIN, the VULBOX_LLM_* set, GEMINI_API_KEY).
  - Fix the compose api service to env_file: ../.env (or ${VULBOX_DEV_MODE:-false}) instead of the hardcoded true.
  - Why this first: every later phase needs prod mode reliably on; this removes the whole class of "silently fell back to dev" bugs.

  1B. Durability across reboot (pick one)
  - Recommended: a minimal systemd unit (EnvironmentFile=/home/bbei/Desktop/vulbox/.env, Restart=on-failure, WorkingDirectory, venv's
  uvicorn). Replaces nohup, survives reboot, restarts on crash, gives you journalctl logs instead of a stray uvicorn.log.
  - Lighter interim: a scripts/serve.sh wrapper that sources .env then nohups uvicorn — keeps your current style but centralizes the env.
  Still not reboot-safe.

  1C. Make the mode observable
  - Today nothing exposes whether you're in dev or prod. Add a startup log line (and/or a field on an existing health/root endpoint)
  echoing dev_mode, epss_min, and epss snapshot loaded: N. So "is it actually in prod?" is a one-line check, not a guess.
  
  1D. Prod hygiene callouts (not new, but worth fixing while here)
  - VULBOX_SECRET_KEY still defaults to dev-secret-key-change-in-production — set a real one in .env.
  - Decide LLM remediation on/off in prod (VULBOX_LLM_REMEDIATION, GEMINI_API_KEY); it already falls back to rule-based, so this is just a
  cost/quality choice.
  
  Acceptance: reboot the VM → API comes back in prod mode with EPSS loaded, verified from the startup log/health endpoint.

  ---
  Phase 2 — Verify the new EPSS/CWE/fan-out features in prod

  Goal: confirm the coverage lift works against real images before investing in a big corpus.

  - Pre-reqs: trivy on PATH, Docker reachable, python scripts/fetch_epss.py to refresh the snapshot.
  - Fast loop — extend scripts/validate_e2e.py: it already runs Trivy + build_queue per image in prod mode. Add per-image reporting of the
  new signals: EPSS-score distribution, count of techniques resolved via cwe-bridge vs cve-map, and the coverage ratio (tested_cves / 
  detected_cves). This is the deterministic, no-sandbox way to see the lift. Output goes to the existing docs/validation_report.md.
  - Full-pipeline smoke (one target): POST /runs against a buildable vuln repo → GET /reports/{id}; confirm the coverage block,
  match_source, and epss_score on matrix rows, plus the new PDF columns/caption.
  - Gate behavior: sweep VULBOX_EPSS_MIN (0.0 → 0.3 → 0.6), confirm matrix entry count shrinks while KEV/ransomware CVEs persist.
  - Acceptance: at least one real image shows CVEs reaching an exploitability verdict via the CWE bridge that the old CVE-map-only path
  would have dropped, and the coverage ratio is reported.

  ---
  Phase 3 — Multi-stack e2e with vulhub
  
  Key structural fact: vulhub environments are docker-compose stacks (often app + DB), not single Dockerfiles, while VulBox's pipeline
  clones a repo and docker builds one image, then keeps it running for ART under Falco. So I would not point the orchestrator at vulhub
  compose files directly. Two tiers instead:

  Tier A — image-scan corpus (static, CI-friendly). Add ~6–10 known-vulnerable images (pulled at runtime, not vendored) to
  tests/ground_truth/manifest.yml, one per stack mapped to your existing tech_attack_profiles.yml. Extend the manifest's expectations with
  the new dimensions (must-bridge CWE, min coverage ratio, EPSS-ordered queue head). Runs via the extended validate_e2e.py. Deterministic,
  no sandbox flake → good for CI.

  Candidate stack matrix (tune to what your CVE map + bridge actually cover):

  ┌──────────────────┬───────────────────────────────────────────────┬───────────────────────────────────┐
  │      Stack       │                 Example basis                 │             Validates             │
  ├──────────────────┼───────────────────────────────────────────────┼───────────────────────────────────┤
  │ node/express     │ your existing vulnerable_target               │ baseline, fan-out                 │
  ├──────────────────┼───────────────────────────────────────────────┼───────────────────────────────────┤
  │ python/flask     │ Werkzeug debug-console RCE                    │ python profile + cve-map          │
  ├──────────────────┼───────────────────────────────────────────────┼───────────────────────────────────┤
  │ java/spring      │ Spring4Shell (CVE-2022-22965, already tagged) │ stack-relevant priority           │
  ├──────────────────┼───────────────────────────────────────────────┼───────────────────────────────────┤
  │ php              │ ThinkPHP / older php-fpm                      │ web-stack fallback + bridge       │
  ├──────────────────┼───────────────────────────────────────────────┼───────────────────────────────────┤
  │ tomcat / struts2 │ Struts OGNL (in your map)                     │ T1059 cve-map                     │
  ├──────────────────┼───────────────────────────────────────────────┼───────────────────────────────────┤
  │ apache CGI       │ Shellshock (CVE-2014-6271, in your map)       │ shell fallback                    │
  ├──────────────────┼───────────────────────────────────────────────┼───────────────────────────────────┤
  │ ruby/rails       │ old rails image                               │ bridge-only coverage (no cve-map) │
  └──────────────────┴───────────────────────────────────────────────┴───────────────────────────────────┘

  Tier B — full dynamic targets (gated). Add a small set of buildable single-Dockerfile target repos (one per stack) under
  tests/e2e/fixtures/, then parametrize test_full_pipeline over them (your conftest already auto-skips without Docker/Trivy/Falco). This is
   what actually exercises Presence × Exploitability × Detectability + stack detection per stack and proves the per-CVE coverage lift
  end-to-end. Run nightly/manual, not in PR CI.

  Risks / callouts for Phase 3:
  - Sandbox network is internal: true (no outbound) — fine for Trivy/queue/stack-detection; relevant only if a given ART technique needs
  egress. Keep Tier B targets self-contained.
  - Multi-container vulhub apps: a single Trivy scan covers one image — target the app image, not the DB. Full dynamic needs the app's
  entrypoint to stay up (your assert_running gate already enforces this).
  - Corpus cost: vulhub images are large and amd64-centric; keep the set tight and pull-on-demand. Add an EPSS-refresh step (or cache) to
  CI so scores aren't stale.
  - Licensing: vulhub is MIT — safe to reference and pull at runtime; don't vendor their images into the repo.

  (dynamic targets). Tiers A/B are independently shippable.


  ---
  This also closes the verification gap I flagged last turn: the real-Docker coverage-lift assertion only runs under pytest -m e2e, and
  Phases 2–3 are exactly how you'd exercise it on the VM.

  One thing worth recording so it doesn't bite future-you:

  Read 1 file, recalled 1 memory, wrote 2 memories (ctrl+o to expand)

● Plan delivered above — no code changed, per your "full plan only" choice. Summary of the three answers:

  1. Why prod reverts: config reads VULBOX_DEV_MODE at import with no .env loader, your nohup launch doesn't survive reboot, and a shell
  This also closes the verification gap I flagged last turn: the real-Docker coverage-lift assertion only runs under pytest -m e2e, and
  Phases 2–3 are exactly how you'd exercise it on the VM.

  One thing worth recording so it doesn't bite future-you:

  Read 1 file, recalled 1 memory, wrote 2 memories (ctrl+o to expand)

● Plan delivered above — no code changed, per your "full plan only" choice. Summary of the three answers:

  1. Why prod reverts: config reads VULBOX_DEV_MODE at import with no .env loader, your nohup launch doesn't survive reboot, and a shell
  export is session-only. Fix = file-backed config (pydantic-settings + .env) and ideally a systemd unit (Phase 1).
  2. Testing the features: prod mode on + trivy/Docker + refresh EPSS, then use an extended validate_e2e.py for the fast static loop and
  one full-pipeline run to check the new coverage/match_source/epss_score report fields (Phase 2).
  One thing worth recording so it doesn't bite future-you:

  Read 1 file, recalled 1 memory, wrote 2 memories (ctrl+o to expand)

● Plan delivered above — no code changed, per your "full plan only" choice. Summary of the three answers:

  1. Why prod reverts: config reads VULBOX_DEV_MODE at import with no .env loader, your nohup launch doesn't survive reboot, and a shell
  export is session-only. Fix = file-backed config (pydantic-settings + .env) and ideally a systemd unit (Phase 1).
  2. Testing the features: prod mode on + trivy/Docker + refresh EPSS, then use an extended validate_e2e.py for the fast static loop and
  one full-pipeline run to check the new coverage/match_source/epss_score report fields (Phase 2).
  3. Vulhub: don't drive their compose stacks directly — two tiers, an image-scan corpus in manifest.yml (CI) and buildable per-stack
  3. Vulhub: don't drive their compose stacks directly — two tiers, an image-scan corpus in manifest.yml (CI) and buildable per-stack
  targets parametrizing test_full_pipeline (gated) (Phase 3).


  Sequencing: Phase 1 (small, unblocks prod) → Phase 2 (validate_e2e extension, one smoke run) → Phase 3 Tier A (corpus) → Phase 3 Tier B
  (dynamic targets). Tiers A/B are independently shippable.

  ---
  This also closes the verification gap I flagged last turn: the real-Docker coverage-lift assertion only runs under pytest -m e2e, and
  Phases 2–3 are exactly how you'd exercise it on the VM.

  One thing worth recording so it doesn't bite future-you:

  Read 1 file, recalled 1 memory, wrote 2 memories (ctrl+o to expand)

● Plan delivered above — no code changed, per your "full plan only" choice. Summary of the three answers:

  1. Why prod reverts: config reads VULBOX_DEV_MODE at import with no .env loader, your nohup launch doesn't survive reboot, and a shell
  export is session-only. Fix = file-backed config (pydantic-settings + .env) and ideally a systemd unit (Phase 1).
  2. Testing the features: prod mode on + trivy/Docker + refresh EPSS, then use an extended validate_e2e.py for the fast static loop and
  one full-pipeline run to check the new coverage/match_source/epss_score report fields (Phase 2).
  3. Vulhub: don't drive their compose stacks directly — two tiers, an image-scan corpus in manifest.yml (CI) and buildable per-stack
  targets parametrizing test_full_pipeline (gated) (Phase 3).

  I saved a project memory on the launch setup + persistence root cause so this doesn't have to be re-diagnosed.