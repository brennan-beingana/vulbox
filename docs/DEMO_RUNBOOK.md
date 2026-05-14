# VulBox Demo Runbook

This is the checklist to follow before, during, and after a live demo. It
exists because "it worked on my laptop" is not a defensible answer when a
projector is on and ten people are watching.

If any step in the **T-24h** or **T-1h** sections fails, **do not demo in
full mode**. Fall back to dev mode (fixtures) and tell the audience explicitly
that the pipeline is in fixture-replay mode — the matrix is still real, only
the binaries behind it are stubbed.

---

## T-24h — Pre-flight on the demo machine

Run every command from a clean shell on the actual machine you'll demo from.
Not your laptop. Not the VM you tested on yesterday. The demo machine.

### 1. Tooling versions

```bash
docker --version    # >= 24
trivy --version     # >= 0.50
falco --version     # >= 0.38   (optional — note if missing)
node --version      # >= 18
python3 --version   # >= 3.12
```

If anything is missing or below minimum: stop, fix, and re-run this section.

### 2. Pre-pull images (conference Wi-Fi will not save you)

```bash
docker pull node:14-alpine
docker pull node:18-alpine
# only if you plan to show Falco live:
docker pull falcosecurity/falco:0.38.0
```

### 3. Pre-download the Trivy DB

The first `trivy image` invocation downloads ~300 MB. Do it now, not at T-0.

```bash
trivy image --download-db-only
```

### 4. Backend boot test

```bash
cd ~/Desktop/vulbox
source venv/bin/activate
pip install -r requirements.txt   # in case anything drifted
rm -f data/findings.db
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
sleep 3
curl -fsS http://127.0.0.1:8000/health || echo "BACKEND DOWN"
kill %1 2>/dev/null
```

Expect `{"status":"ok",...}`. Any other response → debug now.

### 5. Frontend boot test

```bash
cd frontend
npm install
npm run dev &
sleep 5
curl -fsS http://127.0.0.1:5173/ >/dev/null && echo "frontend OK" || echo "FRONTEND DOWN"
kill %1 2>/dev/null
cd ..
```

---

## T-1h — Smoke test the real pipeline

Run the bundled E2E test against the in-repo `vulnerable_target/` fixture.
This is the only step that proves the full pipeline works end-to-end on
*this* machine *today*.

```bash
cd ~/Desktop/vulbox
source venv/bin/activate
VULBOX_DEV_MODE=false VULBOX_FALCO_ENABLED=false pytest -m e2e -v --tb=short
```

Expected: **1 passed in 2-5 minutes**. The test:

1. `git init`s a copy of `tests/e2e/fixtures/vulnerable_target/` in a tmp dir.
2. POSTs to `/runs` with `file:///tmp/...`.
3. Waits for the run to reach `COMPLETE`.
4. Asserts `trivy_findings_count >= 5` and the matrix is non-empty.

If it fails:

- **`docker daemon not reachable`** → start Docker Desktop / `systemctl start docker`.
- **`trivy not on PATH`** → reinstall Trivy (see T-24h step 1).
- **build failed** → check `data/runs/<id>/logs/build.log` — usually a stale Docker cache.
- **timeout** → conference Wi-Fi pulling base images. Re-run after pre-pull.

If you can't get it green within 30 minutes: **demo in dev mode**. Set
`VULBOX_DEV_MODE=true` and use `scripts/demo.py` to ingest fixtures.

---

## T-15m — Seed demo state

The Reports page looks lifeless on first load with no completed runs. Pre-seed
three:

```bash
cd ~/Desktop/vulbox
source venv/bin/activate
python scripts/seed_demo_data.py --reset
```

This creates three completed runs (`payments-api`, `auth-service`,
`storage-gateway`) and a `demo@vulbox.local` user. Login password printed by
the script — write it on a sticky note.

Then start the API + frontend in tmux panes so you can watch logs:

```bash
# pane 1
uvicorn app.main:app --host 0.0.0.0 --port 8000

# pane 2
cd frontend && npm run dev

# pane 3 — kept idle, for live recovery
```

---

## The demo flow

Read from this script. Each step lists what to say, what to click, and the
expected screen state. The right-hand column is your fallback if it breaks
live.

| # | Say | Click | Expected | If broken |
|---|-----|-------|----------|-----------|
| 1 | "VulBox combines static scanning, runtime detection, and active exploitation into one verdict." | Open `http://localhost:5173/login`, register a new account. | Dashboard appears. | Log in as `demo@vulbox.local` instead — already seeded. |
| 2 | "Let's run an assessment against a known-vulnerable target." | Paste the **bundled vulnerable_target** path (or `https://github.com/OWASP/NodeGoat`). Check consent. Submit. | Redirected to `/runs/N/status`. | Skip live run — click into a seeded run instead. |
| 3 | "The pipeline streams its phase transitions over WebSocket." | Narrate the stepper: BUILDING → SCANNING → TESTING → REPORTING. | Phases advance within 90s. | If TESTING takes > 2 min, switch to a seeded run in another tab. |
| 4 | "And here's the three-dimensional Security Matrix." | Click into Report. Point at a single cell. | Matrix table renders with Present × Exploitable × Detectable + risk score. | Use seeded `payments-api` run (CVE-2021-44228, risk 70). |
| 5 | "Each row maps to an actionable remediation." | Scroll to the Remediation panel. | Three remediation cards, each with summary + priority action + example fix. | (no fallback needed — seeded data has these) |
| 6 | "And the whole report exports for compliance evidence." | Click Export → CSV. Open the file in a terminal to show raw data. | CSV downloads, 8 columns, one row per matrix entry. | PDF if CSV fails (requires `weasyprint`). |

**Time budget**: cap step 2's live run to **90 seconds**. If it isn't in
TESTING by then, jump to step 4 using a seeded run. Do not stand silent
watching a progress bar.

---

## Live recovery

### Something exploded — reset to a known state

```bash
scripts/demo_reset.sh
```

This kills orphan `vulbox-run-*` containers, frees port 8000, drops the DB,
re-seeds three demo runs, and restarts the API. Done in ~5 seconds.

`--no-restart` skips the uvicorn relaunch if you want to restart it yourself
with a different config.

### The pipeline is stuck mid-run during the demo

Open the third tmux pane and:

```bash
# show the most recent run
curl -s http://localhost:8000/runs | python -m json.tool | head -40

# inspect its phase logs
ls data/runs/$(ls data/runs/ | sort -n | tail -1)/logs/
```

Then talk over it. Audiences forgive a 10-second silence; they don't forgive
a frozen screen.

---

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Falco fails to load (kernel modules) | High | Demo Falco-disabled by default. Show a Falco-enabled screenshot. |
| Trivy DB blocks first scan | Medium | Pre-downloaded at T-24h. Dev-mode fallback ready. |
| Docker Hub rate limit | Medium | Pre-pulled at T-24h. |
| Live ART fails to exploit | Medium | Bundled `vulnerable_target` has `eval()` — guaranteed exploit. |
| WebSocket disconnects mid-demo | Low | Status page already handles reconnect. Reports view as backup. |
| Run exceeds 5 minutes | High | Cap to 90s; pre-completed run in another tab. |

---

## After the demo

```bash
# stash logs for the postmortem
tar czf demo-$(date +%Y%m%d-%H%M).tar.gz data/runs/ data/findings.db

# clean state
scripts/demo_reset.sh --no-restart
```
