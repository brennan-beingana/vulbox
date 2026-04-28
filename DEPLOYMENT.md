# VulBox — Deployment & Setup Guide

This guide covers everything needed to run VulBox from zero to a fully functional security assessment pipeline. There are two operational modes — read both sections before deciding which to use.

---

## Modes of Operation

| Mode | `VULBOX_DEV_MODE` | What runs | Use for |
|---|---|---|---|
| **Dev / Demo** | `true` (default) | FastAPI + SQLite + React. Adapters read fixture JSON files instead of running real tools. | Development, demos, marking, CI smoke tests |
| **Full / Production** | `false` | All of the above **plus** Docker daemon, Trivy CLI, Falco sidecar, and Atomic Red Team scripts | Real assessments against actual repositories |

---

## Part A — Dev / Demo Mode (Recommended Starting Point)

### Prerequisites

| Tool | Minimum version | Install |
|---|---|---|
| Python | 3.11 | `python3 --version` |
| Node.js | 18 | `node --version` |
| npm | 9 | `npm --version` |
| git | 2.x | `git --version` |

### 1. Clone and enter the repository

```bash
git clone <repo-url> vulbox
cd vulbox
```

### 2. Set up the Python backend

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

Verify installation:

```bash
python -c "from app import models; print('OK')"
```

### 3. Create the database

```bash
# The data/ directory must exist (it does in the repo)
# On first startup, SQLAlchemy auto-creates all tables.
# If you need a clean slate after schema changes:
rm -f data/findings.db
```

### 4. Start the API server

```bash
# Make sure the virtualenv is active
source venv/bin/activate

# VULBOX_DEV_MODE=true is the default — no need to set it explicitly
uvicorn app.main:app --reload
```

The API is now available at:
- **REST API** → `http://127.0.0.1:8000`
- **Interactive docs** → `http://127.0.0.1:8000/docs`
- **Health check** → `http://127.0.0.1:8000/health`

### 5. Start the React frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend at → `http://localhost:5173`

### 6. Run the end-to-end demo

With the API running in one terminal, in another:

```bash
source venv/bin/activate
python scripts/demo.py
```

The demo authenticates, submits a run with `consent_granted=true`, ingests the three fixture files, polls the orchestrator to completion, and prints the Security Matrix and remediation table.

### 7. Run the test suite

```bash
source venv/bin/activate
pytest tests/ -v
```

All 18 tests should pass (parsers, correlation, remediation).

---

## Part B — Full / Production Mode

Full mode requires Docker, Trivy, and Falco installed on the host. The orchestrator will clone the target repository, build it into a Docker image, launch it in an isolated sandbox, run live Trivy and Falco scans, and execute Atomic Red Team tests.

### System Requirements

| Requirement | Notes |
|---|---|
| Linux (Ubuntu 22.04+ recommended) | Falco requires kernel module or eBPF — does not work inside Docker Desktop on macOS |
| 4 GB RAM minimum | 8 GB recommended for concurrent builds |
| Docker Engine 24+ | `docker --version` |
| Docker Compose v2 | `docker compose version` |
| Trivy 0.50+ | `trivy --version` |
| Falco 0.38+ | `falco --version` |
| Atomic Red Team (PowerShell / bash) | Optional — see §B.4 |

### B.1 Install Docker Engine

```bash
# Ubuntu
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker run --rm hello-world
```

### B.2 Install Trivy

```bash
# Ubuntu/Debian
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
  gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb \
  $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy

# Verify
trivy --version

# Download vulnerability DB (first run — takes a few minutes)
trivy image --download-db-only
```

### B.3 Install Falco

Falco requires kernel-level access. It must run on bare metal or a VM, not inside a Docker container itself.

```bash
# Ubuntu (kernel module method — simplest)
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update
sudo apt-get install -y falco

# Load kernel module
sudo modprobe falco

# Verify (starts and shows active rules)
sudo falco --version
```

Configure Falco to write JSON output to a file (required for `FalcoAdapter._read_live_alerts`):

```bash
sudo mkdir -p /var/log/falco

# Edit /etc/falco/falco.yaml — set:
#   json_output: true
#   file_output:
#     enabled: true
#     filename: /var/log/falco/events.json
sudo nano /etc/falco/falco.yaml
```

Or apply with `sed`:

```bash
sudo sed -i 's/json_output: false/json_output: true/' /etc/falco/falco.yaml
sudo sed -i 's/# file_output:/file_output:/' /etc/falco/falco.yaml
sudo sed -i 's/#   enabled: false/  enabled: true/' /etc/falco/falco.yaml
sudo sed -i 's/#   filename: .*/  filename: \/var\/log\/falco\/events.json/' /etc/falco/falco.yaml
```

Start Falco as a system service:

```bash
sudo systemctl enable falco
sudo systemctl start falco
sudo systemctl status falco
```

### B.4 Atomic Red Team (Optional)

The `scanners/atomic_runner.sh` is a stub that prints a placeholder. To enable real ART tests:

1. Install [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) (PowerShell) or the [bash equivalents](https://github.com/carlospolop/PEASS-ng).
2. Edit `scanners/atomic_runner.sh` to invoke the correct runner for your test_id argument.
3. The script must exit with:
   - `0` — test executed (exploited = true)
   - `1` — test blocked / no effect (exploited = false)
   - `2` — target container crashed (crash_occurred = true → self-healing pipeline triggers)

```bash
# atomic_runner.sh minimal example (bash-based ART)
#!/usr/bin/env bash
set -euo pipefail
[[ "${ATOMIC_CONSENT:-false}" != "true" ]] && { echo "Consent required"; exit 1; }
TECHNIQUE_ID="$1"
# Run the test and interpret exit codes per VulBox convention
atomic-runner run "$TECHNIQUE_ID"
```

### B.5 Configure environment variables

Create a `.env` file in the project root (never commit this):

```bash
cat > .env << 'EOF'
# REQUIRED in production
VULBOX_SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
VULBOX_DEV_MODE=false

# Optional overrides
# DATABASE_URL=sqlite:///./data/findings.db
EOF
```

Load it before starting the server:

```bash
export $(grep -v '^#' .env | xargs)
```

**Generate a strong secret key:**

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### B.6 Start the API in production mode

```bash
source venv/bin/activate
export $(grep -v '^#' .env | xargs)

# Single worker (development-production)
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Multi-worker (production — use gunicorn as process manager)
pip install gunicorn
gunicorn app.main:app \
  --workers 2 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile - \
  --error-logfile -
```

### B.7 Build and serve the frontend for production

```bash
cd frontend
npm install
npm run build
# Output is in frontend/dist/

# Serve with any static file server, e.g.:
npx serve dist -p 5173

# Or configure nginx to serve dist/ and proxy /api → port 8000
```

---

## Part C — Docker Compose Deployment

Docker Compose is the simplest way to run all services together.

### Dev mode (no Falco)

```bash
cd docker
docker compose up --build
```

- API → `http://localhost:8000`
- Frontend → `http://localhost:5173`
- `VULBOX_DEV_MODE=true` by default — adapters use fixture files

### Full mode (with Falco)

```bash
cd docker
docker compose --profile full up --build
```

This adds the Falco container. Note that the Falco container requires `privileged: true` and access to `/proc`, `/dev`, and kernel modules — this only works on a Linux host with Docker Engine (not Docker Desktop).

### Persistent data

The compose file mounts `../data` into the API container at `/app/data`. The SQLite database at `data/findings.db` survives restarts. To reset:

```bash
rm -f data/findings.db
docker compose up --build
```

---

## Part D — First-Use Walkthrough

After the API and frontend are running, follow these steps in order.

### Step 1: Create an account

Navigate to `http://localhost:5173/register`.

Or via curl:

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"yourpassword","role":"admin"}'
```

### Step 2: Log in

Navigate to `http://localhost:5173/login`.

Or via curl:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"yourpassword"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "Token: $TOKEN"
```

### Step 3: Submit an assessment

In the UI, navigate to the home screen, enter a project name, optionally a repository URL, check the consent checkbox, and click **Start Assessment**.

Via curl:

```bash
curl -X POST http://localhost:8000/runs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "project_name": "my-app",
    "repo_url": "https://github.com/your-org/your-repo",
    "branch": "main",
    "image_tag": "latest",
    "consent_granted": true
  }'
```

The API responds immediately with the run ID (≤3 seconds). The Orchestrator starts as a background task.

### Step 4: Watch live status

Open the browser at `http://localhost:5173/runs/<run_id>/status`.

The page connects to the WebSocket and shows phase transitions in real time.

Or stream events manually:

```bash
# Install wscat if needed: npm install -g wscat
wscat -c ws://localhost:8000/ws/runs/<run_id>/status
```

You will see JSON events like:

```json
{"event": "phase", "phase": "BUILDING"}
{"event": "phase", "phase": "SCANNING"}
{"event": "scan_complete", "findings": 12}
{"event": "test_start", "test_id": "T1059.004"}
{"event": "test_complete", "test_id": "T1059.004", "exploited": true, "detected": true, "risk_score": 40}
{"event": "complete"}
```

### Step 5: View the report

Navigate to `http://localhost:5173/runs/<run_id>/report`.

Or via curl:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/reports/<run_id> | python3 -m json.tool
```

### Step 6: Export

```bash
# CSV
curl http://localhost:8000/reports/<run_id>/export?format=csv -o report.csv

# PDF (requires weasyprint — pip install weasyprint)
curl http://localhost:8000/reports/<run_id>/export?format=pdf -o report.pdf

# JSON
curl http://localhost:8000/reports/<run_id>/export?format=json | python3 -m json.tool
```

---

## Part E — API Quick Reference

All routes except `/health`, `/auth/register`, and `/auth/login` require `Authorization: Bearer <token>`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `POST` | `/auth/register` | Create user account |
| `POST` | `/auth/login` | Get JWT token |
| `GET` | `/auth/me` | Current user info |
| `POST` | `/runs` | Submit assessment (fires Orchestrator) |
| `GET` | `  /runs` | List all runs |
| `GET` | `/runs/{id}` | Get run status |
| `DELETE` | `/runs/{id}` | Delete run (blocked during TESTING/REBUILDING) |
| `GET` | `/runs/{id}/validations` | List ARTTestResult rows |
| `WS` | `/ws/runs/{id}/status` | Real-time event stream |
| `GET` | `/reports/{id}` | Full Security Matrix + remediations |
| `GET` | `/reports/{id}/export` | Download report (`?format=json\|csv\|pdf`) |
| `POST` | `/runs/{id}/ingest/trivy` | Dev: push Trivy fixture directly |
| `POST` | `/runs/{id}/ingest/falco` | Dev: push Falco fixture directly |
| `POST` | `/runs/{id}/ingest/atomic` | Dev: push Atomic fixture directly |

---

## Part F — Environment Variable Reference

| Variable | Default | Description |
|---|---|---|
| `VULBOX_SECRET_KEY` | `dev-secret-key-change-in-production` | JWT signing secret — **must change in production** |
| `VULBOX_DEV_MODE` | `true` | `false` enables real Docker/Trivy/Falco/ART |
| `ATOMIC_CONSENT` | `false` | Must be `true` for `atomic_runner.sh` to execute |

---

## Part G — Security Checklist Before Going Live

- [ ] `VULBOX_SECRET_KEY` is a 64-character random hex string (`python -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] `VULBOX_DEV_MODE=false` is set
- [ ] The API is not exposed directly to the internet — sit it behind nginx with TLS
- [ ] The `data/` directory is outside the web root
- [ ] The Falco output directory (`/var/log/falco`) is not world-readable
- [ ] Sandbox containers run with `--network none` (enforced by `DockerManager.run_sandbox`)
- [ ] `ATOMIC_CONSENT=true` is only set per-run, not globally in `.env`
- [ ] Admin accounts use strong passwords

---

## Part H — Troubleshooting

### API won't start: `ModuleNotFoundError`

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### `data/findings.db` schema errors after upgrade

The project uses no migration framework. Drop and recreate:

```bash
rm -f data/findings.db
uvicorn app.main:app --reload
```

### Orchestrator stuck at `BUILDING`

In dev mode this should complete in seconds. In full mode:
- Check Docker daemon: `docker info`
- Check the repo URL is reachable from the server
- Check the Dockerfile exists in the target repo

### Falco not detecting events

- Confirm Falco is running: `sudo systemctl status falco`
- Confirm JSON output is enabled in `/etc/falco/falco.yaml`
- Check `data/falco/events.json` exists and is growing during tests
- Falco requires the sandbox container to be visible via the Docker socket — confirm Falco has access to `/var/run/docker.sock`

### Trivy: `TOOMANYREQUESTS` from GitHub Advisory DB

```bash
# Set a GitHub token for higher rate limits
export GITHUB_TOKEN=<your-pat>
trivy image --token $GITHUB_TOKEN <image>
```

### WebSocket disconnects immediately

Ensure the API has CORS configured for your frontend origin. The `app/main.py` allows `localhost:5173` by default. Add your domain if deploying elsewhere:

```python
# app/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://yourdomain.com"],
    ...
)
```

### PDF export fails

```bash
pip install weasyprint
# On Ubuntu, weasyprint also requires:
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2
```

---

## Part I — CI/CD Integration

### GitHub Actions

Copy `ci/github-actions.yml` to `.github/workflows/security-assessment.yml`. The workflow:
1. Starts the VulBox API as a service container
2. POSTs `/runs` with `consent_granted: true`
3. Polls until `COMPLETE` or `FAILED`
4. Downloads the JSON report as an artifact

### GitLab CI

Copy `ci/gitlab-ci-sample.yml` to `.gitlab-ci.yml` and set `VULBOX_API` to your deployed instance URL.

---

## Summary — Minimum Commands to Get Running

```bash
# Clone repo
git clone <repo-url> vulbox && cd vulbox

# Backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload &

# Frontend (new terminal)
cd frontend && npm install && npm run dev

# Demo
python scripts/demo.py

# Tests
pytest tests/ -v
```

Open `http://localhost:5173` → Register → Login → Submit a run → Watch the status page → View the Security Matrix report.
