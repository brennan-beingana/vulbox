#!/usr/bin/env bash
# One-shot demo recovery: kill orphan VulBox containers, drop the DB, re-seed,
# restart the API. Run in a tmux pane during the demo when something goes
# sideways and you need a clean state in <10 seconds.
#
# Usage:
#   scripts/demo_reset.sh                # full reset
#   scripts/demo_reset.sh --no-restart   # reset state only; you'll start the API yourself

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

RESTART=true
for arg in "$@"; do
  case "$arg" in
    --no-restart) RESTART=false ;;
    -h|--help)
      sed -n '2,11p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 64
      ;;
  esac
done

echo "[1/4] killing orphan vulbox-run-* containers"
if command -v docker >/dev/null 2>&1; then
  mapfile -t orphans < <(docker ps -aq --filter "name=vulbox-run-")
  if [[ ${#orphans[@]} -gt 0 ]]; then
    docker rm -f "${orphans[@]}" >/dev/null
    echo "      removed ${#orphans[@]} container(s)"
  else
    echo "      none found"
  fi
else
  echo "      docker not on PATH — skipping"
fi

echo "[2/4] killing stray API process on :8000 (if any)"
# Best-effort: don't fail if nothing is listening or fuser isn't installed.
if command -v fuser >/dev/null 2>&1; then
  fuser -k 8000/tcp >/dev/null 2>&1 || true
fi

echo "[3/4] dropping data/findings.db and re-seeding"
rm -f data/findings.db
# shellcheck disable=SC1091
source venv/bin/activate
python scripts/seed_demo_data.py --reset

if [[ "$RESTART" == "true" ]]; then
  echo "[4/4] restarting API on :8000 (logs → data/runs/api.log)"
  mkdir -p data/runs
  nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 \
    > data/runs/api.log 2>&1 &
  API_PID=$!
  echo "      uvicorn pid=$API_PID"

  # Wait up to 10s for /health to come up before declaring success.
  for i in $(seq 1 20); do
    if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
      echo "      /health is up"
      exit 0
    fi
    sleep 0.5
  done
  echo "      WARNING: /health did not respond within 10s; check data/runs/api.log" >&2
  exit 1
else
  echo "[4/4] --no-restart: skipping API launch"
fi
