#!/usr/bin/env bash
# Launch the VulBox API with config loaded from .env.
#
# The app itself reads .env via pydantic-settings (app/core/config.py), so this
# wrapper's job is just to run uvicorn from the project's venv with a consistent
# working directory — whether invoked by systemd (see deploy/vulbox.service) or
# manually.
#
# Usage:
#   ./scripts/serve.sh                 # foreground (Ctrl-C to stop)
#   nohup ./scripts/serve.sh &         # detached (NOT reboot-safe — prefer systemd)
#
# Override host/port via env: HOST=0.0.0.0 PORT=8000 ./scripts/serve.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Export .env into the shell too, so any non-Python tooling sees the same vars.
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

UVICORN="$ROOT/venv/bin/uvicorn"
[[ -x "$UVICORN" ]] || UVICORN="uvicorn"  # fall back to PATH

exec "$UVICORN" app.main:app \
  --host "${HOST:-0.0.0.0}" \
  --port "${PORT:-8000}"
