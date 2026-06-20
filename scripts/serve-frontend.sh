#!/usr/bin/env bash
# Build the VulBox frontend and serve the production bundle (Vite preview), bound
# to all interfaces so it's reachable from outside the VM. Mirrors
# scripts/serve.sh for the backend.
#
# It builds first, then serves: a reboot/restart always serves the latest code,
# and a broken build fails loudly instead of serving a stale bundle. For a small
# Vite app the build is a few seconds.
#
# node/npm usually live under nvm (a version-specific path systemd can't see), so
# this wrapper sources nvm to put the default node on PATH, then runs vite. That
# keeps the systemd unit (deploy/vulbox-frontend.service) independent of the exact
# node version, surviving node upgrades.
#
# Usage:
#   ./scripts/serve-frontend.sh           # foreground (Ctrl-C to stop)
#   nohup ./scripts/serve-frontend.sh &   # detached (NOT reboot-safe — prefer systemd)
#
# Override host/port via env: HOST=0.0.0.0 PORT=5173 ./scripts/serve-frontend.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/frontend"

# Make nvm's default node available when run by systemd (no login shell → no PATH).
if [[ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]]; then
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh"
fi

npm run build
exec npm run preview -- --host "${HOST:-0.0.0.0}" --port "${PORT:-5173}"
