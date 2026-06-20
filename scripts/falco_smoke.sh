#!/usr/bin/env bash
# Falco smoke test — run on the Falco-enabled host (VM with Docker + Falco).
#
# Purpose: prove that Falco, launched with VulBox's exact config + rules, fires
# on the kind of activity ART produces and therefore writes its JSON output.
# This is the empirical check from falco_fix.md, cleaned up and wired to the
# bundled VulBox rules.
#
# It splits the diagnosis three ways:
#   * Both the host read AND the container read alert  -> rules + engine OK.
#   * Host read alerts but the container read does not  -> container engine not
#     attaching metadata (a Falco config issue, not ours).
#   * Nothing fires at all                              -> rules not loaded.
#
# Usage:  sudo scripts/falco_smoke.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VULBOX_RULES="$REPO_ROOT/deploy/falco/vulbox_rules.yaml"
OUT_JSON="/tmp/vulbox_falco_smoke.json"
STDOUT_LOG="/tmp/vulbox_falco_smoke.stdout.log"

if ! command -v falco >/dev/null 2>&1; then
  echo "falco not found on PATH — run this on the Falco-enabled host." >&2
  exit 1
fi

rm -f "$OUT_JSON" "$STDOUT_LOG"

# Mirror app/adapters/falco_adapter.py: stock rules (if present) + VulBox rules.
RULE_ARGS=()
for p in /etc/falco/falco_rules.yaml /etc/falco/falco_rules.local.yaml /etc/falco/rules.d; do
  [[ -e "$p" ]] && RULE_ARGS+=(-r "$p")
done
[[ -f "$VULBOX_RULES" ]] && RULE_ARGS+=(-r "$VULBOX_RULES")

echo "=== launching falco (rules: ${RULE_ARGS[*]:-config default}) ==="
falco \
  -o json_output=true \
  -o json_include_output_property=true \
  -o file_output.enabled=true \
  -o "file_output.filename=$OUT_JSON" \
  -o stdout_output.enabled=true \
  "${RULE_ARGS[@]}" > "$STDOUT_LOG" 2>&1 &
FPID=$!

cleanup() { kill -INT "$FPID" 2>/dev/null; wait "$FPID" 2>/dev/null; }
trap cleanup EXIT

echo "=== waiting for the BPF driver to load (8s) ==="
sleep 8

echo "=== trigger 1: read a sensitive file on the host ==="
cat /etc/shadow > /dev/null 2>&1 || true

echo "=== trigger 2: same read inside a container (mimics the ART docker-exec path) ==="
docker run --rm alpine sh -c 'cat /etc/shadow >/dev/null 2>&1; id' >/dev/null 2>&1 || true

sleep 3
cleanup
trap - EXIT

echo
echo "=== did file_output write? ==="
if [[ -s "$OUT_JSON" ]]; then
  ls -la "$OUT_JSON"
  echo "--- VulBox rule hits ---"
  grep -i "VulBox" "$OUT_JSON" || echo "(no VulBox-tagged alerts)"
else
  echo "NO OUTPUT FILE — no rule fired. Check that rules loaded (see stdout log below)."
fi

echo
echo "=== alerts on stdout (tail) ==="
grep -iE "warning|notice|error|critical|priority|rules?|loaded" "$STDOUT_LOG" | tail -25
