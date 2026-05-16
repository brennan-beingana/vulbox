#!/usr/bin/env bash
# Refresh the vendored ART atomics tree under data/sources/atomics/.
#
# Strategy: sparse-clone redcanaryco/atomic-red-team's atomics/ folder, then
# copy only the technique YAMLs that appear in our CVE→technique maps. This
# keeps the repo footprint small (~5MB instead of ~80MB for the full tree)
# while preserving reproducibility — the source commit SHA is recorded in
# data/sources/atomics/SOURCE_SHA.
#
# Re-run after editing data/cve_technique_map.yml or regenerating the
# generated map; the script discovers techniques fresh each invocation.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ATOMICS_DEST="$PROJECT_ROOT/data/sources/atomics"
REPO_URL="https://github.com/redcanaryco/atomic-red-team.git"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Sparse-cloning $REPO_URL ..."
git clone --filter=blob:none --no-checkout --depth 1 "$REPO_URL" "$TMP_DIR/art" >/dev/null 2>&1
(
  cd "$TMP_DIR/art"
  git sparse-checkout init --cone >/dev/null
  git sparse-checkout set atomics >/dev/null
  git checkout >/dev/null 2>&1
)
SOURCE_SHA="$(cd "$TMP_DIR/art" && git rev-parse HEAD)"

echo "==> Reading technique list from data/cve_technique_map*.yml ..."
export VULBOX_ROOT="$PROJECT_ROOT"
TECHS="$(python3 - <<'PY'
import os, yaml
from pathlib import Path
root = Path(os.environ["VULBOX_ROOT"])
techs = set()
for f in ("data/cve_technique_map.yml", "data/cve_technique_map.generated.yml"):
    p = root / f
    if not p.is_file():
        continue
    d = yaml.safe_load(p.read_text()) or {}
    for e in d.get("mappings", []) or []:
        t = e.get("technique")
        if not t:
            continue
        techs.add(t)
        techs.add(t.split(".")[0])  # also pull the base technique YAML
    for fb in d.get("fallbacks", []) or []:
        t = fb.get("technique")
        if t:
            techs.add(t)
            techs.add(t.split(".")[0])
for t in sorted(techs):
    print(t)
PY
)"

total=$(echo "$TECHS" | wc -l)
echo "==> Found $total techniques in maps. Copying matching YAMLs ..."

mkdir -p "$ATOMICS_DEST"
# Wipe existing tree so removed techniques don't linger.
find "$ATOMICS_DEST" -mindepth 1 -maxdepth 1 -type d -name 'T*' -exec rm -rf {} +

copied=0
missing=0
for t in $TECHS; do
  src="$TMP_DIR/art/atomics/$t/$t.yaml"
  if [[ -f "$src" ]]; then
    mkdir -p "$ATOMICS_DEST/$t"
    cp "$src" "$ATOMICS_DEST/$t/"
    copied=$((copied + 1))
  else
    missing=$((missing + 1))
  fi
done

printf '%s  %s\n' "$SOURCE_SHA" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ATOMICS_DEST/SOURCE_SHA"

echo "==> Done."
echo "    Copied:   $copied YAMLs"
echo "    Missing:  $missing techniques (no YAML in upstream)"
echo "    SHA:      $SOURCE_SHA"
echo "    Path:     $ATOMICS_DEST"
