#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <image-name[:tag]>"
  exit 1
fi

IMAGE="$1"
OUTPUT_DIR="data/sample_outputs"
mkdir -p "$OUTPUT_DIR"

trivy image --format json --output "$OUTPUT_DIR/trivy-${IMAGE//[:\/]/_}.json" "$IMAGE"
echo "Trivy output written to $OUTPUT_DIR"
