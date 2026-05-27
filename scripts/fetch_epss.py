#!/usr/bin/env python3
"""Refresh the vendored EPSS snapshot at ``data/sources/epss.csv.gz``.

EPSS (Exploit Prediction Scoring System, https://www.first.org/epss/) publishes
a daily CSV of every CVE's predicted-exploitation probability. We vendor a
snapshot so ``app.services.epss`` can rank/gate the ART queue offline, the same
way ``data/sources/kev.json`` is vendored for the CVE map.

Usage::

    python scripts/fetch_epss.py            # download today's snapshot
    python scripts/fetch_epss.py 2024-01-01 # a specific score date

The published file is already gzipped CSV (``cve,epss,percentile`` rows behind
a ``#model_version,score_date`` comment line), so we stream it straight to disk.

Snapshots age: re-run periodically (a stale snapshot just means stale scores,
never a crash). The download URL is the canonical FIRST.org daily endpoint.
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = ROOT / "data" / "sources" / "epss.csv.gz"
BASE_URL = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"
CURRENT_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def main() -> int:
    date = sys.argv[1] if len(sys.argv) > 1 else None
    url = BASE_URL.format(date=date) if date else CURRENT_URL
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url}")
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 — fixed host
            data = resp.read()
    except Exception as exc:  # noqa: BLE001 — surface any network/HTTP error
        print(f"download failed: {exc}", file=sys.stderr)
        return 1
    OUT_PATH.write_bytes(data)
    print(f"Wrote {len(data):,} bytes → {OUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
