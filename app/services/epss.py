"""EPSS (Exploit Prediction Scoring System) lookup.

Loads a vendored FIRST.org EPSS snapshot once at import into an in-memory
``{cve_id: score}`` dict and exposes :func:`score_for` for O(1) lookup. The
score is the model's predicted probability (0.0–1.0) that a CVE will be
exploited in the wild within the next 30 days.

Used in two places:
  * ``trivy_adapter`` enriches each finding with its EPSS score.
  * ``art_adapter.build_queue`` ranks (and optionally gates) the ART queue by
    EPSS so actively-predicted-exploitable CVEs are tested first.

The snapshot lives at ``data/sources/epss.csv.gz`` (FIRST.org daily CSV:
``cve,epss,percentile`` rows, ~250k of them). It's refreshed by
``scripts/fetch_epss.py``. A missing/corrupt file degrades to an empty map —
no scores, no crash — mirroring how the CVE map seeds itself on a failed deploy.
"""
from __future__ import annotations

import csv
import gzip
import io
from pathlib import Path
from typing import Dict, Optional

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_SNAPSHOT_PATH = settings.project_root / "data" / "sources" / "epss.csv.gz"


def _load_snapshot(path: Path) -> Dict[str, float]:
    """Parse the gzipped EPSS CSV into a ``{cve: score}`` dict.

    The FIRST.org file opens with a ``#model_version,score_date`` comment line,
    then a ``cve,epss,percentile`` header, then the rows. We skip any leading
    ``#`` comment lines and tolerate a missing/garbled file by returning {}.
    """
    if not path.is_file():
        logger.warning("EPSS snapshot missing; scores unavailable", extra={"path": str(path)})
        return {}
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        logger.warning("EPSS snapshot unreadable", extra={"path": str(path), "err": str(exc)})
        return {}

    lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    scores: Dict[str, float] = {}
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    for row in reader:
        cve = (row.get("cve") or "").strip()
        if not cve.startswith("CVE-"):
            continue
        try:
            scores[cve] = float(row["epss"])
        except (KeyError, TypeError, ValueError):
            continue
    logger.info("EPSS snapshot loaded", extra={"path": str(path), "scored_cves": len(scores)})
    return scores


_EPSS_SCORES: Dict[str, float] = _load_snapshot(_SNAPSHOT_PATH)


def score_for(cve_id: str) -> Optional[float]:
    """Return the EPSS score (0.0–1.0) for ``cve_id``, or None if not scored."""
    return _EPSS_SCORES.get(cve_id)


def is_loaded() -> bool:
    """True if the snapshot loaded any scores (used by diagnostics/tests)."""
    return bool(_EPSS_SCORES)
