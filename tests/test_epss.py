"""Tests for the EPSS snapshot loader (app.services.epss)."""
import gzip

from app.services import epss


def test_snapshot_loaded_with_real_scores():
    # The vendored snapshot ships hundreds of thousands of scored CVEs.
    assert epss.is_loaded()
    assert len(epss._EPSS_SCORES) > 1000


def test_score_for_known_cve_in_range():
    # Log4Shell is universally present in any recent EPSS snapshot, scored high.
    score = epss.score_for("CVE-2021-44228")
    assert score is not None
    assert 0.0 <= score <= 1.0


def test_score_for_unknown_cve_is_none():
    assert epss.score_for("CVE-0000-0000") is None


def test_missing_file_degrades_to_empty(tmp_path):
    # A non-existent snapshot path yields an empty map, never an exception.
    assert epss._load_snapshot(tmp_path / "nope.csv.gz") == {}


def test_corrupt_file_degrades_to_empty(tmp_path):
    bad = tmp_path / "bad.csv.gz"
    bad.write_bytes(b"not a gzip stream")
    assert epss._load_snapshot(bad) == {}


def test_loader_parses_minimal_snapshot(tmp_path):
    # Build a tiny snapshot mirroring the FIRST.org format: a leading comment
    # line, a header, then rows. The comment line must be skipped.
    path = tmp_path / "mini.csv.gz"
    body = "#model_version:test,score_date:2026-01-01\ncve,epss,percentile\nCVE-1111-2222,0.5,0.9\nnotacve,0.1,0.2\n"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write(body)
    scores = epss._load_snapshot(path)
    assert scores == {"CVE-1111-2222": 0.5}
