"""Falco collect-time parsing — regression for the dead Detectability column.

On the Python 3.10 deploy host, Falco's nanosecond-precision `time` string blew
up `datetime.fromisoformat`, the event was treated as ts=0 ("infinitely old"),
and every alert was filtered out — so `is_detectable` was always False despite
Falco firing correctly. These lock in the fix.
"""
import json
import time
from datetime import datetime, timezone

import app.adapters.falco_adapter as fa
from app.adapters.falco_adapter import FalcoAdapter, _event_epoch


def test_event_epoch_parses_nanosecond_iso_string():
    # 9 fractional digits — what Falco emits, what fromisoformat<3.11 rejects.
    obj = {"time": "2026-06-25T11:31:47.138886485Z"}
    ts = _event_epoch(obj)
    assert ts is not None
    assert abs(ts - datetime(2026, 6, 25, 11, 31, 47, tzinfo=timezone.utc).timestamp()) < 1


def test_event_epoch_prefers_integer_nanos():
    obj = {"time": "garbage", "output_fields": {"evt.time": 1782387107138886485}}
    assert _event_epoch(obj) == 1782387107138886485 / 1e9


def test_event_epoch_unparseable_returns_none():
    assert _event_epoch({"time": "not-a-time"}) is None
    assert _event_epoch({}) is None


def test_read_live_alerts_keeps_recent_in_container_event(tmp_path, monkeypatch):
    run_id = 999
    log = tmp_path / "falco.json"
    cid = "15bf543cd0516c3fd773dd5b25f80c39226c14fda365c71eab8ffe6e690a9b62"

    now_ns = int(time.time() * 1e9)
    events = [
        # in-container detection, nanosecond ISO time, recent → must survive
        {
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{now_ns % 1_000_000_000:09d}Z",
            "rule": "VulBox Host Filesystem Access",
            "priority": "Critical",
            "output": "host fs access",
            "output_fields": {"container.id": "15bf543cd051", "evt.time": now_ns},
        },
        # host-side runner noise → correctly filtered by container attribution
        {
            "rule": "VulBox Sensitive File Read",
            "priority": "Warning",
            "output": "host read",
            "output_fields": {"container.id": "host", "evt.time": now_ns},
        },
    ]
    log.write_text("\n".join(json.dumps(e) for e in events))

    monkeypatch.setattr(fa, "_run_log_path", lambda rid: log)
    fa._falco_containers[run_id] = cid
    try:
        out = FalcoAdapter._read_live_alerts(run_id, window_seconds=30)
    finally:
        fa._falco_containers.pop(run_id, None)

    rules = [o.get("rule") for o in out]
    assert "VulBox Host Filesystem Access" in rules   # detection survives
    assert "VulBox Sensitive File Read" not in rules   # host noise filtered
