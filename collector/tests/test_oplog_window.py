"""The oplog window: how long a member can be away and still catch up.

Runs the real analysis over FTDC written by ftdcwrite, so the expression, the rule and the
detector are exercised together -- the same writes into a small oplog and into a large one.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bson
import pytest
from bson.int64 import Int64

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ftdcwrite  # noqa: E402
from state import State, now  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
BIGHOLE = HERE.parent / "big-hole"
T0 = datetime(2026, 9, 30, 0, 0, tzinfo=timezone.utc)
MB = 1024 ** 2
STEP = 10           # seconds between samples
HOURS = 3

pytestmark = pytest.mark.skipif(
    shutil.which("npx") is None or not (BIGHOLE / "node_modules").exists(),
    reason="needs the engine installed to run the analysis")


def cluster(tmp: Path, oplog_mb: int, mb_per_s: float) -> Path:
    """Three members writing `mb_per_s` into an oplog of `oplog_mb`, for three hours."""
    base = tmp / "data" / "c"
    for name in ["db1:27017", "db2:27017", "db3:27017"]:
        n = HOURS * 3600 // STEP
        clock = iter(T0 + timedelta(seconds=STEP * i) for i in range(n + 10))
        meta = {"hostInfo": {"system": {"hostname": name.split(":")[0]}}}
        w = ftdcwrite.Writer(base / "ftdc" / name.replace(":", "_"), lambda: meta,
                             clock=lambda: next(clock))
        for i in range(n):
            w.add(bson.encode({
                "start": T0 + timedelta(seconds=STEP * i),
                "serverStatus": {"uptimeMillis": Int64(10_000_000 + STEP * 1000 * i)},
                "local.oplog.rs.stats": {"storageStats": {
                    "maxSize": Int64(oplog_mb * MB),
                    "wiredTiger": {"cursor": {
                        "insert key and value bytes": Int64(int(mb_per_s * MB * STEP * i))}},
                }},
            }))
        w.flush()
    st = State.load(base / "state.json", "c")
    for f in sorted((base / "ftdc").rglob("metrics.*")):
        st.record(f.parent.name, f.name, f.stat().st_size)
    st.last_capture = now()
    st.save(base / "state.json")
    (tmp / "config.json").write_text(json.dumps(
        {"clusters": [{"id": "c", "source": {"type": "directory", "path": "/nowhere"}}]}))
    subprocess.run([sys.executable, str(HERE / "analyze.py"), "--config", str(tmp / "config.json"),
                    "--data", str(tmp / "data"), "--quiet"], cwd=HERE, check=True,
                   capture_output=True, timeout=300)
    return base


def window_findings(base: Path) -> list[dict]:
    path = base / "findings.jsonl"
    rows = [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []
    return [f for f in rows if f["rule"].startswith("oplog-window")]


def test_a_small_oplog_under_load_is_reported(tmp_path):
    # 512 MB at 1 MB/s: under nine minutes of window, the shape rs-local had under load.
    found = window_findings(cluster(tmp_path, oplog_mb=512, mb_per_s=1.0))
    assert {f["rule"] for f in found} == {"oplog-window-short", "oplog-window-critical"}
    assert {f["node"] for f in found} == {"db1", "db2", "db3"}


def test_a_window_of_days_says_nothing(tmp_path):
    # 50 GB at 100 KB/s: about six days. The same writes, an oplog sized for them.
    assert window_findings(cluster(tmp_path, oplog_mb=50 * 1024, mb_per_s=0.1)) == []
