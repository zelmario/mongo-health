"""Swapping: pages coming back in from swap, in the shape it really has.

Real swap-ins flap -- on rs-local the longest unbroken stretch above the line was 151 s inside
165 minutes of it -- and a healthy Atlas host still has the odd one-second burst. Runs the real
analysis over FTDC written by ftdcwrite.
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

pytestmark = pytest.mark.skipif(
    shutil.which("npx") is None or not (BIGHOLE / "node_modules").exists(),
    reason="needs the engine installed to run the analysis")


def cluster(tmp: Path, swapping) -> Path:
    """Three members sampled every second for an hour; `swapping(i)` says whether second i
    brings 500 pages back from swap."""
    base = tmp / "data" / "c"
    for name in ["db1:27017", "db2:27017", "db3:27017"]:
        clock = iter(T0 + timedelta(seconds=i) for i in range(3700))
        meta = {"hostInfo": {"system": {"hostname": name.split(":")[0]}}}
        w = ftdcwrite.Writer(base / "ftdc" / name.replace(":", "_"), lambda: meta,
                             clock=lambda: next(clock))
        pages = 0
        for i in range(3600):
            pages += 500 if swapping(i) else 0
            w.add(bson.encode({
                "start": T0 + timedelta(seconds=i),
                "serverStatus": {"uptimeMillis": Int64(10_000_000 + 1000 * i)},
                "systemMetrics": {"vmstat": {"pswpin": Int64(pages)}},
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


def swap_findings(base: Path) -> list[dict]:
    path = base / "findings.jsonl"
    rows = [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []
    return [f for f in rows if f["rule"] == "swapping"]


def test_swapping_in_flaps_is_reported(tmp_path):
    # Twenty seconds on, ten off, for five minutes: never a minute unbroken, 200 s in all.
    found = swap_findings(cluster(tmp_path, lambda i: 1200 <= i < 1500 and i % 30 < 20))
    assert {f["node"] for f in found} == {"db1", "db2", "db3"}


def test_the_odd_burst_is_not_swapping(tmp_path):
    # Two-second bursts every ten minutes, as Cluster1 has: a minute never adds up.
    assert swap_findings(cluster(tmp_path, lambda i: i % 600 < 2)) == []
