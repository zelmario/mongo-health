"""Retransmissions: the network losing packets, and the two shapes that only look like it.

A retry storm retransmits plenty -- SYNs into an overflowing listen queue -- but out of so many
segments that the share stays small; a quiet Atlas host has the odd burst of a few seconds.
Runs the real analysis over FTDC written by ftdcwrite.
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


def cluster(tmp: Path, traffic) -> Path:
    """Three members sampled every second for an hour; `traffic(i)` gives the segments sent and
    retransmitted in second i."""
    base = tmp / "data" / "c"
    for name in ["db1:27017", "db2:27017", "db3:27017"]:
        clock = iter(T0 + timedelta(seconds=i) for i in range(3700))
        meta = {"hostInfo": {"system": {"hostname": name.split(":")[0]}}}
        w = ftdcwrite.Writer(base / "ftdc" / name.replace(":", "_"), lambda: meta,
                             clock=lambda: next(clock))
        out = retrans = 0
        for i in range(3600):
            sent, again = traffic(i)
            out += sent
            retrans += again
            w.add(bson.encode({
                "start": T0 + timedelta(seconds=i),
                "serverStatus": {"uptimeMillis": Int64(10_000_000 + 1000 * i)},
                "systemMetrics": {"netstat": {"Tcp:OutSegs": Int64(out),
                                              "Tcp:RetransSegs": Int64(retrans)}},
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


def retrans_findings(base: Path) -> list[dict]:
    path = base / "findings.jsonl"
    rows = [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []
    return [f for f in rows if f["rule"] == "packets-retransmitted"]


def test_packet_loss_is_reported(tmp_path):
    # Two minutes at 2% of 1,000 segments a second: what netem's 0.5% loss looked like.
    found = retrans_findings(cluster(
        tmp_path, lambda i: (1000, 20) if 1200 <= i < 1320 else (1000, 0)))
    assert {f["node"] for f in found} == {"db1", "db2", "db3"}


def test_a_retry_storm_is_not_packet_loss(tmp_path):
    # Five minutes at 100 retransmits a second, out of 50,000 segments: 0.2%.
    found = retrans_findings(cluster(
        tmp_path, lambda i: (50_000, 100) if 1200 <= i < 1500 else (1000, 0)))
    assert found == []


def test_the_odd_burst_is_not_packet_loss(tmp_path):
    # Two seconds of loss every ten minutes, as Cluster1 has.
    assert retrans_findings(cluster(
        tmp_path, lambda i: (100, 20) if i % 600 < 2 else (100, 0))) == []
