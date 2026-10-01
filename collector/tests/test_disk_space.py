"""The disk checks watch the disk the data is on -- and only that one.

Runs the real analysis over FTDC written by ftdcwrite, so the mount resolution in the runner,
the rule substitution and the detector are all exercised together.
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
T0 = datetime(2026, 9, 30, 8, 0, tzinfo=timezone.utc)
GB = 1024 ** 3

pytestmark = pytest.mark.skipif(
    shutil.which("npx") is None or not (BIGHOLE / "node_modules").exists(),
    reason="needs the engine installed to run the analysis")


def cluster(tmp: Path, data_free: float, root_free: float) -> Path:
    """Three members, an hour of samples every 10 s, data under /data/db on its own mount."""
    base = tmp / "data" / "c"
    members = ["db1:27017", "db2:27017", "db3:27017"]
    for name in members:
        clock = iter(T0 + timedelta(seconds=10 * i) for i in range(400))
        meta = {"hostInfo": {"system": {"hostname": name.split(":")[0]}},
                "getCmdLineOpts": {"parsed": {"storage": {"dbPath": "/data/db"}}}}
        w = ftdcwrite.Writer(base / "ftdc" / name.replace(":", "_"), lambda: meta,
                             clock=lambda: next(clock))
        for i in range(360):
            w.add(bson.encode({
                "start": T0 + timedelta(seconds=10 * i),
                "serverStatus": {"uptimeMillis": Int64(10_000_000 + 10_000 * i)},
                "systemMetrics": {"mounts": {
                    "/": {"capacity": Int64(20 * GB), "available": Int64(int(20 * GB * root_free))},
                    "/data": {"capacity": Int64(100 * GB),
                              "available": Int64(int(100 * GB * data_free))},
                    # Full by design on many healthy hosts: must never raise anything.
                    "/dev/shm": {"capacity": Int64(64 * 1024 ** 2), "available": Int64(0)},
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


def disk_findings(base: Path) -> list[dict]:
    path = base / "findings.jsonl"
    rows = [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []
    return [f for f in rows if f["rule"].startswith("disk-space")]


def test_a_full_data_disk_is_reported_on_its_own_mount(tmp_path):
    found = disk_findings(cluster(tmp_path, data_free=0.03, root_free=0.60))
    assert {f["rule"] for f in found} == {"disk-space-low", "disk-space-critical"}
    assert {f["node"] for f in found} == {"db1", "db2", "db3"}
    assert all("mounts./data." in f["metric"] for f in found), "the data's mount, not / or shm"


def test_a_full_root_disk_is_not_the_datas_problem(tmp_path):
    """The data lives on /data; a nearly full / is somebody else's alarm."""
    assert disk_findings(cluster(tmp_path, data_free=0.40, root_free=0.03)) == []


def test_the_members_configuration_reaches_the_summary(tmp_path):
    """The runner reads it from the metadata; recommend.py judges it from summary.json. The
    path between them is what this checks -- Atlas once lost the whole of it to one field."""
    base = cluster(tmp_path, data_free=0.40, root_free=0.60)
    nodes = json.loads((base / "summary.json").read_text())["nodes"]
    assert {n["config"]["dbPath"] for n in nodes} == {"/data/db"}
    assert {n["config"]["hostname"] for n in nodes} == {"db1", "db2", "db3"}
