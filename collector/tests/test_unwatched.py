"""The poller's own downtime is not the member's outage.

Every rebuild of the app restarts the poller, and each restart read as "Node stopped reporting"
on every connected cluster. The poller records the hole as its own (poller.own_gap) and the
runner drops it (--unwatched). Runs the real analysis over FTDC written by ftdcwrite.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bson
import pytest
from bson.int64 import Int64

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ftdcwrite  # noqa: E402
import poller  # noqa: E402
from state import State, now  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
BIGHOLE = HERE.parent / "big-hole"
T0 = datetime(2026, 9, 30, 0, 0, tzinfo=timezone.utc)
HOLE = (1800, 1900)  # seconds into the hour with no sample, on every member

engine = pytest.mark.skipif(
    shutil.which("npx") is None or not (BIGHOLE / "node_modules").exists(),
    reason="needs the engine installed to run the analysis")


def cluster(tmp: Path, unwatched: list[dict]) -> list[dict]:
    base = tmp / "data" / "c"
    for name in ["db1:27017", "db2:27017"]:
        clock = iter(T0 + timedelta(seconds=i) for i in range(3700))
        meta = {"hostInfo": {"system": {"hostname": name.split(":")[0]}}}
        w = ftdcwrite.Writer(base / "ftdc" / name.replace(":", "_"), lambda: meta,
                             clock=lambda: next(clock))
        for i in range(3600):
            if HOLE[0] <= i < HOLE[1]:
                continue
            w.add(bson.encode({
                "start": T0 + timedelta(seconds=i),
                "serverStatus": {"uptimeMillis": Int64(10_000_000 + 1000 * i)},
            }))
        w.flush()
    if unwatched:
        (base / "unwatched.jsonl").write_text("".join(json.dumps(r) + "\n" for r in unwatched))
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
    path = base / "findings.jsonl"
    rows = [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []
    return [f for f in rows if f["rule"] == "ftdc-long-outage"]


@engine
def test_a_hole_the_poller_declared_is_not_an_outage(tmp_path):
    # Declared for db1 only, from the last sample before the hole to the first after it, with
    # the poller's clock five seconds off mongod's.
    own = {"member": "db1_27017",
           "from": (T0 + timedelta(seconds=HOLE[0] - 1 + 5)).isoformat(),
           "to": (T0 + timedelta(seconds=HOLE[1] + 5)).isoformat()}
    found = cluster(tmp_path, [own])
    assert {f["node"] for f in found} == {"db2"}


@engine
def test_without_a_declaration_both_members_report_it(tmp_path):
    assert {f["node"] for f in cluster(tmp_path, [])} == {"db1", "db2"}


# ------------------------------------------------------------------------- the poller side

def sample(uptime: float, sectioned: bool = False) -> bytes:
    status = {"serverStatus": {"uptime": uptime}}
    return bson.encode({"common": status} if sectioned else status)


def member(tmp: Path, resume_from: datetime | None) -> poller.MemberPoller:
    return poller.MemberPoller("mongodb://x/", "db1:27017", tmp / "incoming" / "db1_27017",
                               threading.Event(), {}, 10, resume_from=resume_from,
                               unwatched=tmp / poller.UNWATCHED)


def test_uptime_is_found_before_and_after_role_sections():
    assert poller.uptime_of(sample(3600.0)) == 3600.0
    assert poller.uptime_of(sample(42.0, sectioned=True)) == 42.0
    assert poller.uptime_of(bson.encode({"x": 1})) is None


def test_a_restart_of_the_poller_is_recorded_as_its_own(tmp_path):
    m = member(tmp_path, T0)
    rec = m.own_gap(sample(86400.0), T0 + timedelta(seconds=80))
    assert rec["member"] == "db1_27017" and rec["from"] == T0.isoformat()
    lines = (tmp_path / poller.UNWATCHED).read_text().splitlines()
    assert json.loads(lines[0])["to"] == (T0 + timedelta(seconds=80)).isoformat()
    assert m.own_gap(sample(86400.0), T0 + timedelta(seconds=90)) is None, "only once"


def test_a_member_that_restarted_inside_the_hole_keeps_its_outage(tmp_path):
    # mongod up for 30 s after an 80 s hole: it was down too.
    assert member(tmp_path, T0).own_gap(sample(30.0), T0 + timedelta(seconds=80)) is None
    assert not (tmp_path / poller.UNWATCHED).exists()


def test_a_hole_shorter_than_two_reads_is_not_recorded(tmp_path):
    assert member(tmp_path, T0).own_gap(sample(86400.0), T0 + timedelta(seconds=15)) is None


def test_where_the_previous_run_stopped_writing(tmp_path):
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"members": {
        "db1:27017": {"last_sample": "2026-09-30T00:10:00+00:00",
                      "last_written": "2026-09-30T00:09:00+00:00", "error": None},
        "db2:27017": {"last_sample": "2026-09-30T00:10:00+00:00", "error": None},
        "db3:27017": {"last_sample": "2026-09-30T00:10:00+00:00",
                      "last_written": "2026-09-30T00:09:00+00:00", "error": "timed out"}}}))
    prev = poller.previous_writes(status)
    assert prev["db1:27017"] == datetime(2026, 9, 30, 0, 9, tzinfo=timezone.utc)
    # An older poller never flushed on the way out: back by the most a chunk holds.
    assert prev["db2:27017"] == datetime(2026, 9, 30, 0, 5, tzinfo=timezone.utc)
    assert "db3:27017" not in prev, "a failing member's hole may be its own"
    assert poller.previous_writes(tmp_path / "missing.json") == {}


def test_the_writer_knows_the_newest_sample_on_disk(tmp_path):
    clock = iter(T0 + timedelta(seconds=i) for i in range(10))
    w = ftdcwrite.Writer(tmp_path / "m", lambda: {}, clock=lambda: next(clock))
    w.add(bson.encode({"start": T0, "serverStatus": {"uptime": 1.0}}), at=T0)
    assert w.written_through is None, "still in memory"
    w.flush()
    assert w.written_through == T0
