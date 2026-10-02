"""What we know about FTDC files, written down so it cannot be forgotten twice.

Every test here corresponds to a bug that reached a real cluster and produced a false "the
node stopped reporting" alarm over data we had simply failed to fetch. They cost a morning to
find, they were invisible against bundles already on disk, and they all live in about thirty
lines of state.py. Without these tests nothing stops them coming back, and they would come
back looking like a rule problem rather than a capture problem.

The comments say what each one protects, because a test whose purpose is unclear gets
"fixed" by whoever the assertion inconveniences next.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from state import SeenFile, State, timestamp_of  # noqa: E402

NODE = "atlas-abc-shard-00-00.mongodb.net"
NAME = "metrics.2026-08-07T01-15-12Z-00000"


def fresh() -> State:
    return State(cluster_id="k")


# --------------------------------------------------------------- bug 1: they are not frozen

def test_numbered_file_is_refetched_when_it_grows():
    """A numbered file keeps growing until mongod rotates away from it.

    Observed on Atlas: 284 KB stored under a name that was being served at 8,360 KB nine
    hours later. Treating the name as identity loses everything written in between, silently.
    """
    s = fresh()
    s.record(NODE, NAME, 284_000)
    assert s.is_new(NODE, NAME, 8_360_000), "a grown numbered file must be fetched again"


def test_unchanged_file_is_not_refetched():
    """The other half: same size means same content, and re-downloading it wastes a bundle."""
    s = fresh()
    s.record(NODE, NAME, 284_000)
    assert not s.is_new(NODE, NAME, 284_000)


# ------------------------------------------------------------------- bug 3: interim shrinks

def test_interim_is_refetched_when_it_shrinks():
    """`metrics.interim` buffers samples not yet flushed, so it gets SMALLER on every flush.

    Observed going from 62 KB to 46 KB. A grew-only test never fetches it again after the
    first shrink, and the copy on disk freezes hours in the past while the cluster moves on.
    """
    s = fresh()
    s.record(NODE, "metrics.interim", 62_000)
    assert s.is_new(NODE, "metrics.interim", 46_000), "a shrunken interim is still new content"


# ------------------------------------------------ bug 2 and 4: what the date filter anchors to

def test_anchor_is_none_before_anything_is_stored():
    """No files means no filter: ask Atlas for everything it has."""
    assert fresh().oldest_open_file() is None


def test_anchor_uses_file_time_not_capture_time():
    """Atlas filters on the timestamp in the file NAME, not on the data inside it.

    The file holding the last ten minutes of metrics can be named from this morning, so an
    anchor derived from the clock excludes exactly the file the new data is in.
    """
    s = fresh()
    s.record(NODE, NAME, 1_000)
    assert s.oldest_open_file() == datetime(2026, 8, 7, 1, 15, 12, tzinfo=timezone.utc)


def test_anchor_takes_the_oldest_across_nodes():
    """Nodes roll over at slightly different times.

    Anchoring on anything newer than the oldest node's file silently drops that node.
    """
    s = fresh()
    s.record("n0", "metrics.2026-08-07T01-16-00Z-00000", 1_000)
    s.record("n1", "metrics.2026-08-07T01-14-00Z-00000", 1_000)  # the oldest
    s.record("n2", "metrics.2026-08-07T01-15-00Z-00000", 1_000)
    assert s.oldest_open_file() == datetime(2026, 8, 7, 1, 14, tzinfo=timezone.utc)


def test_anchor_does_not_jump_forward_on_rotation():
    """THE one that has not bitten us yet, and is the reason `stable` exists.

    Members of a replica set start together, so their files roll over together. If the anchor
    followed the newest file of each node, the previous file would leave the filtered window
    the moment every node rotated -- taking whatever mongod appended to it since our last
    capture with it, permanently and without a symptom.
    """
    s = fresh()
    for node, name in [("n0", "metrics.2026-08-07T01-10-00Z-00000"),
                       ("n1", "metrics.2026-08-07T01-11-00Z-00000")]:
        s.record(node, name, 8_000_000)          # captured once; not yet proven complete
        s.files[f"{node}/{name}"].seen_at = "2026-08-07T02:05:00+00:00"   # by an earlier run
    for node, name in [("n0", "metrics.2026-08-07T12-50-00Z-00000"),
                       ("n1", "metrics.2026-08-07T12-51-00Z-00000")]:
        s.record(node, name, 200_000)            # both nodes roll over

    anchor = s.oldest_open_file()
    assert anchor is not None and anchor.hour == 1, (
        "the anchor must stay on the pre-rotation file until it is proven complete, "
        "otherwise its tail is lost"
    )


def test_anchor_advances_once_files_are_proven_complete():
    """The counterweight: once a file is confirmed final, holding the anchor back is waste.

    Without this the bundle would carry an extra ~10 MB per node forever.
    """
    s = fresh()
    old = "metrics.2026-08-07T01-10-00Z-00000"
    s.record("n0", old, 8_000_000)
    s.seen_unchanged("n0", old, 8_000_000)       # same size twice => finished growing
    s.record("n0", "metrics.2026-08-07T12-50-00Z-00000", 200_000)
    anchor = s.oldest_open_file()
    assert anchor is not None and anchor.hour == 12


def test_stability_needs_two_sightings():
    """One sighting proves nothing: every file is 'unchanged' the instant it is first stored."""
    s = fresh()
    s.record(NODE, NAME, 1_000)
    assert not s.files[f"{NODE}/{NAME}"].stable
    s.seen_unchanged(NODE, NAME, 1_000)
    assert s.files[f"{NODE}/{NAME}"].stable


def test_a_file_that_grows_again_loses_stability():
    """Being stable is not permanent. If it grew, our copy is no longer the final one."""
    s = fresh()
    s.record(NODE, NAME, 1_000)
    s.seen_unchanged(NODE, NAME, 1_000)
    s.record(NODE, NAME, 2_000)
    assert not s.files[f"{NODE}/{NAME}"].stable


# ---------------------------------------------------------------------- names and timestamps

def test_timestamp_parsing():
    assert timestamp_of(NAME) == datetime(2026, 8, 7, 1, 15, 12, tzinfo=timezone.utc)
    assert timestamp_of("metrics.interim") is None, "the interim carries no timestamp"
    assert timestamp_of("metrics.garbage") is None
    assert timestamp_of("metrics.2026-13-45T99-99-99Z-00000") is None, "impossible date"


# ------------------------------------------------------------------------ analysis bookkeeping

def test_changed_file_must_be_analysed_again():
    """A file that grew is no longer covered by the analysis that read its shorter version."""
    s = fresh()
    s.record(NODE, NAME, 1_000)
    s.mark_analyzed([f"{NODE}/{NAME}"])
    assert not s.pending_analysis()
    s.record(NODE, NAME, 2_000)
    assert s.pending_analysis(), "growth must reopen the file for analysis"


def test_roundtrip_through_disk(tmp_path: Path):
    """State survives a restart, including the flags the anchor depends on."""
    s = fresh()
    s.record(NODE, NAME, 1_000)
    s.seen_unchanged(NODE, NAME, 1_000)
    s.last_capture = "2026-08-07T01:20:00+00:00"
    s.reported_findings.append("abc123")
    s.save(tmp_path / "state.json")

    back = State.load(tmp_path / "state.json", "k")
    assert back.files[f"{NODE}/{NAME}"].stable
    assert back.last_capture == s.last_capture
    assert back.reported_findings == ["abc123"]


def test_save_is_atomic(tmp_path: Path):
    """An interrupted run must not leave a truncated state file.

    State is the record of what was already downloaded and already emailed; half of it is
    worse than none, because the missing half gets re-sent.
    """
    path = tmp_path / "state.json"
    s = fresh()
    s.record(NODE, NAME, 1_000)
    s.save(path)
    assert json.loads(path.read_text())["files"], "state must be readable right after saving"
    assert not (tmp_path / "state.tmp").exists(), "the temporary file must not be left behind"


def test_an_old_state_inherits_its_last_arrival_from_its_last_run(tmp_path):
    """Upgrading must not leave a dead source permanently unreportable.

    `last_new_data` only moves when a run brings something back. A state file written before
    that field existed has none, and a cluster whose source had already stopped would never get
    one -- so it could never be reported as unwatched, which is the one cluster that needed it.
    """
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"cluster_id": "prod",
                                "last_capture": "2026-08-20T10:00:00+00:00", "files": {}}))

    assert State.load(path, "prod").last_new_data == "2026-08-20T10:00:00+00:00"


def test_files_that_came_with_a_newer_one_were_already_complete():
    """mongod opens a file only after closing the last. Cluster1's first capture brought 126
    files at once, each seen once, and the anchor stayed at the oldest: every hourly capture
    asked Atlas for twenty days again, and Atlas cut every one."""
    s = fresh()
    names = [f"metrics.2026-09-{d:02d}T06-00-00Z-00000" for d in (12, 13, 14)]
    for name in names:
        s.record("n0", name, 10_000_000)       # one capture, seconds apart
    anchor = s.oldest_open_file()
    assert anchor is not None and anchor.day == 14, "only the newest can still be open"
