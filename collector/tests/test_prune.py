"""Guards on the only code here that destroys anything.

Every other failure in this system produces a wrong answer, which is recoverable. This one
deletes captures that Atlas has long since dropped, so a mistake is permanent and silent — the
data is simply not there the day somebody asks for it.

The tests are therefore weighted towards what must NOT be deleted, which is the direction that
actually costs something. Deleting too little wastes disk; deleting too much ends the service.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prune import prunable, prune_cluster  # noqa: E402

NOW = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)


def make_cluster(tmp: Path, files: dict[str, list[tuple[str, int]]]) -> Path:
    """A data directory shaped like the real one. `files` is {node: [(name, size)]}."""
    base = tmp / "prod"
    for node, entries in files.items():
        d = base / "ftdc" / node
        d.mkdir(parents=True, exist_ok=True)
        for name, size in entries:
            (d / name).write_bytes(b"x" * size)
    for extra in ("baseline.jsonl", "findings.jsonl", "usage.jsonl"):
        (base / extra).write_text('{"kept": true}\n')
    (base / "state.json").write_text(json.dumps({
        "cluster_id": "prod", "files": {
            f"{node}/{name}": {"node": node, "name": name, "bytes": size,
                               "seen_at": "2026-08-01T00:00:00+00:00", "analyzed_at": None,
                               "stable": True}
            for node, entries in files.items() for name, size in entries
        },
    }))
    return base


def name_at(when: datetime) -> str:
    return "metrics." + when.strftime("%Y-%m-%dT%H-%M-%SZ") + "-00000"


OLD = name_at(NOW - timedelta(days=40))
MID = name_at(NOW - timedelta(days=20))
NEW = name_at(NOW - timedelta(days=1))


# ------------------------------------------------------------------- what must never go

def test_interim_is_never_pruned(tmp_path: Path):
    """It is the live buffer: deleting it throws away the most recent samples we hold."""
    base = make_cluster(tmp_path, {"n0": [(OLD, 100), ("metrics.interim", 50)]})
    doomed, _ = prunable(base / "ftdc", NOW - timedelta(days=30))
    assert all("interim" not in f.name for f in doomed)


def test_newest_file_of_a_node_is_never_pruned(tmp_path: Path):
    """Its NAME can be ancient while mongod is still appending to it.

    That gap between a file's name and its contents is what caused three separate capture
    bugs. Deleting the file mongod is actively writing would be the worst version of it.
    """
    base = make_cluster(tmp_path, {"n0": [(OLD, 100)]})
    doomed, spared = prunable(base / "ftdc", NOW)      # retention 0: everything is "old"
    assert doomed == [], "the only file of a node is the one it may still be writing"
    assert spared, "and sparing it should be reported, not silent"


def test_derived_files_survive(tmp_path: Path):
    """Baseline and findings cannot be recomputed once the raw data is gone.

    They are also ~1/420th of the size, so there is nothing to gain by touching them.
    """
    base = make_cluster(tmp_path, {"n0": [(OLD, 100), (NEW, 100)]})
    spec = {"cluster_id": "prod", "retention_days": 30}
    prune_cluster(spec, tmp_path, apply=True, verbose=False)
    for kept in ("baseline.jsonl", "findings.jsonl", "usage.jsonl"):
        assert (base / kept).exists(), f"{kept} must never be pruned"


def test_dry_run_deletes_nothing(tmp_path: Path):
    """The default path must be incapable of removing anything.

    This is the test that matters most: `--apply` is opt-in precisely so that a mistake in
    the caller costs nothing.
    """
    base = make_cluster(tmp_path, {"n0": [(OLD, 100), (MID, 100), (NEW, 100)]})
    before = {p.name for p in (base / "ftdc" / "n0").iterdir()}
    result = prune_cluster({"cluster_id": "prod", "retention_days": 30}, tmp_path, apply=False, verbose=False)
    after = {p.name for p in (base / "ftdc" / "n0").iterdir()}
    assert before == after, "a dry run must not touch the filesystem"
    assert result["files"] > 0, "but it must still report what it would have removed"
    assert result["applied"] is False


# ------------------------------------------------------------------------ what should go

def test_old_files_are_pruned_when_a_newer_one_exists(tmp_path: Path):
    base = make_cluster(tmp_path, {"n0": [(OLD, 100), (MID, 100), (NEW, 100)]})
    doomed, _ = prunable(base / "ftdc", NOW - timedelta(days=30))
    assert [f.name for f in doomed] == [OLD]


def test_state_entries_go_with_their_files(tmp_path: Path):
    """Otherwise state.json grows forever, and claims to hold files that are gone.

    A stale entry makes `is_new` answer False for a file we no longer have, so it would never
    be fetched again — a deletion turning into a permanent hole.
    """
    base = make_cluster(tmp_path, {"n0": [(OLD, 100), (NEW, 100)]})
    prune_cluster({"cluster_id": "prod", "retention_days": 30}, tmp_path, apply=True, verbose=False)
    state = json.loads((base / "state.json").read_text())
    assert f"n0/{OLD}" not in state["files"], "the deleted file must leave the state"
    assert f"n0/{NEW}" in state["files"], "the surviving one must stay"


def test_each_node_keeps_its_own_newest(tmp_path: Path):
    """Nodes rotate at different times; 'newest' is per node, not per cluster."""
    base = make_cluster(tmp_path, {"n0": [(OLD, 100), (NEW, 100)], "n1": [(OLD, 100)]})
    doomed, _ = prunable(base / "ftdc", NOW)
    names = {(f.parent.name, f.name) for f in doomed}
    assert ("n0", OLD) in names, "n0 has something newer, so its old file can go"
    assert ("n1", OLD) not in names, "n1 has nothing else — that file may still be open"
