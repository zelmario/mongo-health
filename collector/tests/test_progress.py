"""The progress a running capture reports, and what the numbers are allowed to claim.

The point of these is not that a bar moves. It is that every number it shows came from
something counted -- bytes against a Content-Length, files against a listing -- and that the
one phase which cannot be counted says so instead of inventing a percentage.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import progress  # noqa: E402
import sources  # noqa: E402
from capture import capture_cluster  # noqa: E402
from sources import AtlasSource  # noqa: E402
from state import State  # noqa: E402
from tests.test_capture import FakeResponse, _EmptyTar, make_source_dir  # noqa: E402


def test_the_phases_move_forward_and_never_go_backwards():
    """A bar that goes back has said something false in one of the two directions."""
    seen = [p.start for p in progress.PHASES]
    assert seen == sorted(seen)
    assert progress.PHASES[-1].end == 100


def test_a_fraction_of_a_known_total_is_where_the_number_comes_from(tmp_path):
    progress.report(tmp_path, "download", done=183_000_000, total=366_000_000)
    state = progress.read(tmp_path)

    download = progress.BY_KEY["download"]
    assert state["percent"] == round(download.start + (download.end - download.start) * 0.5)
    assert state["certain"] is True


def test_a_phase_with_nothing_to_count_stays_at_its_start(tmp_path):
    """Atlas reports a status, never a percentage. Nothing to count means nothing to claim."""
    progress.report(tmp_path, "build", note="42", certain=False)
    state = progress.read(tmp_path)

    assert state["percent"] == progress.BY_KEY["build"].start
    assert state["certain"] is False


def test_the_wait_for_atlas_is_reported_against_the_last_measured_one(monkeypatch):
    """The only ground for a fraction there is how long this same cluster took last time."""
    reported = []
    monkeypatch.setattr(sources.requests, "get",
                        lambda url, **kw: FakeResponse({"status": "IN_PROGRESS"}))
    monkeypatch.setattr(sources.time, "sleep", lambda s: None)

    source = AtlasSource("g", "rs", "pub", "priv", job_timeout=1, job_estimate=100,
                         on_progress=lambda phase, **kw: reported.append((phase, kw)))
    with pytest.raises(TimeoutError):
        source._wait("job1", timeout=0.001)

    phase, kw = reported[0]
    assert phase == "build"
    assert kw["certain"] is False, "an estimate must not be dressed up as a measurement"
    assert 0 <= kw["done"] <= 0.95, "and it never reaches the end while still waiting"


def test_a_resumed_job_is_not_timed(monkeypatch):
    """It was ordered by an earlier run, so the wait here measures us, not the build.

    Recording it would teach the next run that a first capture takes two seconds, and every
    bar after that would sit at 95% for five minutes.
    """
    monkeypatch.setattr(sources.requests, "get",
                        lambda url, **kw: FakeResponse({"status": "SUCCESS"}))
    monkeypatch.setattr(AtlasSource, "_download", lambda self, job_id, target: None)
    monkeypatch.setattr(sources.tarfile, "open", lambda *a, **kw: _EmptyTar())

    source = AtlasSource("g", "rs", "pub", "priv", pending_job="job7")
    list(source.fetch(None))
    assert source.job_seconds is None

    fresh = AtlasSource("g", "rs", "pub", "priv")
    monkeypatch.setattr(sources.requests, "post",
                        lambda url, **kw: FakeResponse({"id": "job9"}))
    list(fresh.fetch(None))
    assert fresh.job_seconds is not None, "a job we ordered is the one worth timing"


def test_a_capture_reports_what_it_is_storing(tmp_path):
    """Works for any source, not only Atlas: the count is of files, which they all yield."""
    root = make_source_dir(tmp_path, {"n1": [("metrics.2026-08-07T01-15-12Z-00000", 1024)]})
    spec = {"cluster_id": "c0",
            "source": {"type": "directory", "path": str(root)}}
    capture_cluster(spec, tmp_path / "data", verbose=False)

    state = progress.read(tmp_path / "data" / "c0")
    assert state["phase"] == "store"
    assert state["done"] == 1


def test_the_measured_job_time_is_kept_for_the_next_run(monkeypatch, tmp_path):
    monkeypatch.setattr(sources.requests, "post",
                        lambda url, **kw: FakeResponse({"id": "job1"}))
    monkeypatch.setattr(sources.requests, "get",
                        lambda url, **kw: FakeResponse({"status": "SUCCESS"}))
    monkeypatch.setattr(AtlasSource, "_download", lambda self, job_id, target: None)
    monkeypatch.setattr(sources.tarfile, "open", lambda *a, **kw: _EmptyTar())

    spec = {"cluster_id": "c0",
            "source": {"type": "atlas", "group_id": "g", "replica_set": "rs",
                       "public_key": "p", "private_key": "k"}}
    capture_cluster(spec, tmp_path, verbose=False)

    state = State.load(tmp_path / "c0" / "state.json", "c0")
    assert state.last_job_seconds is not None
