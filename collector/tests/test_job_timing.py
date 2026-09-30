"""How long Atlas takes to build a bundle, measured and kept for the next run.

The only honest ground for an estimate of the wait is how long this same cluster took last time;
a job an earlier run ordered measures us, not the build, and must not be timed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sources  # noqa: E402
from capture import capture_cluster  # noqa: E402
from sources import AtlasSource  # noqa: E402
from state import State  # noqa: E402
from tests.test_capture import FakeResponse, _EmptyTar  # noqa: E402


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
