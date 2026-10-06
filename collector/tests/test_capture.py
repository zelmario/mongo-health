"""Capture: what gets stored, what gets skipped, and what gets said out loud.

Most of this runs against a real `DirectorySource` over real files in a temporary directory,
rather than against a mock. The dedup logic is the part worth protecting and it does not care
where the bytes came from, so exercising it through an actual source keeps the tests honest —
a mock would only prove that the mock behaves as written.

Only the Atlas HTTP calls are faked, because the alternative is a live account and a paid
cluster in the test suite.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sources  # noqa: E402
from capture import capture_cluster  # noqa: E402
from sources import AtlasSource, node_from_path  # noqa: E402
from state import State  # noqa: E402

NAME = "metrics.2026-08-07T01-15-12Z-00000"


def make_source_dir(tmp: Path, files: dict[str, list[tuple[str, int]]]) -> Path:
    """A directory shaped like an extracted Atlas bundle: <host>/27017/diagnostic.data/…"""
    root = tmp / "bundle"
    for node, entries in files.items():
        d = root / node / "27017" / "diagnostic.data"
        d.mkdir(parents=True, exist_ok=True)
        for name, size in entries:
            (d / name).write_bytes(b"x" * size)
    return root


def spec_for(path: Path) -> dict:
    return {"cluster_id": "prod", "notify": [],
            "source": {"type": "directory", "path": str(path)}}


# ------------------------------------------------------------------ which node a file is from

def test_node_from_atlas_layout():
    """`<host>/27017/diagnostic.data/…` — the port must not be mistaken for the node.

    Getting this wrong collapsed three nodes into one directory called "27017", which is how
    it was found the first time.
    """
    p = Path("/x/atlas-abc-shard-00-01.mongodb.net/27017/diagnostic.data/" + NAME)
    assert node_from_path(p, "fallback") == "atlas-abc-shard-00-01.mongodb.net"


def test_node_from_standalone_layout():
    """A plain mongod: the directory above diagnostic.data is the node."""
    p = Path("/var/lib/db1/diagnostic.data/" + NAME)
    assert node_from_path(p, "fallback") == "db1"


def test_node_falls_back_when_the_path_says_nothing():
    assert node_from_path(Path("/tmp/" + NAME), "fallback") == "fallback"


# --------------------------------------------------------------------------- storing files

def test_first_capture_stores_everything(tmp_path: Path):
    src = make_source_dir(tmp_path, {"n0": [(NAME, 1000), ("metrics.interim", 50)],
                                     "n1": [(NAME, 1000)]})
    result = capture_cluster(spec_for(src), tmp_path / "data", verbose=False)
    assert result["files_new"] == 3
    assert result["nodes"] == 2
    stored = sorted(p.name for p in (tmp_path / "data/prod/ftdc").rglob("metrics.*"))
    assert stored == [NAME, NAME, "metrics.interim"]


def test_second_capture_stores_nothing_new(tmp_path: Path):
    src = make_source_dir(tmp_path, {"n0": [(NAME, 1000)]})
    capture_cluster(spec_for(src), tmp_path / "data", verbose=False)
    again = capture_cluster(spec_for(src), tmp_path / "data", verbose=False)
    assert again["files_new"] == 0
    assert again["files_skipped"] == 1


def test_a_grown_file_is_stored_again(tmp_path: Path):
    """The whole capture bug, end to end: mongod keeps writing to the file it already gave us."""
    src = make_source_dir(tmp_path, {"n0": [(NAME, 1000)]})
    capture_cluster(spec_for(src), tmp_path / "data", verbose=False)

    (src / "n0/27017/diagnostic.data" / NAME).write_bytes(b"x" * 9000)
    again = capture_cluster(spec_for(src), tmp_path / "data", verbose=False)

    assert again["files_new"] == 1
    stored = tmp_path / "data/prod/ftdc/n0" / NAME
    assert stored.stat().st_size == 9000, "the stored copy must be the grown one"


def test_a_shrunken_interim_is_stored_again(tmp_path: Path):
    """It shrinks on every flush, and a grew-only test freezes it in the past."""
    src = make_source_dir(tmp_path, {"n0": [("metrics.interim", 6000)]})
    capture_cluster(spec_for(src), tmp_path / "data", verbose=False)
    (src / "n0/27017/diagnostic.data/metrics.interim").write_bytes(b"x" * 4000)
    again = capture_cluster(spec_for(src), tmp_path / "data", verbose=False)
    assert again["files_new"] == 1


def test_empty_source_is_reported(tmp_path: Path, capsys):
    """Returning nothing is not the same as returning nothing new.

    It means a wrong path, revoked credentials or a renamed cluster — and it looks exactly
    like a healthy quiet run unless somebody says so.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    capture_cluster(spec_for(empty), tmp_path / "data", verbose=False)
    assert "no files at all" in capsys.readouterr().err


def test_usage_is_recorded(tmp_path: Path):
    """Nobody is paying yet, but per-run cost cannot be reconstructed after the fact."""
    src = make_source_dir(tmp_path, {"n0": [(NAME, 1000)]})
    capture_cluster(spec_for(src), tmp_path / "data", verbose=False)
    rows = [json.loads(l) for l in
            (tmp_path / "data/prod/usage.jsonl").read_text().splitlines() if l]
    assert rows[0]["operation"] == "capture"
    assert rows[0]["bytes_new"] == 1000


def test_a_pruned_file_is_not_stored_again(tmp_path: Path):
    """dft: an upload directory still offered the files prune had deleted, so every round
    stored the same 22 files again, 228 MB, analysed them and pruned them once more."""
    from datetime import datetime, timedelta, timezone
    from prune import prune_cluster

    fresh = "metrics." + (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H-%M-%SZ") + "-00000"
    old = "metrics.2026-01-01T00-00-00Z-00000"
    src = make_source_dir(tmp_path, {"n0": [(old, 1000), (fresh, 1000)]})
    data = tmp_path / "data"
    spec = dict(spec_for(src), retention_days=30)

    capture_cluster(spec, data, verbose=False)
    prune_cluster(spec, data, apply=True, verbose=False)
    assert not (data / "prod/ftdc/n0" / old).exists()

    again = capture_cluster(spec, data, verbose=False)
    assert again["files_new"] == 0, "the source still offers it, and it must not come back"
    assert not (data / "prod/ftdc/n0" / old).exists()

    # Gone from the source too: nothing can bring it back, so the record goes.
    (src / "n0/27017/diagnostic.data" / old).unlink()
    capture_cluster(spec, data, verbose=False)
    assert State.load(data / "prod/state.json", "prod").pruned == {}


def test_state_survives_between_runs(tmp_path: Path):
    src = make_source_dir(tmp_path, {"n0": [(NAME, 1000)]})
    capture_cluster(spec_for(src), tmp_path / "data", verbose=False)
    state = State.load(tmp_path / "data/prod/state.json", "prod")
    assert state.last_capture is not None
    assert f"n0/{NAME}" in state.files


# --------------------------------------------------------------------- the Atlas date filter

class FakeResponse:
    def __init__(self, payload, headers=None):
        self.payload = payload
        self.headers = headers or {}

    def json(self):
        return self.payload

    def raise_for_status(self):
        pass


def test_atlas_job_asks_for_everything_when_there_is_no_anchor(monkeypatch):
    """No anchor means a new cluster: pull the whole retention window Atlas is holding.

    This is the onboarding bootstrap, and sending a date filter here would silently start the
    customer's history at today instead of ten days ago.
    """
    sent = {}

    def fake_post(url, **kwargs):
        sent.update(kwargs["json"])
        return FakeResponse({"id": "job1"})

    monkeypatch.setattr(sources.requests, "post", fake_post)
    AtlasSource("g", "rs", "pub", "priv")._create_job(None)

    assert "logCollectionFromDate" not in sent
    assert sent["logTypes"] == ["FTDC"]
    assert sent["resourceName"] == "rs"


def test_atlas_job_anchors_on_the_file_not_the_clock(monkeypatch):
    """Atlas filters on the timestamp in the file NAME.

    The caller passes the oldest file that might still be open, and the margin here only
    absorbs clock skew. A wall-clock offset would exclude the very file the new data is in.
    """
    sent = {}

    def fake_post(url, **kwargs):
        sent.update(kwargs["json"])
        return FakeResponse({"id": "job1"})

    monkeypatch.setattr(sources.requests, "post", fake_post)
    anchor = datetime(2026, 8, 7, 1, 15, 12, tzinfo=timezone.utc)
    AtlasSource("g", "rs", "pub", "priv")._create_job(anchor)

    sent_from = datetime.strptime(sent["logCollectionFromDate"], "%Y-%m-%dT%H:%M:%SZ")
    assert sent_from <= anchor.replace(tzinfo=None), "must not ask from later than the anchor"
    assert anchor.replace(tzinfo=None) - sent_from <= timedelta(minutes=10), "margin is small"


def test_atlas_end_date_is_in_the_past(monkeypatch):
    """Atlas rejects a job whose date range reaches into the future."""
    sent = {}

    def fake_post(url, **kwargs):
        sent.update(kwargs["json"])
        return FakeResponse({"id": "job1"})

    monkeypatch.setattr(sources.requests, "post", fake_post)
    AtlasSource("g", "rs", "pub", "priv")._create_job(
        datetime(2026, 8, 7, tzinfo=timezone.utc))

    to = datetime.strptime(sent["logCollectionToDate"], "%Y-%m-%dT%H:%M:%SZ")
    assert to < datetime.utcnow()


def test_atlas_reports_a_failed_job(monkeypatch):
    """A failed job must raise rather than return an empty capture that reads as 'nothing new'."""
    monkeypatch.setattr(sources.requests, "get",
                        lambda url, **kw: FakeResponse({"status": "FAILURE"}))
    with pytest.raises(RuntimeError, match="failed"):
        AtlasSource("g", "rs", "pub", "priv")._wait("job1")


# ------------------------------------------------ a job that outlives the run that ordered it

def test_a_first_capture_waits_longer_than_a_routine_one(monkeypatch):
    """The two requests are not the same size, so they do not get the same deadline.

    A first capture asks for everything Atlas holds -- days, across every member. Measured on a
    real M10 that crossed five minutes and returned 366 MB, while a routine run of the same
    cluster takes seconds.
    """
    waited = []
    monkeypatch.setattr(sources.requests, "post",
                        lambda url, **kw: FakeResponse({"id": "job1"}))
    monkeypatch.setattr(AtlasSource, "_wait",
                        lambda self, job_id, timeout=None: waited.append(timeout))
    monkeypatch.setattr(AtlasSource, "_download",
                        lambda self, job_id, target: target.write_bytes(b""))
    monkeypatch.setattr(sources.tarfile, "open", lambda *a, **kw: _EmptyTar())

    source = AtlasSource("g", "rs", "pub", "priv")
    list(source.fetch(None))                       # bootstrap
    list(source.fetch(datetime(2026, 8, 7, tzinfo=timezone.utc)))   # routine

    assert waited == [AtlasSource.BOOTSTRAP_TIMEOUT, AtlasSource.JOB_TIMEOUT]


class _EmptyTar:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    # Python 3.11.2, which the image runs, has no tarfile data filter, so `extract` lists the
    # members itself. Without this the five tests that use it failed in the image and passed
    # only on a newer Python.
    def getmembers(self):
        return []

    def extractall(self, *a, **kw):
        pass


def test_a_job_that_outran_the_deadline_is_remembered(monkeypatch, tmp_path):
    """Atlas finishes the job whether we waited or not, and keeps it downloadable for a month.

    Forgetting the id means the next run orders the same bundle again and pays the same wait --
    which is how a first capture of a busy cluster can never finish.
    """
    monkeypatch.setattr(sources.requests, "post",
                        lambda url, **kw: FakeResponse({"id": "job7"}))
    monkeypatch.setattr(sources.requests, "get",
                        lambda url, **kw: FakeResponse({"status": "IN_PROGRESS"}))
    # The real deadline is half an hour, and the point being tested is what happens after it,
    # not how long it is.
    monkeypatch.setattr(AtlasSource, "BOOTSTRAP_TIMEOUT", 0)
    monkeypatch.setattr(sources.time, "sleep", lambda s: None)

    spec = {"cluster_id": "c0",
            "source": {"type": "atlas", "group_id": "g", "replica_set": "rs",
                       "public_key": "p", "private_key": "k"}}
    with pytest.raises(TimeoutError):
        capture_cluster(spec, tmp_path, verbose=False)

    state = State.load(tmp_path / "c0" / "state.json", "c0")
    # A first capture orders a window of the history (AtlasSource.history), so that is what
    # is remembered.
    assert state.pending_window[2] == "job7"
    assert state.last_capture is None, "a run that collected nothing did not capture"


def test_the_next_run_collects_the_pending_job_instead_of_ordering_another(monkeypatch,
                                                                          tmp_path):
    ordered = []
    monkeypatch.setattr(sources.requests, "post",
                        lambda url, **kw: ordered.append(1) or FakeResponse({"id": "new"}))
    monkeypatch.setattr(sources.requests, "get",
                        lambda url, **kw: FakeResponse({"status": "SUCCESS"}))

    collected = []
    monkeypatch.setattr(AtlasSource, "_download",
                        lambda self, job_id, target: collected.append(job_id))
    monkeypatch.setattr(sources.tarfile, "open", lambda *a, **kw: _EmptyTar())

    base = tmp_path / "c0"
    base.mkdir(parents=True)
    # An hourly run, on a cluster whose history is in: `pending_job` is the hourly bundle.
    state = State(cluster_id="c0", pending_job="job7", history_done=True)
    state.record("n0", "metrics.2026-08-07T01-15-12Z-00000", 100)
    state.save(base / "state.json")

    spec = {"cluster_id": "c0",
            "source": {"type": "atlas", "group_id": "g", "replica_set": "rs",
                       "public_key": "p", "private_key": "k"}}
    capture_cluster(spec, tmp_path, verbose=False)

    assert collected == ["job7"], "the bundle already built is the one to download"
    assert ordered == [], "ordering a second one pays the slow part twice"
    reloaded = State.load(base / "state.json", "c0")
    assert reloaded.pending_job is None, "collected: nothing left pending"


def test_a_pending_job_that_died_does_not_wedge_the_cluster(monkeypatch, tmp_path):
    """An expired or deleted job must be replaced, not retried for ever."""
    monkeypatch.setattr(sources.requests, "post",
                        lambda url, **kw: FakeResponse({"id": "fresh"}))

    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        # The dead one first, then the replacement.
        return FakeResponse({"status": "FAILURE" if "job7" in url else "SUCCESS"})

    monkeypatch.setattr(sources.requests, "get", fake_get)
    collected = []
    monkeypatch.setattr(AtlasSource, "_download",
                        lambda self, job_id, target: collected.append(job_id))
    monkeypatch.setattr(sources.tarfile, "open", lambda *a, **kw: _EmptyTar())

    source = AtlasSource("g", "rs", "pub", "priv", pending_job="job7")
    list(source.fetch(None))

    assert collected == ["fresh"]
    assert source.pending_job is None


# ------------------------------------------------------- the API this all depends on

def test_a_retirement_announcement_is_said_out_loud(monkeypatch, capsys):
    """`logCollectionJobs` exists only in the v1.0 API — verified against the v2 spec, where
    "logCollection" appears in none of its 335 routes and the only log endpoint downloads text
    logs, not FTDC.

    So the day Atlas retires v1.0, collection stops for every Atlas customer at once, and the
    usual fallback is not one: polling `getDiagnosticData` needs a database user, which is the
    thing `docs/api-key.md` promises we never ask for. Nothing here can prevent that. What it
    can do is make sure we read the announcement instead of discovering the outage.
    """
    monkeypatch.setattr(sources.requests, "post",
                        lambda url, **kw: FakeResponse(
                            {"id": "job1"},
                            headers={"sunset": "Wed, 01 Jul 2026 00:00:00 GMT",
                                     "link": "<https://mongodb.com/notice>; rel=\"deprecation\""}))
    source = AtlasSource("g", "rs", "pub", "priv")
    source._create_job(None)

    warned = capsys.readouterr().err
    assert "RETIREMENT ANNOUNCED" in warned
    assert "Wed, 01 Jul 2026" in warned
    assert "no equivalent in v2" in warned


def test_a_normal_reply_says_nothing(monkeypatch, capsys):
    """The quiet path is the one that runs every hour for years; it must stay silent."""
    monkeypatch.setattr(sources.requests, "post",
                        lambda url, **kw: FakeResponse({"id": "job1"}))
    AtlasSource("g", "rs", "pub", "priv")._create_job(None)

    assert capsys.readouterr().err == ""


def test_uploaded_files_alone_are_not_on_the_watchdog_roster(tmp_path: Path):
    """Nothing sends more after an upload, so its age must never read as a stopped capture."""
    import capture
    capture.write_roster(tmp_path, [
        {"cluster_id": "uploaded", "source": {"type": "onprem"}},
        {"cluster_id": "connected", "source": {"type": "onprem", "uri": "mongodb://h/"}},
        {"cluster_id": "atlas", "source": {"type": "atlas"}},
    ])
    listed = {c["cluster_id"] for c in json.loads((tmp_path / "roster.json").read_text())["clusters"]}
    assert listed == {"connected", "atlas"}


def test_a_fetch_says_what_it_is_doing_and_clears_it_even_when_it_fails(monkeypatch, tmp_path):
    """The page reads capturing.json to say "Collecting the FTDC" instead of "Not being
    watched". Left behind by a failed fetch, it would say collecting for two hours."""
    seen = {}

    class Failing:
        pending_job = None
        job_seconds = None

        def __init__(self, on_progress):
            self.on_progress = on_progress

        def describe(self):
            return "atlas:g/rs"

        def fetch(self, since):
            self.on_progress("build", done=0, total=0, note="42")
            seen.update(json.loads((tmp_path / "c0" / "capturing.json").read_text()))
            raise RuntimeError("job failed")
            yield  # pragma: no cover

    monkeypatch.setattr(sources, "build", lambda spec, on_progress=None, **kw: Failing(on_progress))
    spec = {"cluster_id": "c0", "source": {"type": "atlas", "group_id": "g", "replica_set": "rs",
                                           "public_key": "p", "private_key": "k"}}
    with pytest.raises(RuntimeError):
        capture_cluster(spec, tmp_path, verbose=False)

    assert seen["stage"] == "build" and seen["elapsed"] == 42
    assert not (tmp_path / "c0" / "capturing.json").exists()


# ------------------------------------------------- the first capture, window by window

def _bundle(path: Path, names: list[str], size: int = 1000) -> None:
    import io
    import tarfile as tf
    with tf.open(path, "w:gz") as t:
        for name in names:
            data = b"x" * size
            info = tf.TarInfo(f"bundle/host-00-00.example.net/27017/diagnostic.data/{name}")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


def _history_source(monkeypatch, oldest: datetime, cut_above: timedelta | None = None):
    """An AtlasSource whose jobs return one file per day in the window, back to `oldest`."""
    ordered = []
    source = AtlasSource("g", "rs", "pub", "priv")

    def create(since, window=None):
        assert window is not None, "a first capture must never order the whole history"
        ordered.append(window)
        return f"job{len(ordered)}"

    def download(job_id, target):
        start, end = ordered[int(job_id[3:]) - 1]
        if cut_above is not None and end - start > cut_above:
            raise sources.requests.exceptions.ChunkedEncodingError("Response ended prematurely")
        days = []
        d = end
        while d > start and d > oldest:
            days.append(d.strftime("metrics.%Y-%m-%dT%H-%M-%SZ-00000"))
            d -= timedelta(days=1)
        _bundle(target, days)

    monkeypatch.setattr(source, "_create_job", create)
    monkeypatch.setattr(source, "_wait", lambda *a, **kw: None)
    monkeypatch.setattr(source, "_download", download)
    return source, ordered


def test_the_history_comes_newest_first_and_stops_at_an_empty_window(monkeypatch):
    """Atlas cuts every download at about two minutes, so a first bundle of 1.24 GB never
    arrived. The history is asked for in windows instead, until one comes back empty."""
    now_ = datetime.now(timezone.utc)
    source, ordered = _history_source(monkeypatch, oldest=now_ - timedelta(days=9))
    names = [f.name for f in source.history(None)]

    assert len(names) >= 8
    assert all(later[1] == earlier[0] for earlier, later in zip(ordered, ordered[1:])), \
        "each window ends where the one after it starts: no gap, newest first"
    assert ordered[0][1] - ordered[0][0] == AtlasSource.HISTORY_FIRST_WINDOW
    assert source.history_done


def test_a_window_too_big_to_arrive_is_asked_for_again_with_half_the_days(monkeypatch):
    now_ = datetime.now(timezone.utc)
    source, ordered = _history_source(monkeypatch, oldest=now_ - timedelta(days=3),
                                      cut_above=timedelta(days=1))
    list(source.history(None))

    assert ordered[0][1] - ordered[0][0] == timedelta(days=2)
    assert ordered[1][1] == ordered[0][1], "the same end, retried"
    assert ordered[1][1] - ordered[1][0] == timedelta(days=1)
    assert source.history_done


def test_a_first_capture_keeps_its_place_in_the_history(monkeypatch, tmp_path):
    """Stopped halfway, the next run goes on from the oldest window collected."""
    now_ = datetime.now(timezone.utc)
    source, ordered = _history_source(monkeypatch, oldest=now_ - timedelta(days=30))
    calls = {"n": 0}
    real = source._wait

    def wait(job_id, *a, **kw):
        calls["n"] += 1
        if calls["n"] == 3:
            raise TimeoutError("still building")
        return real(job_id, *a, **kw)

    monkeypatch.setattr(source, "_wait", wait)
    monkeypatch.setattr(sources, "build", lambda spec, **kw: source)
    spec = {"cluster_id": "c0", "source": {"type": "atlas", "group_id": "g", "replica_set": "rs",
                                           "public_key": "p", "private_key": "k"}}
    with pytest.raises(TimeoutError):
        capture_cluster(spec, tmp_path, verbose=False)

    saved = json.loads((tmp_path / "c0" / "state.json").read_text())
    assert saved["files"], "the windows collected before the stop are kept"
    assert saved["last_capture"], "and counted as captured: the page said the capture failed"
    assert saved["history_done"] is False
    assert saved["history_before"] == ordered[1][0].isoformat()
    assert saved["pending_window"][2] == "job3", "the window ordered is collected next time"


def test_a_bundle_cut_on_every_attempt_is_not_collected_again(monkeypatch):
    """Too big to arrive before Atlas ends the download, it was retried every hour for ever."""
    monkeypatch.setattr(sources.requests, "get",
                        lambda url, **kw: FakeResponse({"status": "SUCCESS"}))

    def cut(self, job_id, target):
        raise sources.requests.exceptions.ChunkedEncodingError("Response ended prematurely")

    monkeypatch.setattr(AtlasSource, "_download", cut)
    source = AtlasSource("g", "rs", "pub", "priv", pending_job="huge")
    with pytest.raises(sources.requests.exceptions.ChunkedEncodingError):
        list(source.fetch(datetime(2026, 10, 2, 6, tzinfo=timezone.utc)))
    assert source.pending_job is None
