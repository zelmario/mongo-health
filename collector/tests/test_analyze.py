"""Analysis: what becomes a finding, what gets said twice, and what the customer is told.

The engine itself lives in Big Hole and is tested there, so it is stubbed here. What these
tests protect is the layer around it — identity, deduplication and the two numbers the report
puts in front of the customer.

Deduplication is the one worth the most care. A finding reported twice is not a cosmetic
problem: it is a second email about something the reader already dealt with, and that is the
failure that gets a monitoring service muted.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analyze  # noqa: E402
from analyze import analyze_cluster, days_observed, days_of_raw_ftdc, finding_id  # noqa: E402

T0 = 1_754_000_000_000
HOUR = 3_600_000


def node_payload(name="n0", series=None, recent=None, percentiles=None, gaps=()) -> dict:
    return {
        "node": name, "hostname": f"{name}.mongodb.net", "version": "8.0.29",
        "fromMs": T0, "toMs": T0 + 24 * HOUR, "samples": 86_400, "cadenceMs": 1000,
        "gaps": list(gaps),
        "percentiles": percentiles or [
            {"metric": "m1", "n": 100, "min": 0, "p50": 1, "p95": 2, "p99": 3, "max": 4, "mean": 1}],
        "recent": recent or [],
        "recentFromMs": T0 + 20 * HOUR, "recentToMs": T0 + 24 * HOUR,
        "series": series or {},
    }


def engine_output(findings=(), nodes=None, unresolved=()) -> dict:
    return {
        "nodes": nodes or [node_payload()],
        "findings": list(findings),
        "findingsSkippedAsOld": 0,
        "rulesUnresolved": list(unresolved),
        "rulesEvaluated": 14,
    }


def a_finding(rule="read-tickets-saturated", node="n0.mongodb.net", worst=T0) -> dict:
    return {"rule": rule, "title": "Read ticket pool saturated", "severity": "critical",
            "node": node, "metric": "pct(a,b)", "episodes": 1,
            "fromMs": worst, "toMs": worst + HOUR, "worstFromMs": worst,
            "worstToMs": worst + HOUR, "secondsInState": 600, "peak": 100,
            "unit": "percent", "what": "…", "check": "…", "chart": None}


def setup(tmp_path: Path) -> dict:
    """A cluster with one captured file, recorded in state as awaiting analysis.

    Registering it matters: `analyze_cluster` skips a cluster with nothing pending, which is
    correct behaviour and would otherwise make these tests pass by doing nothing at all.
    """
    from state import State

    base = tmp_path / "data/prod"
    (base / "ftdc/n0").mkdir(parents=True)
    name = "metrics.2026-08-07T01-00-00Z-00000"
    (base / "ftdc/n0" / name).write_bytes(b"x")

    state = State(cluster_id="prod")
    state.record("n0", name, 1)
    state.last_capture = "2026-08-07T02:00:00+00:00"
    state.save(base / "state.json")

    return {"cluster_id": "prod", "notify": [], "source": {}}


def stub_engine(monkeypatch, output: dict) -> None:
    monkeypatch.setattr(analyze, "run_engine", lambda ftdc, since, **kw: output)


# ------------------------------------------------------------------------------- identity

def test_same_episode_keeps_the_same_id():
    """The id must not move when an ongoing episode grows.

    An episode that is still happening reports a longer duration on every run. If duration
    were part of the identity, each run would look like a new finding and send another email
    about the same incident.
    """
    f = a_finding()
    first = finding_id("prod", f)
    f["secondsInState"] = 9999
    f["toMs"] = f["toMs"] + 10 * HOUR
    assert finding_id("prod", f) == first


def test_a_later_episode_gets_a_different_id():
    assert finding_id("prod", a_finding(worst=T0)) != \
           finding_id("prod", a_finding(worst=T0 + 50 * HOUR))


def test_the_same_episode_on_two_nodes_has_two_ids():
    """Grouping happens at notification time; here they are still distinct observations."""
    assert finding_id("prod", a_finding(node="n0")) != \
           finding_id("prod", a_finding(node="n1"))


def test_clusters_never_collide():
    assert finding_id("prod", a_finding()) != finding_id("staging", a_finding())


def test_excursions_are_identified_by_day():
    """A level change persists, and would otherwise be re-reported on every run for days.

    Load a cluster and the cache stays full afterwards: genuinely above its old ceiling, and
    genuinely not worth saying four times a day.
    """
    e = {"rule": "baseline-excursion", "node": "n0", "metric": "cache",
         "worstFromMs": T0, "detected_day": "2026-08-09"}
    same_day = dict(e, worstFromMs=T0 + 5 * HOUR)          # different window, same day
    next_day = dict(e, detected_day="2026-08-10")
    assert finding_id("p", e) == finding_id("p", same_day)
    assert finding_id("p", e) != finding_id("p", next_day)


# -------------------------------------------------------------------------- deduplication

def test_a_reported_finding_is_not_reported_again(tmp_path: Path, monkeypatch):
    spec = setup(tmp_path)
    stub_engine(monkeypatch, engine_output(findings=[a_finding()]))

    first = analyze_cluster(spec, tmp_path / "data", verbose=False)
    assert first["findings_new"] == 1

    second = analyze_cluster(spec, tmp_path / "data", redo=True, verbose=False)
    assert second["findings_new"] == 0, "the same episode must not be reported twice"

    rows = [json.loads(l) for l in
            (tmp_path / "data/prod/findings.jsonl").read_text().splitlines() if l]
    assert len(rows) == 1, "and it must not be written twice either"


def test_a_new_episode_is_reported(tmp_path: Path, monkeypatch):
    spec = setup(tmp_path)
    stub_engine(monkeypatch, engine_output(findings=[a_finding()]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)

    stub_engine(monkeypatch, engine_output(findings=[a_finding(worst=T0 + 100 * HOUR)]))
    again = analyze_cluster(spec, tmp_path / "data", redo=True, verbose=False)
    assert again["findings_new"] == 1


# ------------------------------------------------------------------------------- baseline

def test_baseline_keeps_both_scopes_apart(tmp_path: Path, monkeypatch):
    """`baseline` is what normal is built from; `window` is what gets judged against it.

    Mixing them would fold every excursion into the ceiling meant to detect it.
    """
    spec = setup(tmp_path)
    recent = [{"metric": "m1", "n": 10, "min": 0, "p50": 9, "p95": 9, "p99": 9,
               "max": 9, "mean": 9}]
    stub_engine(monkeypatch, engine_output(nodes=[node_payload(recent=recent)]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)

    rows = [json.loads(l) for l in
            (tmp_path / "data/prod/baseline.jsonl").read_text().splitlines() if l]
    scopes = {r["scope"] for r in rows}
    assert scopes == {"baseline", "window"}


def test_series_are_written_for_the_report(tmp_path: Path, monkeypatch):
    spec = setup(tmp_path)
    stub_engine(monkeypatch, engine_output(
        nodes=[node_payload(series={"m1": {"t": [T0], "v": [1.0]}})]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)
    assert (tmp_path / "data/prod/series.json").exists()


# ------------------------------------------------------- the two numbers shown to the customer

def test_raw_ftdc_window_comes_from_the_capture():
    assert days_of_raw_ftdc([{"fromMs": T0, "toMs": T0 + 48 * HOUR}]) == 2.0
    assert days_of_raw_ftdc([]) == 0.0


def test_observed_history_comes_from_the_baseline(tmp_path: Path):
    """It must NOT shrink when old FTDC is pruned.

    "We have watched this cluster for fourteen months" and "you can still open the last
    twelve" are different claims, and only the second one is affected by retention.
    """
    path = tmp_path / "baseline.jsonl"
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    path.write_text("\n".join(
        json.dumps({"run": (start + timedelta(days=d)).isoformat(), "scope": "baseline"})
        for d in (0, 10, 100)))
    assert days_observed(path) == 100.0


def test_observed_history_needs_two_runs(tmp_path: Path):
    """One run spans no time, and claiming otherwise would overstate the service on day one."""
    path = tmp_path / "baseline.jsonl"
    path.write_text(json.dumps({"run": "2026-01-01T00:00:00+00:00", "scope": "baseline"}))
    assert days_observed(path) == 0.0
    assert days_observed(tmp_path / "missing.jsonl") == 0.0


# ---------------------------------------------------------------------------- the summary

def test_unresolved_rules_reach_the_summary(tmp_path: Path, monkeypatch):
    """A rule that cannot resolve looks exactly like a rule that found nothing.

    This project has been bitten by that repeatedly, so the number has to travel all the way
    to the customer's page rather than dying in a log.
    """
    spec = setup(tmp_path)
    stub_engine(monkeypatch, engine_output(
        unresolved=[{"id": "flow-control-engaged", "metric": "scale(rate(x), 0.1)"}]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)

    summary = json.loads((tmp_path / "data/prod/summary.json").read_text())
    assert len(summary["rules_unresolved"]) == 1
    assert summary["rules_evaluated"] == 14


def test_analysed_files_are_not_reanalysed(tmp_path: Path, monkeypatch):
    spec = setup(tmp_path)
    stub_engine(monkeypatch, engine_output())
    analyze_cluster(spec, tmp_path / "data", verbose=False)
    second = analyze_cluster(spec, tmp_path / "data", verbose=False)
    assert second.get("skipped") is True


def test_missing_capture_is_an_error_not_a_silent_pass(tmp_path: Path, monkeypatch):
    """Analysing a cluster with no captures must fail loudly.

    Returning quietly would present "no findings" for a cluster nobody ever collected.
    """
    stub_engine(monkeypatch, engine_output())
    import pytest
    with pytest.raises(FileNotFoundError):
        analyze_cluster({"cluster_id": "y"}, tmp_path / "data",
                        verbose=False)


def test_two_settings_changing_together_are_two_findings():
    """A tier change moves memory and cache in the same instant on the same node.

    One rule id covers five different settings, so keyed only by rule, node and minute those
    two changes share an identity — and publishing them upserted one over the other. Found in
    real data, where "the host was resized" silently replaced "the cache was resized" on all
    three members and the report lost half of what changed.
    """
    memoria = a_finding(worst=T0)
    memoria.update(rule="setting-changed", metric="systemMetrics.memory.MemTotal_kb")
    cache = a_finding(worst=T0)
    cache.update(rule="setting-changed",
                 metric="serverStatus.wiredTiger.cache.maximum bytes configured")

    assert finding_id("prod", memoria) != finding_id("prod", cache)


def test_the_same_setting_changing_twice_a_minute_apart_stays_one_finding():
    """The minute bucket still applies: two runs judging the same step must not report twice."""
    uno = a_finding(worst=T0)
    uno.update(rule="setting-changed", metric="systemMetrics.memory.MemTotal_kb")
    otro = dict(uno)
    otro["worstFromMs"] = T0 + 5_000

    assert finding_id("prod", uno) == finding_id("prod", otro)


# ------------------------------------------------------------------ daily summaries, runner

def test_the_engine_is_given_the_daily_directory(tmp_path: Path, monkeypatch):
    """Without it every run decodes everything held, and the cost grows with the retention."""
    spec = setup(tmp_path)
    seen = {}

    def engine(ftdc, since, **kw):
        seen.update(kw)
        return engine_output()

    monkeypatch.setattr(analyze, "run_engine", engine)
    analyze_cluster(spec, tmp_path / "data", verbose=False)
    assert seen["daily"] == tmp_path / "data/prod/daily"


def test_the_status_page_counts_gaps_over_everything_held(tmp_path: Path, monkeypatch):
    """`gaps` only covers the two days a run decodes; the page promises the whole history."""
    spec = setup(tmp_path)
    recent = [{"fromMs": T0, "toMs": T0 + 60_000, "seconds": 60, "missingSamples": 60}]
    node = dict(node_payload(gaps=recent), gapsHeld={"count": 7, "seconds": 4200})
    stub_engine(monkeypatch, engine_output(nodes=[node]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)
    summary = json.loads((tmp_path / "data/prod/summary.json").read_text())
    assert summary["nodes"][0]["gaps"] == 7
    assert summary["nodes"][0]["seconds_without_data"] == 4200


def test_the_versioned_runner_is_what_runs(tmp_path: Path, monkeypatch):
    """The copy in Big Hole's tools/ drifted a month from the versioned one once. Never again."""
    runner = tmp_path / "runner.ts"
    runner.write_text("// versioned\n")
    monkeypatch.setattr(analyze, "RUNNER", runner)
    repo = tmp_path / "big-hole"
    (repo / "tools").mkdir(parents=True)

    script = analyze.sync_runner(repo)
    assert script.read_text() == "// versioned\n"

    script.write_text("// edited by hand in tools/\n")
    analyze.sync_runner(repo)
    assert script.read_text() == "// versioned\n", "an edit in tools/ must not survive"


def test_a_missing_runner_is_named(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(analyze, "RUNNER", tmp_path / "nowhere.ts")
    (tmp_path / "big-hole/tools").mkdir(parents=True)
    try:
        analyze.sync_runner(tmp_path / "big-hole")
    except FileNotFoundError as e:
        assert "nowhere.ts" in str(e)
    else:
        raise AssertionError("expected FileNotFoundError")


# ------------------------------------------------------------------- redrawn by a re-analysis

def test_a_reanalysis_redraws_the_charts_of_findings_it_already_holds(tmp_path, monkeypatch):
    """Otherwise an improvement to the charts reached only incidents found after it."""
    spec = setup(tmp_path)
    old = dict(a_finding(), chart={"t": [1], "v": [5.0]})
    stub_engine(monkeypatch, engine_output(findings=[old]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)
    path = tmp_path / "data/prod/findings.jsonl"
    first = json.loads(path.read_text().splitlines()[0])
    rows = [dict(first, notified_at="2026-08-07T03:00:00+00:00")]
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))

    new = dict(a_finding(), chart={"t": [1], "v": [5.0], "series": [{"lo": [0.0]}]})
    stub_engine(monkeypatch, engine_output(findings=[new]))
    analyze_cluster(spec, tmp_path / "data", redo=True, verbose=False)
    held = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(held) == 1, "the same incident, not a second one"
    assert held[0]["chart"]["series"][0]["lo"] == [0.0]
    assert held[0]["notified_at"] == "2026-08-07T03:00:00+00:00", "and never sent again"
    assert held[0]["detected_at"] == first["detected_at"]


def test_a_reanalysis_rewords_the_findings_it_already_holds(tmp_path, monkeypatch):
    spec = setup(tmp_path)
    stub_engine(monkeypatch, engine_output(findings=[dict(a_finding(), what="0.1 to 0.1 minutes")]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)
    stub_engine(monkeypatch, engine_output(findings=[dict(a_finding(), what="7 seconds")]))
    analyze_cluster(spec, tmp_path / "data", redo=True, verbose=False)
    held = [json.loads(line) for line in (tmp_path / "data/prod/findings.jsonl").read_text().splitlines()]
    assert [h["what"] for h in held] == ["7 seconds"]


def test_a_routine_run_leaves_held_charts_alone(tmp_path, monkeypatch):
    spec = setup(tmp_path)
    stub_engine(monkeypatch, engine_output(findings=[dict(a_finding(), chart={"v": [1.0]})]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)
    from state import State
    state = State.load(tmp_path / "data/prod/state.json", "prod")
    state.record("n0", "metrics.2026-08-07T02-00-00Z-00000", 1)
    state.save(tmp_path / "data/prod/state.json")
    (tmp_path / "data/prod/ftdc/n0/metrics.2026-08-07T02-00-00Z-00000").write_bytes(b"x")
    stub_engine(monkeypatch, engine_output(findings=[dict(a_finding(), chart={"v": [2.0]})]))
    analyze_cluster(spec, tmp_path / "data", verbose=False)
    held = [json.loads(line) for line in (tmp_path / "data/prod/findings.jsonl").read_text().splitlines()]
    assert held[0]["chart"] == {"v": [1.0]}


def test_files_older_than_the_last_analysis_are_read_from_the_start():
    """A first Atlas capture comes newest first. The older days arrived after the first
    analysis, and the next one, reading from a day before it, judged 43 hours of 20 days."""
    from state import SeenFile
    late = SeenFile("n0", "metrics.2026-09-12T18-14-46Z-00000", 10, "2026-10-02T19:00:00+00:00")
    recent = SeenFile("n0", "metrics.2026-10-02T06-00-00Z-00000", 10, "2026-10-02T19:00:00+00:00")
    assert analyze.backfilled([late, recent], "2026-10-02T18:40:00+00:00")
    assert not analyze.backfilled([recent], "2026-10-02T18:40:00+00:00")


def test_an_analysis_run_by_hand_waits_for_the_round(tmp_path, monkeypatch):
    """A --redo started between two rounds overwrote the state a round saved in the middle."""
    import fcntl
    lock = tmp_path / ".run.lock"
    monkeypatch.setenv("LOCK", str(lock))
    monkeypatch.delenv("ROUND_LOCK_HELD", raising=False)
    with open(lock, "a") as round_holds:
        fcntl.flock(round_holds, fcntl.LOCK_EX)
        with open(lock, "a") as probe:
            # While the round holds it, the analysis could not have it either.
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                got = True
            except BlockingIOError:
                got = False
        assert not got
    with analyze.round_lock():
        with open(lock, "a") as probe:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                free = True
            except BlockingIOError:
                free = False
    assert not free, "held for the whole analysis"


def test_inside_a_round_the_analysis_does_not_wait_for_its_own_parent(monkeypatch):
    monkeypatch.setenv("ROUND_LOCK_HELD", "1")
    with analyze.round_lock():
        pass
