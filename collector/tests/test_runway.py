"""What runs out, and when.

The risk with a prediction is not missing one -- it is announcing a date that never arrives. A
detector that cries "full in ten days" every week on a cluster that is fine gets muted, and then
it is not predicting anything. So most of this tests the ways a projection could be manufactured:
from a step, from a constant, from a handful of hours, from one member on its own.
"""
from __future__ import annotations

import json
from pathlib import Path

import runway

DAY = 86_400.0
CACHE = "serverStatus.wiredTiger.cache.bytes currently in the cache"
CACHE_MAX = "serverStatus.wiredTiger.cache.maximum bytes configured"
GB = 1 << 30


def write(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def series(node: str, metric: str, values: list[float], start: float = 0.0,
           step_hours: float = 1.0) -> list[dict]:
    """One baseline row per run, an hour apart, exactly as the collector writes them."""
    import datetime as dt
    out = []
    for i, v in enumerate(values):
        when = dt.datetime.fromtimestamp(start + i * step_hours * 3600, dt.timezone.utc)
        out.append({"run": when.isoformat().replace("+00:00", "Z"), "scope": "baseline",
                    "node": node, "metric": metric, "p50": v, "p95": v, "min": v, "max": v})
    return out


def climbing(n: int = 96) -> list[float]:
    """From 40% to 70% of a 1 GB cache over four days -- full in about four more."""
    return [0.40 * GB + (0.30 * GB) * i / (n - 1) for i in range(n)]


def rows_for(nodes: list[str], values: list[float]) -> list[dict]:
    out = []
    for node in nodes:
        out += series(node, CACHE, values)
        out += series(node, CACHE_MAX, [float(GB)] * len(values))
    return out


def test_a_steady_climb_towards_the_limit_is_reported(tmp_path):
    found = runway.find(write(tmp_path / "b.jsonl", rows_for(["a", "b", "c"], climbing())))
    assert len(found) == 1
    assert found[0].metric == CACHE
    # Days, not a vague direction: the number is the whole point of the finding.
    assert 2 < found[0].days < 10


def test_it_says_nothing_about_a_flat_cluster(tmp_path):
    flat = [0.70 * GB] * 96
    assert runway.find(write(tmp_path / "b.jsonl", rows_for(["a", "b", "c"], flat))) == []


def test_a_step_is_not_a_trend(tmp_path):
    """Idle, then busy, and it stays there.

    Least squares loves this shape -- a straight line through it has a fine R2 -- and it is the
    single most common thing a real cluster does: somebody deploys, the level moves once. Rank
    correlation is what tells the two apart, and this is the test that would fail if anyone
    swapped it back for a slope.
    """
    step = [0.40 * GB] * 48 + [0.78 * GB] * 48
    assert runway.find(write(tmp_path / "b.jsonl", rows_for(["a", "b", "c"], step))) == []


def test_half_a_day_of_history_predicts_nothing(tmp_path):
    """The same climb, compressed into twelve hours. A morning is not a trend."""
    rows = []
    for node in ("a", "b", "c"):
        rows += series(node, CACHE, climbing(12), step_hours=1.0)
        rows += series(node, CACHE_MAX, [float(GB)] * 12, step_hours=1.0)
    assert runway.find(write(tmp_path / "b.jsonl", rows)) == []


def test_one_member_climbing_alone_is_not_a_capacity_problem(tmp_path):
    """A cluster is sized as a whole; one node drifting is that host, and the peer comparison
    already reports it. Two of three is the bar."""
    rows = rows_for(["a"], climbing())
    for node in ("b", "c"):
        rows += series(node, CACHE, [0.40 * GB] * 96)
        rows += series(node, CACHE_MAX, [float(GB)] * 96)
    assert runway.find(write(tmp_path / "b.jsonl", rows)) == []


def test_a_climb_that_arrives_in_a_year_is_arithmetic_not_advice(tmp_path):
    # 4% of the cache over four days: the limit is more than a year away.
    slow = [0.40 * GB + (0.0004 * GB) * i for i in range(96)]
    assert runway.find(write(tmp_path / "b.jsonl", rows_for(["a", "b", "c"], slow))) == []


def test_a_pool_at_three_percent_is_not_extrapolated(tmp_path):
    """Doubling from nothing is still nothing. Below a third of the limit the straight line is
    fitted to a curve, and the date it produces is invented."""
    tiny = [0.01 * GB + (0.02 * GB) * i / 95 for i in range(96)]
    assert runway.find(write(tmp_path / "b.jsonl", rows_for(["a", "b", "c"], tiny))) == []


def test_a_constant_series_has_no_rank_correlation():
    """Ties averaged, not broken by position.

    Half the metrics with a ceiling are constants -- pool sizes, total memory, core counts --
    and ranking them by position hands every one of them a perfect 1.0. Measured: it made every
    cluster report a flawless upward trend in its number of CPUs.
    """
    flat = [(float(i), 5.0) for i in range(50)]
    assert runway.spearman(flat) == 0.0


def test_falling_free_memory_is_reported_too(tmp_path):
    """The direction that matters is towards the wall, not upwards."""
    total = 16.0 * (1 << 20)          # kB
    free = [0.55 * total - (0.30 * total) * i / 95 for i in range(96)]
    rows = []
    for node in ("a", "b", "c"):
        rows += series(node, "systemMetrics.memory.MemAvailable_kb", free)
        rows += series(node, "systemMetrics.memory.MemTotal_kb", [total] * 96)
    found = runway.find(write(tmp_path / "b.jsonl", rows))
    assert len(found) == 1
    assert found[0].direction == "down"


# ---------------------------------------------------------------- the picture of the claim

def chart_for(tmp_path, rows):
    found = runway.find(write(tmp_path / "b.jsonl", rows))
    assert found, "the fixture is supposed to produce a finding"
    return found[0], runway.as_findings(found, 0, 3_600_000)[0]["chart"]


def test_the_projected_line_ends_on_the_limit_it_names(tmp_path):
    """The line and the sentence come from the same fit, so they cannot disagree.

    Drawn from a second fit they could, and the reader checks the picture against the words --
    which is the only reason to draw it at all.
    """
    r, chart = chart_for(tmp_path, rows_for(["a", "b", "c"], climbing()))
    projected = chart["series"][1]["v"]

    assert chart["threshold"] == r.limit
    # It runs a little past the crossing so the meeting point is not cut in half by the frame.
    crosses = [i for i, v in enumerate(projected) if v >= chart["threshold"]]
    assert crosses and crosses[0] < len(projected) - 1


def test_a_falling_metric_projects_to_the_last_tenth_not_to_zero(tmp_path):
    """The same floor `find` measured the days against. A chart drawn to zero would be claiming
    a date the finding never made."""
    total = 16.0 * GB
    free = [0.55 * total - (0.30 * total) * i / 95 for i in range(96)]
    rows = []
    for node in ("a", "b", "c"):
        rows += series(node, "systemMetrics.memory.MemAvailable_kb", free)
        rows += series(node, "systemMetrics.memory.MemTotal_kb", [total] * 96)
    r, chart = chart_for(tmp_path, rows)

    assert chart["threshold"] == 0.10 * r.limit


def test_nothing_measured_is_drawn_past_now(tmp_path):
    """The whole defence of a forecast chart: where the readings stop is visible.

    A projection drawn as one continuous line reads as a line that was measured all the way to
    the wall, and the reader has no way to see that most of it is arithmetic.
    """
    _, chart = chart_for(tmp_path, rows_for(["a", "b", "c"], climbing()))
    measured, projected = chart["series"][0]["v"], chart["series"][1]["v"]

    assert chart["nowMs"] in chart["t"]
    now_at = chart["t"].index(chart["nowMs"])
    assert all(v is not None for v in measured[:now_at + 1])
    assert all(v is None for v in measured[now_at + 1:]), "no readings after the last reading"
    assert all(v is not None for v in projected), "the fit is drawn across its own evidence too"
    assert chart["thresholdIsForecast"] is True


def test_host_memory_is_reported_in_the_unit_it_is_stored_in(tmp_path):
    """`MemTotal_kb` holds bytes by the time it gets here -- the reader normalises on the way in.

    Trusting the name divided by a further 1024 and told a 16 GB host it had 15,801 GB.
    """
    assert runway._human(16.0 * GB, "systemMetrics.memory.MemTotal_kb") == "16.0 GB"
