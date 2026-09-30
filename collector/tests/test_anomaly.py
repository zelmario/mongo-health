"""The detector that says "this is unusual for this cluster".

An anomaly detector has two ways to be useless and they look identical from outside: firing on
everything, and firing on nothing. Both read as silence — one because it gets muted, the other
because there is nothing to mute.

So these tests pin both edges. The ones about NOT firing matter most: this feature exists to
make the reports worth reading, and a detector that cries wolf makes them worth less than
having none at all.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anomaly import FACTOR, MIN_RUNS, as_findings, find  # noqa: E402

METRIC = "serverStatus.wiredTiger.concurrentTransactions.read.out"


def history(values: list[float], node="n0", metric=METRIC, span: float = 1.0) -> dict:
    """One baseline row per past run. `span` widens min/max so the size guard can be satisfied."""
    return {(node, metric): [
        {"p95": v, "min": 0.0, "max": v + span, "run": f"2026-08-0{i%9+1}T00:00:00+00:00"}
        for i, v in enumerate(values)
    ]}


def node(recent_p95: float, name="n0", metric=METRIC) -> dict:
    return {"node": name, "hostname": name,
            "recent": [{"metric": metric, "p95": recent_p95, "min": 0.0,
                        "max": recent_p95, "p50": 0.0, "p99": recent_p95,
                        "mean": recent_p95, "n": 100}]}


# ------------------------------------------------------------------- when it must stay quiet

def test_silent_without_enough_history():
    """A new cluster has no normal yet, so nothing about it can be abnormal.

    Without this, every cluster spends its first days reporting that everything is unusual —
    which is the first impression the whole product depends on.
    """
    found = find([node(1000.0)], history([1.0] * (MIN_RUNS - 1)))
    assert found == []


def test_silent_when_within_the_usual_range():
    found = find([node(4.0)], history([5.0] * MIN_RUNS))
    assert found == []


def test_silent_just_below_the_factor():
    """The threshold is a real edge, not an approximation."""
    found = find([node(10.0 * FACTOR - 0.1)], history([10.0] * MIN_RUNS))
    assert found == []


def test_silent_on_a_tiny_absolute_change():
    """0.001 -> 0.01 is ten times larger and means nothing.

    Relative change alone is a trap: the smaller a metric's usual range, the easier it is to
    multiply. The absolute guard is what keeps noise out of the report.
    """
    found = find([node(0.01)], history([0.001] * MIN_RUNS, span=0.0))
    assert found == []


def test_the_run_being_judged_is_not_part_of_its_own_ceiling():
    """`load_history` excludes it, and this is why.

    Folding the excursion into the ceiling it is measured against is how a detector talks
    itself out of every finding it makes.
    """
    past = history([1.0] * MIN_RUNS)
    found = find([node(30.0)], past)
    assert found, "with the excursion excluded from history, 30 against 1 must be reported"


# ---------------------------------------------------------------------- when it must speak

def test_reports_a_clear_excursion():
    found = find([node(30.0)], history([1.0] * MIN_RUNS))
    assert len(found) == 1
    assert found[0].recent == 30.0
    assert found[0].ceiling == 1.0
    assert found[0].ratio == 30.0


def test_reports_a_metric_that_never_moved_before():
    """The real case: read.out sat at zero for eight runs and then reached 24.

    A ratio is undefined against a ceiling of zero, so this path has to exist explicitly.
    """
    found = find([node(24.0)], history([0.0] * MIN_RUNS, span=24.0))
    assert len(found) == 1
    assert found[0].ceiling == 0.0
    assert found[0].ratio == float("inf")
    assert "first time" in found[0].headline


def test_ceiling_is_the_maximum_not_the_average():
    """A cluster's normal includes its busy hours.

    Averaging would flag every weekday morning on a cluster with a daily peak.
    """
    # 35 rather than 25: against the mean of ~2.5 either would look enormous, but only a value
    # clearing 3x the *ceiling* of 10 should be reported at all. That is the distinction.
    found = find([node(35.0)], history([1.0, 1.0, 1.0, 1.0, 1.0, 10.0]))
    assert found[0].ceiling == 10.0, "the busiest past run defines normal, not the mean"


def test_a_busy_day_within_the_usual_peak_is_not_reported():
    """The counterweight: 25 against a ceiling of 10 is a busy day, not an anomaly.

    Against the *mean* of that same history it would look like a tenfold excursion, which is
    why the ceiling is what it is measured against.
    """
    assert find([node(25.0)], history([1.0, 1.0, 1.0, 1.0, 1.0, 10.0])) == []


def test_biggest_departure_comes_first():
    past = {**history([1.0] * MIN_RUNS, metric="a"), **history([1.0] * MIN_RUNS, metric="b")}
    n = {"node": "n0", "hostname": "n0", "recent": [
        {"metric": "a", "p95": 5.0, "min": 0.0, "max": 5.0},
        {"metric": "b", "p95": 50.0, "min": 0.0, "max": 50.0},
    ]}
    found = find([n], past)
    assert [e.metric for e in found] == ["b", "a"]


# ----------------------------------------------------------------------------- reporting

def test_findings_are_info_not_warnings():
    """An excursion is a lead, not a verdict — the cluster may just be busier today.

    It belongs in the weekly summary, not in an out-of-hours email.
    """
    found = find([node(30.0)], history([1.0] * MIN_RUNS))
    out = as_findings(found, 0, 1000)
    assert all(f["severity"] == "info" for f in out)


def test_findings_carry_no_chart():
    """Its evidence is a comparison against history, not a shape in one window.

    Drawing the window alone would show a normal-looking line and undercut the claim.
    """
    out = as_findings(find([node(30.0)], history([1.0] * MIN_RUNS)), 0, 1000)
    assert all(f["chart"] is None for f in out)


def test_the_text_says_what_it_was_measured_against():
    """A reader must be able to disagree with it, which needs both numbers and the sample size."""
    out = as_findings(find([node(30.0)], history([1.0] * MIN_RUNS)), 0, 1000)
    what = out[0]["what"]
    assert "30" in what and "1" in what and str(MIN_RUNS) in what
