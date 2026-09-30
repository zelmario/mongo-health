"""The one-word answer, and the edges that decide it."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verdict import evaluate  # noqa: E402

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
MS = int(NOW.timestamp() * 1000)
HOUR = 3_600_000


def f(fid, severity="warning", ended_hours_ago=2, rule=None, lasted_hours=1):
    end = MS - ended_hours_ago * HOUR
    return {"id": fid, "rule": rule or f"rule-{fid}", "title": f"Title {fid}",
            "severity": severity, "node": "n0.example.net", "metric": "m",
            "fromMs": end - lasted_hours * HOUR, "toMs": end,
            "worstFromMs": end - lasted_hours * HOUR, "worstToMs": end, "secondsInState": 600}


def verdict(findings, silent=None, captured=True, days=20.0):
    return evaluate(findings, NOW, silent, captured, days)


def test_nothing_serious_is_healthy_and_says_over_how_much():
    v = verdict([f("a", severity="info")])
    assert v.state == "healthy"
    assert "20 days" in v.reason


def test_a_critical_today_puts_it_at_risk():
    v = verdict([f("a", "critical", ended_hours_ago=3), f("b", "warning", ended_hours_ago=1)])
    assert v.state == "at_risk"
    assert v.reason.startswith("Title a"), "the critical one is named, not the more recent one"


def test_a_critical_three_days_ago_is_attention_not_risk():
    assert verdict([f("a", "critical", ended_hours_ago=72)]).state == "attention"


def test_a_warning_this_week_needs_attention():
    v = verdict([f("a", "warning", ended_hours_ago=100)])
    assert v.state == "attention"
    assert "4 days ago" in v.reason


def test_what_ended_more_than_a_week_ago_no_longer_counts():
    assert verdict([f("a", "critical", ended_hours_ago=24 * 8)]).state == "healthy"


def test_what_began_long_ago_but_is_still_going_is_now():
    """Judged by when it ended: a week-old saturation that has not stopped is today's."""
    v = verdict([f("a", "critical", ended_hours_ago=0.5, lasted_hours=24 * 9)])
    assert v.state == "at_risk"


def test_the_count_of_the_rest_is_given():
    v = verdict([f("a", ended_hours_ago=2), f("b", ended_hours_ago=30, rule="other")])
    assert "and 1 more incident in the last week" in v.reason


def test_silence_overrides_everything():
    """With no data arriving, "healthy" would be a statement about a cluster nobody is watching."""
    v = verdict([], silent=30.0)
    assert v.state == "unwatched"
    assert "30 hours" in v.reason


def test_a_cluster_never_captured_is_not_called_healthy():
    assert verdict([], captured=False).state == "unwatched"


def test_the_moment_that_decided_it_is_kept_for_the_link():
    v = verdict([f("a", "critical", ended_hours_ago=1)])
    assert v.evidence[0].groups[0].worst["id"] == "a"
