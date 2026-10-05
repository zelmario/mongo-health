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


def test_files_not_yet_analysed_are_not_called_healthy():
    """An upload is captured minutes before its first analysis ends, with no findings yet."""
    v = evaluate([], NOW, None, True, 0.0, analysed=False)
    assert v.state == "pending"
    assert v.label == "Not checked yet"


def test_the_moment_that_decided_it_is_kept_for_the_link():
    v = verdict([f("a", "critical", ended_hours_ago=1)])
    assert v.evidence[0].groups[0].worst["id"] == "a"


def test_uploaded_files_are_judged_as_of_their_last_sample():
    """A day-old upload with a critical in its last hour: problems in the files, never "at risk"."""
    ends = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)
    end_ms = int(ends.timestamp() * 1000)
    critical = dict(f("a", "critical"), toMs=end_ms - HOUR // 2, worstToMs=end_ms - HOUR // 2)
    v = evaluate([critical], NOW, None, True, 4.5, ends=ends)
    assert v.state == "files_problems"
    assert "in the last hour of the FTDC" in v.reason
    assert "19 Aug 2026 12:00 UTC" in v.reason


def test_uploaded_files_with_nothing_serious_say_so_about_the_files():
    ends = datetime(2026, 8, 1, tzinfo=timezone.utc)
    v = evaluate([], NOW, None, True, 4.5, ends=ends)
    assert v.state == "files_clean"
    assert "last 7 days of the FTDC" in v.reason


def test_an_analysis_running_says_so_rather_than_not_watched():
    v = evaluate([], NOW, 30.0, True, 4.5, analyzing={"files": 26})
    assert v.state == "analyzing"
    assert v.label == "Analyzing FTDC"
    assert "26 new files" in v.reason


def test_a_cluster_whose_samples_are_arriving_is_waiting_not_unwatched():
    v = evaluate([], NOW, None, False, 0.0, arriving={"members": 3})
    assert v.state == "waiting" and "3 members" in v.reason


def test_a_poller_error_is_said_as_it_was_said():
    v = evaluate([], NOW, None, False, 0.0, arriving={"error": "Authentication failed."})
    assert v.state == "unwatched" and "Authentication failed." in v.reason


def test_a_failed_first_analysis_says_so_instead_of_promising_one():
    v = evaluate([], NOW, None, True, 0.0, analysed=False,
                 failed={"error": "RuntimeError: engine failed (1)"})
    assert v.state == "failed" and "engine failed" in v.reason
    assert "updates when" not in v.reason


def test_a_first_atlas_capture_is_collecting_not_unwatched():
    """Added a minute ago, Atlas building the bundle: it read "Not being watched" for the half
    hour that takes."""
    v = evaluate([], NOW, None, False, 0.0, capturing={"stage": "build"})
    assert v.state == "capturing" and "half an hour" in v.reason
    v = evaluate([], NOW, None, False, 0.0, capturing={"stage": "download"})
    assert v.state == "capturing" and "Downloading" in v.reason


def test_a_routine_capture_does_not_hide_the_verdict():
    assert evaluate([], NOW, None, True, 20.0, capturing={"stage": "build"}).state == "healthy"


def test_a_failed_first_capture_says_so_instead_of_unwatched():
    """Atlas cut the first download three times; the page said "Not being watched"."""
    failed = {"error": "ChunkedEncodingError: Response ended prematurely"}
    v = evaluate([], NOW, None, False, 0.0, capture_failed=failed)
    assert v.state == "capture_failed" and "Response ended prematurely" in v.reason
    # A retry under way says that, not the failure before it.
    v = evaluate([], NOW, None, False, 0.0, capture_failed=failed, capturing={"stage": "download"})
    assert v.state == "capturing"


def test_the_verdict_names_the_rolling_restart_the_alerts_came_from():
    """Cluster1: "member not answering" alone read as an outage; it was Atlas restarting it."""
    restart = f("r", severity="info", rule="rolling-restart", ended_hours_ago=30)
    restart["title"] = "Rolling restart: 3 members, one at a time"
    down = f("d", severity="critical", rule="member-unhealthy", ended_hours_ago=30)
    v = verdict([restart, down])
    assert v.state == "attention" and v.reason.startswith("Rolling restart")


def test_a_rolling_restart_with_nothing_serious_is_not_a_problem():
    restart = f("r", severity="info", rule="rolling-restart", ended_hours_ago=30)
    assert verdict([restart]).state == "healthy"


def blip(fid, node, seconds=30, ended_hours_ago=13):
    out = f(fid, "warning", ended_hours_ago=ended_hours_ago, rule="packets-retransmitted",
            lasted_hours=45 / 3600)
    out.update(node=node, secondsInState=seconds)
    return out


def test_a_lone_short_packet_loss_is_listed_not_the_verdict():
    # Cluster1: 45 s of retransmissions on one member, the only time in 22 days.
    v = verdict([blip("a", "shard-00-01")])
    assert v.state == "healthy"
    assert "1 brief network blip on a single member is listed below" in v.reason


def test_packet_loss_long_enough_still_needs_attention():
    assert verdict([blip("a", "shard-00-01", seconds=60)]).state == "attention"


def test_packet_loss_on_two_members_at_once_is_not_a_blip():
    v = verdict([blip("a", "shard-00-01"), blip("b", "shard-00-02")])
    assert v.state == "attention"


def test_a_blip_does_not_hide_anything_else():
    v = verdict([blip("a", "shard-00-01"), f("b", "warning", ended_hours_ago=5)])
    assert v.state == "attention"
    assert v.reason.startswith("Title b")
