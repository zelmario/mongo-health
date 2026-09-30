"""The weekly note, and above all the quiet version of it.

A normal week here produces no findings and no email, which is the product working. It is also
how somebody forgets they are paying for it: the cancellation does not come from a bad week, it
comes from a quiet quarter and a look at the invoices. So the case that matters most is the one
where there is nothing to report — and it still has to be worth the four seconds it takes to
read.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from digest import compose, week_of  # noqa: E402

SENDER = "Collector <collector@example.com>"
T0 = 1_786_000_000_000


def body(msg) -> str:
    return msg.get_payload(decode=True).decode()


def test_a_quiet_week_still_sends_something():
    """The whole point. Silence is what the service sounds like when it is working, and a
    customer cannot tell that apart from a service that has stopped."""
    msg = compose("prod", [], 31.0, ["dba@x"], SENDER)
    assert "a quiet week" in msg["Subject"]
    assert "none fired" in body(msg)


def test_the_quiet_note_still_carries_the_number_that_sells_it():
    """What silence cannot say: the history is growing and only exists here."""
    text = body(compose("prod", [], 31.0, ["dba@x"], SENDER))
    assert "31 days" in text
    assert "28 days of it exists only here" in text


def test_a_new_cluster_is_not_told_it_has_nothing():
    """In its first days there is no history beyond what Atlas still holds, and "0 days exist
    only here" deflates the exact argument this message is for."""
    text = body(compose("prod", [], 2.0, ["dba@x"], SENDER))
    assert "0 days" not in text
    assert "what it drops stays with you" in text


def test_one_day_is_not_one_days():
    """The kind of detail that quietly makes a reader trust the numbers less."""
    assert "1 day of it" in body(compose("prod", [], 4.0, ["dba@x"], SENDER))


def test_a_busy_week_names_the_worst_and_counts_the_rest():
    class Group:
        def headline(self):
            return "Read ticket pool saturated"

    class Moment:
        severity = "critical"
        groups = [Group()]

    text = body(compose("prod", [Moment()] * 8, 20.0, ["dba@x"], SENDER))
    assert "8 thing(s)" in text
    assert "and 3 more" in text, "five in full, the rest counted — like the alert mail"


def test_only_the_last_seven_days_count():
    week = 7 * 86_400_000
    findings = [{"worstFromMs": T0}, {"worstFromMs": T0 - week - 1}]
    assert week_of(findings, T0 - week) == [{"worstFromMs": T0}]


def test_it_carries_the_headers_that_get_it_delivered():
    """Same treatment as every other message: this one is recurring mail by definition, which
    is exactly what a filter looks hardest at."""
    msg = compose("prod", [], 31.0, ["dba@x"], SENDER)
    assert msg["Message-ID"].endswith("@example.com>")
    assert msg["List-Unsubscribe"]
    assert msg["Auto-Submitted"] == "auto-generated"


# ------------------------------------------------------- the one finding that saves money

def a_spare_finding(at_ms: int) -> dict:
    return {"rule": "oversized-cluster", "severity": "info", "worstFromMs": at_ms,
            "what": "Across 89 days, this cluster never used more than half of anything it has."}


def test_the_sizing_advice_has_nowhere_else_to_go():
    """Two correct decisions that between them silenced it.

    Sizing advice only fires when the window had NO trouble, and a run whose findings are all
    informational sends no mail — so the one thing in the product that saves the reader money
    rather than costing them an afternoon would never reach anybody. A quiet week is exactly
    when it is true and exactly when there is room to say it.
    """
    msg = compose("prod", [], 92.0, ["dba@x"], SENDER, spare=a_spare_finding(T0))
    assert "never used more than half" in body(msg)


def test_it_is_not_listed_as_a_problem():
    """Buried among "things worth a look" it reads as another fault, and it is the opposite."""
    text = body(compose("prod", [], 92.0, ["dba@x"], SENDER, spare=a_spare_finding(T0)))
    assert "not a problem" in text


def test_a_stale_conclusion_is_not_repeated():
    """It is a standing statement about the cluster rather than an event, but one from last
    month describes a workload that may since have changed."""
    from digest import spare_capacity

    now = T0
    old = a_spare_finding(now - 40 * 86_400_000)
    assert spare_capacity([old], now) is None
    assert spare_capacity([a_spare_finding(now - 3 * 86_400_000)], now) is not None


def test_the_newest_conclusion_wins():
    from digest import spare_capacity

    now = T0
    older = {**a_spare_finding(now - 5 * 86_400_000), "what": "older"}
    newer = {**a_spare_finding(now - 1 * 86_400_000), "what": "newer"}
    assert spare_capacity([older, newer], now)["what"] == "newer"
