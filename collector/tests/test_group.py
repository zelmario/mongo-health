"""What one incident looks like when three nodes report it.

The rules are per node and per metric, which is right: a node either crossed a threshold or it
did not. But a reader experiences one bad afternoon, not fifteen findings, and the first real
email said "15 findings" in its subject for exactly that reason.

These tests hold the line in both directions. Grouping too little produces noise; grouping too
much hides an incident inside another one, which is worse — a finding that is never reported
cannot be recovered from by reading more carefully.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from group import TOGETHER_MS, group, moments, subject_for  # noqa: E402

HOUR = 3_600_000
T0 = 1_754_000_000_000


def finding(rule="memory-low", node="n0", from_ms=T0, to_ms=T0 + HOUR,
            severity="critical", seconds=600, title="Host running out of memory") -> dict:
    return {"rule": rule, "title": title, "severity": severity,
            "node": f"{node}.abcde.mongodb.net", "fromMs": from_ms, "toMs": to_ms,
            "worstFromMs": from_ms, "worstToMs": to_ms, "secondsInState": seconds}


def test_same_symptom_on_three_nodes_is_one_incident():
    groups = group([finding(node=f"n{i}") for i in range(3)])
    assert len(groups) == 1
    assert len(groups[0].nodes) == 3
    assert "3 nodes" in groups[0].headline()


def test_different_rules_stay_apart():
    """Running out of memory and saturating the ticket pool are two things to look at."""
    groups = group([finding(rule="memory-low"), finding(rule="read-tickets-saturated")])
    assert len(groups) == 2


def test_distant_episodes_of_the_same_rule_stay_apart():
    """Tuesday's outage and Friday's are two incidents.

    Merging them would report one long event that never happened, and quietly bury the second.
    """
    groups = group([finding(from_ms=T0, to_ms=T0 + HOUR),
                    finding(from_ms=T0 + 50 * HOUR, to_ms=T0 + 51 * HOUR)])
    assert len(groups) == 2


def test_nodes_reacting_minutes_apart_are_still_one_incident():
    """A replica set reacts together but not to the millisecond."""
    offset = TOGETHER_MS // 2
    groups = group([finding(node="n0", from_ms=T0, to_ms=T0 + HOUR),
                    finding(node="n1", from_ms=T0 + HOUR + offset, to_ms=T0 + 2 * HOUR)])
    assert len(groups) == 1


def test_duration_is_the_worst_node_not_the_sum():
    """Nodes suffer at the same time, not one after another.

    Adding their durations would claim the incident lasted three times longer than it did.
    """
    groups = group([finding(node=f"n{i}", seconds=s) for i, s in enumerate((600, 900, 300))])
    assert groups[0].seconds_in_state == 900


def test_group_takes_the_worst_severity():
    """Two warnings and a critical is a critical: that is what decides if anyone is woken."""
    groups = group([finding(node="n0", severity="warning"),
                    finding(node="n1", severity="critical"),
                    finding(node="n2", severity="warning")])
    assert groups[0].severity == "critical"


def test_worst_member_is_the_one_shown():
    """One chart per incident, drawn from the node that suffered most."""
    groups = group([finding(node="n0", seconds=100), finding(node="n1", seconds=999)])
    assert groups[0].worst["node"].startswith("n1")


def test_ordering_puts_critical_first():
    groups = group([finding(rule="a", severity="info"),
                    finding(rule="b", severity="critical"),
                    finding(rule="c", severity="warning")])
    assert [g.severity for g in groups] == ["critical", "warning", "info"]


# ------------------------------------------------------------------------- subject lines

def test_subject_names_a_single_incident():
    """A specific subject is what gets opened; a count is what gets ignored."""
    subject = subject_for("prod", moments(group([finding()])))
    assert "Host running out of memory" in subject
    assert "prod" in subject


def test_subject_counts_incidents_not_findings():
    """The whole point: 12 findings must never read as 12 of anything.

    Four rules firing at the same time are ONE bad moment with four signals, so that is what
    the subject says. What it must never do is count findings.
    """
    findings = [finding(rule=f"r{i}", node=f"n{j}", title=f"Problem {i}")
                for i in range(4) for j in range(3)]
    groups = group(findings)
    assert len(groups) == 4

    subject = subject_for("prod", moments(groups))
    assert "12" not in subject
    assert "3 other signals" in subject


def test_subject_counts_moments_when_they_are_apart():
    """Four problems on four different days are four incidents."""
    findings = [finding(rule=f"r{i}", title=f"Problem {i}",
                        from_ms=T0 + i * 24 * HOUR, to_ms=T0 + i * 24 * HOUR + HOUR)
                for i in range(4)]
    subject = subject_for("prod", moments(group(findings)))
    assert "3 more" in subject


def test_subject_stays_short_with_many_nodes():
    """Atlas hostnames run to forty characters and would bury the subject.

    The body has room for the full names; the subject has to say what happened.
    """
    subject = subject_for("prod", moments(group([finding(node=f"n{i}") for i in range(2)])))
    assert "2 nodes" in subject
    assert "mongodb.net" not in subject
    assert len(subject) < 80


def test_no_findings_is_no_groups():
    assert group([]) == []


# ------------------------------------------------------------------ cluster-wide findings

def test_an_election_is_not_blamed_on_a_node():
    """Every member lives through the same election.

    The one that reported it first is not where anybody should go looking, and naming it in
    the headline reads as an accusation of a host that did nothing wrong.
    """
    g = group([finding(rule="election-held", node="n0",
                       title="The replica set elected a new primary")])[0]
    assert g.headline() == "The replica set elected a new primary"
    assert "n0" not in g.headline()


def test_a_node_scoped_finding_still_names_its_node():
    """The exception must stay an exception: everything else is about a specific member.

    Short name, not the full hostname — `nodes` trims the Atlas suffix on purpose.
    """
    g = group([finding(rule="memory-low", node="n0")])[0]
    assert g.headline() == "Host running out of memory on n0"


def test_replication_lag_is_not_blamed_on_a_node():
    """Every member measures the same spread across the same members.

    The one that reported it is a witness, not the one falling behind.
    """
    g = group([finding(rule="replication-lag", node="n0",
                       title="A member is falling behind the others")])[0]
    assert g.headline() == "A member is falling behind the others"


# ---------------------------------------------------------------- moments

def test_things_that_started_together_are_one_moment():
    """An incident announces itself with several symptoms within a few minutes."""
    from group import moments

    a = finding(rule="read-tickets-saturated", from_ms=T0, to_ms=T0 + 600_000)
    b = finding(rule="checkpoint-slow", from_ms=T0 + 120_000, to_ms=T0 + 900_000,
                severity="warning")
    m = moments(group([a, b]))
    assert len(m) == 1
    assert len(m[0].groups) == 2
    assert "other signal" in m[0].headline()


def test_a_long_finding_does_not_swallow_the_day():
    """Matched on when things STARTED, not on overlap.

    One finding that runs for a day overlaps everything else in it. Chaining on overlap
    collapsed a whole capture into a single moment holding 37 signals — a report that says
    "everything happened at once" is no more useful than no report.
    """
    from group import moments

    todo_el_dia = finding(rule="checkpoint-slow", from_ms=T0, to_ms=T0 + 24 * HOUR)
    mas_tarde = finding(rule="memory-low", from_ms=T0 + 12 * HOUR, to_ms=T0 + 13 * HOUR)
    m = moments(group([todo_el_dia, mas_tarde]))
    assert len(m) == 2, "a day-long finding pulled a later one into its moment"


def test_a_moment_is_as_severe_as_its_worst_signal():
    from group import moments

    m = moments(group([
        finding(rule="checkpoint-slow", severity="warning"),
        finding(rule="memory-low", severity="critical"),
    ]))
    assert m[0].severity == "critical"


def test_moments_lead_with_the_worst_thing_that_happened():
    """The headline names what somebody remembers, not the first thing sorted alphabetically."""
    from group import moments

    m = moments(group([
        finding(rule="checkpoint-slow", severity="warning", title="Checkpoints running long"),
        finding(rule="memory-low", severity="critical", title="Host running out of memory"),
    ]))
    assert m[0].headline().startswith("Host running out of memory")


def test_no_findings_is_no_moments():
    from group import moments

    assert moments(group([])) == []


# ------------------------------------------------------------------ naming the nodes

def test_one_machine_running_three_nodes_reads_as_one_machine():
    """mongod omits the port when it is 27017 and includes it otherwise.

    So a replica set sharing a host arrives as "dbhost, dbhost:27018, dbhost:27019",
    which reads as three unrelated machines and hides the thing worth noticing: they are one.
    """
    from group import name_nodes

    assert name_nodes(["dbhost", "dbhost:27018", "dbhost:27019"]) \
        == "dbhost (27017, 27018, 27019)"


def test_separate_hosts_are_left_alone():
    """On Atlas the names differ from the first character; there is nothing to collapse."""
    from group import name_nodes

    nodes = ["atlas-x-shard-00-00", "atlas-x-shard-00-01"]
    assert name_nodes(nodes) == "atlas-x-shard-00-00, atlas-x-shard-00-01"


def test_a_lone_node_is_named_as_it_came():
    from group import name_nodes

    assert name_nodes(["db1"]) == "db1"
    assert name_nodes(["db1:27018"]) == "db1:27018"


def test_no_nodes_is_empty_not_an_error():
    from group import name_nodes

    assert name_nodes([]) == ""


def test_the_node_list_is_ordered():
    """Two findings of the same rule must not list their nodes in a different order."""
    a = group([finding(rule="memory-low", node="n2"), finding(rule="memory-low", node="n0")])[0]
    b = group([finding(rule="memory-low", node="n0"), finding(rule="memory-low", node="n2")])[0]
    assert a.nodes == b.nodes
