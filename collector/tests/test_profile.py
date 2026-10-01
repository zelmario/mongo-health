"""The onboarding report, which has to be worth reading on a cluster where nothing is wrong.

Most clusters are healthy. If the first thing a new customer receives is "no findings", the
product reads as doing nothing — so the report describes behaviour rather than listing alarms,
and every row carries its own interpretation.

That interpretation is the part these tests guard. A number with the wrong sentence attached is
worse than no sentence: it teaches the reader to distrust the whole page. One such
contradiction shipped and was caught only by looking at the rendered output — "sub-second
throughout" printed beside a 2602 ms peak — which is why the readings get their own tests now.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from profile import build_profile, load, pick, render, sparkline  # noqa: E402

NOW = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)
GB = 1073741824


def row(metric: str, p50=0.0, p95=0.0, max_=0.0, node="n0") -> dict:
    return {"metric": metric, "node": node, "p50": p50, "p95": p95, "max": max_,
            "min": 0.0, "p99": p95, "mean": p50, "n": 1000, "scope": "baseline",
            "run": "2026-08-09T12:00:00+00:00"}


def summary(findings=0, rules=14) -> dict:
    return {"customer_id": "acme", "cluster_id": "prod", "days_of_raw_ftdc": 9.4,
            "days_observed": 9.4, "megabytes": 500.0, "rules_evaluated": rules,
            "rules_unresolved": [], "findings_total": findings,
            "nodes": [{"node": "n0", "hostname": "n0.mongodb.net", "version": "8.0.29",
                       "samples": 812_000, "gaps": 0}]}


def find_row(rows, name):
    return next((r for r in rows if r["name"] == name), None)


# ----------------------------------------------------------------- readings match the numbers

def test_a_comfortable_ticket_pool_reads_as_comfortable():
    rows = build_profile([
        row("serverStatus.wiredTiger.concurrentTransactions.read.out", 0, 1, 2),
        row("serverStatus.wiredTiger.concurrentTransactions.read.totalTickets", 128, 128, 128),
    ])
    assert "not queueing" in find_row(rows, "Read tickets in use")["reading"]


def test_a_saturated_ticket_pool_reads_as_trouble():
    rows = build_profile([
        row("serverStatus.wiredTiger.concurrentTransactions.read.out", 60, 120, 128),
        row("serverStatus.wiredTiger.concurrentTransactions.read.totalTickets", 128, 128, 128),
    ])
    assert "queue" in find_row(rows, "Read tickets in use")["reading"].lower()


def test_a_slow_checkpoint_is_not_called_sub_second():
    """The contradiction that shipped: p95 fine, peak in seconds, text claiming otherwise.

    A row that disagrees with itself costs the reader's trust in every other row.
    """
    rows = build_profile([row(
        "serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)",
        24, 90, 2602)])
    reading = find_row(rows, "Checkpoint duration")["reading"]
    assert "sub-second throughout" not in reading
    assert "2.6 s" in reading, "the peak the reader can see must be the peak described"


def test_a_genuinely_fast_checkpoint_says_so():
    rows = build_profile([row(
        "serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)",
        20, 40, 90)])
    assert "Sub-second throughout" in find_row(rows, "Checkpoint duration")["reading"]


def test_a_persistently_slow_checkpoint_is_described_as_stalling():
    rows = build_profile([row(
        "serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)",
        1500, 4000, 9000)])
    assert "stall" in find_row(rows, "Checkpoint duration")["reading"]


def test_scan_ratio_flags_a_missing_index():
    """Thousands of documents read to answer one query is the signature worth naming."""
    rows = build_profile([
        row("rate(serverStatus.metrics.queryExecutor.scannedObjects)", 50_000, 90_000, 1e5),
        row("rate(serverStatus.metrics.document.returned)", 10, 20, 30),
    ])
    assert "index" in find_row(rows, "Documents read per document returned")["reading"]


def test_an_efficient_cluster_is_told_its_queries_use_indexes():
    rows = build_profile([
        row("rate(serverStatus.metrics.queryExecutor.scannedObjects)", 12, 20, 30),
        row("rate(serverStatus.metrics.document.returned)", 10, 18, 25),
    ])
    assert "using indexes" in find_row(rows, "Documents read per document returned")["reading"]


def test_a_full_cache_is_reported_as_full():
    rows = build_profile([
        row("serverStatus.wiredTiger.cache.bytes currently in the cache", 7 * GB, 7.8 * GB, 8 * GB),
        row("serverStatus.wiredTiger.cache.maximum bytes configured", 8 * GB, 8 * GB, 8 * GB),
        row("serverStatus.wiredTiger.cache.tracked dirty bytes in the cache", 0.1 * GB, 0.2 * GB, 0.3 * GB),
    ])
    assert "off disk" in find_row(rows, "Cache in use")["reading"]


# --------------------------------------------------------------------------- which node wins

def test_the_profile_describes_the_busiest_node():
    """A problem on one node must not be diluted by two healthy peers."""
    rows = build_profile([
        row("serverStatus.connections.current", 10, 20, 25, node="quiet"),
        row("serverStatus.connections.current", 300, 900, 950, node="busy"),
        row("serverStatus.connections.available", 500, 500, 500, node="busy"),
    ])
    assert "900" in find_row(rows, "Connections")["busiest"]


def test_pick_returns_nothing_for_an_absent_metric():
    assert pick([row("a")], "b") is None


def test_a_metric_resolved_through_an_alias_is_still_matched():
    """The baseline records "canonical (via resolved)" so an upgrade stays traceable.

    Matching must survive that annotation, or the profile silently empties out on 8.0.
    """
    r = row("serverStatus.connections.current (via serverStatus.connections.current)",
            10, 20, 30)
    assert pick([r], "serverStatus.connections.current") is not None


# ------------------------------------------------------------------------------- rendering

def test_a_healthy_cluster_gets_a_positive_report():
    """Not "no findings" — "all 14 checks ran and none crossed its threshold"."""
    page = render(summary(findings=0), [], [row("serverStatus.connections.current", 5, 9, 12)],
                  {}, NOW)
    assert "Nothing fired" in page
    assert "14 checks ran" in page


def a_real_finding(**over) -> dict:
    """The shape the collector actually writes.

    The report groups findings into moments now, the same way the page and the emails do, and
    grouping needs the rule and the timestamps. A fixture missing them tested a renderer that
    no longer exists.
    """
    base = {"rule": "read-tickets-saturated", "severity": "critical",
            "title": "Read ticket pool saturated", "what": "…", "check": "…",
            "node": "n0.mongodb.net", "secondsInState": 600,
            "fromMs": 1_754_000_000_000, "toMs": 1_754_000_600_000,
            "worstFromMs": 1_754_000_000_000, "worstToMs": 1_754_000_600_000}
    return {**base, **over}


def test_findings_come_after_the_profile_not_instead_of_it():
    f = a_real_finding()
    baseline = [row("serverStatus.connections.current", 5, 9, 12),
                row("serverStatus.connections.available", 500, 500, 500)]
    page = render(summary(findings=1), [f], baseline, {}, NOW)
    assert page.index("How this cluster behaves") < page.index("Read ticket pool saturated")


def test_one_symptom_on_three_nodes_is_one_entry():
    """The report a customer gets on day one, and the last of the three views to learn this.

    Ungrouped it listed "Read ticket pool saturated" once per node, which reads as a cluster in
    three times worse shape than it is and as a tool that cannot tell one problem from three.
    """
    findings = [a_real_finding(node=f"n{i}.mongodb.net") for i in range(3)]
    page = render(summary(findings=3), findings, [], {}, NOW)
    assert page.count("Read ticket pool saturated") == 1


def test_the_rescued_window_is_the_headline():
    page = render(summary(), [], [], {}, NOW)
    assert "9.4" in page and "rescued" in page


def test_charts_are_embedded_not_linked():
    """The report gets emailed and forwarded; a folder of images arrives broken."""
    series = {"serverStatus.connections.current":
              {"t": [1_754_000_000_000 + i * 60_000 for i in range(50)],
               "v": [float(i) for i in range(50)]}}
    baseline = [row("serverStatus.connections.current", 5, 9, 12),
                row("serverStatus.connections.available", 500, 500, 500)]
    page = render(summary(), [], baseline, series, NOW)
    assert "data:image/png;base64," in page
    assert "<img src=\"http" not in page


def test_a_flat_series_gets_no_sparkline():
    """A straight line adds nothing the numbers do not already say."""
    assert sparkline({"t": [1, 2, 3], "v": [5.0, 5.0, 5.0]}) is None
    assert sparkline(None) is None
    assert sparkline({"t": [], "v": []}) is None


def test_load_survives_a_cluster_with_no_extras(tmp_path: Path):
    """Findings and series are optional; only the summary is required."""
    import json
    (tmp_path / "summary.json").write_text(json.dumps(summary()))
    s, f, b, series = load(tmp_path)
    assert s["cluster_id"] == "prod"
    assert f == [] and b == [] and series == {}


# ------------------------------------------------- one row describes one node, not an average

def test_a_row_never_mixes_two_nodes_numbers():
    """The bug this guards: tickets in use on one member over the pool size of another.

    Each metric used to be picked independently, so a row could divide a number from the busy
    node by a number from a quiet one — a ratio of two values that never existed together.
    """
    rows = build_profile([
        row("serverStatus.wiredTiger.concurrentTransactions.read.out", 0, 0, 80, node="busy"),
        row("serverStatus.wiredTiger.concurrentTransactions.read.totalTickets",
            4, 4, 83, node="busy"),
        row("serverStatus.wiredTiger.concurrentTransactions.read.out", 0, 0, 1, node="quiet"),
        row("serverStatus.wiredTiger.concurrentTransactions.read.totalTickets",
            4, 6, 6, node="quiet"),
    ])
    reading = find_row(rows, "Read tickets in use")["reading"]
    assert "80 of 83" in reading, "both halves come from the member that actually saturated"


def test_the_worst_node_is_chosen_by_its_peak_not_its_typical_second():
    """An incident lasting an hour is invisible in a percentile over five days.

    Measured on a real cluster: the member that hit 80 of 83 read tickets during an incident
    had a p95 of zero, so ranking on p95 picked a member where nothing ever happened.
    """
    rows = build_profile([
        row("serverStatus.wiredTiger.concurrentTransactions.read.out", 0, 0, 80, node="spiky"),
        row("serverStatus.wiredTiger.concurrentTransactions.read.totalTickets",
            4, 4, 83, node="spiky"),
        row("serverStatus.wiredTiger.concurrentTransactions.read.out", 1, 2, 3, node="steady"),
        row("serverStatus.wiredTiger.concurrentTransactions.read.totalTickets",
            8, 8, 8, node="steady"),
    ])
    assert "80 of 83" in find_row(rows, "Read tickets in use")["reading"]


def test_a_metric_is_found_under_the_name_the_server_renamed_it_to():
    """8.0 moved the ticket pool to `queues.execution`; the stored row carries both names.

    A row that silently fails to resolve prints nothing and looks exactly like a cluster with
    nothing to say — the same silent-failure shape as a rule that cannot find its metric.
    """
    rows = build_profile([
        row("serverStatus.wiredTiger.concurrentTransactions.read.out "
            "(via serverStatus.queues.execution.read.out)", 0, 0, 80),
        row("serverStatus.wiredTiger.concurrentTransactions.read.totalTickets "
            "(via serverStatus.queues.execution.read.totalTickets)", 4, 4, 83),
    ])
    assert find_row(rows, "Read tickets in use") is not None


# --------------------------------------------------------------------------- units a person reads

def test_durations_are_written_the_way_somebody_would_say_them():
    from profile import ms
    assert ms(26) == "26 ms"
    assert ms(2602) == "2.6 s"
    assert ms(260068) == "4 min 20 s", "260068 ms is nobody's idea of a readable number"


def test_the_operations_row_does_not_call_a_cluster_idle_next_to_its_peak():
    rows = build_profile([
        row("rate(serverStatus.opcounters.query)", 0, 8, 18_000),
    ])
    reading = find_row(rows, "Operations")["reading"]
    assert "18,000/s" in reading, "a peak the reader can see must be acknowledged in words"


def test_the_first_report_shows_three_incidents_and_counts_the_rest():
    """Twelve entries is a wall on the one page somebody reads to decide if this is worth it.

    Counted rather than hidden: a number the reader can act on beats a list they scroll past,
    and it is the same shape the email already uses — a few in full, the remainder named.
    """
    findings = [a_real_finding(rule=f"rule-{i}", title=f"Thing {i}",
                               fromMs=1_754_000_000_000 + i * 3_600_000,
                               toMs=1_754_000_600_000 + i * 3_600_000,
                               worstFromMs=1_754_000_000_000 + i * 3_600_000,
                               worstToMs=1_754_000_600_000 + i * 3_600_000)
                for i in range(7)]
    page = render(summary(findings=7), findings, [], {}, NOW)

    assert page.count('class="finding"') == 3
    assert "4 more" in page


def test_the_first_report_says_it_has_happened_before():
    """The one thing a service without history cannot say, in the report that sells it.

    Anyone can report a saturated ticket pool. Only somebody who was watching in March can say
    it is the third time — and the day-one report is built from the days Atlas was about to
    delete, so it can say it from the first minute.
    """
    HORA = 3_600_000
    findings = [a_real_finding(fromMs=1_754_000_000_000 + i * 24 * HORA,
                               toMs=1_754_000_600_000 + i * 24 * HORA,
                               worstFromMs=1_754_000_000_000 + i * 24 * HORA,
                               worstToMs=1_754_000_600_000 + i * 24 * HORA)
                for i in range(3)]
    page = render(summary(findings=3), findings, [], {}, NOW)

    assert "This has happened 3 times on this cluster" in page


def test_an_incident_is_not_its_own_precedent():
    """Counted from the start of its own window, or a four-hour episode finds itself."""
    page = render(summary(findings=1), [a_real_finding()], [], {}, NOW)
    assert "First time we have seen this" in page
    assert "has happened" not in page


def test_gaps_that_came_through_json_do_not_sink_the_profile(tmp_path):
    """NaN in the runner is null in series.json. Seen on rs-local: the comparison raised, and
    the cluster page lost its behaviour section without a word."""
    import json as _json
    import profile as profile_mod
    (tmp_path / "summary.json").write_text(_json.dumps({"nodes": []}))
    (tmp_path / "series.json").write_text(_json.dumps({
        "a": {"m": {"t": [0, 1, 2], "v": [None, 3.0, None]}},
        "b": {"m": {"t": [0, 1, 2], "v": [1.0, None, 2.0]}}}))
    _, _, _, series = profile_mod.load(tmp_path)
    v = series["m"]["v"]
    assert v[1] == 3.0 and v[0] != v[0] and v[2] != v[2], "the busiest node, gaps as NaN"
