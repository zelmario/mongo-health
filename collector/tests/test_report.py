"""The static report: what it shows, where it links, and what it leaves behind."""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import report  # noqa: E402

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
MS = int(NOW.timestamp() * 1000)
HOUR = 3_600_000
DAY = 24 * HOUR


def finding(fid, rule="memory-low", node="n0", at=MS - 2 * DAY, severity="critical",
            title="Host running out of memory", chart=True) -> dict:
    return {
        "id": fid, "cluster_id": "prod", "rule": rule, "title": title, "severity": severity,
        "node": f"{node}.example.net", "metric": "pct(a,b)", "episodes": 1,
        "fromMs": at, "toMs": at + HOUR, "worstFromMs": at, "worstToMs": at + HOUR,
        "secondsInState": 600, "peak": 95, "unit": "percent",
        "what": "Available memory is low.", "check": "Look at the cache size.",
        "chart": ({"t": [at + i * 60_000 for i in range(60)], "v": [float(i) for i in range(60)],
                   "threshold": 20, "fromMs": at, "toMs": at + HOUR} if chart else None),
    }


def cluster(data: Path, findings: list[dict], last_data: datetime = NOW - timedelta(hours=1),
            name: str = "prod") -> dict:
    base = data / name
    base.mkdir(parents=True, exist_ok=True)
    (base / "findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in findings))
    (base / "state.json").write_text(json.dumps({
        "cluster_id": name, "last_capture": last_data.isoformat(),
        "last_new_data": last_data.isoformat(), "source_kind": "atlas", "files": {}}))
    (base / "summary.json").write_text(json.dumps({
        "cluster_id": name, "days_of_raw_ftdc": 9.5, "days_observed": 30.0, "megabytes": 200}))
    return {"cluster_id": name, "mute": [], "notify": []}


def build(tmp: Path, specs: list[dict]) -> Path:
    out = tmp / "site"
    report.build(specs, tmp / "data", out, NOW)
    return out


# Pages the server answers rather than files the report writes; hidden when opened from disk.
SERVER_ROUTES = {"add"}


def links_in(page: Path) -> list[str]:
    return re.findall(r'(?:href|src)="([^"#:]+)"', page.read_text())


# ----------------------------------------------------------------------------- the pages

def test_every_link_in_the_site_leads_somewhere(tmp_path):
    """The site is opened from disk as often as it is served, so every link is relative and
    every one of them has to resolve to a file that was written."""
    spec = cluster(tmp_path / "data", [
        finding("a", node="n0"), finding("b", node="n1"),
        finding("old", at=MS - 60 * DAY),
        finding("c", rule="setting-changed", title="The cache was resized", at=MS - 3 * DAY),
    ])
    out = build(tmp_path, [spec])
    pages = list(out.rglob("*.html"))
    assert len(pages) > 3
    for page in pages:
        for link in links_in(page):
            if link in SERVER_ROUTES:
                continue
            assert (page.parent / link).resolve().exists(), f"{page.name} -> {link}"


def test_every_member_of_an_incident_has_an_address(tmp_path):
    """An email groups the findings it had, which is not always the set the site groups: a link
    to any member must land on the incident."""
    spec = cluster(tmp_path / "data", [finding("a", node="n0"), finding("b", node="n1")])
    out = build(tmp_path, [spec])
    incidents = out / "prod" / "incidents"
    assert (incidents / "a.html").exists() and (incidents / "b.html").exists()
    stubs = [p for p in incidents.glob("*.html") if "http-equiv" in p.read_text()]
    assert len(stubs) == 1, "one page for the incident, one redirect for the other member"


def test_a_change_is_a_point_on_the_axis_not_an_incident(tmp_path):
    """As a card it said the same resize twice: once as an incident, once as context."""
    spec = cluster(tmp_path / "data", [
        finding("a"),
        finding("c", rule="setting-changed", title="The cache was resized", at=MS - 3 * DAY)])
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert page.count("The cache was resized") == 1
    assert 'class="change"' in page
    assert "1 incident " in page


def test_old_incidents_move_to_the_history_page(tmp_path):
    data = tmp_path / "data"
    spec = cluster(data, [finding("new"), finding("old", at=MS - 60 * DAY)])
    out = build(tmp_path, [spec])
    assert 'href="history.html"' in (out / "prod" / "index.html").read_text()
    assert "incidents/old.html" in (out / "prod" / "history.html").read_text()

    # And the page goes once there is nothing old left, rather than lingering stale.
    cluster(data, [finding("new")])
    build(tmp_path, [spec])
    assert not (out / "prod" / "history.html").exists()


def test_a_silent_cluster_says_so_above_everything_else(tmp_path):
    spec = cluster(tmp_path / "data", [], last_data=NOW - timedelta(days=3))
    out = build(tmp_path, [spec])
    page = (out / "prod" / "index.html").read_text()
    assert "Not being watched" in page and "No data has arrived for 3 days" in page
    assert page.index("Not being watched") < page.index("What happened"), "answer first"
    assert "The API key was deleted" in page, "and what usually causes it"
    assert "up to the silence" in page, "and the empty list must not read as an all-clear"
    index = (out / "index.html").read_text()
    assert "Not being watched" in index and "nobody is watching it" in index


def test_the_verdict_links_to_what_decided_it(tmp_path):
    spec = cluster(tmp_path / "data", [finding("a", at=MS - 3 * HOUR)])
    out = build(tmp_path, [spec])
    page = (out / "prod" / "index.html").read_text()
    assert "At risk" in page
    assert 'href="incidents/a.html">See it</a>' in page
    assert "At risk" in (out / "index.html").read_text()


def test_a_quiet_cluster_is_called_healthy(tmp_path):
    spec = cluster(tmp_path / "data", [finding("old", at=MS - 20 * DAY)])
    out = build(tmp_path, [spec])
    assert "Healthy" in (out / "prod" / "index.html").read_text()


def test_a_muted_rule_is_still_shown_and_says_it_is_muted(tmp_path):
    spec = cluster(tmp_path / "data", [finding("a")])
    spec["mute"] = ["memory-low"]
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert "Host running out of memory" in page
    assert "Muted in the config" in page


def test_a_cluster_with_nothing_captured_is_listed(tmp_path):
    out = build(tmp_path, [{"cluster_id": "fresh", "mute": [], "notify": []}])
    assert "nothing captured yet" in (out / "index.html").read_text()


# ------------------------------------------------------------------------------ the charts

def test_charts_are_drawn_once(tmp_path, monkeypatch):
    """Drawing is the expensive part and a finding's chart never changes, so an hourly rebuild
    draws only what is new."""
    drawn = []
    real = report.incident_chart
    monkeypatch.setattr(report, "incident_chart",
                        lambda *a, **kw: drawn.append(1) or real(*a, **kw))
    spec = cluster(tmp_path / "data", [finding("a")])
    build(tmp_path, [spec])
    first = len(drawn)
    build(tmp_path, [spec])
    assert first > 0 and len(drawn) == first


def test_charts_nothing_references_are_removed(tmp_path):
    data = tmp_path / "data"
    spec = cluster(data, [finding("a"), finding("b", rule="cache-full", at=MS - 5 * DAY)])
    out = build(tmp_path, [spec])
    assert len(list((out / "prod" / "charts").glob("*.png"))) == 2
    cluster(data, [finding("a")])
    build(tmp_path, [spec])
    assert len(list((out / "prod" / "charts").glob("*.png"))) == 1
    assert not (out / "prod" / "incidents" / "b.html").exists()


def test_relative_times_are_measured_from_the_build(tmp_path):
    """A report built as of a past moment must not say "a month ago" beside a date it treats
    as the present."""
    spec = cluster(tmp_path / "data", [finding("a", at=MS - 2 * HOUR)])
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert "2 hours ago" in page


def test_a_change_has_its_own_page_without_a_duration(tmp_path):
    """The email names changes, so they need an address; but a change is a moment, and "0s in
    state" beside it reads as a measurement of nothing."""
    change = finding("c", rule="setting-changed", title="The cache was resized", at=MS - 3 * DAY)
    change.update(secondsInState=0, unit="bytes", peak=1610612736)
    spec = cluster(tmp_path / "data", [change])
    page = (build(tmp_path, [spec]) / "prod" / "incidents" / "c.html").read_text()
    assert "The cache was resized" in page
    assert "in state" not in page and "on the worst-affected node" not in page


def test_bytes_are_written_the_way_a_person_reads_them():
    assert report.unit_value(1610612736, "bytes") == "1.5 GiB"
    assert report.unit_value(12, "bytes") == "12 bytes"


def test_old_samples_delivered_today_are_still_old(tmp_path):
    """Files that arrived an hour ago but end in August describe August, not now."""
    spec = cluster(tmp_path / "data", [], last_data=NOW - timedelta(hours=1))
    summary_path = tmp_path / "data" / "prod" / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["nodes"] = [{"node": "n0", "to": (NOW - timedelta(days=40)).isoformat()}]
    summary_path.write_text(json.dumps(summary))
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert "Not being watched" in page and "40 days" in page


# ------------------------------------------------------------------------------ capacity

def baseline_rows(data: Path, node: str, values: dict[str, float], days: float = 10) -> None:
    rows = [{"scope": "baseline", "run": NOW.isoformat(), "node": node, "metric": m,
             "fromMs": MS - int(days * DAY), "toMs": MS,
             "min": v, "max": v, "p50": v, "p95": v, "p99": v, "mean": v, "n": 100}
            for m, v in values.items()]
    (data / "prod" / "baseline.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


GB = 1024 ** 3
BUSY_HOST = {
    "systemMetrics.memory.MemTotal_kb": 16 * GB, "systemMetrics.memory.MemAvailable_kb": 3 * GB,
    "systemMetrics.cpu.num_logical_cores": 20,
    "rate(systemMetrics.cpu.user_ms)": 16_000, "rate(systemMetrics.cpu.system_ms)": 9_000,
    "serverStatus.wiredTiger.cache.bytes currently in the cache": 1.4 * GB,
    "serverStatus.wiredTiger.cache.maximum bytes configured": 1.5 * GB,
    "serverStatus.wiredTiger.concurrentTransactions.read.out": 57,
    "serverStatus.wiredTiger.concurrentTransactions.read.totalTickets": 63,
}


def with_nodes(data: Path, *nodes: tuple[str, str]) -> None:
    path = data / "prod" / "summary.json"
    summary = json.loads(path.read_text())
    summary["nodes"] = [{"node": n, "hostname": h, "to": NOW.isoformat()} for n, h in nodes]
    path.write_text(json.dumps(summary))


def test_capacity_shows_each_resource_at_its_busiest(tmp_path):
    data = tmp_path / "data"
    spec = cluster(data, [])
    with_nodes(data, ("rs27017", "db1"))
    baseline_rows(data, "rs27017", BUSY_HOST)
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert "<h2>Capacity</h2>" in page
    assert "Tight: execution tickets peaked at 90%" in page
    assert "57 of 63 read tickets" in page


def test_cpu_is_a_range_when_the_two_peaks_cannot_be_added(tmp_path):
    """16 cores of user and 9 of system on a 20-core host: at least 16, at most 20. Never 25."""
    data = tmp_path / "data"
    spec = cluster(data, [])
    with_nodes(data, ("rs27017", "db1"))
    baseline_rows(data, "rs27017", BUSY_HOST)
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert "16.0–20.0 of 20 cores" in page
    assert "25." not in page.split("<h2>Capacity</h2>")[1].split("</table>")[0]


def test_a_full_cache_is_not_called_tight(tmp_path):
    """WiredTiger fills its cache by design."""
    data = tmp_path / "data"
    spec = cluster(data, [])
    with_nodes(data, ("n0", "n0"))
    calm = {k: v for k, v in BUSY_HOST.items()}
    calm.update({"rate(systemMetrics.cpu.user_ms)": 2_000, "rate(systemMetrics.cpu.system_ms)": 500,
                 "serverStatus.wiredTiger.concurrentTransactions.read.out": 5})
    baseline_rows(data, "n0", calm)
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert "Has headroom" in page


def test_an_idle_cluster_is_called_larger_than_it_needs(tmp_path):
    data = tmp_path / "data"
    spec = cluster(data, [])
    with_nodes(data, ("n0", "n0"))
    idle = {k: v for k, v in BUSY_HOST.items()}
    idle.update({"systemMetrics.memory.MemAvailable_kb": 12 * GB,
                 "rate(systemMetrics.cpu.user_ms)": 2_000, "rate(systemMetrics.cpu.system_ms)": 500,
                 "serverStatus.wiredTiger.cache.bytes currently in the cache": 0.5 * GB,
                 "serverStatus.wiredTiger.concurrentTransactions.read.out": 5})
    baseline_rows(data, "n0", idle, days=30)
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert "Larger than it needs: in 30 days" in page


# ---------------------------------------------------------------------- marked as fixed

import resolutions  # noqa: E402


def test_a_fixed_incident_leaves_the_report_and_the_verdict(tmp_path):
    data = tmp_path / "data"
    spec = cluster(data, [finding("a", node="n0", at=MS - 3 * HOUR),
                          finding("b", node="n1", at=MS - 3 * HOUR)])
    resolutions.resolve(data / "prod", ["a", "b"], "Added an index on orders.customer_id", NOW)
    out = build(tmp_path, [spec])
    page = (out / "prod" / "index.html").read_text()
    assert "Healthy" in page, "what was dealt with no longer decides the verdict"
    assert "Host running out of memory" not in page.split("<h2>What happened</h2>")[1]
    history = (out / "prod" / "history.html").read_text()
    assert "Added an index on orders.customer_id" in history
    assert 'action="reopen"' in history
    incident = (out / "prod" / "incidents" / "a.html").read_text()
    assert "Marked as fixed" in incident and 'action="../reopen"' in incident


def test_the_same_thing_happening_again_is_news_and_a_repeat(tmp_path):
    data = tmp_path / "data"
    spec = cluster(data, [finding("old", at=MS - 5 * DAY), finding("new", at=MS - 2 * HOUR)])
    resolutions.resolve(data / "prod", ["old"], "", NOW)
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert "At risk" in page
    assert "This has happened 2 times" in page, "the fixed one still counts as history"


def test_putting_it_back_restores_it(tmp_path):
    data = tmp_path / "data"
    spec = cluster(data, [finding("a", at=MS - 3 * HOUR)])
    resolutions.resolve(data / "prod", ["a"], "", NOW)
    resolutions.reopen(data / "prod", ["a"])
    assert "At risk" in (build(tmp_path, [spec]) / "prod" / "index.html").read_text()


def test_forms_are_offered_and_hidden_from_disk(tmp_path):
    spec = cluster(tmp_path / "data", [finding("a")])
    page = (build(tmp_path, [spec]) / "prod" / "index.html").read_text()
    assert 'action="resolve"' in page and 'name="ids" value="a"' in page
    assert 'class="fixed needs-server"' in page and "from-disk" in page
