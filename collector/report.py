#!/usr/bin/env python3
"""The report: a static site you can open from disk or serve from anywhere.

    python3 report.py --config config.json --data data --out site

    site/index.html                         every cluster, and whether it is being watched
    site/<cluster>/index.html               what happened, newest first, and how it behaves
    site/<cluster>/history.html             incidents older than the report window
    site/<cluster>/incidents/<id>.html      one incident: every node, every earlier time
    site/<cluster>/charts/<id>.png          one chart per finding, drawn once and kept

Rebuilt after every run, from the files the collector already writes. Nothing here needs a
server, a database or a login: put `site/` behind any web server, or open it from disk. Set
`report_url` in the config to where it is served, and the emails link into it.

Same palette and typography as the emails, so following a link does not feel like being handed
to a different product.
"""
from __future__ import annotations

import argparse
import json
import secrets
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import config
import logsummary
import profile as profile_report
# For the human names of the metrics a projection can be made about.
import runway
from group import group as group_findings, moments as by_moment, name_nodes
from notify import changes_before
from verdict import Verdict, evaluate
import resolutions
import catalog
import recommend
import sizing
from profile import earlier_incidents
from watchdog import STALE_AFTER_HOURS

CSS = """
*, *::before, *::after { box-sizing: border-box; }
/* One theme, chosen rather than inherited. This used to follow the reader's operating system,
   which meant the product had two appearances and neither was designed -- the charts were drawn
   on white whatever the page did, so half the readers got a lit rectangle in a dark page.
   A monitoring screen is read in a dim room next to other dark tools, and committing to that
   also makes the picture and the page one thing again. */
:root {
  color-scheme: dark;
  --ground: #0f1216; --panel: #171c23; --edge: #262d37; --edge-soft: #1e242c;
  --ink: #e7ecf3; --ink-soft: #93a0ae; --ink-faint: #6b7683;
  --signal: #f0a538; --signal-soft: #2a2113;
  --ok: #5cb98c; --warn: #e2a33c; --bad: #e4645a;
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
body { margin: 0; background: var(--ground); color: var(--ink);
       font-family: var(--sans); font-size: 15px; line-height: 1.55; }
.wrap { max-width: 44rem; margin: 0 auto; padding: clamp(1rem, 4vw, 2.5rem); }
.wrap.narrow { max-width: 26rem; }

header.top { display: flex; justify-content: space-between; align-items: baseline;
             padding-bottom: 1rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--edge); }
header.top a { color: var(--ink-faint); font-size: 0.8125rem; text-decoration: none; }
/* Declared after the rule above so the brand keeps its own size and weight: it is a link now,
   but it is still the masthead. */
header.top a.brand { font-family: var(--mono); font-size: 1.05rem; font-weight: 700;
                     color: var(--ink); }
header.top a:hover, header.top a:focus { color: var(--ink); text-decoration: underline; }

h1 { font-size: 1.5rem; font-weight: 600; margin: 0 0 0.3rem; text-wrap: balance; }
.lede { margin: 0 0 1.5rem; color: var(--ink-soft); }

.card { background: var(--panel); border: 1px solid var(--edge); padding: 1.4rem; }
label { display: block; font-size: 0.8125rem; font-weight: 600; margin: 0 0 0.3rem; }
.hint { font-weight: 400; color: var(--ink-faint); }
input[type=text], input[type=email], input[type=password], textarea, select {
  width: 100%; padding: 0.55rem 0.7rem; margin-bottom: 1rem;
  background: var(--ground); color: var(--ink);
  border: 1px solid var(--edge); border-radius: 0; font: inherit;
}
input:focus-visible, textarea:focus-visible, button:focus-visible, a:focus-visible {
  outline: 2px solid var(--signal); outline-offset: 2px;
}
button {
  padding: 0.55rem 1.1rem; border: none; background: var(--ink); color: var(--ground);
  font: 600 0.9375rem var(--sans); cursor: pointer;
}
button:hover { background: var(--signal); }
button:disabled, button:disabled:hover { background: var(--ink-soft); cursor: wait; }
button.secondary { background: transparent; color: var(--ink-soft);
                   border: 1px solid var(--edge); }

.flash { background: var(--signal-soft); border-left: 3px solid var(--signal);
         padding: 0.7rem 0.9rem; margin-bottom: 1.2rem; font-size: 0.875rem; }
/* A standing condition, not an event, so it is quieter than a flash and does not scroll away
   with one. */
.unverified { background: var(--panel); border: 1px solid var(--edge);
              border-left: 3px solid var(--warn); padding: 0.6rem 0.9rem;
              margin-bottom: 1.2rem; font-size: 0.875rem; color: var(--ink-soft); }
.divider { display: flex; align-items: center; gap: 0.7rem; margin: 1.2rem 0;
           color: var(--ink-faint); font-size: 0.75rem; text-transform: uppercase;
           letter-spacing: 0.08em; }
.divider::before, .divider::after { content: ""; flex: 1; height: 1px; background: var(--edge); }

/* The click path for the credentials this form asks for. Open by default -- somebody filling
   this in for the first time needs it, and somebody filling it in for the second time can shut
   it. Separated from the form by a rule so it reads as help rather than as more fields. */
.help { margin-top: 1.3rem; padding-top: 1rem; border-top: 1px solid var(--edge-soft); }
.help > summary { cursor: pointer; color: var(--ink-soft); font-size: 0.8125rem;
                  font-weight: 600; }
.steps { margin: 0.9rem 0 0; padding-left: 1.2rem; display: grid; gap: 0.7rem; }
.steps li { font-size: 0.875rem; color: var(--ink-soft); }
.steps li b { display: block; color: var(--ink); font-weight: 600; }

.cluster { display: flex; gap: 0.9rem; align-items: flex-start;
           padding: 0.9rem 0; border-top: 1px solid var(--edge-soft); }
.cluster:first-of-type { border-top: none; }
.cluster input[type=checkbox] { margin-top: 0.3rem; width: 1rem; height: 1rem; }
.cluster .name { font-family: var(--mono); font-weight: 600; }
.cluster .name a { color: inherit; text-decoration: none; }
.cluster .name a:hover { color: var(--signal); text-decoration: underline; }
.cluster .meta { color: var(--ink-faint); font-size: 0.8125rem; }
.cluster input[type=text] { margin: 0.4rem 0 0; }
.cluster.blocked { opacity: 0.55; }
/* How many incidents are still open, at the right of the row. Reads as a count, not as an
   alert: colouring it red would make a settled cluster look like an emergency for ever. */
.cluster .count { flex: none; align-self: center; font-family: var(--mono);
                  font-size: 0.75rem; color: var(--signal); background: var(--signal-soft);
                  border: 1px solid var(--signal-soft); padding: 0.2rem 0.5rem;
                  text-decoration: none; white-space: nowrap; }
.cluster .count.none { color: var(--ink-faint); background: transparent;
                       border-color: var(--edge-soft); }
.cluster .count:hover { border-color: var(--signal); }
.badge { display: inline-block; padding: 0.1rem 0.4rem; font-size: 0.6875rem;
         font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; }
.badge.warn { background: var(--signal-soft); color: var(--signal); }

.mono { font-family: var(--mono); font-size: 0.9em; }
pre.code { font-family: var(--mono); font-size: 0.8125rem; line-height: 1.5;
           background: var(--ground); border: 1px solid var(--edge);
           padding: 0.8rem 0.9rem; margin: 0; overflow-x: auto; white-space: pre; }
pre.code.token { font-size: 0.9375rem; word-break: break-all; white-space: pre-wrap;
                 border-color: var(--signal); }

/* A moment: everything that started within a quarter of an hour of everything else. The
   heading carries the time, so the findings beneath it no longer each need to repeat it. */
/* One moment, one box. The count above this page says "2 incidents" and means two moments, so
   two is what the eye has to be able to count -- and boxes are what the eye counts. Drawn as a
   line between loose cards, the same page said 2 and showed 5 things, which makes a reader
   trust neither number. The signals inside are rows, not cards, for the same reason. */
.moment { background: var(--panel); border: 1px solid var(--edge);
          border-left: 3px solid var(--sev-colour); padding: 1.1rem 1.3rem; }
.moment[data-sev="critical"] { --sev-colour: var(--bad); }
.moment[data-sev="warning"]  { --sev-colour: var(--warn); }
.moment[data-sev="info"]     { --sev-colour: var(--ink-faint); }
.moment-head { display: flex; align-items: baseline; gap: 0.7rem; margin-bottom: 0.9rem;
               padding-bottom: 0.5rem; border-bottom: 1px solid var(--edge-soft); }
.moment-head b { font-family: var(--mono); font-size: 1.0625rem; }
.moment-head span { color: var(--ink-faint); font-size: 0.8125rem; }

/* --------------------------------------------------------------------------- the axis
   Time as a vertical spine, with every kind of event pinned to it: incidents, and the changes
   somebody made to the cluster. It is the one arrangement that states the product's actual
   claim -- we hold the before -- without a sentence claiming it, because a reader who can see
   a resize sitting a day above a checkpoint stall draws that line themselves.
   Marker colour is the event's own severity; a change gets the signal colour, since it is not
   a problem and must never be counted as one. */
ol.axis { list-style: none; margin: 0; padding: 0 0 0 1.7rem; position: relative;
          display: grid; gap: 1.6rem; }
ol.axis::before { content: ""; position: absolute; left: 0.34rem; top: 0.6rem; bottom: 0.6rem;
                  width: 2px; background: var(--edge); }
/* `min-width: 0` is load-bearing: a grid item defaults to `auto`, so the track was sized by the
   widest unbreakable thing inside a card -- a metric path -- and the whole axis grew past the
   page on a phone. */
ol.axis > li { position: relative; min-width: 0; }
ol.axis > li::before { content: ""; position: absolute; left: -1.7rem; top: 0.42rem;
                       width: 0.75rem; height: 0.75rem; border-radius: 50%;
                       background: var(--dot, var(--ink-faint));
                       border: 2px solid var(--dot, var(--ink-faint)); }
ol.axis > li[data-sev="critical"] { --dot: var(--bad); }
ol.axis > li[data-sev="warning"]  { --dot: var(--warn); }
ol.axis > li[data-sev="info"]     { --dot: var(--ink-faint); }
ol.axis > li.change { --dot: var(--signal); }
/* The rail carries the time, so nothing pinned to it has to repeat it. */
.stamp { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.5rem;
         margin: 0 0 0.55rem; font-family: var(--mono); font-size: 0.8125rem;
         color: var(--ink-faint); font-variant-numeric: tabular-nums; }
.stamp b { color: var(--ink); font-weight: 600; }
/* A change is a line on the axis, not a card: it is context for what sits below it, and given
   a panel of its own it competed with the incidents for the reader's alarm. */
li.change .what { margin: 0; color: var(--ink-soft); font-size: 0.9375rem; }
li.change .what b { color: var(--signal); font-weight: 600; }
li.change .what span { color: var(--ink-faint); }
/* Where the axis stops, because the history does. Without it, the oldest thing on the page
   reads as the first thing that ever happened to this cluster. */
li.origin .what { margin: 0; color: var(--ink-faint); font-size: 0.8125rem; }

/* Inside a moment the signal keeps its severity chip -- one moment can hold a critical and a
   warning, and flattening that would lose the reason the moment is as bad as it is -- but it
   gives up the box, the panel and the accent bar that made it look like a separate incident. */
.moment .finding { background: none; border: 0; padding: 0; margin: 0; }
.moment .finding + .finding { margin-top: 1.1rem; padding-top: 1.1rem;
                              border-top: 1px solid var(--edge-soft); }

/* Folded away, at the foot: the two things nobody should reach for by accident. */
.danger { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--edge); }
.danger > summary { cursor: pointer; color: var(--ink-faint); font-size: 0.8125rem; }
.danger button { background: var(--bad); }
.danger button.secondary { background: transparent; color: var(--ink-soft); }

.empty { text-align: center; padding: 2.5rem 1rem; color: var(--ink-soft); }
footer { margin-top: 2rem; color: var(--ink-faint); font-size: 0.75rem; }
footer a { color: var(--ink-faint); }
"""

SEVERITY_LABEL = {"critical": "Critical", "warning": "Worth a look", "info": "Unusual"}


def when_ms(ms) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(int(ms) / 1000, timezone.utc).strftime("%d %b %Y · %H:%M UTC")


# What each rule is actually measuring, in words, plus which direction is bad. A chart
# labelled `pct(serverStatus.queues.execution.read.out, …)` forces the reader to work out both
# from the path -- and a reader who gets the direction wrong reads a recovery as a failure.
# That happened on the very first chart anybody looked at.

# Axis units. FTDC counts bytes and kilobytes because that is what the server reports, so a
# cache chart's axis reads 3,500,000 and the reader does arithmetic before they can see the
# shape. Rescaling is presentation only: stored values, thresholds and the prose all stay in
# the unit the rule measured in.
_BYTES_PER = {"bytes": 1, "kB": 1024}
_STEPS = ((1024 ** 3, "GiB"), (1024 ** 2, "MiB"), (1024, "KiB"), (1, "bytes"))

# Durations, for the same reason as bytes. A replication spread of 23,575,000 ms is six and a
# half hours, and matplotlib renders it as an axis labelled 1e6 with ticks from 0.0 to 2.0 --
# technically correct and unreadable. Nobody holds a stopwatch in millions of milliseconds.
_TIME_PER = {"ms": 1, "us": 0.001, "seconds": 1000}
_TIME_STEPS = ((3_600_000, "hours"), (60_000, "minutes"), (1000, "s"), (1, "ms"))


def _axis_units(unit: str, series: list) -> tuple[float, str]:
    """(divisor, axis label) for a chart's y axis, or (1, unit) to leave it alone.

    The step follows the largest value drawn. A fixed step would put a dirty-cache chart at
    0.03 GiB and a host-memory chart at 3.5 GiB, and only one of those is readable.
    """
    table = _BYTES_PER if unit in _BYTES_PER else _TIME_PER
    steps = _STEPS if unit in _BYTES_PER else _TIME_STEPS
    per = table.get(unit)
    if per is None:
        return 1, (unit or "")

    peak = max((abs(v) * per for s in series for v in s["v"] if v is not None and v == v),
               default=0)
    for step, label in steps:
        if peak >= step:
            return step / per, label
    return 1, unit


def compact_number(v: float) -> str:
    """A tick label a person reads at a glance: 10M, not 1.0 next to a "1e7" in the corner.

    matplotlib moves the magnitude of a large axis into an offset label at the top left, and on
    a query-targeting chart peaking at ten million that label was the only thing saying so. The
    reader saw a line at "1.0" and a threshold at 100 and concluded nothing was wrong.
    """
    a = abs(v)
    for step, suffix in ((1e12, "T"), (1e9, "B"), (1e6, "M"), (1e3, "k")):
        if a >= step:
            return f"{v / step:.3g}{suffix}"
    return f"{v:.6g}"


# How far above its threshold a chart's peak has to go before a linear axis stops showing the
# threshold at all. At a thousand times, the line sits at a tenth of a percent of the height:
# the query-targeting chart drew its limit of 100 under peaks of ten million, flat on zero.
LOG_AXIS_FROM = 1000


def log_axis_from(values, threshold, higher_is_worse: bool) -> float | None:
    """The linear zone of a symlog y axis for this chart, or None to keep it linear.

    Symlog rather than log because these series sit at zero for most of their length -- a ratio
    with nothing scanned is 0 -- and a log axis has nowhere to put zero. Below a tenth of the
    threshold the axis stays linear, so the quiet stretches still read as quiet.
    """
    if threshold is None or not higher_is_worse or threshold <= 0:
        return None
    seen = [v for v in values if v is not None and v == v]
    if not seen or min(seen) < 0 or max(seen) < threshold * LOG_AXIS_FROM:
        return None
    return threshold / 10


MEASURES = {
    "read-tickets-saturated":  ("WiredTiger read tickets", "tickets", False),
    "write-tickets-saturated": ("WiredTiger write tickets", "tickets", False),
    "read-tickets-exhausted":  ("WiredTiger read tickets", "tickets", False),
    "write-tickets-exhausted": ("WiredTiger write tickets", "tickets", False),
    "cache-dirty-high":        ("Dirty pages in cache", "bytes", True),
    "cache-full":              ("WiredTiger cache", "bytes", True),
    "read-queue-building":     ("Reads waiting", "operations", True),
    "write-queue-building":    ("Writes waiting", "operations", True),
    "flow-control-engaged":    ("Write throttling", "% of time", True),
    "page-faults-sustained":   ("Page faults", "per second", True),
    # The pair that partitions "slow commands": one says the server is slow, the other says it
    # is not. Same measure on the axis, because they read the same number -- what differs is
    # the companion line drawn beside it.
    "command-latency-high":    ("Time per command", "us", True),
    "slow-wire-not-server":    ("Time per command", "us", True),
    "checkpoint-slow":         ("Checkpoint duration", "milliseconds", True),
    "oplog-backlog":           ("Oplog waiting to be applied", "bytes", True),
    # bytes, not kB: the reader scales `_kb` paths on the way out (see PATH_SCALES).
    "memory-low":              ("Host memory", "bytes", False),
    "connections-high":        ("Connections", "count", True),
    # Not "count": the axis and the threshold line read "100 count", which says nothing about
    # what is being counted. The title names the measure; the unit says what one of it is.
    "query-targeting-poor":    ("Documents read per document returned", "read per returned", True),
    "collection-scans-sustained": ("Full collection scans", "per-sec", True),
    "eviction-by-app-threads": ("Query threads forced to evict", "percent", True),
    "eviction-aggressive":     ("Aggressive eviction", "count", True),
    "disk-read-latency-high":  ("Time per disk read", "ms", True),
    "disk-write-latency-high": ("Time per disk write", "ms", True),
    "member-unhealthy":        ("Member heartbeat", "count", False),
    "election-held":           ("Replica set term", "count", True),
    "oversized-cluster":       ("Busiest moment observed", "percent", True),
    "replication-lag":         ("Spread between members", "ms", True),
    "disk-space-low":          ("Free space on the data disk", "percent", False),
    "disk-space-critical":     ("Free space on the data disk", "percent", False),
    "swapping":                ("Pages swapped in", "per second", True),
    "packets-retransmitted":   ("TCP segments sent again", "per second", True),
    "oplog-window-short":      ("Oplog window", "seconds", False),
    "oplog-window-critical":   ("Oplog window", "seconds", False),
    # Without an entry the chart was titled with the raw metric expression, which on oplog-churn
    # ran the width of the chart and through the threshold label. test_report checks every rule
    # in rules.json has one.
    "oplog-churn":             ("Journal bytes per write", "bytes", True),
    "write-conflicts":         ("Write conflicts", "per second", True),
    "cursors-leaking":         ("Open cursors", "count", True),
    "ttl-storm":               ("Documents deleted by TTL", "per second", True),
    "connection-storm":        ("Connections opened", "per second", True),
    "history-store-pinned":    ("History store share of the cache", "percent", True),
    "sorts-spilling-to-disk":  ("Sorts spilling to disk", "per second", True),
    "sorts-spilling-burst":    ("Sorts spilling to disk", "per second", True),
    "client-disconnect-kills": ("Operations killed after the client left", "per second", True),
    "pages-read-into-cache":   ("Pages read into the cache", "per second", True),
    "maxtime-kills":           ("Operations stopped by maxTimeMS", "per second", True),
    "aborted-transactions":    ("Transactions aborted", "per second", True),
    "rejected-connections":    ("Connections refused", "per second", True),
    "cursor-timeouts":         ("Idle cursors timed out", "per second", True),
    "rolling-restart":         ("Uptime", "seconds", False),
    "member-restarted":        ("Uptime", "seconds", False),
}


def measured(rule: str, metric: str) -> tuple[str, str, bool]:
    """(what it is, its unit, whether higher is worse). Falls back to the raw expression."""
    # The alarm counters are one rule per metric path, so there is nothing to tabulate: the
    # last component of the path is already the human name ("total failed number of
    # checkpoints"), and inventing a second name for each would be a list to keep in step.
    if rule.startswith("alarm:"):
        return rule.split(".")[-1], "count", True
    if rule == "capacity-runway":
        # One rule, whichever metric has a ceiling -- so it cannot be tabulated above, but it
        # does not have to fall back to the path either: the detector already keeps a human
        # name for every metric it can project, and the finding's own prose uses it. Without
        # this the card said "the cache" in its sentence and
        # `serverStatus.wiredTiger.cache.bytes currently in the cache` in its label.
        canonical = metric.split(" (via")[0]
        return (runway.PRETTY.get(canonical, canonical),
                "bytes" if canonical in runway.CHART_UNIT else "", True)
    return MEASURES.get(rule, (metric or "value", "", True))


def unit_value(value, unit) -> str:
    """A number with its unit attached the way a person writes it: "4.9%", not "4.9percent"."""
    if value is None:
        return "—"
    if unit == "seconds" and abs(float(value)) >= 120:
        # A window of 86,400 s is a day; nobody sizes an oplog in seconds.
        v = float(value)
        return (f"{v / 3600:.1f}".rstrip("0").rstrip(".") + " h" if abs(v) >= 7200
                else f"{v / 60:.0f} min")
    if unit == "bytes":
        # "1610612736 bytes" is a number to convert; "1.5 GiB" is the fact.
        step, name = next((s, n) for s, n in _STEPS if abs(float(value)) >= s or s == 1)
        return f"{float(value) / step:.1f}".rstrip("0").rstrip(".") + f" {name}"
    number = f"{float(value):.1f}".rstrip("0").rstrip(".")
    suffix = {"percent": "%", "ms": " ms", "seconds": " s", "bytes": " bytes",
              "per-sec": "/s", "count": "", "": ""}.get(unit, f" {unit}")
    return f"{number}{suffix}"


def extent(finding: dict, seconds: int) -> tuple[str, str]:
    """(the number, what it means) for the headline figure of a finding.

    Most findings are conditions that lasted, and elapsed time is the honest measure. Some are
    the echo of an event -- `checkpoint most recent time` holds the last checkpoint's duration
    until the next one -- and for those elapsed time answers a question nobody asked. A real
    capture reported "10.6 h" for what was 620 slow checkpoints out of 865.

    The detector supplies the counts when they mean something; the absence of them is the
    signal to fall back to duration.
    """
    hits = finding.get("occurrences")
    total = finding.get("observed")
    if hits and total:
        return f"{hits} of {total}", "times it went over"
    return duration(seconds), "on the worst-affected node"


def how_long_before(ms, reference_ms) -> str:
    """The distance between two moments, which is the only number this line exists to give.

    "Three days before this" is what makes a resize and an incident click together; the same
    two events written as absolute timestamps make the reader do the subtraction, and most
    readers will not. Deliberately coarse -- hours or days -- because a resize is not the kind
    of event whose minute matters.
    """
    seconds = (int(reference_ms) - int(ms)) / 1000
    # The short end used to round everything under ninety minutes up to "about an hour", which
    # was invisible until the two events sat on one axis with their clocks showing: a change
    # forty seconds before an incident was labelled an hour before it, directly under two
    # stamps reading the same minute. A reader who catches the page contradicting itself once
    # stops believing the timings, which are the whole product.
    if seconds < 180:
        return "at the same time as this"
    if seconds < 5400:
        return f"{int(round(seconds / 60))} minutes before this"
    if seconds < 86400:
        return f"{int(round(seconds / 3600))} hours before this"
    if seconds < 172800:
        return "the day before this"
    return f"{int(seconds // 86400)} days before this"


def how_long_ago(ms) -> str:
    """"Two days ago" answers the first question a reader actually has.

    An absolute timestamp answers the second one, so both are shown -- but this one goes first
    and larger, because "is this happening now?" decides whether they keep reading.
    """
    from datetime import datetime, timezone

    delta = (_NOW or datetime.now(timezone.utc)) - datetime.fromtimestamp(int(ms) / 1000,
                                                                         timezone.utc)
    seconds = delta.total_seconds()
    if seconds < 3600:
        return "in the last hour"
    # Plural only when it is plural. "1 hours ago" sat at the top of every incident card that
    # was between one and two hours old -- the first line of the page, and the one place a
    # reader decides whether this thing is careful.
    def ago(n: int, word: str) -> str:
        return f"{n} {word}{'' if n == 1 else 's'} ago"

    if seconds < 86400:
        return ago(int(seconds // 3600), "hour")
    if seconds < 172800:
        return "yesterday"
    if seconds < 2592000:
        return ago(int(seconds // 86400), "day")
    return ago(int(seconds // 2592000), "month")


def time_labels(at: list[datetime]) -> list[str]:
    """Tick labels as precise as the ticks are close, with the date only where it changes.

    A fixed `%d %b %H:%M` printed "28 Sep 11:07" twice on a four-minute chart ticked every
    30 seconds, and repeated the same date on every tick of a chart that covers one day.
    """
    step = min(((b - a).total_seconds() for a, b in zip(at, at[1:])), default=3600)
    if step >= 86400:
        return [t.strftime("%d %b") for t in at]
    clock = "%H:%M:%S" if step < 60 else "%H:%M"
    out, day = [], None
    for t in at:
        out.append(t.strftime(clock if t.date() == day else f"%d %b {clock}"))
        day = t.date()
    return out


def _time_axis():
    """`time_labels` as a matplotlib formatter, built here because matplotlib is imported late."""
    import matplotlib.dates as mdates
    import matplotlib.ticker as mticker

    class TimeAxis(mticker.Formatter):
        def __call__(self, x, pos=None):
            return self.format_ticks([x])[0]

        def format_ticks(self, values):
            return time_labels([mdates.num2date(v, tz=timezone.utc) for v in values])

    return TimeAxis()


def _episode_label(t: datetime, start: datetime, end: datetime) -> str:
    """With seconds when the chart is short: two episodes a minute apart read "11:09" twice."""
    return t.strftime("%H:%M:%S" if (end - start).total_seconds() < 2 * 3600 else "%H:%M")


def _label_rows(at: list[datetime], start: datetime, end: datetime,
                rows: int = 2) -> list[tuple[int, int]]:
    """(index, row) for each episode label that fits, in the first row with room.

    Episodes seconds apart put their labels on top of each other ("11:11:08"). A second row
    takes the next one; past that it is left out, and its shaded band still marks it.
    """
    span = (end - start).total_seconds() or 1
    width = (0.075 if span < 2 * 3600 else 0.05)  # of the axes width, for "HH:MM:SS" / "HH:MM"
    last = [float("-inf")] * rows
    placed = []
    for i, t in enumerate(at):
        x = (t - start).total_seconds() / span
        for row in range(rows):
            if x >= last[row] + width:
                last[row] = x
                placed.append((i, row))
                break
    return placed


def incident_chart(chart: dict | None, severity: str, worst_from: int, worst_to: int,
                   rule: str = "", metric: str = "",
                   window: tuple[int, int] | None = None) -> str | None:
    """The shape of the metric that fired, as an inline image.

    Drawn here rather than served from a URL so the page is one document: no second request to
    fail, nothing to expire, and the same picture whether this is viewed in the browser or
    saved to send to somebody.
    """
    if not chart or not chart.get("t"):
        return None

    import io
    from datetime import datetime, timezone

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt

    # Drawn on the page's own panel colour rather than on white. A light chart in a dark page
    # is not a style mismatch, it is a lamp: the eye goes to the brightest rectangle and stays
    # there, whatever the reader was looking for.
    colour = {"critical": "#e4645a", "warning": "#e2a33c"}.get(severity, "#93a0ae")
    PANEL, INK, SOFT, EDGE, SIGNAL = "#171c23", "#e7ecf3", "#93a0ae", "#262d37", "#f0a538"
    times = [datetime.fromtimestamp(ms / 1000, timezone.utc) for ms in chart["t"]]

    fig, ax = plt.subplots(figsize=(CHART_IN[0], CHART_IN[1]), dpi=CHART_DPI)
    fig.patch.set_facecolor(PANEL)
    ax.set_facecolor(PANEL)

    # Shade every stretch that actually crossed the threshold, derived from the very points
    # being drawn. Marking only the worst episode implied the rest of the window was fine,
    # when in one real case five episodes spanned sixteen minutes and only four were shaded.
    #
    # Reading the regions off the plotted series rather than off the detector's own episode
    # list is deliberate: whatever is shaded is, by construction, what the line shows. The two
    # cannot disagree, which is the failure a reader would notice first and trust last.
    threshold = chart.get("threshold")
    # Some conditions have no single height on this axis but do have a line: `memory-low` tests
    # a share of the host's total memory, so the limit is 20% of whatever total was reported at
    # that moment. Drawn per sample, and used for the shading the same way a flat one is.
    threshold_series = chart.get("thresholdSeries")
    # A baseline line is a description of the past, not the condition being reported: the
    # finding is the whole judged window, and crossings of the old ceiling are what a metric
    # idling near it does all day. Shade the window, as when there is no threshold at all.
    baseline_line = bool(chart.get("thresholdIsBaseline"))
    # A forecast line is where the series is GOING, not something it has crossed. The crossing
    # is in the future by construction, so there is nothing to shade -- and shading the hour
    # this ran, on a chart six weeks wide, points at the one stretch where nothing happened.
    forecast = bool(chart.get("thresholdIsForecast"))

    # Which side of the line is the bad side. Testing `v >= threshold` for everything shaded
    # the exact opposite of the truth on every rule that fires when a number falls: the
    # heartbeat chart, whose threshold is 0 and whose values are 1 while the member is healthy,
    # came out shaded end to end -- including the minutes the member was answering.
    name, unit, higher_is_worse = measured(rule, metric)

    def limit_at(i: int):
        if threshold_series is not None and i < len(threshold_series):
            edge = threshold_series[i]
            return edge if edge == edge else None      # NaN: no limit for this sample
        return threshold

    def in_breach(i: int, v) -> bool:
        edge = limit_at(i)
        if edge is None or v is None or v != v:
            return False
        return v >= edge if higher_is_worse else v <= edge

    crossings: list[tuple[int, int]] = []
    if (threshold is not None or threshold_series is not None) and not baseline_line \
            and not forecast:
        hot_at = [in_breach(i, v) for i, v in enumerate(chart["v"])]
        start = None
        for i, hot in enumerate(hot_at):
            if hot and start is None:
                start = i
            elif not hot and start is not None:
                crossings.append((start, i))
                start = None
        if start is not None:
            crossings.append((start, len(hot_at) - 1))

    # Past a handful of crossings, drawing each one stops being a chart and becomes a barcode.
    # A metric oscillating around its threshold -- which is what query targeting does, and what
    # any ratio does near its cut -- produced thirty stripes that hid the line they were meant
    # to point at. Above the limit the whole finding is shaded instead: "this happened
    # repeatedly through here" is the true statement, and it is also the readable one.
    MOST_STRIPES = 8
    if crossings and len(crossings) <= MOST_STRIPES:
        for a, b in crossings:
            ax.axvspan(times[a], times[b], color=colour, alpha=0.12, zorder=1, linewidth=0)
        # When it happened more than once, each stretch is labelled with the time it started.
        # "Twice" is the fact the reader takes away from a chart like this, and the follow-up
        # question is always "when" -- which the axis can only answer by squinting at a shaded
        # band. Skipped when there is only one: the card already states its time.
        if len(crossings) > 1:
            for i, row in _label_rows([times[a] for a, _ in crossings], times[0], times[-1]):
                a = crossings[i][0]
                ax.annotate(_episode_label(times[a], times[0], times[-1]),
                            xy=(times[a], 1.0), xycoords=("data", "axes fraction"),
                            xytext=(2, -9 - 11 * row), textcoords="offset points",
                            fontsize=7, color=colour, ha="left", va="top", zorder=4,
                            # On a spiky metric the peak is exactly where this label goes, and
                            # the two were unreadable on top of each other.
                            bbox=dict(boxstyle="square,pad=0.12", facecolor=PANEL,
                                      edgecolor="none", alpha=0.75))
    elif crossings:
        span = window or (worst_from, worst_to)
        ax.axvspan(datetime.fromtimestamp(span[0] / 1000, timezone.utc),
                   datetime.fromtimestamp(span[1] / 1000, timezone.utc),
                   color=colour, alpha=0.10, zorder=1, linewidth=0)
    elif not forecast:
        # No threshold to draw against: the chart shows a different series from the one the
        # rule tested. Shade the whole incident instead -- start of the first episode to end
        # of the last -- because that is the claim being made. Shading only the worst episode
        # would point at an arbitrary stretch of a uniformly bad line.
        span = window or (worst_from, worst_to)
        # Unless it covers the chart. Shading exists to say "this part"; a band across the whole
        # width says nothing and costs the contrast that makes the line readable. The baseline
        # excursions hit this every time -- their window IS the chart.
        drawn_span = (chart.get("toMs") or 0) - (chart.get("fromMs") or 0)
        if drawn_span <= 0 or (span[1] - span[0]) / drawn_span < 0.9:
            ax.axvspan(datetime.fromtimestamp(span[0] / 1000, timezone.utc),
                       datetime.fromtimestamp(span[1] / 1000, timezone.utc),
                       color=colour, alpha=0.12, zorder=1, linewidth=0)

    # The worst episode gets an outline, but only when it is a distinct part of the incident
    # AND there is a threshold to judge that against. On a finding that was continuously in
    # breach, boxing one arbitrary stretch of an evenly bad line reads as though the rest were
    # fine -- the opposite of true, and the first thing a reader noticed.
    #
    # "Continuous" means how much of the window was in breach, not how long the worst episode
    # ran: this one sat above its threshold for 84% of its samples, and the five episodes the
    # detector counted were one- and two-sample dips, an artefact of the tolerance rather than
    # events worth pointing at.
    if (threshold is not None or threshold_series is not None) and not baseline_line \
            and not forecast:
        plotted = [(i, v) for i, v in enumerate(chart["v"]) if v is not None and v == v]
        breached = sum(1 for i, v in plotted if in_breach(i, v)) / max(len(plotted), 1)
        if breached < 0.8:
            ax.axvspan(datetime.fromtimestamp(worst_from / 1000, timezone.utc),
                       datetime.fromtimestamp(worst_to / 1000, timezone.utc),
                       facecolor="none", edgecolor=colour, alpha=0.55, zorder=2,
                       linewidth=1.1, linestyle=(0, (3, 2)))

    # One line per displayed series. Tickets come as available + totalTickets, which is what
    # makes the picture readable on 8.0: the pool itself moves, so "12 left" means nothing
    # without the ceiling it is counting down from.
    series = chart.get("series") or [{"label": "", "v": chart["v"]}]

    # The chart's own unit wins. `MEASURES` names the unit the RULE works in, but the reader
    # normalises on the way out -- `MemAvailable_kb` arrives already multiplied into bytes --
    # and a table maintained by hand alongside that one drifts. It said "kB" for host memory,
    # which put a 1.8 GiB host on an axis reading 1,907 GiB.
    # Only for deciding the SCALE. The axis keeps the human word from MEASURES when nothing
    # was rescaled -- "tickets" beats the reader's "count", and "count" is all a metric path
    # can tell you.
    chart_unit = (series[0].get("unit") or unit) if series else unit
    scale, rescaled_label = _axis_units(chart_unit, series)
    axis_label = rescaled_label if scale != 1 else (unit or rescaled_label)

    # Scaling the VALUES, not the tick labels. Rescaling labels leaves matplotlib choosing its
    # ticks in bytes, so a memory chart came out labelled 0.465661 / 0.931323 / 1.39698 -- the
    # round numbers were round in the wrong unit.
    def rescale(v):
        return float("nan") if v is None or v != v else v / scale

    shades = [colour, "#6b7683", "#5b6570"]
    # The subject's spread inside each bucket, under its mean. A bucket on a three-hour chart
    # is ~45 s, and a condition that holds for 20 s at a time averages away: the read-ticket
    # pool that emptied again and again showed as a line that never came near empty. The band
    # is where the samples actually went; the line is still the mean.
    if series and series[0].get("lo") and series[0].get("hi"):
        ax.fill_between(times, [rescale(v) for v in series[0]["lo"]],
                        [rescale(v) for v in series[0]["hi"]], color=colour, alpha=0.22,
                        linewidth=0, zorder=2, label=None)
    for i, s in enumerate(series):
        ax.plot(times, [rescale(v) for v in s["v"]], color=shades[i % len(shades)],
                linewidth=1.2 if i == 0 else 0.9,
                linestyle="-" if i == 0 else (0, (5, 2)),
                # A lone series is named by the chart title already; putting it in the legend
                # only gives it something to overlap the threshold line with.
                zorder=3 - i, label=(s.get("label") or None) if len(series) > 1 else None)
    if threshold is not None:
        edge = "above" if higher_is_worse else "below"
        # A chart may name its own line. The baseline excursions do: their threshold is this
        # node's own history, not a limit anybody set, and calling it "a problem above this
        # line" would state the opposite of what the finding claims -- unusual, not wrong.
        # The number is formatted here because only here is the axis unit known.
        shown = f"{threshold / scale:,.3g}{(' ' + axis_label) if axis_label else ''}"
        # `shown` in both branches: the line is drawn at `threshold / scale`, so labelling it
        # with the raw number puts "1000" against an axis in seconds — right where the reader
        # is trying to check that the line sits where the text says it does.
        note = (f"{shown} — {chart['thresholdNote']}" if chart.get("thresholdNote")
                else f"{shown} — a problem {edge} this line")
        ax.axhline(threshold / scale, color=SIGNAL, linewidth=1, linestyle=(0, (4, 3)),
                   zorder=2, label=note)
    elif threshold_series is not None:
        # A limit that moves with the data: 20% of the host's total memory, which is what the
        # rule actually tested. Drawn as a line rather than named with a number, because there
        # is no single number -- and the shading comes from these same values, so the picture
        # and the claim cannot disagree.
        edge = "above" if higher_is_worse else "below"
        note = chart.get("thresholdNote") or f"the limit — a problem {edge} this line"
        ax.plot(times, [rescale(v) for v in threshold_series], color=SIGNAL, linewidth=1,
                linestyle=(0, (4, 3)), zorder=2, label=note)

    # Where measurement stops and arithmetic starts. Only the forecasts carry it, and without
    # it they are indefensible: a line drawn to the limit reads as a line measured to the limit,
    # and the reader has no way to see that the last stretch of it is a claim.
    #
    # Drawn after the limit so its label can be put at whichever end of the chart the limit is
    # not. Both fixed corners were tried and both collided: the top on a cache filling up, the
    # bottom on memory draining away.
    now_ms = chart.get("nowMs")
    if now_ms:
        at = datetime.fromtimestamp(now_ms / 1000, timezone.utc)
        ax.axvline(at, color=SOFT, linewidth=0.8, linestyle=(0, (2, 3)), alpha=0.7, zorder=2)
        lo, hi = ax.get_ylim()
        high_limit = (threshold is not None and hi > lo
                      and (threshold / scale - lo) / (hi - lo) > 0.5)
        ax.annotate("now", xy=(at, 0.0 if high_limit else 1.0),
                    xycoords=("data", "axes fraction"),
                    xytext=(3, 3 if high_limit else -3), textcoords="offset points",
                    fontsize=7, color=SOFT, ha="left",
                    va="bottom" if high_limit else "top", zorder=4,
                    bbox=dict(boxstyle="square,pad=0.12", facecolor=PANEL,
                              edgecolor="none", alpha=0.75))

    # One legend, drawn after every line that belongs in it. Two calls meant the second silently
    # replaced the first, so a chart with both companion series and a threshold lost the names
    # of its series.
    if ax.get_legend_handles_labels()[1]:
        if len(series) > 1:
            # Below the axes: these charts run close to the top of their range, so a legend
            # inside the plot sits on top of the very lines it is naming.
            ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), frameon=False,
                      fontsize=7.5, labelcolor=SOFT, handlelength=1.8,
                      ncol=len(series) + 1)
        else:
            # Above the plot, beside the title. Inside it, in a corner, the label sat on its own
            # line whenever the limit was near that edge -- which is where most limits are.
            ax.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), frameon=False,
                      fontsize=7.5, labelcolor=SIGNAL, handlelength=1.6, borderaxespad=0.2)

    # A peak far above its threshold squashes the threshold onto zero on a linear axis, and the
    # chart then argues against its own finding. Decided on what is drawn, after rescaling.
    linthresh = (log_axis_from([rescale(v) for s in series for v in s["v"]],
                               None if threshold is None else threshold / scale,
                               higher_is_worse)
                 if not baseline_line and not forecast else None)
    if linthresh:
        ax.set_yscale("symlog", linthresh=linthresh)
        ax.set_ylim(bottom=0)
        axis_label = f"{axis_label} (log scale)" if axis_label else "log scale"
    # After the scale: set_yscale replaces the formatter.
    from matplotlib.ticker import FuncFormatter
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: compact_number(v)))
    ax.set_ylabel(axis_label, fontsize=7.5, color=SOFT)
    # MEASURES is keyed by rule, which cannot name a baseline excursion: the same rule fires on
    # whichever metric moved, so the title has to come from the finding.
    ax.set_title(chart.get("title") or name, fontsize=9, color=INK, loc="left",
                 pad=6, fontweight="600")
    ax.tick_params(labelsize=7, colors=SOFT, length=3, width=0.6)
    locator = mdates.AutoDateLocator(tz=timezone.utc, minticks=4, maxticks=9)
    ax.xaxis.set_major_locator(locator)
    ax.xaxis.set_major_formatter(_time_axis())
    ax.margins(x=0)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(EDGE)
        ax.spines[side].set_linewidth(0.8)
    ax.grid(axis="y", color=EDGE, linewidth=0.7, alpha=0.9)
    ax.set_axisbelow(True)
    fig.tight_layout(pad=0.4)
    # tight_layout leaves the axis label hanging off the left edge when the legend sits below
    # the axes, and "tickets" came out as "ickets". Measured after a draw -- before one the
    # label has not been placed yet -- and moved in.
    fig.canvas.draw()
    overhang = -ax.yaxis.label.get_window_extent().x0
    if overhang > 0:
        width = fig.get_size_inches()[0] * fig.dpi
        fig.subplots_adjust(left=fig.subplotpars.left + (overhang + 4) / width)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=PANEL)
    plt.close(fig)
    return buf.getvalue()


# 2.6in tall, not 2.0: at 2.0 a page width flattened every episode into a line. 200 dpi so the
# enlarged view, a click away, is as sharp as the one on the page.
CHART_IN, CHART_DPI = (8.4, 2.6), 200
CHART_W, CHART_H = round(CHART_IN[0] * CHART_DPI), round(CHART_IN[1] * CHART_DPI)
# Part of every chart's name: a change to how charts are drawn redraws the ones already held,
# which are otherwise kept for ever because what they show never changes.
CHART_STYLE = 7


def has_chart(finding: dict) -> bool:
    """Whether there is a series to draw, answered without drawing it.

    The page needs to know this for every card it renders, and the only honest alternative --
    rendering to find out -- is what made a report of twenty-eight incidents take two seconds
    of matplotlib before the first byte reached the browser.
    """
    chart = finding.get("chart")
    return bool(chart and chart.get("t"))


def duration(seconds) -> str:
    seconds = int(seconds or 0)
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    return f"{seconds / 3600:.1f} h"


def episodes_fact(group) -> str:
    """"It happened three times", when it did.

    A single timestamp under a chart with two shaded stretches invites the reader to take the
    first one for the whole story. The count is per node -- the most any one member saw --
    because three members reporting one episode each is one thing that happened, not three.
    """
    most = max((m.get("episodes") or 1) for m in group.members)
    if most <= 1:
        return ""
    return f'<span title="separate stretches">{most} episodes</span>'



REPORT_CSS = """
.unmute { display:flex; align-items:baseline; gap:.5rem; flex-wrap:wrap;
          margin-top:.9rem; padding-top:.8rem; border-top:1px solid var(--edge-soft);
          font-size:.875rem; color:var(--ink-faint); }
button.link { background:none; border:none; padding:0; font:inherit; cursor:pointer;
              color:var(--signal); text-decoration:underline; }
button.link:hover { color:var(--ink); }
.muted-rules { margin:0; padding-left:1.1rem; color:var(--ink-soft); font-size:.9375rem; }
.muted-rules li { margin-bottom:.35rem; }
.back { color: var(--ink-faint); text-decoration: none; font-size: 0.8125rem; }
.back:hover { color: var(--ink); }
.finding { background: var(--panel); border: 1px solid var(--edge);
           border-left: 3px solid var(--sev-colour); padding: 1.1rem 1.3rem;
           margin-bottom: 0.8rem; }
.finding[data-sev="critical"] { --sev-colour: var(--bad); }
.finding[data-sev="warning"]  { --sev-colour: var(--warn); }
.finding[data-sev="info"]     { --sev-colour: var(--ink-faint); }
.finding .sev { font-size: 0.6875rem; font-weight: 600; text-transform: uppercase;
                letter-spacing: 0.07em; color: var(--sev-colour); }
.finding h3 { margin: 0.2rem 0 0.35rem; font-size: 1.0625rem; }
.finding h3 a { color: inherit; text-decoration: none; }
.finding h3 a:hover, .finding h3 a:focus { color: var(--signal);
                                           text-decoration: underline; }
.finding .head { display: flex; justify-content: space-between; align-items: flex-start;
                 gap: 1rem; }
/* "How long ago" is the first question, so it gets read weight the timestamp does not. */
/* Any chart, anywhere. Scoped to `.finding` this only fitted the report list, and the same
   image on the incident page ran off the side of the card -- the panels there are a different
   container and inherited nothing. `max-width` as well as `width` so it cannot happen again
   from a parent that sizes differently. */
.shape { width: 100%; max-width: 100%; height: auto; display: block; }
/* Wider where there are charts: at 44rem they were drawn at half their size. The prose keeps a
   line a person can read. */
.wrap:has(img.shape) { max-width: 64rem; }
.wrap:has(img.shape) p { max-width: 46rem; }
img.shape { cursor: zoom-in; }
.zoom { position: fixed; inset: 0; z-index: 10; background: rgb(0 0 0 / .85); display: flex;
        align-items: center; justify-content: center; cursor: zoom-out; padding: 2vh 2vw; }
.zoom img { max-width: 100%; max-height: 100%; width: auto; height: auto; }
.finding .shape { margin: 0.9rem 0 0.3rem; }
.finding .metric { font-family: var(--mono); font-size: 0.6875rem; color: var(--ink-faint);
                   margin-bottom: 0.5rem; word-break: break-all; }
/* The raw expression is what you need when you go looking in Big Hole, and clutter until
   then. Named in the summary, spelled out on demand. */
.raw { margin-bottom: 0.6rem; }
.raw summary { font-size: 0.8125rem; color: var(--ink-soft); cursor: pointer; }
/* A metric path has no spaces in it -- `serverStatus.wiredTiger.cache.bytes dirty in the
   cache cumulative` is one word to a browser -- and inside a card on the axis it pushed the
   whole page sideways on a phone. It breaks where it has to rather than moving the page. */
.raw summary, .raw code, .finding h3, .finding .metric { overflow-wrap: anywhere; }
.raw code { display: block; margin-top: 0.3rem; font-size: 0.6875rem;
            color: var(--ink-faint); word-break: break-all; }
.finding p { margin: 0; color: var(--ink-soft); font-size: 0.9375rem; }
.finding .facts { display: flex; flex-wrap: wrap; gap: 0.9rem; margin-top: 0.6rem;
                  font-family: var(--mono); font-size: 0.75rem; color: var(--ink-faint); }
.finding details { margin-top: 0.7rem; font-size: 0.875rem; color: var(--ink-soft); }
.finding summary { cursor: pointer; color: var(--ink-faint); font-size: 0.8125rem; }

/* The recurrence line is the product's whole argument, so it gets the accent. */
.sharing { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--edge); }
.sharing > summary { cursor: pointer; color: var(--ink-soft); font-size: 0.8125rem;
                     font-weight: 600; }
.fresh { background: var(--signal-soft); border-left: 3px solid var(--signal);
         padding: 0.7rem 0.9rem; margin-bottom: 0.9rem; font-size: 0.8125rem; }
.fresh input { width: 100%; margin-top: 0.4rem; font-family: var(--mono); font-size: 0.75rem; }
.shares { list-style: none; margin: 0 0 0.9rem; padding: 0; font-size: 0.8125rem;
          color: var(--ink-soft); }
.shares li { display: flex; justify-content: space-between; align-items: center; gap: 1rem;
             padding: 0.4rem 0; border-top: 1px solid var(--edge-soft); }

.changed { margin-top: 0.7rem; padding: 0.5rem 0.7rem; background: var(--panel);
           border-left: 2px solid var(--edge); font-size: 0.8125rem; color: var(--ink-soft); }
.changed b { display: block; color: var(--ink); font-size: 0.75rem; text-transform: uppercase;
             letter-spacing: 0.06em; margin-bottom: 0.25rem; }
.changed ul { margin: 0; padding-left: 1.1rem; }
.changed li { margin-top: 0.15rem; }
.changed li b { display: inline; text-transform: none; letter-spacing: 0; font-size: inherit; }

.recurrence { margin-top: 0.7rem; padding: 0.5rem 0.7rem; background: var(--signal-soft);
              border-left: 2px solid var(--signal); color: var(--signal);
              font-size: 0.8125rem; font-weight: 600; }
.recurrence a { color: var(--ink); margin-left: .3rem; }
.logq td, .logq th { font-size: .8125rem; white-space: nowrap; }
.logq td code { white-space: normal; overflow-wrap: anywhere; }
/* A namespace is one word: broken anywhere it read "calib.sca / n". The table scrolls instead. */
.logq td.ns code { white-space: nowrap; overflow-wrap: normal; }
.logq .collscan { color: var(--bad); }
.tod { margin: .4rem 0 .8rem; max-width: 40rem; }
.tod figcaption { font-size: .8125rem; color: var(--ink-faint); }
.tod svg { width: 100%; height: auto; display: block; }
.tod .axis, .tod .tick { stroke: var(--edge); stroke-width: 1; }
.tod text { fill: var(--ink-faint); font-size: 10px; text-anchor: middle; }
.tod circle.then { fill: var(--ink-soft); opacity: .75; }
.tod circle.now { fill: var(--signal); }
.pattern { border-left: 3px solid var(--signal); padding: .4rem .8rem; margin: 0 0 1rem;
           background: var(--signal-soft); }
.recurrence.first { background: transparent; border-left-color: var(--edge);
                    color: var(--ink-faint); font-weight: 400; }

.quiet { background: var(--panel); border: 1px solid var(--edge);
         border-left: 3px solid var(--ok); padding: 1.1rem 1.3rem; }
.quiet b { color: var(--ok); }
/* Work in flight is not a clean bill of health, so it does not get the green: the same accent
   the product uses everywhere for "look here", and no other difference. */
.working { border-left: 3px solid var(--signal); }
.quiet.working b { color: var(--signal); }
.working-head { display: flex; justify-content: space-between; align-items: baseline;
                margin: 0 0 .6rem; }
/* The percentage is the thing being read, so it is the one number in monospace: it changes
   every few seconds and proportional digits make it jump around. */
.working-head span { font-family: var(--mono); font-size: .8125rem; color: var(--ink-soft); }
.working-note { margin: .5rem 0 0; color: var(--ink-soft); font-size: .875rem; }
.bar { height: .4rem; background: var(--edge-soft); overflow: hidden; }
.bar > span { display: block; height: 100%; background: var(--signal);
              transition: width .4s linear; }
/* Striped when the fraction is an estimate rather than a count -- the phase where Atlas is
   building the bundle and tells us nothing but "in progress". The texture is the difference
   between a measurement and a guess, without a sentence having to say it twice. */
.bar.guess > span { background-image: linear-gradient(115deg,
                    rgba(255,255,255,.35) 25%, transparent 25%, transparent 50%,
                    rgba(255,255,255,.35) 50%, rgba(255,255,255,.35) 75%, transparent 75%);
                    background-size: .7rem .7rem; }
.quiet p { margin: 0.3rem 0 0; color: var(--ink-soft); font-size: 0.875rem; }

/* "I fixed this" sits closed by default: it is an action on an incident you have already read,
   so it must not compete with reading it. */
.fixed summary { color: var(--ok); }
.fixed form { display: flex; gap: .5rem; align-items: flex-end; flex-wrap: wrap;
              margin-top: .4rem; }
.fixed input[type=text] { flex: 1; min-width: 14rem; margin: 0; }
.fixed label { display: block; font-size: .8125rem; color: var(--ink-soft); }
.fixed .hint { margin: .5rem 0 0; font-size: .8125rem; color: var(--ink-faint); }

.aside { margin: 1rem 0 0; font-size: .875rem; }
.aside a { color: var(--ink-soft); }
.keep { margin: 3rem 0 0; font-size: .875rem; color: var(--ink-soft); }
.keep + .remove, .keep + .keep { margin-top: .6rem; padding-top: 0; border-top: none; }
.remove { margin: 3rem 0 0; padding-top: 1rem; border-top: 1px solid var(--edge-soft);
          font-size: .875rem; }
.remove a { color: var(--bad); }

/* The history: same anatomy as a finding card, without the chart and without the accent --
   nothing here is asking for attention. */
.closed { background: var(--panel); border: 1px solid var(--edge);
          border-left: 3px solid var(--edge); padding: 1rem 1.2rem; margin-bottom: .8rem; }
.closed .head { display: flex; justify-content: space-between; align-items: flex-start;
                gap: 1rem; }
.closed h3 { margin: 0 0 .3rem; font-size: 1rem; }
.closed h3 a { color: inherit; text-decoration: none; }
.closed h3 a:hover { color: var(--signal); text-decoration: underline; }
.closed .facts { display: flex; flex-wrap: wrap; gap: .8rem; font-family: var(--mono);
                 font-size: .75rem; color: var(--ink-faint); }
/* The customer's own sentence about their cluster. It is the most valuable line on the page,
   so it is set as a quotation and not as metadata. */
.closed .note { margin: .8rem 0 0; padding-left: .8rem; border-left: 2px solid var(--ok);
                color: var(--ink); font-size: .9375rem; }
.closed .note.none { border-left-color: var(--edge-soft); color: var(--ink-faint);
                     font-style: italic; }
.closed .when { margin-top: .6rem; font-size: .75rem; color: var(--ink-faint); }
button.small { padding: .3rem .6rem; font-size: .8125rem; }

h2 { font-size: 1.0625rem; margin: 2rem 0 0.8rem; }
/* Wider than the rest of the page, on purpose. The `.wrap` around everything else is 44rem
   because that is a comfortable line of prose, and this section is not prose -- it is five
   columns of measurements. Inside the reading column the metric names wrapped over three lines
   next to numbers that needed none. Widened symmetrically about the centre and clamped to the
   viewport, so it can never be the thing that makes the page scroll sideways. */
.embedded { --wide: min(58rem, calc(100vw - 2rem));
            width: var(--wide); margin-left: calc(50% - var(--wide) / 2);
            background: var(--panel); border: 1px solid var(--edge); padding: 0.5rem 1rem; }
.embedded .wrap { padding: 0; max-width: none; }
.embedded .head, .embedded footer { display: none; }
.embedded > h2:first-child { margin-top: 0; }
/* The introduction and the legend are prose and stay at a readable measure, even though the
   table beside them is wider. */
.embedded > p { color: var(--ink-soft); font-size: 0.875rem; margin: 0 0 0.9rem;
                max-width: 42rem; }
""" + profile_report.table_css(".embedded") + """
"""

INCIDENT_CSS = """
/* Adding a cluster: two doors, then the drop zone for FTDC files. */
.doors { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 1rem;
         margin-top: 1rem; }
a.door { display: flex; flex-direction: column; gap: .5rem; padding: 1.4rem 1.3rem;
         background: var(--panel); border: 1px solid var(--edge); text-decoration: none;
         color: var(--ink-soft); }
a.door b { color: var(--ink); font-size: 1.125rem; }
a.door:hover, a.door:focus-visible { border-color: var(--signal); }
a.door.recommended { border-left: 3px solid var(--signal); }
h2 .optional { font-weight: 400; color: var(--ink-faint); font-size: .875rem; }
.drop { display: flex; flex-direction: column; gap: .4rem; align-items: center; text-align: center;
        padding: 1.8rem 1rem; border: 1px dashed var(--edge); color: var(--ink-soft); }
.drop.over { border-color: var(--signal); background: var(--signal-soft); }
.drop b { color: var(--ink); }
.drop input[type=file] { display: none; }
label.link { display: inline; font-weight: 400; color: var(--signal); text-decoration: underline;
             cursor: pointer; font-size: inherit; margin: 0; }
.upload { padding: .7rem 0; border-bottom: 1px solid var(--edge-soft); }
.upload .use-bar { margin-top: .4rem; }
.progress { display: flex; gap: .6rem; align-items: center; margin-top: .6rem; max-width: 32rem; }
.progress .meta { font-size: .875rem; color: var(--ink-soft); white-space: nowrap; }
.progress .use-bar::after { background: var(--ink-soft); transition: width .4s; }
.upload ul { margin: .4rem 0 0; padding-left: 1.1rem; font-size: .875rem; color: var(--ink-soft); }
.upload.failed .meta { color: var(--bad); }

/* The catalog of checks. */
article.rule { scroll-margin-top: 1rem; }
article.rule:target { outline: 1px solid var(--signal); }
code.rule-id { font-size: .75rem; color: var(--ink-faint); font-weight: 400; margin-left: .3rem; }
p.speaks { font-size: .9375rem; color: var(--ink-soft); }
p.speaks b { color: var(--ink); font-weight: 600; margin-right: .3rem; }
p.metric-expr code { font-size: .75rem; color: var(--ink-faint); word-break: break-all; }
ul.watched { margin: .4rem 0 .6rem; padding-left: 1.1rem; font-size: .9rem; }
ul.watched code { font-size: .72rem; color: var(--ink-faint); word-break: break-all; }

/* The add page: the one command to create the monitoring user, and the folded file option. */
pre.snippet { background: var(--ground); border: 1px solid var(--edge); padding: .7rem .9rem;
              font-family: var(--mono); font-size: .8125rem; white-space: pre-wrap;
              overflow-x: auto; color: var(--ink); }
details.card-fold { margin-top: 1rem; }
details.card-fold > summary { cursor: pointer; color: var(--ink-soft); font-size: .9375rem;
                              margin-bottom: .6rem; }

/* The cluster picker on the add page. */
label.pick { display: flex; gap: .6rem; align-items: baseline; font-weight: 400;
             padding: .5rem 0; border-bottom: 1px solid var(--edge-soft); }
label.pick input { margin: 0; }

/* Forms need the server that serves the site; opened from disk there is none. */
.from-disk .needs-server { display: none; }
/* Printed, which in practice means saved as PDF to send to somebody. The page keeps its dark
   colours: the charts are drawn on the panel colour, and on white paper each one became a dark
   slab. Forms and the button go, since nobody can submit anything from a PDF. A chart is never
   cut across two pages, but a finding is: kept whole, each one is 40% of a page, and every one
   that did not fit left the rest of the page blank -- 36 pages for `test`, a third of them
   empty. What has to stay together is a heading or a timestamp with what follows it. */
header.top button.save-pdf { margin-left: 0.8rem; }
@media print {
  @page { margin: 0; }
  html, body { -webkit-print-color-adjust: exact; print-color-adjust: exact;
               background: var(--ground); }
  /* Cloned, so every page gets the top and bottom padding and not just the first and last:
     a margin on @page would print white around the dark page. */
  .wrap { max-width: none; padding: 12mm 14mm; box-decoration-break: clone;
          -webkit-box-decoration-break: clone; }
  .save-pdf, .needs-server, .zoom, form { display: none !important; }
  .card, img.shape, figure, tr, .facts, .recurrence { break-inside: avoid; }
  h1, h2, h3, .stamp, .finding .head, .finding .head + p { break-after: avoid; }
  /* A grid row does not split across pages in Chrome: a moment with two signals, taller
     than what was left of the page, moved whole and left a blank page behind it. */
  ol.axis { display: block; }
  ol.axis > li + li { margin-top: 1.6rem; }
}
form.inline { display: inline; margin: 0; }
.fixed-note { margin: 1.5rem 0; border-left: 3px solid var(--ok); }
.fixed-note p { margin: 0 0 .4rem; }

/* Capacity: one row per resource, the bar is the share of it used at the busiest moment. */
table.capacity th { text-align: left; }
table.capacity td.num, table.capacity .num { font-family: var(--mono); white-space: nowrap; }
.bar-cell { display: flex; align-items: center; gap: .5rem; min-width: 9rem; }
.use-bar { flex: 1; height: .45rem; background: var(--edge); position: relative; }
.use-bar::after { content: ""; position: absolute; inset: 0 auto 0 0; width: var(--w);
                  background: var(--ink-faint); }
.use-bar[data-level="high"]::after { background: var(--bad); }
.use-bar[data-level="low"]::after { background: var(--ok); }
.capacity-line { font-weight: 600; margin: 0 0 .8rem; }
.capacity-line[data-state="tight"] { color: var(--bad); }
.capacity-line[data-state="spare"] { color: var(--ok); }
ul.forecasts { margin: 0 0 1rem; padding-left: 1.1rem; }
ul.forecasts a { color: var(--warn); }
/* Configuration: true all the time, so not on the timeline. A list to work through. */
ol.config { list-style: none; margin: 0 0 1rem; padding: 0; display: grid; gap: .6rem; }
ol.config > li { background: var(--panel); border: 1px solid var(--edge);
                 border-left: 3px solid var(--sev-colour, var(--ink-faint)); padding: .9rem 1.1rem; }
ol.config > li[data-sev="warning"] { --sev-colour: var(--warn); }
ol.config b { display: block; margin-bottom: .2rem; }
ol.config p { margin: .25rem 0 0; color: var(--ink-soft); font-size: .9rem; }
ol.config p.fix { color: var(--ink); }
ol.config .who { font-family: var(--mono); font-size: .8rem; color: var(--ink-faint); }

/* The verdict: the answer before the evidence. The colour is the state; the rail makes it
   readable in a glance down a list, and the text says it again for anyone who cannot rely on
   colour. */
.verdict { border: 1px solid var(--edge); border-left: 4px solid var(--v); background: var(--panel);
           padding: 1rem 1.2rem; margin: 0 0 1.5rem; }
.verdict, .verdict-pill { --v: var(--ink-faint); }
[data-state="healthy"] { --v: var(--ok); }
[data-state="attention"] { --v: var(--warn); }
[data-state="at_risk"] { --v: var(--bad); }
[data-state="unwatched"] { --v: var(--signal); }
[data-state="analyzing"], [data-state="pending"], [data-state="waiting"],
[data-state="capturing"] { --v: var(--ink-soft); }
[data-state="failed"], [data-state="capture_failed"] { --v: var(--bad); }
[data-state="files_problems"] { --v: var(--warn); }
[data-state="files_clean"] { --v: var(--ok); }
.verdict-label { color: var(--v); font-weight: 700; font-size: 1.125rem; margin-bottom: .25rem; }
.verdict p { margin: 0; color: var(--ink-soft); }
.verdict a { color: var(--ink); }
.verdict ul { margin: .6rem 0 0; padding-left: 1.1rem; color: var(--ink-soft); font-size: .9375rem; }
.verdict-pill { display: inline-block; margin-left: .5rem; padding: 0 .45rem; font-size: .75rem;
                font-weight: 600; color: var(--v); border: 1px solid var(--v); vertical-align: middle; }

/* The incident itself, pinned to the axis. It gets the panel and the severity rail; the two
   events above it on the spine are lines, because they are context and this is the subject. */
.here { background: var(--panel); border: 1px solid var(--edge);
        border-left: 3px solid var(--sev-colour); padding: 1.2rem 1.4rem; }
li[data-sev="critical"] .here { --sev-colour: var(--bad); }
li[data-sev="warning"] .here  { --sev-colour: var(--warn); }
li[data-sev="info"] .here     { --sev-colour: var(--ink-faint); }
.here h1 { font-size: 1.375rem; }
.here h2 { font-size: 0.8125rem; text-transform: uppercase; letter-spacing: 0.07em;
           color: var(--ink-faint); margin: 1.6rem 0 0.5rem; }
.what.earlier { margin: 0; color: var(--ink-soft); font-size: 0.9375rem; }
.sev.big { font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
           letter-spacing: 0.08em; margin-bottom: 0.2rem; }
.facts.big { display: flex; flex-wrap: wrap; gap: 2rem; margin: 1.3rem 0 0;
             padding: 1rem 0; border-top: 1px solid var(--edge);
             border-bottom: 1px solid var(--edge); }
.facts.big b { display: block; font-family: var(--mono); font-size: 1.25rem; font-weight: 600; }
.facts.big span { font-size: 0.75rem; color: var(--ink-faint); }
.advice { background: var(--panel); border: 1px solid var(--edge); padding: 1rem 1.2rem;
          color: var(--ink-soft); font-size: 0.9375rem; }
.node-panel { background: var(--panel); border: 1px solid var(--edge); padding: 0.9rem 1.1rem;
              margin-bottom: 0.7rem; }
.node-head { display: flex; justify-content: space-between; align-items: baseline;
             gap: 1rem; font-size: 0.8125rem; }
.node-head b { font-family: var(--mono); }
.node-head span { color: var(--ink-faint); font-size: 0.75rem; }
.node-panel .shape { margin: 0.6rem 0 0; }
table .current { background: var(--signal-soft); font-weight: 600; }
table .current td { color: var(--signal); }
td.muted { color: var(--ink-faint); }
"""


# --------------------------------------------------------------------------- the pages

# The moment the site is built as of; see build().
_NOW: datetime | None = None

# How far back the cluster page looks. Everything older is on the history page, not gone:
# there is no "mark as fixed" without a database, so age is what keeps the report readable.
WINDOW_DAYS = 30

# What to go and look at when a cluster goes quiet, by how its files arrive. Spelled the way
# `state.json` spells the kind.
CAUSES = {
    "atlas": [
        "the API key was deleted, or the access list it is allowed from changed",
        "the cluster was paused or deleted in Atlas",
    ],
    "directory": [
        "the server stopped writing diagnostics — most often because it is not running",
        "the directory the collector reads moved, or the mount went away",
    ],
    "ssh": [
        "the host stopped answering, or the key the collector uses was removed",
    ],
    "onprem": [
        "the collector cannot connect: the password changed, the user was dropped, or the "
        "network path to the members is closed",
        "the poller service is not running",
    ],
}
CAUSES["mongodb"] = CAUSES["onprem"]  # the name the first version gave this source
DEFAULT_CAUSES = ["something between the cluster and the collector stopped"]


def esc(v) -> str:
    return (str(v).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def layout(title: str, body: str, root: str, generated: datetime) -> str:
    """Every page shares one stylesheet. `root` is the relative way back to the site's top,
    so the site works from disk and from any path it is served under."""
    stamp = generated.strftime("%d %b %Y · %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title><style>{CSS}{REPORT_CSS}{INCIDENT_CSS}</style></head>
<body><script>
  /* Opened from disk there is no server to receive a form, so the forms are not offered. */
  if (location.protocol === "file:") document.documentElement.classList.add("from-disk");
</script><div class="wrap">
<header class="top"><a class="brand" href="{root}index.html">mongo-health</a>
  <span>as of {esc(stamp)}
    <button type="button" class="secondary small save-pdf">Save as PDF</button></span></header>
{body}
<footer>Rebuilt after every collector run. Times are UTC. Analysis by
  <a href="https://github.com/zelmario/Big-hole">Big Hole</a>.</footer>
</div><script>{ZOOM_JS}</script></body></html>"""


# A chart, a click away from filling the screen; a click or Esc puts it back.
ZOOM_JS = r"""
document.addEventListener('click', (e) => {
  const open = document.querySelector('.zoom');
  if (open) { open.remove(); return; }
  const img = e.target.closest('img.shape');
  if (!img) return;
  const zoom = document.createElement('div');
  zoom.className = 'zoom';
  zoom.innerHTML = '<img alt="">';
  zoom.firstChild.src = img.currentSrc || img.src;
  zoom.firstChild.alt = img.alt;
  document.body.appendChild(zoom);
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') document.querySelector('.zoom')?.remove();
});

/* The browser's own print dialog, with "Save as PDF" as the destination. Folded sections are
   opened first, because a PDF cannot be clicked: whatever is closed when it is made is lost to
   whoever it is sent to. They are folded back afterwards, so the page is left as it was.

   Charts load lazily, so one the reader never scrolled to was not there yet when print() ran,
   and the PDF had an empty box where it should be. Every chart is fetched first. */
document.querySelector('.save-pdf')?.addEventListener('click', async () => {
  const closed = [...document.querySelectorAll('details:not([open])')]
    .filter((d) => !d.closest('.needs-server'));
  closed.forEach((d) => { d.open = true; });
  const images = [...document.images];
  images.forEach((img) => { img.loading = 'eager'; });
  await Promise.all(images.map((img) => img.complete ? null : new Promise((done) => {
    img.addEventListener('load', done, { once: true });
    img.addEventListener('error', done, { once: true });
  })));
  addEventListener('afterprint', () => closed.forEach((d) => { d.open = false; }), { once: true });
  print();
});
/* Ctrl+P skips the button. Too late to wait for the charts, but it starts fetching them, so a
   second try has them all. */
addEventListener('beforeprint', () => {
  [...document.images].forEach((img) => { img.loading = 'eager'; });
});
"""


def chart_name(finding: dict) -> str:
    """Named by what is drawn, not by which finding it belongs to: a re-analysis that changes
    the series produces a new file, and nothing has to remember to invalidate the old one."""
    import hashlib
    drawn = {"style": CHART_STYLE, "chart": finding["chart"]}
    return hashlib.sha256(json.dumps(drawn, sort_keys=True).encode()).hexdigest()[:16] + ".png"


def draw_chart(finding: dict, charts: Path) -> str | None:
    """The chart's file name, drawing it only if it is not there yet.

    Drawing is the expensive part of the whole report -- a second of matplotlib per chart --
    and a finding's chart never changes, so an hourly rebuild draws only what is new.
    """
    if not has_chart(finding):
        return None
    name = chart_name(finding)
    path = charts / name
    if not path.exists():
        png = incident_chart(finding["chart"], finding.get("severity", "warning"),
                             finding["worstFromMs"], finding["worstToMs"], finding["rule"],
                             finding.get("metric") or "",
                             window=(finding["fromMs"], finding["toMs"]))
        if png is None:
            return None
        charts.mkdir(parents=True, exist_ok=True)
        tmp = charts / f".{name}.{secrets.token_hex(4)}.tmp"
        tmp.write_bytes(png)
        tmp.replace(path)      # atomic: a reader never gets half a picture
    return name


def chart_img(src: str, alt: str, css_class: str = "shape") -> str:
    # Width and height are stated so the text does not jump about as the images load.
    return (f'<img class="{css_class}" width="{CHART_W}" height="{CHART_H}" loading="lazy" '
            f'src="{esc(src)}" alt="{esc(alt)}">')


def silent_hours(state: dict, now: datetime, summary: dict | None = None) -> float | None:
    """Hours since the newest sample held, if that is longer than the watchdog allows, else None.

    The newest SAMPLE, from the analysis, not when files last arrived: a directory that is
    handed six-week-old files today delivers new files and no present, and the page said "no
    data for 9 hours" about a replica set whose last sample was from August. Before there is an
    analysis, the arrival is all there is. Measured on Atlas, the newest sample trails the
    capture by minutes, so the watchdog's threshold holds for both.

    Worked out from timestamps and the clock when the page is built, never read from a stored
    "healthy" flag -- the collector having stopped is exactly when such a flag would be wrong.
    """
    at = newest_sample(state, summary)
    if at is None:
        return None
    hours = (now - at).total_seconds() / 3600
    return hours if hours > STALE_AFTER_HOURS else None


ANALYZING_FOR_AT_MOST_HOURS = 6
# Atlas gets half an hour to build the first bundle (sources.BOOTSTRAP_TIMEOUT) and the download
# ten minutes; past twice that, the marker is from a run that was killed.
CAPTURING_FOR_AT_MOST_HOURS = 2


def read_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def arriving(base: Path) -> dict | None:
    """What has reached `incoming/` for a cluster that has not been captured yet.

    `members` counts the members the poller is reading without error, or that have files
    waiting; `error` is the first error the poller reported, said as it said it.
    """
    incoming = base / "incoming"
    if not incoming.is_dir():
        return None
    try:
        status = json.loads((incoming / "status.json").read_text())
    except (OSError, ValueError):
        status = {}
    members = status.get("members") or {}
    error = status.get("error") or next((m["error"] for m in members.values()
                                         if isinstance(m, dict) and m.get("error")), None)
    if error:
        return {"error": error}
    reading = {k for k, m in members.items() if isinstance(m, dict) and m.get("last_sample")}
    with_files = {d.name for d in incoming.iterdir() if d.is_dir() and any(d.glob("metrics.*"))}
    n = max(len(reading), len(with_files))
    return {"members": n} if n else None


def analyzing(base: Path, now: datetime) -> dict | None:
    """What an analysis running over this cluster is reading, if one is.

    One older than any analysis takes is a run that was killed before it could clear it, and
    trusting it would say "Analyzing FTDC" for ever.
    """
    try:
        marker = json.loads((base / "analyzing.json").read_text())
        started = datetime.fromisoformat(marker["started"].replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return marker if (now - started).total_seconds() < ANALYZING_FOR_AT_MOST_HOURS * 3600 else None


def capturing(base: Path, now: datetime) -> dict | None:
    """What a fetch from this cluster's source is doing, if one is running (capture.py)."""
    try:
        marker = json.loads((base / "capturing.json").read_text())
        started = datetime.fromisoformat(marker["started"].replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return marker if (now - started).total_seconds() < CAPTURING_FOR_AT_MOST_HOURS * 3600 else None


def newest_sample(state: dict, summary: dict | None = None) -> datetime | None:
    """The newest sample held, or, before there is an analysis, when files last arrived."""
    samples = [n.get("to") for n in (summary or {}).get("nodes") or [] if n.get("to")]
    last = max(samples) if samples else (state.get("last_new_data") or state.get("last_capture"))
    if not last:
        return None
    try:
        return datetime.fromisoformat(last.replace("Z", "+00:00"))
    except ValueError:
        return None


def how_long_silent(hours: float) -> str:
    """Rounded the way somebody says it, and never rounded down to "0 hours"."""
    if hours < 48:
        return "about an hour" if hours < 1.5 else f"about {hours:.0f} hours"
    return f"{hours / 24:.0f} days"


def is_change(f: dict) -> bool:
    """A setting that moved. Drawn as a point on the axis, not as an incident card: it is
    context for the incidents around it, and as a card it said the same resize twice."""
    return f.get("rule") == "setting-changed"


SHOWN_TIMES = 50

# When a check keeps firing at the same time of day, or the same minutes of the hour, that is
# the signature of something on a schedule. Searching every minute of the period for the best
# window finds one by chance easily -- four of five starts inside some six-minute window of the
# hour happens about one time in twenty -- so a window is only called a pattern when that many
# starts falling in it by chance, anywhere in the period, is under one in a hundred.
SCHEDULES = [(1440, 15), (60, 3), (30, 3)]
PATTERN_AT_LEAST, PATTERN_CHANCE = 4, 0.01


def _chance(hits: int, n: int, share: float, tries: int) -> float:
    """How likely `hits` of `n` uniform starts land in a window covering `share` of the
    period, at the best of `tries` positions (Bonferroni: generous, so it errs towards
    saying nothing)."""
    from math import comb

    tail = sum(comb(n, k) * share ** k * (1 - share) ** (n - k) for k in range(hits, n + 1))
    return min(1.0, tail * tries)


def schedule_pattern(starts_ms: list[int]) -> dict | None:
    """The schedule these starts keep, if one is strong enough not to be chance.

    Returns {"period", "at" (minutes into the period), "hits", "text"}. Of the schedules that
    pass, the least likely to be chance wins: nine of nine at :02 or :32 is said as such, not
    as the five of them that happen to be at :02.
    """
    n = len(starts_ms)
    if n < PATTERN_AT_LEAST:
        return None
    minutes = [(ms // 60000) % 1440 for ms in starts_ms]
    found = []
    for period, window in SCHEDULES:
        def off(m, c):
            d = abs(m % period - c)
            return min(d, period - d)
        best = max(range(period), key=lambda c: (sum(off(m, c) <= window for m in minutes),
                                                 -sum(min(off(m, c), window) for m in minutes)))
        hits = sum(off(m, best) <= window for m in minutes)
        chance = _chance(hits, n, (2 * window + 1) / period, period)
        if hits >= PATTERN_AT_LEAST and chance < PATTERN_CHANCE:
            found.append((chance, -period, period, window, best, hits))
    if not found:
        return None
    _, _, period, window, best, hits = min(found)
    if period == 1440:
        at = f"{best // 60:02d}:{best % 60:02d} UTC"
    elif period == 60:
        at = f":{best:02d} past the hour"
    else:
        at = f":{best:02d} or :{best + 30:02d}"
    return {"period": period, "at": best, "hits": hits,
            "text": f"{hits} of {n} started within {window} minutes of {at}. That is the shape "
                    f"a scheduled job leaves: a cron, a backup, a batch load."}


def time_of_day(starts_ms: list[int], pattern: dict | None) -> str:
    """Where in the day each one started, or where in the hour when that is the pattern. The
    newest is this incident, and is drawn in the accent."""
    hourly = pattern is not None and pattern["period"] < 1440
    span = 60 if hourly else 1440
    ticks = ([(0, ":00"), (15, ":15"), (30, ":30"), (45, ":45"), (60, ":00")] if hourly else
             [(h * 60, f"{h:02d}h") for h in (0, 6, 12, 18, 24)])
    left, width = 10, 580
    x = lambda minute: left + width * minute / span  # noqa: E731
    marks = "".join(f'<line class="tick" x1="{x(m):.1f}" x2="{x(m):.1f}" y1="20" y2="25"/>'
                    f'<text x="{x(m):.1f}" y="38">{label}</text>' for m, label in ticks)
    dots = []
    for i, ms in enumerate(starts_ms):
        minute = ((ms / 60000) % span) if hourly else ((ms / 60000) % 1440)
        dots.append(f'<circle class="{"now" if i == 0 else "then"}" cx="{x(minute):.1f}" '
                    f'cy="{12 - (i % 3) * 3}" r="4"><title>{esc(when_ms(ms))}</title></circle>')
    name = "Minute of the hour" if hourly else "Time of day, UTC"
    return (f'<figure class="tod"><figcaption>{name}</figcaption>'
            f'<svg viewBox="0 0 600 42" role="img" aria-label="{name} of each start">'
            f'<line class="axis" x1="{left}" x2="{left + width}" y1="20" y2="20"/>'
            f'{marks}{"".join(dots[1:])}{dots[0]}</svg></figure>')


def recurrence(earlier: list, every: str = "") -> str:
    """`earlier` are incidents, newest first; `every` is where the full list is."""
    if earlier:
        n = len(earlier) + 1
        link = f' <a href="{esc(every)}">See all {n}</a>' if every else ""
        return (f'<div class="recurrence">This has happened {n} times on this cluster. The one '
                f'before was {esc(when_ms(earlier[0].from_ms))}.{link}</div>')
    # Said explicitly rather than left blank: "first time we have seen this" is information
    # too, and its absence would read as missing data.
    return '<div class="recurrence first">First time we have seen this on this cluster.</div>'


def change_points(changes: list[dict]) -> list[tuple[int, str]]:
    """One point per change, however many analysis windows reported it.

    Oldest first before deduplicating, so a run of repeats collapses onto the earliest --
    which is when the change happened, not when the last window noticed it. Same title within
    an hour is the same change.
    """
    seen: list[tuple[str, int]] = []
    out = []
    for c in sorted(changes, key=lambda c: c["worstFromMs"]):
        if any(t == c["title"] and abs(ms - c["worstFromMs"]) < 3_600_000 for t, ms in seen):
            continue
        seen.append((c["title"], c["worstFromMs"]))
        out.append((c["worstFromMs"], f"""
            <li class="change">
              <p class="stamp">{esc(when_ms(c["worstFromMs"]))}
                <span>{esc(how_long_ago(c["worstFromMs"]))}</span></p>
              <p class="what"><b><a href="incidents/{esc(c["id"])}.html">{esc(c["title"])}</a></b>
                <span>— something changed on this cluster</span></p>
            </li>"""))
    return out


def fix_form(g, action: str) -> str:
    """"I fixed this", with room to say what was done. Posted to the server that serves the
    site; hidden when the site is opened from disk, where there is nothing to post to."""
    ids = ",".join(m["id"] for m in g.members)
    return f"""
          <details class="fixed needs-server">
            <summary>I fixed this</summary>
            <form method="post" action="{esc(action)}">
              <input type="hidden" name="ids" value="{esc(ids)}">
              <label for="note-{esc(g.worst['id'])}">What did you do? (optional)</label>
              <input id="note-{esc(g.worst['id'])}" name="note" type="text" autocomplete="off"
                     maxlength="{resolutions.NOTE_LIMIT}"
                     placeholder="Added an index on orders.customer_id">
              <button type="submit" class="secondary">Mark as fixed</button>
            </form>
            <p class="hint">It leaves the report and goes to the cluster's history, with your
              note. If it happens again, it comes back and counts as a repeat.</p>
          </details>"""


def reopen_form(g, action: str) -> str:
    ids = ",".join(m["id"] for m in g.members)
    return f"""
            <form method="post" action="{esc(action)}" class="needs-server inline">
              <input type="hidden" name="ids" value="{esc(ids)}">
              <button type="submit" class="secondary small">Put it back</button>
            </form>"""


def card(g, cluster_id: str, findings: list[dict], chart_file, muted: set[str]) -> str:
    """One incident on the cluster page: the worst-affected node's chart, and its history."""
    f = g.worst
    if (name := chart_file(f)):
        label, _, _ = measured(g.rule, f.get("metric") or "")
        chart = (chart_img(f"charts/{name}", f"{label} during the incident")
                 + f'<details class="raw"><summary>{esc(label)}</summary>'
                 f'<code>{esc(f.get("metric") or "")}</code></details>')
    else:
        # Gap findings have no series behind them -- their evidence is its absence.
        chart = ('<div class="metric">This one is the absence of data, not a value — '
                 'there is no series to plot.</div>')
    hushed = ('<p class="hint">Muted in the config: still detected and shown here, '
              'no email.</p>' if g.rule in muted else "")
    return f"""
        <article class="finding" data-sev="{esc(g.severity)}">
          <div class="head">
            <div>
              <div class="sev">{esc(SEVERITY_LABEL.get(g.severity, g.severity))}</div>
              <h3><a href="incidents/{esc(f['id'])}.html">{esc(g.headline())}</a></h3>
            </div>
          </div>
          <p>{esc(f.get('what') or '')}</p>
          {chart}
          <div class="facts">
            <span title="nodes">{esc(name_nodes(g.nodes))}</span>
            {f'<span title="how long">{esc(duration(g.seconds_in_state))} in state</span>'
             if g.seconds_in_state else ''}
            {episodes_fact(g)}
          </div>
          {recurrence(earlier_incidents(findings, g.rule, g.from_ms),
                      f"incidents/{f['id']}.html#times")}
          <details>
            <summary>What to check next</summary>
            <p>{esc(f.get('check') or '')}</p>
            <p><a href="../rules.html#{esc(catalog.anchor(g.rule))}" target="_blank"
               rel="noopener">About this check</a> —
               what it measures and why at that threshold.</p>
          </details>
          {hushed}
          {fix_form(g, "resolve")}
        </article>"""


# Polls the server for how far an analysis has got. When it has finished, waits for the page
# itself to be rebuilt before reloading: reloading straight away showed the old page again, which
# started polling again, and reloaded in a loop until the rebuild landed.
PROGRESS_JS = r"""
(function () {
  if (window.__progress || location.protocol === 'file:') return;
  window.__progress = true;
  const els = Array.from(document.querySelectorAll('[data-progress]'));
  const short = (n) => String(n).split('.')[0].replace(/_\d+$/, '');
  function draw(el, p) {
    const bar = el.querySelector('.use-bar'), meta = el.querySelector('.meta');
    const mb = (b) => (b / 1048576).toFixed(0) + ' MB';
    const mins = (s) => s < 90 ? Math.round(s) + ' s' : Math.round(s / 60) + ' min';
    // A full re-analysis is several runs, each counting its own files: one bar across them all.
    const many = p.parts > 1;
    const whole = (f) => many ? (p.part - 1 + f) / p.parts : f;
    const week = many ? (p.part < p.parts ? 'week ' + p.part + ' of ' + (p.parts - 1) : 'last days')
      + ' · ' : '';
    if (p.stage === 'checks') {
      bar.style.setProperty('--w', (100 * whole(1)).toFixed(0) + '%');
      meta.textContent = week + 'running the checks…';
    } else if (p.stage === 'queued') {
      meta.textContent = 'files received, the analysis starts in a moment…';
    } else if (p.stage === 'order') {
      meta.textContent = 'asking Atlas for the FTDC…';
    } else if (p.stage === 'build') {
      // Atlas reports a status and no percentage: a fraction only when this cluster has been
      // timed before (sources.AtlasSource._wait), otherwise just how long it has been.
      if (p.total) bar.style.setProperty('--w', (100 * p.done / p.total).toFixed(0) + '%');
      meta.textContent = 'Atlas is preparing the bundle · ' + mins(p.elapsed || 0) + ' so far';
    } else if (p.stage === 'download') {
      if (p.total) bar.style.setProperty('--w', (100 * p.done / p.total).toFixed(0) + '%');
      meta.textContent = 'downloading · ' + mb(p.done) + (p.total ? ' of ' + mb(p.total) : '');
    } else if (p.total) {
      bar.style.setProperty('--w', (100 * whole(p.done / p.total)).toFixed(0) + '%');
      meta.textContent = week + p.done + ' of ' + p.total + ' files'
        + (p.node ? ' · ' + short(p.node) : '');
    }
  }
  function settled() {
    fetch(location.href, { cache: 'no-store' }).then((r) => r.text()).then((t) => {
      if (t.includes('data-progress')) setTimeout(settled, 3000); else location.reload();
    }).catch(() => setTimeout(settled, 3000));
  }
  function tick() {
    Promise.all(els.map((el) => fetch(el.dataset.progress, { cache: 'no-store' })
      .then((r) => r.json())
      .then((p) => { if (p.analyzing) { draw(el, p); return false; } return true; })
      .catch(() => false)))
      .then((finished) => {
        if (finished.some(Boolean)) {
          els.forEach((el) => { el.querySelector('.meta').textContent = 'finished, updating the page…'; });
          settled();
        } else setTimeout(tick, 2000);
      });
  }
  tick();
})();
"""


# The states something is running in, which get the progress bar: a first fetch, files waiting
# for the analysis that follows it, and the analysis itself. One bar across all three, so the page
# does not go still in the gap between capture and analysis.
BUSY = ("capturing", "pending", "analyzing")


def progress_bar(url: str) -> str:
    """Filled in by PROGRESS_JS from the server; opened from disk there is none to ask."""
    return (f'<div class="progress needs-server" data-progress="{esc(url)}">'
            f'<div class="use-bar" style="--w:0%"></div><span class="meta">starting…</span></div>'
            f'<script>{PROGRESS_JS}</script>')


def verdict_block(v: Verdict, state: dict, incidents: str, progress: str = "") -> str:
    """The answer, before any of the evidence. `incidents` is the relative path to the
    incident pages, so the moment that decided it is one click away."""
    link = ""
    if v.evidence:
        worst = v.evidence[0].groups[0].worst
        link = (f' <a href="{esc(incidents)}{esc(worst["id"])}.html">'
                f'See {"it" if len(v.evidence) == 1 else "the worst one"}</a>')
    causes = ""
    if v.state == "unwatched" and state.get("last_capture"):
        # What usually stops collection, by how the files arrive. Said here rather than in a
        # banner of its own: the verdict already says nobody is watching, and a second box
        # saying the same thing reads as two problems.
        causes = "<ul>" + "".join(
            f"<li>{esc(c[:1].upper() + c[1:])}.</li>"
            for c in CAUSES.get(state.get("source_kind") or "", DEFAULT_CAUSES)) + "</ul>"
    return f"""
    <section class="verdict" data-state="{esc(v.state)}">
      <div class="verdict-label">{esc(v.label)}</div>
      <p>{esc(v.reason)}{link}</p>
      {progress_bar(progress) if progress and v.state in BUSY else ""}
      {causes}
    </section>"""


# What each dimension of capacity is called on the page, in the order a DBA would read them.
RESOURCES = [("memory", "Memory"), ("cpu", "CPU"), ("cache", "WiredTiger cache"),
             ("concurrency", "Execution tickets"), ("connections", "Connections")]

# Above this at its worst moment, a resource is tight. Not the cache: WiredTiger keeps it filled
# to around 80% and evicts harder towards 95% by design, so a full cache is the engine working,
# and calling it tight would put "tight" on every busy cluster.
TIGHT_ABOVE = 0.9


def capacity(base: Path, summary: dict, findings: list[dict], now: datetime) -> dict:
    """Peak use of each resource against what the cluster has, over all the history held.

    The busiest member decides each row: every member of a replica set is the same size, so a
    resource is only spare if it is spare on the one that works hardest.
    """
    rows = sizing._rows(base / "baseline.jsonl")
    worst: dict[str, tuple[sizing.Resource, str]] = {}
    for node in summary.get("nodes") or []:
        key = node.get("node") or node.get("hostname")
        for r in sizing.resources_for(rows, key) if key else []:
            if r.name not in worst or r.fraction > worst[r.name][0].fraction:
                worst[r.name] = (r, node.get("hostname") or key)
    spans = [(row.get("fromMs"), row.get("toMs")) for row in rows
             if row.get("fromMs") and row.get("toMs")]
    days = ((max(t for _, t in spans) - min(f for f, _ in spans)) / 86_400_000) if spans else 0.0

    # CPU is stored as two rates, user and system, and their peaks need not be the same moment.
    # Their sum is what sizing uses, deliberately high; on the page it read 25.1 of 20 cores for
    # three members sharing one host. What is known is a range: at least the larger of the two,
    # at most the sum or the host, whichever is less. Tight is judged on the floor.
    cpu_floor = {}
    if "cpu" in worst:
        r, label = worst["cpu"]
        node = next((n for n in summary.get("nodes") or []
                     if (n.get("hostname") or n.get("node")) == label), {})
        key = node.get("node") or label
        ceiling = r.capacity
        user = sizing._peak(rows, "rate(systemMetrics.cpu.user_ms)", key, possible=ceiling) or 0
        system = sizing._peak(rows, "rate(systemMetrics.cpu.system_ms)", key,
                              possible=ceiling) or 0
        cpu_floor = {"low": max(user, system), "high": min(r.used, ceiling)}
        worst["cpu"] = (sizing.Resource("cpu", cpu_floor["low"], ceiling, "cores"), label)

    tight = [(name, worst[name][0]) for name, _ in RESOURCES
             if name in worst and name != "cache" and worst[name][0].fraction >= TIGHT_ABOVE]
    if not worst:
        state, line = "unknown", "Not enough measured yet to say."
    elif tight:
        label = dict(RESOURCES)
        state = "tight"
        line = "Tight: " + ", ".join(f"{label[n].lower()} peaked at {r.fraction * 100:.0f}%"
                                     for n, r in tight) + "."
    elif (days >= sizing.MIN_DAYS and {"memory", "cpu"} <= set(worst)
          and all(r.fraction < sizing.SPARE_BELOW for r, _ in worst.values())):
        state = "spare"
        line = (f"Larger than it needs: in {days:.0f} days nothing went past half of what the "
                f"cluster has.")
    else:
        state, line = "headroom", "Has headroom: nothing came close to its limit."

    now_ms = int(now.timestamp() * 1000)
    forecasts = [f for f in findings if f.get("rule") == "capacity-runway"
                 and int(f["toMs"]) >= now_ms - 7 * 86_400_000]
    return {"state": state, "line": line, "days": days, "worst": worst, "forecasts": forecasts,
            "cpu_range": cpu_floor}


def capacity_section(cap: dict) -> str:
    if not cap["worst"] and not cap["forecasts"]:
        return ""
    rows = []
    for name, label in RESOURCES:
        if name not in cap["worst"]:
            continue
        r, node = cap["worst"][name]
        pct = min(100.0, r.fraction * 100)
        amount = sizing._amount(r)
        if name == "cpu" and cap.get("cpu_range") and cap["cpu_range"]["high"] > r.used:
            rng = cap["cpu_range"]
            amount = (f"{rng['low'] / 1000:.1f}–{rng['high'] / 1000:.1f} of "
                      f"{r.capacity / 1000:.0f} cores")
        rows.append(f"""
          <tr><td>{esc(label)}</td>
              <td class="num">{esc(amount)}</td>
              <td class="bar-cell"><span class="use-bar" style="--w:{pct:.0f}%"
                  data-level="{'high' if r.fraction >= TIGHT_ABOVE and name != 'cache'
                               else 'low' if r.fraction < sizing.SPARE_BELOW else 'mid'}">
                  </span><span class="num">{pct:.0f}%</span></td>
              <td class="muted">{esc(node.split('.')[0])}</td></tr>""")
    forecasts = "".join(
        f'<li><a href="incidents/{esc(f["id"])}.html">{esc(f["title"])}</a></li>'
        for f in cap["forecasts"])
    span = f"{cap['days']:.0f} days" if cap["days"] >= 2 else "the history held"
    return f"""
    <h2>Capacity</h2>
    <p class="capacity-line" data-state="{esc(cap['state'])}">{esc(cap['line'])}</p>
    {f'<ul class="forecasts">{forecasts}</ul>' if forecasts else ''}
    <div class="scroll"><table class="capacity">
      <thead><tr><th>Resource</th><th>Busiest moment</th><th>Of what it has</th>
        <th>Node</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table></div>
    <p class="aside">The single busiest moment in {esc(span)}, not an average, on whichever
       member worked hardest.</p>"""


def config_section(recs: list, configured: bool) -> str:
    """How the cluster is set up against what MongoDB asks for. See recommend.py."""
    if not configured:
        return ""
    if not recs:
        return ("<h2>Configuration</h2>"
                '<div class="quiet"><b>Nothing to change</b><p>Version, kernel settings, '
                "limits, memory, topology and security all read the way MongoDB recommends, "
                "as far as the FTDC metadata shows them.</p></div>")
    items = "".join(f"""
      <li data-sev="{esc(r.severity)}">
        <b>{esc(r.title)}</b>
        <p>{esc(r.what)} {esc(r.why)}</p>
        <p class="fix">{esc(r.fix)}</p>
        <p class="who">{esc(", ".join(m.split(".")[0] for m in r.members))}</p>
      </li>""" for r in recs)
    return f"""
    <h2>Configuration</h2>
    <p class="lede">Read from the metadata at the top of every FTDC file — the same things mongod
       checks at startup and writes to a log almost nobody reads.</p>
    <ol class="config">{items}</ol>"""


def page_cluster(cluster_id: str, summary: dict, state: dict, recent: list, older: int,
                 findings: list[dict], chart_file, profile_html: str | None,
                 muted: set[str], now: datetime, verdict: Verdict,
                 cap: dict | None = None, retention_days: int | None = None,
                 takes_files: bool = False) -> str:
    """One cluster: what happened to it, newest first, and what normal looks like there."""
    cutoff = int(now.timestamp() * 1000) - WINDOW_DAYS * 86_400_000
    quiet = silent_hours(state, now, summary)

    events: list[tuple[int, str]] = []
    moments = by_moment(list(recent))
    for m in moments:
        cards = "".join(card(g, cluster_id, findings, chart_file, muted) for g in m.groups)
        extra = f"{len(m.groups)} signals" if len(m.groups) > 1 else ""
        events.append((m.from_ms, f"""
            <li data-sev="{esc(m.severity)}">
              <p class="stamp"><b>{esc(when_ms(m.from_ms))}</b>
                <span>{esc(how_long_ago(m.from_ms))}</span>
                {f'<span>· {esc(extra)}</span>' if extra else ''}</p>
              <section class="moment" data-sev="{esc(m.severity)}">{cards}</section>
            </li>"""))
    events += change_points([f for f in findings if is_change(f)
                             and int(f["worstFromMs"]) >= cutoff])

    if moments:
        # Newest first: this is the page somebody opens to find out what is wrong now. Reading
        # down is reading backwards in time, which is also the direction a cause is found in.
        events.sort(key=lambda e: -e[0])
        found = f'<ol class="axis">{"".join(html for _, html in events)}</ol>'
    elif quiet is not None:
        # "Nothing to report" printed under the silence banner reads as an all-clear about now.
        found = ('<div class="quiet"><b>Nothing to report, up to the silence</b>'
                 '<p>Every check ran and none of them fired — on the data held, which ends '
                 'where the gap above begins.</p></div>')
    else:
        found = (f'<div class="quiet"><b>Nothing to report in the last {WINDOW_DAYS} days</b>'
                 '<p>Every check ran and none of them fired.</p></div>')

    # Both numbers, because the reader can see both: the incidents are the boxes below and the
    # signals are the rows inside them.
    signals = sum(len(m.groups) for m in moments)
    tally = f"{len(moments)} incident{'s' if len(moments) != 1 else ''}"
    if signals != len(moments):
        tally += f" · {signals} signals"
    lede = (f'<p class="lede">{esc(summary.get("days_of_raw_ftdc") or 0)} days of raw data · '
            f'{esc(round(float(summary.get("megabytes") or 0)))} MB · '
            f'{tally} in the last {WINDOW_DAYS} days</p>')

    older_link = (f'<p class="aside"><a href="history.html">{older} older or marked as '
                  f'fixed</a></p>' if older else "")
    profile = (f'<h2>How this cluster behaves</h2><div class="embedded">{profile_html}</div>'
               if profile_html else "")
    muted_note = ""
    if muted:
        rules = ", ".join(f"<code>{esc(r)}</code>" for r in sorted(muted))
        muted_note = (f'<p class="aside">Muted in the config for this cluster: {rules}. '
                      f'Still detected and shown here; no email.</p>')

    body = f"""
    <p><a href="../index.html" class="back">← all clusters</a></p>
    <h1>{esc(cluster_id)}</h1>
    {verdict_block(verdict, state, "incidents/", progress=f"../progress/{cluster_id}")}
    {lede}
    <h2>What happened</h2>
    {'<p class="lede">Newest first. Anything that changed on the cluster sits on the same '
     'line as the incidents, in the order it really happened.</p>' if moments else ''}
    {found}
    {older_link}
    {muted_note}
    {config_section(recommend.evaluate(summary.get("nodes", []), now.date()),
                    any(n.get("config") for n in summary.get("nodes", [])))}
    {capacity_section(cap) if cap else ''}
    {profile}
    {f'<p class="keep"><a class="needs-server" href="../files/{esc(cluster_id)}">'
     f'Add FTDC files</a></p>' if takes_files else ''}
    {f'<p class="keep">Raw FTDC kept for {esc(retention_label(retention_days))}. '
     f'<a class="needs-server" href="../settings/{esc(cluster_id)}">Change</a></p>'
     if retention_days else ''}
    <p class="needs-server remove"><a href="../remove/{esc(cluster_id)}">Remove this cluster</a></p>"""
    return layout(f"{cluster_id} · mongo-health", body, "../", now)


def retention_label(days: int) -> str:
    """"3 months" for the lengths the add page offers, the days otherwise."""
    named = {30: "1 month", 60: "2 months", 90: "3 months", 180: "6 months", 365: "1 year"}
    return named.get(days, f"{days} days")


def page_history(cluster_id: str, older: list, fixed: list, now: datetime) -> str:
    """What has been dealt with, with what was said about it, and what is past the report window.
    Out of the report, not out of the data: if the same thing happens again it is still counted
    as a repeat."""
    closed = []
    for g, res in sorted(fixed, key=lambda x: x[1].get("at") or "", reverse=True):
        f = g.worst
        note = res.get("note")
        when = (res.get("at") or "")[:10]
        closed.append(f"""
            <article class="closed" data-sev="{esc(g.severity)}">
              <div class="head"><div>
                <h3><a href="incidents/{esc(f['id'])}.html">{esc(g.headline())}</a></h3>
                <div class="facts">
                  <span>{esc(name_nodes(g.nodes))}</span>
                  <span>{esc(when_ms(g.from_ms))}</span>
                </div>
              </div>{reopen_form(g, "reopen")}</div>
              {f'<p class="note">“{esc(note)}”</p>' if note else
               '<p class="note none">Marked as fixed without a note.</p>'}
              <div class="when">Marked as fixed {esc(when)}</div>
            </article>""")
    rows = []
    for m in sorted(by_moment(list(older)), key=lambda m: -m.from_ms):
        for g in m.groups:
            f = g.worst
            rows.append(f"""
            <article class="closed" data-sev="{esc(g.severity)}">
              <div class="head"><div>
                <h3><a href="incidents/{esc(f['id'])}.html">{esc(g.headline())}</a></h3>
                <div class="facts">
                  <span>{esc(name_nodes(g.nodes))}</span>
                  <span>{esc(when_ms(g.from_ms))}</span>
                  {f'<span>{esc(duration(g.seconds_in_state))} in state</span>'
                   if g.seconds_in_state else ''}
                </div>
              </div></div>
            </article>""")
    body = f"""
    <p><a href="index.html" class="back">← {esc(cluster_id)}</a></p>
    <h1>History</h1>
    <p class="lede">Out of the report, not out of the data: if the same thing happens again it is
       still counted as a repeat.</p>
    {f'<h2>Marked as fixed</h2>{"".join(closed)}' if closed else ''}
    {f'<h2>Older than {WINDOW_DAYS} days</h2>{"".join(rows)}' if rows else ''}"""
    return layout(f"History · {cluster_id} · mongo-health", body, "../", now)


LOG_ROWS = 8

# Incidents about scanning, where the rows that matter are the collection scans, whatever else
# was costly at the time.
SCAN_RULES = {"collection-scans-sustained", "query-targeting-poor"}
SLOWMS_TIP = "db.setProfilingLevel(0, { slowms: 20 })"


def log_section(g, logs: list[dict] | None, add_files: str | None) -> str:
    """The slow queries mongod logged on the affected members while this happened.

    FTDC says that something scanned; the log says which query, on which collection, with
    which plan -- which is the difference between "an index is missing" and which one. Said
    plainly when there is no log, or when the one held does not cover this window, so an empty
    table is never mistaken for "no slow queries".
    """
    members = {m for m in (logsummary.short_host(n) for n in g.nodes) if m}
    mine = [s for s in logs or [] if s.get("member") in members]
    if not mine:
        if add_files is None:
            return ""
        return (f'<h2>What the log says</h2><p class="lede">No mongod log held for '
                f'{esc(name_nodes(g.nodes))}. With it, this would name the queries that were '
                f'slow while it happened. <a class="needs-server" href="{esc(add_files)}">Add '
                f'it with the FTDC</a>.</p>')
    covered = [s for s in mine if s.get("first") is not None and s["first"] <= g.to_ms
               and s["last"] >= g.from_ms - 60_000]
    if not covered:
        return ('<h2>What the log says</h2><p class="lede">The log held for these members '
                'does not cover this window.</p>')
    rows = logsummary.during(covered, members, g.from_ms, g.to_ms)
    if not rows:
        return ('<h2>What the log says</h2><p class="lede">No slow query in the log for this '
                'window. mongod logs a query when it takes longer than slowms, 100 ms unless it '
                'was changed, so faster ones are not here.</p>')
    note = ""
    if g.rule in SCAN_RULES:
        scans = [r for r in rows if r["plan"].startswith("COLLSCAN")
                 and not r["op"].endswith("change stream")]
        rows = scans + [r for r in rows if r not in scans]
        if not scans:
            # Measured on a real set: 56 to 76 collection scans a second for hours, and not one
            # in the log, because each took less than slowms. Without this the table's costliest
            # index scans read as the answer to a question about collection scans.
            note = (f'<p class="pattern">None of these collection scans took longer than '
                    f'slowms (100 ms unless changed), so the log does not name them: they were '
                    f'many and fast. To catch them, lower it for a while on the members, then '
                    f'upload the log again: <code>{esc(SLOWMS_TIP)}</code></p>')
    body = []
    for r in rows[:LOG_ROWS]:
        per = lambda v: f"{v / r['n']:,.0f}" if r["n"] else "0"  # noqa: E731
        plan = (f'<b class="collscan">{esc(r["plan"])}</b>' if r["plan"].startswith("COLLSCAN")
                else esc(r["plan"]))
        source = ", ".join(sorted(r["apps"]) + [f"read {m}" for m in sorted(r["rp"])])
        body.append(
            f'<tr><td class="muted">{esc(r["member"])}</td><td class="ns"><code>{esc(r["ns"])}</code></td>'
            f'<td>{esc(r["op"])}</td><td><code>{esc(r["shape"] or "—")}</code></td>'
            f'<td>{plan}</td><td class="num">{r["n"]:,}</td><td class="num">{per(r["docs"])}</td>'
            f'<td class="num">{per(r["ret"])}</td><td class="num">{r["maxms"]:,} ms</td>'
            f'<td class="muted">{esc(source or "—")}</td></tr>')
    more = (f'<p class="hint">And {len(rows) - LOG_ROWS} more shapes, smaller.</p>'
            if len(rows) > LOG_ROWS else "")
    return f"""
          <h2>What the log says</h2>
          <p class="lede">Slow queries mongod logged on {esc(name_nodes(g.nodes))} during this,
            costliest first. Field names only: the values in the filters are never kept.</p>
          {note}
          <div class="scroll"><table class="logq">
            <thead><tr><th>Node</th><th>Collection</th><th>Operation</th><th>Filter</th>
              <th>Plan</th><th>Times</th><th>Examined each</th><th>Returned each</th>
              <th>Slowest</th><th>From</th></tr></thead>
            <tbody>{''.join(body)}</tbody></table></div>
          {more}"""


def page_incident(cluster_id: str, g, findings: list[dict], chart_file, now: datetime,
                  resolution: dict | None = None, logs: list[dict] | None = None,
                  add_files: str | None = None) -> str:
    """One incident in full.

    Every member gets its own chart, which answers the question the summary cannot: was this
    one sick node, or the whole replica set reacting to the same thing? Those have different
    causes and different fixes.
    """
    figure, figure_means = extent(g.worst, g.seconds_in_state)
    # A change is a moment, not a condition: "0s in state" and a peak say nothing about it.
    change = g.rule == "setting-changed"
    earlier = earlier_incidents(findings, g.rule, g.from_ms)
    changed = changes_before(findings, g.from_ms)

    charts = []
    for m in sorted(g.members, key=lambda x: -(x.get("secondsInState") or 0)):
        name = chart_file(m)
        chart = (chart_img(f"../charts/{name}", m.get("metric") or "") if name else
                 '<div class="metric">No series behind this one — the evidence is the gap '
                 'itself.</div>')
        charts.append(f"""
        <div class="node-panel">
          <div class="node-head">
            <b>{esc(m["node"].split(".")[0])}</b>
            <span>{esc(when_ms(m["worstFromMs"])) if change else
                   esc(duration(m.get('secondsInState'))) + ' in state · peak '
                   + esc(unit_value(m.get('peak'), m.get('unit')))}</span>
          </div>
          {chart}
        </div>""")

    if earlier:
        rows = "".join(
            f'<tr><td><a href="{esc(e.worst["id"])}.html">{esc(when_ms(e.from_ms))}</a></td>'
            f"<td>{esc(how_long_ago(e.from_ms))}</td>"
            f"<td>{esc(duration(e.seconds_in_state))}</td>"
            f'<td class="muted">{esc(name_nodes(e.nodes))}</td></tr>'
            for e in earlier[:SHOWN_TIMES])
        more = (f'<p class="hint">And {len(earlier) - SHOWN_TIMES} older, not listed.</p>'
                if len(earlier) > SHOWN_TIMES else "")
        starts = [g.from_ms] + [e.from_ms for e in earlier]
        pattern = schedule_pattern(starts)
        history = f"""
        <h2 id="times">Every time this has happened</h2>
        <p class="lede">Same check, same cluster: {len(starts)} times.</p>
        {time_of_day(starts, pattern)}
        {f'<p class="pattern">{esc(pattern["text"])}</p>' if pattern else ''}
        <div class="scroll"><table>
          <thead><tr><th>When</th><th></th><th>Duration</th><th>Nodes</th></tr></thead>
          <tbody>
            <tr class="current"><td>{esc(when_ms(g.from_ms))}</td>
              <td>{esc(how_long_ago(g.from_ms))}</td>
              <td>{esc(duration(g.seconds_in_state))}</td>
              <td class="muted">this one</td></tr>
            {rows}
          </tbody></table></div>
        {more}"""
    else:
        history = """
        <h2>Every time this has happened</h2>
        <div class="quiet"><b>This is the first</b>
          <p>Nothing like it in the history held for this cluster. If it repeats, this page
             will say how often and when.</p></div>"""

    # What led here, on one axis, oldest first: this page is where the argument is made --
    # "this happened before, then something changed, then this" -- and an argument reads
    # forwards. The cluster page runs the other way because it is scanned, not read.
    lead = []
    if earlier:
        last = earlier[0]
        lead.append((last.from_ms, f"""
        <li>
          <p class="stamp">{esc(when_ms(last.from_ms))}
            <span>{esc(how_long_ago(last.from_ms))}</span></p>
          <p class="what earlier">The time before this — it ran
            {esc(duration(last.seconds_in_state))} on
            {esc(name_nodes(last.nodes))}.
            {f'One of {len(earlier) + 1} times on record.' if len(earlier) > 1 else ''}</p>
        </li>"""))
    for c in changed:
        lead.append((c["worstFromMs"], f"""
        <li class="change">
          <p class="stamp">{esc(when_ms(c["worstFromMs"]))}
            <span>{esc(how_long_before(c["worstFromMs"], g.from_ms))}</span></p>
          <p class="what"><b>{esc(c["title"])}</b>
            <span>— something changed on this cluster</span></p>
        </li>"""))
    lead.sort(key=lambda e: e[0])
    worst = g.worst

    # The same action as on the cluster page, on the page somebody reads before deciding it is
    # dealt with -- and, once it is, what they said about it.
    if resolution:
        note = resolution.get("note")
        action = f"""
        <div class="card fixed-note">
          <p><b>Marked as fixed {esc((resolution.get("at") or "")[:10])}</b></p>
          {f'<p class="note">“{esc(note)}”</p>' if note else ''}
          {reopen_form(g, "../reopen")}
        </div>"""
    else:
        action = fix_form(g, "../resolve") if g.rule != "setting-changed" else ""

    body = f"""
    <p><a href="../index.html" class="back">← {esc(cluster_id)}</a></p>
    <ol class="axis">
      {''.join(html for _, html in lead)}
      <li data-sev="{esc(g.severity)}">
        <p class="stamp"><b>{esc(when_ms(g.from_ms))}</b>
          <span>{esc(how_long_ago(g.from_ms))}</span></p>
        <div class="here">
          <div class="sev big">{esc(SEVERITY_LABEL.get(g.severity, g.severity))}</div>
          <h1>{esc(g.headline())}</h1>
          <p class="lede">{esc(worst.get('what') or '')}</p>
          <div class="facts big">
            {'' if change else f'<div><b>{esc(figure)}</b><span>{esc(figure_means)}</span></div>'}
            <div><b>{len(g.nodes)}</b><span>node{'s' if len(g.nodes) != 1 else ''} affected</span></div>
          </div>
          <h2>What to check</h2>
          <div class="advice">{esc(worst.get('check') or '')}
            <p style="margin:.6rem 0 0"><a href="../../rules.html#{esc(catalog.anchor(g.rule))}"
               target="_blank" rel="noopener">About this check</a></p></div>
          <h2>What each node was doing</h2>
          <p class="lede">One chart per member. If only one moved, the cause is on that host; if
            all of them did, it is the workload or something they share.</p>
          {''.join(charts)}
          {log_section(g, logs, add_files)}
        </div>
      </li>
    </ol>
    {action}
    {history}"""
    return layout(f"{g.title} · {cluster_id}", body, "../../", now)


def page_redirect(target: str) -> str:
    """A finding that is not its incident's worst member still has an address: an email built
    from a different set of findings may have linked to it."""
    return (f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" '
            f'content="0; url={esc(target)}"><a href="{esc(target)}">{esc(target)}</a>')


def page_rules(now: datetime) -> str:
    """Every check, grouped by what it watches, each at its own anchor so a finding can link
    straight to the one that produced it."""
    items = catalog.entries()
    sections = []
    for key, name in catalog.AREAS:
        group = [e for e in items if e["area"] == key]
        if not group:
            continue
        cards = []
        for e in group:
            listed = "".join(f"<li>{esc(i['title'])} <code>{esc(i['path'])}</code></li>"
                             for i in e.get("items") or [])
            reasoning = "".join(f"<p>{esc(p)}</p>" for p in (e.get("reasoning") or "").split("\n\n")
                                if p.strip())
            cards.append(f"""
        <article class="finding rule" id="{esc(e['id'])}" data-sev="{esc(e['severity'])}">
          <div class="sev">{esc(SEVERITY_LABEL.get(e['severity'], e['severity']))}</div>
          <h3>{esc(e['title'])} <code class="rule-id">{esc(e['id'])}</code></h3>
          <p>{esc(e['what'])}</p>
          <p class="speaks"><b>Speaks when</b> {esc(e['how'])}</p>
          {f'<p class="metric-expr"><code>{esc(e["metric"])}</code></p>' if e.get('metric') else ''}
          {f'<ul class="watched">{listed}</ul>' if listed else ''}
          {f'<details><summary>Why this threshold</summary>{reasoning}</details>' if reasoning else ''}
          <details><summary>What to check</summary><p>{esc(e['check'])}</p></details>
          {f'<p class="hint">Over a connection string at the default of one sample every ten seconds: '
           f'{esc(e["ten_seconds"])}.</p>' if e.get('ten_seconds') else ''}
        </article>""")
        sections.append(f"<h2>{esc(name)}</h2>{''.join(cards)}")
    thresholds = sum(1 for e in items if e["kind"] == "threshold")
    configs = sum(1 for e in items if e["kind"] == "config")
    body = f"""
    <p><a href="index.html" class="back">← all clusters</a></p>
    <h1>The checks</h1>
    <p class="lede">{thresholds} threshold rules, {len(items) - thresholds - configs} detectors
       and {configs} configuration checks. Every
       number is either a documented MongoDB or WiredTiger limit or a value measured on a real
       capture — the reasoning is under each one.</p>
    {''.join(sections)}"""
    return layout("The checks · mongo-health", body, "", now)


def page_index(rows: list[dict], now: datetime) -> str:
    """Every cluster, and whether anybody is watching it."""
    if not rows:
        body = ('<h1>No clusters yet</h1><div class="quiet"><b>Nothing to show</b>'
                '<p><a class="needs-server" href="add">Add a cluster</a>, or add it to '
                '<code>config.json</code>; it appears here after the next run.</p></div>')
        return layout("mongo-health", body, "", now)

    items = []
    for r in rows:
        if not r["captured"] and r["verdict"].state == "waiting":
            state = "connected, first samples arriving…"
        elif r["verdict"].state == "capturing":
            state = "collecting FTDC…"
        elif r["verdict"].state == "capture_failed":
            state = "first capture failed, tried again within the hour"
        elif not r["captured"]:
            state = "configured, nothing captured yet"
        elif r["verdict"].state == "analyzing":
            state = "analyzing FTDC…"
        elif r["quiet"] is not None:
            state = (f"nothing collected for {how_long_silent(r['quiet'])} — "
                     f"nobody is watching it right now")
        elif r.get("ends"):
            state = (f"FTDC ending {r['ends']:%d %b %H:%M} UTC · "
                     f"{r['days_raw']:.1f} days of raw data · {r['megabytes']:.0f} MB")
        else:
            state = (f"{r['days_observed']:.1f} days watched · "
                     f"{r['days_raw']:.1f} days of raw data · {r['megabytes']:.0f} MB")
        n = r["recent"]
        word = "incident" if n == 1 else "incidents"
        badge = (f'<a class="count{" none" if not n else ""}" '
                 f'href="{esc(r["id"])}/index.html">{n} {word}</a>'
                 # Mid-analysis, "0 incidents" reads as checked and clean.
                 if r["captured"] and r["verdict"].state != "analyzing" else "")
        v = r["verdict"]
        items.append(f"""
        <div class="cluster">
          <div style="flex:1;min-width:0">
            <div class="name"><a href="{esc(r['id'])}/index.html">{esc(r['id'])}</a>
              <span class="verdict-pill" data-state="{esc(v.state)}">{esc(v.label)}</span></div>
            <div class="meta">{esc(v.reason)}</div>
            <div class="meta">{esc(state)}</div>
            {progress_bar(f"progress/{r['id']}") if v.state in BUSY else ""}
          </div>
          {badge}
        </div>""")
    body = f"""
    <h1>Is my cluster healthy?</h1>
    <p class="lede">One answer per cluster, from every check over all the history held.
       Incidents counted over the last {WINDOW_DAYS} days.</p>
    <div class="card">{''.join(items)}</div>
    <p class="needs-server" style="margin:1.2rem 0 0"><a href="add">
      <button class="secondary">Add a cluster</button></a></p>
    <p class="aside"><a href="rules.html">The checks</a> — what each one looks at, and why at
       that threshold.</p>"""
    return layout("mongo-health", body, "", now)


# ------------------------------------------------------------------------------ building

def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def profile_section(base: Path, now: datetime) -> str | None:
    """The behaviour table from `profile.py`, the same code the first-day report uses, so the
    two cannot drift into saying different things about the same cluster."""
    if not (base / "summary.json").exists():
        return None
    try:
        summary, findings, baseline, series = profile_report.load(base)
        html = profile_report.render(summary, findings, baseline, series, now)
    except Exception:
        # A missing or half-written profile must not take the page down; the incidents above
        # it are the part that matters.
        return None
    body = re.search(r"<body>(.*)</body>", html, re.S)
    if not body:
        return None
    # Only the behaviour section: the standalone report carries its own findings list, which
    # here would repeat the incidents above it, ungrouped. And without its own heading, or the
    # page reads "How this cluster behaves How this cluster behaves".
    inner = body.group(1)
    start = inner.find("<h2>")
    end = inner.find("<h2>", start + 1)
    section = inner[start:end] if start >= 0 and end > start else inner
    return re.sub(r"^\s*<h2>.*?</h2>", "", section, count=1, flags=re.S)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Named per write: the page and the collector both rebuild the site, at start-up at the
    # same moment, and a shared temporary name let one move the other's half-written file.
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(text)
    tmp.replace(path)


def build_cluster(spec: dict, data: Path, out: Path, now: datetime) -> dict:
    cluster_id = spec["cluster_id"]
    base = data / cluster_id
    site = out / cluster_id
    summary = json.loads((base / "summary.json").read_text()) \
        if (base / "summary.json").exists() else {}
    state = json.loads((base / "state.json").read_text()) \
        if (base / "state.json").exists() else {}
    findings = read_jsonl(base / "findings.jsonl")
    cutoff = int(now.timestamp() * 1000) - WINDOW_DAYS * 86_400_000

    # Changes get a page like anything else -- the email names them when they come with an
    # incident, and their chart is the before and after -- but on the cluster page they are
    # points on the axis, not incidents.
    groups = group_findings(findings)
    done = resolutions.load(base)
    incidents = [g for g in groups if g.rule != "setting-changed"]
    fixed = [(g, r) for g in incidents if (r := resolutions.is_resolved(g, done))]
    open_ = [g for g in incidents if not resolutions.is_resolved(g, done)]
    recent = [g for g in open_ if g.to_ms >= cutoff]
    older = [g for g in open_ if g.to_ms < cutoff]
    settled = {m["id"] for g, _ in fixed for m in g.members}

    charts = site / "charts"
    drawn: set[str] = set()

    def chart_file(f: dict) -> str | None:
        name = draw_chart(f, charts)
        if name:
            drawn.add(name)
        return name

    muted = set(spec.get("mute") or [])
    # What somebody marked as fixed no longer decides the verdict. What happens next does.
    ends = newest_sample(state, summary) if config.files_only(spec) and summary else None
    quiet = None if config.files_only(spec) else silent_hours(state, now, summary)
    verdict = evaluate([f for f in findings if f["id"] not in settled], now, quiet,
                       bool(state.get("last_capture")),
                       float(summary.get("days_of_raw_ftdc") or 0),
                       analysed=bool(summary), ends=ends, analyzing=analyzing(base, now),
                       arriving=None if state.get("last_capture") else arriving(base),
                       failed=read_json(base / "analysis-failed.json"),
                       capturing=capturing(base, now),
                       capture_failed=read_json(base / "capture-failed.json"))
    if state.get("source_kind") == "atlas" and state.get("files") \
            and state.get("history_done") is False and verdict.state not in BUSY:
        # A first capture comes window by window, newest first (sources.AtlasSource.history).
        # Until the last one lands, what is judged is the recent part of the history.
        held = float(summary.get("days_of_raw_ftdc") or 0)
        verdict = Verdict(verdict.state, f"{verdict.reason} Judged on the newest {held:.1f} "
                          f"days so far. The older days Atlas holds are still being collected, "
                          f"and arrive over the next rounds.", verdict.evidence)
    if verdict.state != "failed" and (stale := read_json(base / "analysis-failed.json")):
        # What is shown is the analysis before. Said, rather than presented as current.
        verdict = Verdict(verdict.state, f"{verdict.reason} The latest analysis failed "
                          f"({stale.get('error')}); this is from the one before it.",
                          verdict.evidence)
    write(site / "index.html",
          page_cluster(cluster_id, summary, state, recent,
                       len(by_moment(list(older))) + len(fixed),
                       findings, chart_file, profile_section(base, now), muted, now, verdict,
                       capacity(base, summary, findings, now),
                       retention_days=spec.get("retention_days"),
                       takes_files=(spec.get("source") or {}).get("type") == "onprem"))
    if older or fixed:
        write(site / "history.html", page_history(cluster_id, older, fixed, now))
    elif (site / "history.html").exists():
        (site / "history.html").unlink(missing_ok=True)

    logs = logsummary.held(base / "logs")
    add_files = (f"../../files/{cluster_id}"
                 if (spec.get("source") or {}).get("type") == "onprem" else None)
    pages: set[str] = set()
    for g in groups:
        page = f"{g.worst['id']}.html"
        write(site / "incidents" / page, page_incident(cluster_id, g, findings, chart_file, now,
                                                        resolutions.is_resolved(g, done),
                                                        logs=logs, add_files=add_files))
        pages.add(page)
        for m in g.members:
            if f"{m['id']}.html" not in pages:
                write(site / "incidents" / f"{m['id']}.html", page_redirect(page))
                pages.add(f"{m['id']}.html")

    # What the rebuild no longer references goes, so the site does not grow for ever with
    # pictures of findings that were re-analysed into different ones.
    # missing_ok: the other process rebuilding the site may have removed it first, and a rebuild
    # that dies over a file already gone left the report step failed for the round.
    for stale in (charts.glob("*.png") if charts.exists() else []):
        if stale.name not in drawn:
            stale.unlink(missing_ok=True)
    for stale in ((site / "incidents").glob("*.html") if (site / "incidents").exists() else []):
        if stale.name not in pages:
            stale.unlink(missing_ok=True)

    return {
        "id": cluster_id,
        "captured": bool(state.get("last_capture")),
        "quiet": quiet,
        "ends": ends,
        "days_observed": float(summary.get("days_observed") or 0),
        "days_raw": float(summary.get("days_of_raw_ftdc") or 0),
        "megabytes": float(summary.get("megabytes") or 0),
        "recent": len(by_moment(list(recent))),
        "verdict": verdict,
    }


def build(clusters: list[dict], data: Path, out: Path, now: datetime | None = None) -> list[dict]:
    global _NOW
    now = now or datetime.now(timezone.utc)
    # "3 hours ago" has to be measured from the same moment as everything else on the page,
    # or a report built with --now says "40 days ago" beside a date it calls the present.
    _NOW = now
    rows = [build_cluster(spec, data, out, now) for spec in clusters]
    write(out / "index.html", page_index(rows, now))
    write(out / "rules.html", page_rules(now))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--out", type=Path, default=Path("site"))
    ap.add_argument("--now", help="build as of this ISO time, to reproduce a past report")
    args = ap.parse_args()
    now = (datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now
           else datetime.now(timezone.utc))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    try:
        clusters = config.load_clusters(args.config)
    except config.ConfigError as e:
        print(e, file=sys.stderr)
        return 2

    rows = build(clusters, args.data, args.out, now)
    print(f"{args.out}/index.html · {len(rows)} cluster(s)")
    for r in rows:
        print(f"  {r['id']:24} {r['verdict'].label:18} {r['verdict'].reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
