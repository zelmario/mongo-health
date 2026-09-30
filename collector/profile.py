#!/usr/bin/env python3
"""The report a new cluster gets on day one, whether or not anything is wrong.

    python3 profile.py --data data --cluster orders-prod --out profile.html

A list of findings is a bad first impression, because most clusters are fine. Sign up a healthy
one, run the rules, and the honest output is "nothing fired" — which reads as "this does
nothing" rather than "you are in good shape".

So the first report is a **profile**, not an alert. It says what this cluster looks like when
it is behaving: how much of the ticket pool it actually uses, how full the cache runs, how many
documents it reads to answer one query. That is worth reading on a healthy cluster, it is the
baseline every later "that is unusual" will be measured against, and it quietly demonstrates
the thing being sold — that somebody is looking, and that the data Atlas was about to delete is
now yours.

Findings, when they exist, come after the profile rather than instead of it.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

ATLAS_DAYS = 3

# How many incidents get their own block in the first report. The rest are counted, not hidden:
# a number the reader can act on beats a list they scroll past.
DETAILED_IN_PROFILE = 3

TEXT = {
    "title": "Cluster profile",
    "rescued": "{days} days of diagnostic data rescued",
    "rescued_sub": ("Atlas keeps roughly {atlas} days and then deletes it. That window is now "
                    "yours, and it grows from here."),
    "behaviour": "How this cluster behaves",
    # Says what the table is before it says how it was made. The previous version opened with
    # the sample count, which answers a question nobody had yet.
    "behaviour_sub": ("What normal looks like on this cluster, measured rather than assumed — "
                      "this is what every alert above was judged against. From {samples} "
                      "samples per node, one per second, taken from whichever member was worst "
                      "affected."),
    "legend": ("Typical is the median second. Busy is the 95th percentile — worse than all but "
               "one second in twenty. Worst is the single highest second in the whole capture, "
               "which is where an incident shows up and where an average hides it."),
    "findings": "What we found",
    "and_more": "{n} more on the cluster page.",
    # Word for word what the cluster page says. This sentence is the product's whole argument,
    # and two screens phrasing it differently would read as two different claims.
    "again": "This has happened {n} times on this cluster. The one before was {when}.",
    "first": "First time we have seen this on this cluster.",
    "nothing": "Nothing fired",
    "nothing_sub": ("All {n} checks ran against this capture and none crossed its threshold. "
                    "The profile above is what they were measured against."),
    "coverage": "Checks that ran",
    "nodes": "Nodes",
    "metric": "Metric",
    "typical": "Typical",
    "busiest": "Busy",
    "peak": "Worst seen",
    # No header for the reading: it is no longer a column. It is the sentence under each row's
    # numbers, and a heading over a full-width line of prose labels the obvious.
    "footer": "Generated {when} · Big Hole",
}


def load(base: Path) -> tuple[dict, list[dict], list[dict], dict]:
    summary = json.loads((base / "summary.json").read_text())
    findings = []
    fpath = base / "findings.jsonl"
    if fpath.exists():
        findings = [json.loads(l) for l in fpath.read_text().splitlines() if l]
    baseline = []
    bpath = base / "baseline.jsonl"
    if bpath.exists():
        rows = [json.loads(l) for l in bpath.read_text().splitlines() if l]
        rows = [r for r in rows if r.get("scope", "baseline") == "baseline"]
        if rows:
            newest = max(r["run"] for r in rows)
            baseline = [r for r in rows if r["run"] == newest]
    series = {}
    spath = base / "series.json"
    if spath.exists():
        per_node = json.loads(spath.read_text())
        # The profile describes the busiest node, so its shapes are the ones to draw.
        if per_node:
            busiest = max(per_node, key=lambda n: sum(
                max((v for v in s["v"] if v == v), default=0) for s in per_node[n].values()))
            series = per_node[busiest]
    return summary, findings, baseline, series


def rows_for(baseline: list[dict], metric: str) -> list[dict]:
    """Every node's row for a metric, matching whichever name the server used for it.

    The stored name carries its alias -- `…concurrentTransactions.read.out (via
    …queues.execution.read.out)` on 8.0 -- so the comparison is against the canonical half.
    """
    return [r for r in baseline if r["metric"].split(" (via")[0] == metric]


def pick(baseline: list[dict], metric: str, node: str | None = None) -> dict | None:
    """One node's numbers for a metric: the named node, or the worst one.

    Worst by `max`, not by p95. Over a capture of several days a p95 is dominated by the days
    nothing happened -- on the cluster this was rebuilt against, the read pool went to 80 of 83
    tickets during an incident and its p95 was still 0. Ranking on p95 there picks a node where
    nothing ever happened and calls it the busiest member.
    """
    hits = rows_for(baseline, metric)
    if node is not None:
        return next((r for r in hits if r["node"] == node), None)
    return max(hits, key=lambda r: r["max"]) if hits else None


def worst_node(baseline: list[dict], metric: str) -> str | None:
    row = pick(baseline, metric)
    return row["node"] if row else None


def gb(v: float) -> str:
    return f"{v/1073741824:.1f} GB" if v >= 1073741824 else f"{v/1048576:.0f} MB"


def ms(v: float) -> str:
    """A duration in the unit a person would say it in, from a number of milliseconds.

    `260068 ms` is a real value from a real cluster, and nobody reads that as four and a half
    minutes without doing the arithmetic themselves.
    """
    if v < 1000:
        return f"{v:.0f} ms"
    if v < 60_000:
        return f"{v/1000:.1f} s"
    minutes, seconds = divmod(int(v / 1000), 60)
    return f"{minutes} min {seconds:02d} s" if seconds else f"{minutes} min"


def times_before(findings: list[dict], rule: str, before_ms: int) -> list[dict]:
    """Earlier times this same rule fired, read off the disk.

    Counted from the START of the incident's own window, never from its end: an episode that ran
    for four hours would otherwise find its own later samples and report itself as a precedent.
    """
    out = [f for f in findings
           if f.get("rule") == rule and int(f.get("worstFromMs") or 0) < before_ms]
    return sorted(out, key=lambda f: -int(f["worstFromMs"]))


def when_day(ms) -> str:
    return datetime.fromtimestamp(int(ms) / 1000, timezone.utc).strftime("%d %b %Y · %H:%M UTC")


def seconds_out_loud(seconds) -> str:
    """A length of time as a person would say it. "16158s" is a number to convert; "4.5 h" is
    a fact, and this report is read by somebody deciding whether to keep reading."""
    seconds = int(seconds or 0)
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def build_profile(baseline: list[dict]) -> list[dict]:
    """The handful of numbers a DBA would actually ask for, in plain language.

    Each row carries its own reading. A percentile with no interpretation is a number the
    reader has to already understand to use, which defeats the point of the report.
    """
    rows: list[dict] = []

    # Every companion metric is read from the SAME node as the one the row is about. Picking
    # each one independently once produced a row that put one member's tickets in use over
    # another member's pool size -- a ratio of two numbers that never coexisted.
    node = worst_node(baseline, "serverStatus.wiredTiger.concurrentTransactions.read.out")
    read_out = pick(baseline, "serverStatus.wiredTiger.concurrentTransactions.read.out", node)
    read_tot = pick(baseline, "serverStatus.wiredTiger.concurrentTransactions.read.totalTickets",
                    node)
    if read_out and read_tot and read_tot["p50"]:
        share = 100 * read_out["max"] / max(read_tot["max"], 1)
        rows.append({
            "series": "serverStatus.wiredTiger.concurrentTransactions.read.out",
            "name": "Read tickets in use",
            "scale": f"pool of {read_tot['p50']:.0f}" if read_tot["max"] == read_tot["p50"]
                     else f"pool of {read_tot['p50']:.0f}, grows to {read_tot['max']:.0f}",
            "typical": f"{100*read_out['p50']/max(read_tot['p50'],1):.0f}%",
            "busiest": f"{100*read_out['p95']/max(read_tot['p95'],1):.0f}%",
            "peak": f"{share:.0f}%",
            "reading": (
                f"At its worst {read_out['max']:.0f} of {read_tot['max']:.0f} tickets were in "
                "use. Reads queue behind that pool, and sitting near the top of it is where "
                "latency starts climbing."
                if share >= 50 else
                f"Never went past {share:.0f}% of the pool — reads are not queueing here."
            ),
        })

    node = worst_node(baseline, "serverStatus.wiredTiger.cache.bytes currently in the cache")
    cache = pick(baseline, "serverStatus.wiredTiger.cache.bytes currently in the cache", node)
    dirty = pick(baseline, "serverStatus.wiredTiger.cache.tracked dirty bytes in the cache", node)
    cap = pick(baseline, "serverStatus.wiredTiger.cache.maximum bytes configured", node)
    if cache and cap and cap["p50"]:
        # A percentage needs a denominator that held still. When the cache was resized inside
        # the window there is no single one, and dividing by the median produced "285% full" on
        # a real report -- the cache had been 1.5 GB for part of the capture and 512 MB for the
        # rest. A fraction over 100% is not a rounding problem, it is the report saying
        # something impossible, and a reader who sees it stops believing the other rows too.
        #
        # So when it moved, the row reports bytes and says the cache was resized. Less tidy and
        # true, and the resize itself is now a finding of its own -- see the settings detector.
        resized = cap["max"] != cap["p50"]
        full = 100 * cache["max"] / cap["max"]
        dirty_pct = 100 * dirty["max"] / cap["max"] if dirty else 0
        rows.append({
            "series": "serverStatus.wiredTiger.cache.bytes currently in the cache",
            "name": "Cache in use",
            "scale": (f"resized during this window, {gb(cap['p50'])} to {gb(cap['max'])}"
                      if resized else f"of {gb(cap['p50'])}"),
            "typical": gb(cache["p50"]) if resized else f"{100*cache['p50']/cap['p50']:.0f}%",
            "busiest": gb(cache["p95"]) if resized else f"{100*cache['p95']/cap['p50']:.0f}%",
            "peak": gb(cache["max"]) if resized else f"{full:.0f}%",
            "reading": (
                "Running full. Once it stays here, reads start coming off disk instead of memory."
                if full >= 95 else
                f"Dirty pages peak around {dirty_pct:.0f}% — eviction is keeping up."
            ),
        })

    node = worst_node(baseline, "serverStatus.connections.current")
    conn = pick(baseline, "serverStatus.connections.current", node)
    avail = pick(baseline, "serverStatus.connections.available", node)
    if conn and avail:
        # current + available is the ceiling as the server sees it, and both halves have to come
        # from the same node and the same moment for the sum to mean anything.
        total = conn["p50"] + avail["p50"]
        peak_share = 100 * conn["max"] / max(total, 1)
        rows.append({
            "series": "serverStatus.connections.current", "name": "Connections",
            "scale": f"limit {total:,.0f}",
            "typical": f"{conn['p50']:,.0f}",
            "busiest": f"{conn['p95']:,.0f}",
            "peak": f"{conn['max']:,.0f}",
            "reading": (
                f"Reached the limit of {total:,.0f}. Running out refuses new connections "
                "outright — the application sees errors, not slowness."
                if peak_share >= 100 else
                f"Peaks at {peak_share:.0f}% of the limit. Running out refuses new connections "
                "outright, so this is worth watching as the app scales."
            ),
        })

    node = worst_node(baseline, "rate(serverStatus.metrics.queryExecutor.scannedObjects)")
    scanned = pick(baseline, "rate(serverStatus.metrics.queryExecutor.scannedObjects)", node)
    returned = pick(baseline, "rate(serverStatus.metrics.document.returned)", node)
    if scanned and returned and returned["p50"] > 0:
        ratio = scanned["p50"] / returned["p50"]
        rows.append({
            # Every other row plots one stored metric; this one is a ratio, so the shape has to
            # be divided out second by second. The ratio of the two *stored* shapes would be a
            # different quantity, and the row would be the only one whose picture and whose
            # numbers came from different arithmetic.
            "ratio": ("rate(serverStatus.metrics.queryExecutor.scannedObjects)",
                      "rate(serverStatus.metrics.document.returned)"),
            "name": "Documents read per document returned",
            "scale": "1 : 1 is an index doing its job",
            "typical": f"{ratio:.0f} : 1",
            "busiest": f"{scanned['p95']/max(returned['p95'],1):.0f} : 1",
            # No worst column: the ratio of two peaks that happened at different seconds is not
            # a ratio of anything.
            "peak": "—",
            "reading": (
                "Reading thousands of documents to answer one query is the signature of a query "
                "with no usable index. Worth a look at the slow query log."
                if ratio >= 100 else
                "Close to one document read per document returned — queries are using indexes."
            ),
        })

    ck = pick(baseline, "serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)")
    if ck:
        rows.append({
            "series": "serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)", "name": "Checkpoint duration",
            "scale": "sub-second is healthy",
            "typical": ms(ck["p50"]),
            "busiest": ms(ck["p95"]),
            "peak": ms(ck["max"]),
            # Three readings, not two. A cluster whose p95 is fine but whose peak reached
            # seconds did stall at some point, and saying "sub-second throughout" next to a
            # 2602 ms peak in the same row is the kind of contradiction that costs the whole
            # report its credibility.
            "reading": (
                "Checkpoints reaching seconds stall the writes queued behind them — a common "
                "cause of pauses no throughput graph explains."
                if ck["p95"] >= 1000 else
                f"Usually sub-second, but one took {ms(ck['max'])}. Occasional stalls "
                "rather than a persistent problem."
                if ck["max"] >= 1000 else
                "Sub-second throughout. Checkpoints are not stalling writes here."
            ),
        })

    node = worst_node(baseline, "rate(serverStatus.opcounters.query)")
    ops = {n: pick(baseline, f"rate(serverStatus.opcounters.{n})", node)
           for n in ("query", "insert", "update", "delete")}
    if any(ops.values()):
        typical = sum(o["p50"] for o in ops.values() if o)
        busiest = sum(o["p95"] for o in ops.values() if o)
        peak = max((o["max"] for o in ops.values() if o), default=0)
        detail = ", ".join(f"{n} {o['p50']:.0f}/s" for n, o in ops.items() if o and o["p50"] >= 1)
        rows.append({
            "series": "rate(serverStatus.opcounters.insert)", "name": "Operations",
            "scale": "reads and writes together",
            "typical": f"{typical:,.0f}/s",
            "busiest": f"{busiest:,.0f}/s",
            # The busiest single second of any one kind, which is the number that explains a
            # spike. Summing four peaks that happened at four different seconds would not.
            "peak": f"{peak:,.0f}/s",
            # "Almost idle" next to a peak of 18,000/s is the contradiction this report cannot
            # afford: the median is the answer to "what is normal", and the peak is the answer
            # to "so what were those alerts about". Both, or neither.
            "reading": (detail or
                        (f"Idle for most of the window — the median second has no operations "
                         f"in it, though one second reached {peak:,.0f}/s."
                         if peak else "No operations at all over this window.")),
        })

    return rows


def table_css(scope: str = "") -> str:
    """The behaviour table's own rules, optionally prefixed so they can live inside another page.

    They are a function rather than part of `CSS` because this table is rendered in two places.
    The web app embeds the section into a page that has its own stylesheet, and it does that by
    lifting the markup out of `<body>` — which leaves every rule below behind in the `<head>`
    it discards. The table then inherited the host page's `.shape { width: 100% }`, meant for
    incident charts, and the sparkline column ate the width until "What it means" wrapped one
    word per line; `.scale` stopped being a block, so every metric ran into its own subtitle
    ("Cache in useof 512 MB"). Both looked like the table was badly designed rather than
    unstyled.

    `scope` is a selector the caller is sure contains the table, so importing these rules
    cannot restyle the rest of its page.
    """
    p = f"{scope} " if scope else ""
    return f"""
{p}.overview {{ background: var(--panel); border: 1px solid var(--edge);
            padding: 0.9rem 1rem 0.5rem; margin-bottom: 0.5rem; }}
{p}.overview img {{ width: 100%; height: auto; display: block; }}
/* `display` is set back explicitly: a host page whose own `.shape` rule makes charts blocks
   would otherwise turn this cell into one and collapse the row. */
{p}td.shape {{ width: 8rem; padding: 0.45rem 0.5rem; display: table-cell; }}
/* `max-width` rather than a bare width: the cell can be narrower than 7.5rem on a small
   screen, and a fixed width there would push the table wider than its container. */
{p}.spark {{ width: 100%; max-width: 7.5rem; height: auto; display: block; opacity: 0.85; }}
@media (max-width: 46rem) {{ {p}td.shape, {p}.spark {{ display: none; }} }}

{p}.scroll {{ overflow-x: auto; background: var(--panel); border: 1px solid var(--edge); }}
{p}table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
{p}th {{ text-align: left; padding: 0.55rem 1rem; font-size: 0.6875rem; font-weight: 600;
     text-transform: uppercase; letter-spacing: 0.07em; color: var(--ink-faint);
     border-bottom: 1px solid var(--edge-soft); white-space: nowrap; }}
{p}td {{ padding: 0.7rem 1rem; border-bottom: 1px solid var(--edge-soft);
     vertical-align: top; }}
{p}tr:last-child td {{ border-bottom: none; }}
/* `width: 1%` shrinks these to their own content and hands every spare pixel to the name,
   which is the column with words in it. Left to share the width evenly they took about 170px
   each to hold "17,262/s", and "Documents read per document returned" wrapped over four
   lines beside all that empty space. */
{p}td.num, {p}th.num {{ font-family: var(--mono); font-variant-numeric: tabular-nums;
         white-space: nowrap; width: 1%; padding-left: 0.8rem; padding-right: 0.8rem; }}
{p}th.num {{ font-family: inherit; }}
{p}td.name {{ font-weight: 600; }}
/* The measurements and the sentence that reads them are one block: no rule between them, one
   under the pair. Without this the sentence looked like a row of its own with four empty
   columns. */
{p}tr.metric td {{ border-bottom: none; padding-bottom: 0.2rem; }}
{p}tr.say td {{ padding-top: 0.35rem; padding-bottom: 0.9rem; color: var(--ink-soft);
            max-width: 0; }}
/* What the numbers in this row are measured against — the pool size, the cache, the limit.
   Under the name because it belongs to the whole row, not to any one of the three columns. */
{p}td.name .scale {{ display: block; font-weight: 400; font-size: 0.75rem;
                 color: var(--ink-faint); margin-top: 0.15rem; }}
{p}.legend {{ font-size: 0.8125rem; color: var(--ink-faint); margin: 0.6rem 0 0; }}
"""


CSS = """
*, *::before, *::after { box-sizing: border-box; }
:root {
  color-scheme: light dark;
  --ground: #eef0f2; --panel: #fafbfc; --edge: #d3d8dd; --edge-soft: #e4e8ec;
  --ink: #171b20; --ink-soft: #5b666f; --ink-faint: #8b959d;
  --signal: #c8500f; --signal-soft: #f3e2d8;
  --ok: #2f7d55; --warn: #9a6206; --bad: #a32b22;
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #101317; --panel: #171b20; --edge: #2b3138; --edge-soft: #21262c;
    --ink: #e6eaee; --ink-soft: #97a2ab; --ink-faint: #6b757e;
    --signal: #f07a35; --signal-soft: #3a2317;
    --ok: #56b483; --warn: #d69a30; --bad: #e0685c;
  }
}
:root[data-theme="dark"] {
  --ground: #101317; --panel: #171b20; --edge: #2b3138; --edge-soft: #21262c;
  --ink: #e6eaee; --ink-soft: #97a2ab; --ink-faint: #6b757e;
  --signal: #f07a35; --signal-soft: #3a2317;
  --ok: #56b483; --warn: #d69a30; --bad: #e0685c;
}
:root[data-theme="light"] {
  --ground: #eef0f2; --panel: #fafbfc; --edge: #d3d8dd; --edge-soft: #e4e8ec;
  --ink: #171b20; --ink-soft: #5b666f; --ink-faint: #8b959d;
  --signal: #c8500f; --signal-soft: #f3e2d8;
  --ok: #2f7d55; --warn: #9a6206; --bad: #a32b22;
}
body { margin: 0; background: var(--ground); color: var(--ink);
       font-family: var(--sans); font-size: 15px; line-height: 1.55; }
.wrap { max-width: 54rem; margin: 0 auto; padding: clamp(1rem, 4vw, 2.5rem); }

.head { border-bottom: 2px solid var(--ink); padding-bottom: 1.1rem; margin-bottom: 1.75rem; }
.eyebrow { font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.1em;
           color: var(--ink-faint); }
h1 { margin: 0.3rem 0 0.2rem; font-size: 1.6rem; font-weight: 600; font-family: var(--mono); }
.sub { margin: 0; color: var(--ink-soft); font-size: 0.875rem; }

/* The one number the whole report exists to deliver. */
.rescued { background: var(--signal-soft); border-left: 3px solid var(--signal);
           padding: 1.15rem 1.35rem; margin-bottom: 1.75rem; }
.rescued b { display: block; font-family: var(--mono); font-size: 2rem; font-weight: 600;
             color: var(--signal); line-height: 1; }
.rescued span { display: block; margin-top: 0.4rem; color: var(--ink-soft);
                font-size: 0.875rem; max-width: 42rem; }

h2 { font-size: 1.0625rem; font-weight: 600; margin: 2rem 0 0.3rem; }
h2 + p { margin: 0 0 0.9rem; color: var(--ink-soft); font-size: 0.875rem; }

""" + table_css() + """
.quiet { background: var(--panel); border: 1px solid var(--edge);
         border-left: 3px solid var(--ok); padding: 1.15rem 1.35rem; }
.quiet b { color: var(--ok); }
.quiet p { margin: 0.3rem 0 0; color: var(--ink-soft); font-size: 0.875rem; }

.finding { background: var(--panel); border: 1px solid var(--edge);
           border-left: 3px solid var(--sev); padding: 1rem 1.25rem; margin-bottom: 0.75rem; }
.finding[data-sev="critical"] { --sev: var(--bad); }
.finding[data-sev="warning"]  { --sev: var(--warn); }
.finding[data-sev="info"]     { --sev: var(--ink-faint); }
.finding .tag { font-size: 0.6875rem; font-weight: 600; text-transform: uppercase;
                letter-spacing: 0.07em; color: var(--sev); }
.finding h3 { margin: 0.2rem 0 0.3rem; font-size: 1rem; }
.finding p { margin: 0; color: var(--ink-soft); font-size: 0.875rem; }
.finding .where { margin-top: 0.4rem; font-family: var(--mono); font-size: 0.75rem;
                  color: var(--ink-faint); }
/* The recurrence gets the accent because it is the argument, not decoration: anyone can report
   a saturated ticket pool, and only a service that was watching in March can say it is the
   third time. Same treatment it has on the cluster page, so the claim looks like one claim. */
.finding .again { margin-top: 0.6rem; padding: 0.45rem 0.65rem; background: var(--signal-soft);
                  border-left: 2px solid var(--signal); color: var(--signal);
                  font-size: 0.8125rem; font-weight: 600; }
.finding .again.first { background: none; border-left-color: var(--edge);
                        color: var(--ink-faint); font-weight: 400; }

footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--edge);
         color: var(--ink-faint); font-size: 0.75rem; }
"""


def esc(v) -> str:
    return (str(v).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ------------------------------------------------------------------------------ charts

# One set of colours for two grounds. This table is embedded in the web app, which is dark,
# and mailed as a standalone report, which is light -- so the charts are drawn on no ground at
# all, in mid tones that hold against both. Drawn on white they were a lit rectangle in the
# app; drawn on the panel colour they would be a dark rectangle in the mail.
INK, INK_SOFT, EDGE, SIGNAL = "#8b95a1", "#8b95a1", "#9aa4ae", "#d9822b"


def as_data_uri(fig) -> str:
    """A figure as an inline data: URI, so the report is one self-contained file.

    Reports get emailed and forwarded. One file that opens anywhere beats a folder of images
    that arrives broken.
    """
    buf = io.BytesIO()
    fig.savefig(buf, format="png", transparent=True, bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def times(series: dict) -> list[datetime]:
    return [datetime.fromtimestamp(ms / 1000, timezone.utc) for ms in series["t"]]


def overview_chart(series: dict[str, dict]) -> str | None:
    """The headline figure: what the cluster was doing across the whole rescued window.

    Operations per second, because it is the one line anybody reads without a legend. Filled
    rather than plain, since the point being made is "this much happened and you now own the
    record of it", and an area says that better than a stroke.
    """
    parts = [series.get(f"rate(serverStatus.opcounters.{n})") for n in ("query", "insert", "update")]
    parts = [p for p in parts if p and p.get("t")]
    if not parts:
        return None

    base = max(parts, key=lambda p: len(p["t"]))
    total = [0.0] * len(base["t"])
    for p in parts:
        if len(p["v"]) != len(total):
            continue
        for i, x in enumerate(p["v"]):
            if x == x:  # NaN check
                total[i] += x

    fig, ax = plt.subplots(figsize=(9.2, 2.3), dpi=150)
    t = times(base)
    ax.fill_between(t, total, color=SIGNAL, alpha=0.16, zorder=1)
    ax.plot(t, total, color=SIGNAL, linewidth=1.2, zorder=2)
    ax.set_ylabel("ops/s", fontsize=8, color=INK_SOFT)
    ax.tick_params(labelsize=8, colors=INK_SOFT, length=3, width=0.6)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b %H:%M", tz=timezone.utc))
    ax.margins(x=0)
    ax.set_ylim(bottom=0)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(EDGE)
        ax.spines[s].set_linewidth(0.8)
    ax.grid(axis="y", color=EDGE, linewidth=0.5, alpha=0.35)
    ax.set_axisbelow(True)
    return as_data_uri(fig)


def ratio_series(series: dict[str, dict], top: str, bottom: str) -> dict | None:
    """One series divided by another, second by second.

    For rows whose number is a ratio. Seconds where nothing was returned become NaN rather than
    a large number or a zero: "documents read per document returned" has no value when nothing
    was returned, and either substitute would draw a spike or a floor that did not happen.
    """
    a, b = series.get(top), series.get(bottom)
    if not a or not b or a.get("t") != b.get("t"):
        return None
    nan = float("nan")
    return {"t": a["t"],
            "v": [x / y if x == x and y == y and y else nan for x, y in zip(a["v"], b["v"])]}


def sparkline(series: dict | None) -> str | None:
    """One row's shape, drawn small enough to sit inside a table cell.

    No axes and no labels: the numbers are in the columns beside it. What this adds is whether
    the value was steady, spiky, or climbing — which no percentile can show.
    """
    if not series or not series.get("t"):
        return None
    values = [v for v in series["v"] if v == v]
    if not values or max(values) == min(values):
        return None

    fig, ax = plt.subplots(figsize=(1.9, 0.42), dpi=150)
    ax.plot(times(series), series["v"], color=INK_SOFT, linewidth=0.9)
    ax.fill_between(times(series), series["v"], color=INK_SOFT, alpha=0.12)
    ax.set_ylim(bottom=0)
    ax.margins(x=0, y=0.08)
    ax.axis("off")
    return as_data_uri(fig)


def render(summary: dict, findings: list[dict], baseline: list[dict],
           series: dict, now: datetime) -> str:
    nodes = summary.get("nodes") or []
    days = float(summary.get("days_of_raw_ftdc") or 0)
    samples = max((n["samples"] for n in nodes), default=0)
    version = next((n.get("version") for n in nodes if n.get("version")), "?")

    cells = []
    for r in build_profile(baseline):
        if r.get("ratio"):
            shown = ratio_series(series, *r["ratio"])
        else:
            shown = series.get(r["series"]) if r.get("series") else None
        spark = sparkline(shown)
        shape = f'<img class="spark" src="{spark}" alt="">' if spark else ""
        # The scale lives with the name, not inside a number. Putting "of 512 MB" in one cell
        # and a bare percentage in the next two made three columns that could not be compared
        # with each other, which is the only thing a row of three numbers is for.
        scale = f'<span class="scale">{esc(r["scale"])}</span>' if r.get("scale") else ""
        # Two rows per metric: the measurements, then the sentence that reads them. As a sixth
        # column the sentence was competing with five others for width, and in an automatic
        # table layout prose always loses that argument -- it was rendering one word per line,
        # and inside the web page it was clipped off the right edge entirely. Given the whole
        # width it needs no negotiation, and the numbers get a grid that stays a grid.
        cells.append(
            f'<tr class="metric"><td class="name">{esc(r["name"])}{scale}</td>'
            f'<td class="shape">{shape}</td>'
            f'<td class="num">{esc(r["typical"])}</td>'
            f'<td class="num">{esc(r["busiest"])}</td>'
            f'<td class="num">{esc(r["peak"])}</td></tr>'
            f'<tr class="say"><td colspan="5">{esc(r["reading"])}</td></tr>'
        )
    rows = "".join(cells)

    overview = overview_chart(series)
    overview_html = (
        f'<div class="overview"><img src="{overview}" alt="Operations per second across the '
        f'captured window"></div>' if overview else ""
    )

    if findings:
        # Grouped into moments, the same way the web page and the emails group them. Left raw,
        # this list showed one entry per node per rule: "Read ticket pool saturated" three
        # times and "Node stopped reporting" four, which reads as a cluster in far worse shape
        # than it is and as a tool that cannot tell one problem from three. This is the report a
        # customer receives on their first day, so it is the worst possible place to look
        # careless -- and it was the only one of the three views still doing it.
        from group import group as group_findings, moments as by_moment, name_nodes

        # Three, and the rest counted. Twelve entries is a wall on the one page somebody reads
        # to decide whether this service is worth anything, and the twelfth is never the one
        # that convinces them. The email already works this way -- a few in full, the remainder
        # named -- and the two should not disagree about what a first impression looks like.
        ordered = sorted(by_moment(group_findings(list(findings))),
                         key=lambda m: ({"critical": 0, "warning": 1}.get(m.severity, 2),
                                        -m.from_ms))
        blocks = []
        for m in ordered[:DETAILED_IN_PROFILE]:
            g = m.groups[0]
            f = g.worst
            extra = (f' · {len(m.groups)} signals' if len(m.groups) > 1 else '')
            # The one thing a service without history cannot say, and the reason this report is
            # worth more on day thirty than on day one. Said explicitly when there is no
            # precedent too: left blank, "first time" would read as a value that failed to load.
            earlier = times_before(findings, g.rule, g.from_ms)
            if earlier:
                again = TEXT["again"].format(n=len(earlier) + 1,
                                             when=when_day(earlier[0]["worstFromMs"]))
                again_html = f'<div class="again">{esc(again)}</div>'
            else:
                again_html = f'<div class="again first">{esc(TEXT["first"])}</div>'
            blocks.append(
                f'<div class="finding" data-sev="{esc(m.severity)}">'
                f'<div class="tag">{esc(m.severity)}</div>'
                f'<h3>{esc(g.headline())}</h3><p>{esc(f["what"])}</p>'
                f'<div class="where">{esc(name_nodes(g.nodes))} · '
                f'{esc(seconds_out_loud(g.seconds_in_state))}{esc(extra)}</div>'
                f'{again_html}</div>')
        rest = ordered[DETAILED_IN_PROFILE:]
        if rest:
            blocks.append(f'<p class="legend">{esc(TEXT["and_more"].format(n=len(rest)))}</p>')
        found_html = f"<h2>{TEXT['findings']}</h2>{''.join(blocks)}"
    else:
        found_html = (
            f'<h2>{TEXT["findings"]}</h2>'
            f'<div class="quiet"><b>{TEXT["nothing"]}</b>'
            f'<p>{TEXT["nothing_sub"].format(n=summary.get("rules_evaluated", 0))}</p></div>'
        )

    node_rows = "".join(
        f'<tr><td class="num">{esc(n.get("hostname") or n["node"])}</td>'
        f'<td class="num">{n["samples"]:,}</td>'
        f'<td class="num">{n.get("gaps", 0)}</td></tr>'
        for n in nodes
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TEXT["title"]} — {esc(summary.get("cluster_id",""))}</title>
<style>{CSS}</style></head>
<body><div class="wrap">
  <header class="head">
    <div class="eyebrow">{TEXT["title"]}</div>
    <h1>{esc(summary.get("cluster_id",""))}</h1>
    <p class="sub">MongoDB {esc(version)} · {len(nodes)} nodes</p>
  </header>

  <div class="rescued">
    <b>{days:.1f}</b>
    <span>{TEXT["rescued"].format(days=f"{days:.1f}")}. {TEXT["rescued_sub"].format(atlas=ATLAS_DAYS)}</span>
  </div>

  {overview_html}

  <h2>{TEXT["behaviour"]}</h2>
  <p>{TEXT["behaviour_sub"].format(samples=f"{samples:,}")}</p>
  <div class="scroll"><table><thead><tr>
    <th>{TEXT["metric"]}</th><th></th><th class="num">{TEXT["typical"]}</th>
    <th class="num">{TEXT["busiest"]}</th><th class="num">{TEXT["peak"]}</th>
  </tr></thead><tbody>{rows}</tbody></table></div>
  <p class="legend">{TEXT["legend"]}</p>

  {found_html}

  <h2>{TEXT["nodes"]}</h2>
  <div class="scroll"><table><thead><tr>
    <th>Host</th><th>Samples</th><th>Gaps</th>
  </tr></thead><tbody>{node_rows}</tbody></table></div>

  <footer>{TEXT["footer"].format(when=now.strftime("%d %b %Y %H:%M UTC"))}</footer>
</div></body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--cluster", required=True)
    ap.add_argument("--out", type=Path, default=Path("profile.html"))
    args = ap.parse_args()

    base = args.data / args.cluster
    if not (base / "summary.json").exists():
        print(f"no analysis yet under {base} — run analyze.py first", file=sys.stderr)
        return 2

    summary, findings, baseline, series = load(base)
    args.out.write_text(render(summary, findings, baseline, series, datetime.now(timezone.utc)))
    print(f"{args.out} · {len(build_profile(baseline))} profile rows · {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
