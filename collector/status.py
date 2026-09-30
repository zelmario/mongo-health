#!/usr/bin/env python3
"""Build the status page: every cluster being watched, and how much history is banked.

Runs after `analyze.py`, from the same cron entry, and writes one self-contained HTML file.

    python3 status.py --data data --out status.html

This is deliberately NOT a metrics dashboard. Big Hole already charts all 5,700 series and
the customer's problem was never being unable to see a metric -- it was not knowing which one
to look at. What this page answers is the question a silent service cannot otherwise answer:
is it running, and what am I getting for it?

Which is why the headline number is days of history. Atlas keeps 3 to 10 days; the moment
this passes that, the customer holds something they cannot get anywhere else, and it grows
every day whether or not anything went wrong. That is the whole argument for the service on a
quiet week, and it deserves to be the biggest thing on the page.

There are two such numbers and the page keeps them apart, because conflating them would
misstate what is being sold:

  - **days observed** — how long this cluster has been watched, from the baseline. Never
    shrinks; pruning does not touch the baseline. This is the headline.
  - **days of raw FTDC** — how far back a capture can still be opened and read second by
    second. This is what the retention window buys, and `prune.py` does shrink it.

The bar compares the second against Atlas, since that is the like-for-like comparison. The
first appears underneath only once the two diverge, which is to say only after pruning has
actually removed something.

Static HTML on purpose: no server, no accounts, no framework. It can be emailed, dropped on
S3, or opened from disk. The web app comes later.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------- strings

# Kept apart from the logic so a second language is a file rather than a rewrite. There is no
# translation machinery yet, and there should not be until a customer asks for one.
TEXT = {
    "title": "Cluster status",
    "subtitle": "FTDC capture and analysis",
    "clusters_watched": "clusters watched",
    "days_banked": "days of history banked",
    "findings_week": "findings this week",
    "history": "History",
    "atlas_keeps": "Atlas keeps ~{days} days",
    "you_have": "you have {days}",
    "beyond_atlas": "{days} days Atlas no longer has",
    "not_yet_past": "still inside what Atlas retains",
    "watched": "Watched for {days} days — earlier raw data has been pruned, the measured history is kept",
    "nodes": "Nodes",
    "last_capture": "Last capture",
    "stored": "Stored",
    "coverage": "Coverage",
    "rules_ok": "{n} rules, all resolving",
    "rules_bad": "{n} of {total} rules cannot resolve on this build",
    "no_findings": "Nothing to report",
    "no_findings_sub": "All rules ran and none fired.",
    "recent": "Recent findings",
    "samples": "samples",
    "gaps": "gaps",
    "blind": "blind",
    "never": "never",
    "state_healthy": "Healthy",
    "state_attention": "Needs attention",
    "state_critical": "Critical",
    "state_stale": "Not capturing",
    "state_empty": "No data yet",
    "stale_note": "No capture in {hours}h — the collector may have stopped.",
    "empty_note": "Nothing captured yet. The first run fills this in.",
    "footer": "Generated {when} · Big Hole",
}

# Atlas retention is a range rather than a promise: measured between 3 and 10 days depending
# on cluster size and how fast it writes. The low end is used for the comparison so the claim
# is the conservative one.
ATLAS_DAYS = 3
STALE_AFTER_HOURS = 4  # cron runs hourly; four missed runs is a real problem


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def read_clusters(root: Path) -> list[dict]:
    """One record per cluster, from whatever analyze.py left behind."""
    out = []
    for summary_path in sorted(root.glob("*/summary.json")):
        base = summary_path.parent
        summary = json.loads(summary_path.read_text())

        findings = []
        findings_path = base / "findings.jsonl"
        if findings_path.exists():
            findings = [json.loads(line) for line in findings_path.read_text().splitlines() if line]

        summary["findings"] = findings
        out.append(summary)

    # A cluster that was configured but never captured has no summary.json at all, and that
    # absence is exactly what needs to be seen. Pick those up separately.
    for state_path in sorted(root.glob("*/state.json")):
        base = state_path.parent
        if (base / "summary.json").exists():
            continue
        state = json.loads(state_path.read_text())
        out.append({
            "cluster_id": state.get("cluster_id", base.name),
            "last_capture": state.get("last_capture"),
            "nodes": [],
            "days_of_raw_ftdc": 0,
            "days_observed": 0,
            "megabytes": 0,
            "findings": [],
            "findings_total": 0,
            "rules_evaluated": 0,
            "rules_unresolved": [],
            "empty": True,
        })
    return out


def assess(cluster: dict, now: datetime) -> tuple[str, str, str]:
    """Reduce a cluster to one state: (key, label, note).

    Order matters. A stale collector outranks a clean bill of health, because "no findings"
    from a collector that stopped three days ago is not good news -- it is the absence of
    news, and presenting it as green is the one thing this page must never do.
    """
    if cluster.get("empty"):
        return "empty", TEXT["state_empty"], TEXT["empty_note"]

    last = parse_iso(cluster.get("last_capture"))
    if last is not None:
        hours = (now - last).total_seconds() / 3600
        if hours > STALE_AFTER_HOURS:
            return "stale", TEXT["state_stale"], TEXT["stale_note"].format(hours=int(hours))

    recent = recent_findings(cluster, now)
    if any(f["severity"] == "critical" for f in recent):
        return "critical", TEXT["state_critical"], ""
    if recent:
        return "attention", TEXT["state_attention"], ""
    return "healthy", TEXT["state_healthy"], ""


def recent_findings(cluster: dict, now: datetime, days: int = 7) -> list[dict]:
    cutoff = now - timedelta(days=days)
    out = []
    for f in cluster.get("findings", []):
        detected = parse_iso(f.get("detected_at"))
        if detected is None or detected >= cutoff:
            out.append(f)
    return sorted(out, key=lambda f: f.get("toMs", 0), reverse=True)


def human_age(when: datetime | None, now: datetime) -> str:
    if when is None:
        return TEXT["never"]
    seconds = (now - when).total_seconds()
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{int(seconds // 60)} min ago"
    if seconds < 172800:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} days ago"


def when_ms(ms: float) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%d %b %H:%M")


def esc(value) -> str:
    return (
        str(value)
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


# ------------------------------------------------------------------------------- CSS

CSS = """
*, *::before, *::after { box-sizing: border-box; }

:root {
  color-scheme: light dark;

  /* Instrument greys, biased cold rather than neutral, so the warm accent has something
     to sit against. */
  --ground:      #eef0f2;
  --panel:       #fafbfc;
  --edge:        #d3d8dd;
  --edge-soft:   #e4e8ec;
  --ink:         #171b20;
  --ink-soft:    #5b666f;
  --ink-faint:   #8b959d;

  /* Flight-data-recorder orange. Used for exactly one thing on this page: the history a
     customer has beyond what Atlas retains. Spending it anywhere else would flatten it. */
  --signal:      #c8500f;
  --signal-soft: #f3e2d8;

  /* Semantic state, deliberately separate from the accent. */
  --ok:          #2f7d55;
  --ok-soft:     #dceee4;
  --warn:        #9a6206;
  --warn-soft:   #f7ead1;
  --bad:         #a32b22;
  --bad-soft:    #f7dedb;
  --off:         #6b737a;
  --off-soft:    #e6e9ec;

  --mono: ui-monospace, "SF Mono", "Cascadia Mono", "Roboto Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;

  --gutter: clamp(1rem, 4vw, 2.5rem);
}

@media (prefers-color-scheme: dark) {
  :root {
    --ground:      #101317;
    --panel:       #171b20;
    --edge:        #2b3138;
    --edge-soft:   #21262c;
    --ink:         #e6eaee;
    --ink-soft:    #97a2ab;
    --ink-faint:   #6b757e;
    --signal:      #f07a35;
    --signal-soft: #3a2317;
    --ok:          #56b483;   --ok-soft:   #16301f;
    --warn:        #d69a30;   --warn-soft: #322512;
    --bad:         #e0685c;   --bad-soft:  #351a18;
    --off:         #8b959d;   --off-soft:  #21262c;
  }
}

:root[data-theme="dark"] {
  --ground: #101317; --panel: #171b20; --edge: #2b3138; --edge-soft: #21262c;
  --ink: #e6eaee; --ink-soft: #97a2ab; --ink-faint: #6b757e;
  --signal: #f07a35; --signal-soft: #3a2317;
  --ok: #56b483; --ok-soft: #16301f;
  --warn: #d69a30; --warn-soft: #322512;
  --bad: #e0685c; --bad-soft: #351a18;
  --off: #8b959d; --off-soft: #21262c;
}

:root[data-theme="light"] {
  --ground: #eef0f2; --panel: #fafbfc; --edge: #d3d8dd; --edge-soft: #e4e8ec;
  --ink: #171b20; --ink-soft: #5b666f; --ink-faint: #8b959d;
  --signal: #c8500f; --signal-soft: #f3e2d8;
  --ok: #2f7d55; --ok-soft: #dceee4;
  --warn: #9a6206; --warn-soft: #f7ead1;
  --bad: #a32b22; --bad-soft: #f7dedb;
  --off: #6b737a; --off-soft: #e6e9ec;
}

body {
  margin: 0;
  background: var(--ground);
  color: var(--ink);
  font-family: var(--sans);
  font-size: 15px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

.wrap { max-width: 68rem; margin: 0 auto; padding: var(--gutter); }

/* ---- masthead ---- */

.masthead {
  display: flex; flex-wrap: wrap; gap: 1.5rem 2.5rem;
  align-items: flex-end; justify-content: space-between;
  padding-bottom: 1.25rem; margin-bottom: 1.75rem;
  border-bottom: 2px solid var(--ink);
}
.masthead h1 {
  margin: 0; font-size: 1.5rem; font-weight: 600; letter-spacing: -0.01em;
  text-wrap: balance;
}
.masthead p { margin: 0.15rem 0 0; color: var(--ink-soft); font-size: 0.875rem; }

.tallies { display: flex; gap: 2rem; flex-wrap: wrap; }
.tally { display: flex; flex-direction: column; gap: 0.1rem; }
.tally b {
  font-family: var(--mono); font-size: 1.6rem; font-weight: 600;
  font-variant-numeric: tabular-nums; line-height: 1;
}
.tally span {
  font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.08em;
  color: var(--ink-faint);
}
.tally.accent b { color: var(--signal); }

/* ---- cluster record ---- */

.record {
  background: var(--panel);
  border: 1px solid var(--edge);
  border-left: 3px solid var(--state);
  margin-bottom: 1rem;
}
.record[data-state="healthy"]   { --state: var(--ok);   --state-soft: var(--ok-soft); }
.record[data-state="attention"] { --state: var(--warn); --state-soft: var(--warn-soft); }
.record[data-state="critical"]  { --state: var(--bad);  --state-soft: var(--bad-soft); }
.record[data-state="stale"]     { --state: var(--warn); --state-soft: var(--warn-soft); }
.record[data-state="empty"]     { --state: var(--off);  --state-soft: var(--off-soft); }

.record-head {
  display: flex; flex-wrap: wrap; gap: 0.5rem 1rem;
  align-items: baseline; justify-content: space-between;
  padding: 0.9rem 1.15rem;
  border-bottom: 1px solid var(--edge-soft);
}
.name { font-family: var(--mono); font-size: 1rem; font-weight: 600; }

.pill {
  display: inline-flex; align-items: center; gap: 0.4rem;
  padding: 0.2rem 0.6rem;
  background: var(--state-soft); color: var(--state);
  font-size: 0.6875rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.07em;
  white-space: nowrap;
}
.pill::before {
  content: ""; width: 0.4rem; height: 0.4rem; border-radius: 50%;
  background: currentColor;
}

.note {
  padding: 0.6rem 1.15rem;
  background: var(--state-soft); color: var(--state);
  font-size: 0.8125rem;
  border-bottom: 1px solid var(--edge-soft);
}

/* ---- retention bar: the one place the accent is spent ---- */

.retention { padding: 1.05rem 1.15rem; border-bottom: 1px solid var(--edge-soft); }
.retention-top {
  display: flex; justify-content: space-between; align-items: baseline;
  gap: 1rem; margin-bottom: 0.55rem;
}
.label {
  font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.08em;
  color: var(--ink-faint);
}
.verdict { font-size: 0.8125rem; color: var(--ink-soft); }
.verdict b { color: var(--signal); font-weight: 600; }

.bar {
  position: relative; height: 1.65rem;
  background: var(--edge-soft);
  overflow: hidden;
}
.bar-atlas {
  position: absolute; inset: 0 auto 0 0;
  background: var(--ink-faint); opacity: 0.35;
}
.bar-ours {
  position: absolute; inset: 0 auto 0 0;
  background: var(--signal);
}
/* The stretch beyond Atlas is the product. It gets the solid fill; the part Atlas also
   holds is knocked back so the eye lands on the difference. */
.bar-ours.overlap { background: var(--ink-faint); opacity: 0.55; }
.bar-mark {
  position: absolute; top: 0; bottom: 0; width: 2px;
  background: var(--ink); opacity: 0.55;
}
.watched {
  margin-top: 0.5rem; padding-top: 0.5rem;
  border-top: 1px dashed var(--edge-soft);
  font-size: 0.75rem; color: var(--ink-faint);
}

.bar-scale {
  display: flex; justify-content: space-between;
  margin-top: 0.35rem;
  font-family: var(--mono); font-size: 0.6875rem;
  font-variant-numeric: tabular-nums; color: var(--ink-faint);
}

/* ---- facts ---- */

.facts {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr));
  gap: 1px; background: var(--edge-soft);
  border-bottom: 1px solid var(--edge-soft);
}
.fact { background: var(--panel); padding: 0.75rem 1.15rem; }
.fact b {
  display: block; font-family: var(--mono); font-size: 0.9375rem; font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.fact.warn b { color: var(--warn); }

/* ---- nodes + findings ---- */

.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; }
th {
  text-align: left; padding: 0.5rem 1.15rem;
  font-size: 0.6875rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.07em; color: var(--ink-faint);
  border-bottom: 1px solid var(--edge-soft); white-space: nowrap;
}
td {
  padding: 0.5rem 1.15rem; border-bottom: 1px solid var(--edge-soft);
  vertical-align: top;
}
tr:last-child td { border-bottom: none; }
td.num { font-family: var(--mono); font-variant-numeric: tabular-nums; white-space: nowrap; }
td.host { font-family: var(--mono); }
.muted { color: var(--ink-faint); }

.sev {
  font-family: var(--mono); font-size: 0.6875rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap;
}
.sev.critical { color: var(--bad); }
.sev.warning  { color: var(--warn); }
.sev.info     { color: var(--ink-soft); }

.quiet {
  padding: 1.35rem 1.15rem; display: flex; gap: 0.75rem; align-items: baseline;
}
.quiet b { color: var(--ok); font-size: 0.9375rem; }
.quiet span { color: var(--ink-soft); font-size: 0.8125rem; }

footer {
  margin-top: 2rem; padding-top: 1rem;
  border-top: 1px solid var(--edge);
  color: var(--ink-faint); font-size: 0.75rem;
}

@media (max-width: 34rem) {
  .masthead { gap: 1.25rem; }
  .tallies { gap: 1.5rem; }
  .tally b { font-size: 1.35rem; }
}
"""


def render_retention(cluster: dict) -> str:
    """The comparison bar: our window against what Atlas would still be holding.

    Scaled to whichever is larger so the bar always means something -- on day one it shows
    the customer still inside Atlas's window, which is honest, and it stops being true within
    a couple of weeks.
    """
    ours = float(cluster.get("days_of_raw_ftdc") or cluster.get("days_of_history") or 0)
    span = max(ours, ATLAS_DAYS) * 1.08 or 1
    atlas_pct = min(100, ATLAS_DAYS / span * 100)
    ours_pct = min(100, ours / span * 100)
    overlap_pct = min(atlas_pct, ours_pct)
    beyond = max(0.0, ours - ATLAS_DAYS)

    if beyond > 0:
        verdict = TEXT["beyond_atlas"].format(days=f"<b>{beyond:.0f}</b>")
    else:
        verdict = f'<span class="muted">{TEXT["not_yet_past"]}</span>'

    # "Watched for" and "can be opened" are different claims, and only the second one shrinks
    # when old FTDC is pruned. Shown only once it says something the bar does not, so a
    # cluster that has never been pruned does not carry a line explaining pruning.
    observed = float(cluster.get("days_observed") or 0)
    watched = ""
    if observed > ours + 1:
        watched = f'<div class="watched">{TEXT["watched"].format(days=f"{observed:.0f}")}</div>'

    return f"""
      <div class="retention">
        <div class="retention-top">
          <span class="label">{TEXT["history"]}</span>
          <span class="verdict">{verdict}</span>
        </div>
        <div class="bar" role="img" aria-label="{ours:.1f} days held, Atlas keeps about {ATLAS_DAYS}">
          <div class="bar-atlas" style="width:{atlas_pct:.1f}%"></div>
          <div class="bar-ours" style="width:{ours_pct:.1f}%"></div>
          <div class="bar-ours overlap" style="width:{overlap_pct:.1f}%"></div>
          <div class="bar-mark" style="left:{atlas_pct:.1f}%"></div>
        </div>
        <div class="bar-scale">
          <span>{TEXT["atlas_keeps"].format(days=ATLAS_DAYS)}</span>
          <span>{TEXT["you_have"].format(days=f"{ours:.1f}d")}</span>
        </div>
        {watched}
      </div>"""


def render_nodes(cluster: dict) -> str:
    nodes = cluster.get("nodes") or []
    if not nodes:
        return ""
    rows = []
    for n in nodes:
        blind = n.get("seconds_without_data", 0)
        gaps = n.get("gaps", 0)
        gap_cell = (
            f'<span class="muted">—</span>' if not gaps
            else f'{gaps} {TEXT["gaps"]}, {blind}s {TEXT["blind"]}'
        )
        rows.append(
            f"<tr><td class=\"host\">{esc(n.get('hostname') or n.get('node'))}</td>"
            f"<td class=\"num muted\">{esc(n.get('version') or '?')}</td>"
            f"<td class=\"num\">{n.get('samples', 0):,}</td>"
            f"<td class=\"num\">{gap_cell}</td></tr>"
        )
    return f"""
      <div class="scroll">
        <table>
          <thead><tr>
            <th>{TEXT["nodes"]}</th><th>Version</th><th>{TEXT["samples"]}</th><th>Continuity</th>
          </tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>"""


def render_findings(cluster: dict, now: datetime) -> str:
    recent = recent_findings(cluster, now)
    if not recent:
        return f"""
      <div class="quiet">
        <b>{TEXT["no_findings"]}</b>
        <span>{TEXT["no_findings_sub"]}</span>
      </div>"""

    rows = []
    for f in recent[:8]:
        rows.append(
            f'<tr><td class="sev {esc(f["severity"])}">{esc(f["severity"])}</td>'
            f'<td>{esc(f["title"])}<br><span class="muted">{esc(f["what"])}</span></td>'
            f'<td class="host muted">{esc(f["node"].split(".")[0])}</td>'
            f'<td class="num muted">{when_ms(f["worstFromMs"])}<br>{f["secondsInState"]}s</td></tr>'
        )
    return f"""
      <div class="scroll">
        <table>
          <thead><tr>
            <th></th><th>{TEXT["recent"]}</th><th>Node</th><th>Worst window</th>
          </tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>"""


def render_cluster(cluster: dict, now: datetime) -> str:
    state, label, note = assess(cluster, now)
    last = parse_iso(cluster.get("last_capture"))
    unresolved = cluster.get("rules_unresolved") or []
    total_rules = cluster.get("rules_evaluated", 0)

    if unresolved:
        coverage = TEXT["rules_bad"].format(n=len(unresolved), total=total_rules)
        coverage_class = "fact warn"
    else:
        coverage = TEXT["rules_ok"].format(n=total_rules)
        coverage_class = "fact"

    note_html = f'<div class="note">{esc(note)}</div>' if note else ""
    retention = "" if cluster.get("empty") else render_retention(cluster)

    return f"""
    <article class="record" data-state="{state}">
      <div class="record-head">
        <div class="name">{esc(cluster["cluster_id"])}</div>
        <span class="pill">{esc(label)}</span>
      </div>
      {note_html}
      {retention}
      <div class="facts">
        <div class="fact"><span class="label">{TEXT["last_capture"]}</span>
          <b>{esc(human_age(last, now))}</b></div>
        <div class="fact"><span class="label">{TEXT["stored"]}</span>
          <b>{cluster.get("megabytes", 0)} MB</b></div>
        <div class="{coverage_class}"><span class="label">{TEXT["coverage"]}</span>
          <b>{esc(coverage)}</b></div>
      </div>
      {render_nodes(cluster)}
      {render_findings(cluster, now)}
    </article>"""


def build(clusters: list[dict], now: datetime) -> str:
    # The headline total counts observed history, not raw FTDC: pruning removes the
    # second and never the first, and what the service accumulated is the claim.
    banked = sum(float(c.get("days_observed") or c.get("days_of_raw_ftdc") or 0)
                 for c in clusters)
    week = sum(len(recent_findings(c, now)) for c in clusters)

    records = "\n".join(render_cluster(c, now) for c in clusters) or (
        '<article class="record" data-state="empty">'
        '<div class="record-head"><div class="name">No clusters configured</div></div>'
        '</article>'
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TEXT["title"]}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="masthead">
    <div>
      <h1>{TEXT["title"]}</h1>
      <p>{TEXT["subtitle"]}</p>
    </div>
    <div class="tallies">
      <div class="tally"><b>{len(clusters)}</b><span>{TEXT["clusters_watched"]}</span></div>
      <div class="tally accent"><b>{banked:.0f}</b><span>{TEXT["days_banked"]}</span></div>
      <div class="tally"><b>{week}</b><span>{TEXT["findings_week"]}</span></div>
    </div>
  </header>
  {records}
  <footer>{TEXT["footer"].format(when=now.strftime("%d %b %Y %H:%M UTC"))}</footer>
</div>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--out", type=Path, default=Path("status.html"))
    args = ap.parse_args()

    if not args.data.exists():
        print(f"{args.data} does not exist — run capture.py first", file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)
    clusters = read_clusters(args.data)
    args.out.write_text(build(clusters, now))

    print(f"{args.out} · {len(clusters)} cluster(s)")
    for c in clusters:
        state, label, _ = assess(c, now)
        print(f"  {c['cluster_id']:24} {label:16} "
              f"{c.get('days_observed', 0)}d watched, "
              f"{c.get('days_of_raw_ftdc', 0)}d of raw FTDC")
    return 0


if __name__ == "__main__":
    sys.exit(main())
