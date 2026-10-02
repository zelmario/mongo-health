#!/usr/bin/env python3
"""Every check mongo-health runs: what it looks at, when it speaks, and why that threshold.

    python3 catalog.py --markdown ../docs/rules.md     # the catalog for the repository

The threshold rules come from the engine itself: `rules.json` is generated from
big-hole/src/insights/rules.ts by big-hole/tools/rule-catalog.ts, reasoning included -- the
comment above each rule is where its number is justified, usually against a real capture. A
test regenerates it and fails when it no longer matches, so this catalog cannot describe a rule
that is not the one running.

The other detectors are not thresholds -- gaps in the data, elections, alarm counters, settings
that changed, one member unlike the rest, and the three the collector adds over its own history
-- and are described here, next to the code they summarise.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "rules.json"

# Samples arrive every second from FTDC files and every ten seconds over a connection string.
POLL_SECONDS = 10

AREAS = [
    ("concurrency", "Concurrency and queues"),
    ("cache", "Cache and memory"),
    ("storage", "Storage"),
    ("replication", "Replication"),
    ("queries", "Queries and workload"),
    ("connections", "Connections and network"),
    ("events", "Events"),
    ("history", "Against the cluster's own history"),
    ("configuration", "Configuration"),
]

AREA_OF = {
    "read-tickets-saturated": "concurrency", "write-tickets-saturated": "concurrency",
    "read-tickets-exhausted": "concurrency", "write-tickets-exhausted": "concurrency",
    "read-queue-building": "concurrency", "write-queue-building": "concurrency",
    "flow-control-engaged": "replication",
    "cache-dirty-high": "cache", "cache-full": "cache", "eviction-by-app-threads": "cache",
    "eviction-aggressive": "cache", "memory-low": "cache", "page-faults-sustained": "cache",
    "swapping": "cache",
    "history-store-pinned": "cache",
    "checkpoint-slow": "storage", "disk-read-latency-high": "storage",
    "disk-write-latency-high": "storage",
    "disk-space-low": "storage", "disk-space-critical": "storage",
    "member-unhealthy": "replication", "replication-lag": "replication",
    "oplog-backlog": "replication", "oplog-churn": "replication",
    "oplog-window-short": "replication", "oplog-window-critical": "replication",
    "query-targeting-poor": "queries", "collection-scans-sustained": "queries",
    "sorts-spilling-to-disk": "queries", "sorts-spilling-burst": "queries",
    "write-conflicts": "queries", "cursors-leaking": "queries", "ttl-storm": "queries",
    "connections-high": "connections", "connection-storm": "connections",
    "command-latency-high": "connections", "slow-wire-not-server": "connections",
    "packets-retransmitted": "connections",
}

# The read and write halves of a pair share one comment in rules.ts; the second inherits it.
SIBLING = {"write-tickets-saturated": "read-tickets-saturated",
           "write-tickets-exhausted": "read-tickets-exhausted",
           "write-queue-building": "read-queue-building",
           "disk-write-latency-high": "disk-read-latency-high",
           "disk-space-critical": "disk-space-low"}

UNIT = {"percent": "%", "ms": " ms", "us": " µs", "bytes": " bytes", "per-sec": "/s",
        "count": "", "seconds": ""}


def _seconds(ms: int) -> str:
    s = ms / 1000
    if s >= 3600 and s % 3600 == 0:
        return f"{s / 3600:.0f} h"
    return f"{s / 60:.0f} min" if s >= 120 and s % 60 == 0 else f"{s:.0f} s"


def when_it_speaks(r: dict) -> str:
    """The condition in words: "≥ 50% for 60 s in total, dips up to 15 s tolerated"."""
    op = "≥" if r["op"] == ">=" else "≤"
    value = f"{r['threshold']:,}".rstrip("0").rstrip(".") if isinstance(r["threshold"], float) \
        else f"{r['threshold']:,}"
    if r["unit"] == "seconds":  # a duration reads as one: "24 h", not "86,400"
        value = _seconds(r["threshold"] * 1000)
    text = f"{op} {value}{UNIT.get(r['unit'], ' ' + r['unit'])} for {_seconds(r['sustainMs'])}"
    if r["toleranceMs"]:
        text += f", dips of up to {_seconds(r['toleranceMs'])} tolerated"
    else:
        text += " without a break"
    if r.get("alongside"):
        a = r["alongside"]
        text += f"; only while `{a.get('metric')}` {a.get('op')} {a.get('threshold')} too"
    if r.get("during"):
        d = r["during"]
        dop = "≥" if d.get("op") == ">=" else "≤"
        text += f"; and only if `{d.get('metric')}` reached {dop} {d.get('threshold')} at some point"
    return text


def at_ten_seconds(r: dict) -> str | None:
    """How this check reads when samples arrive every ten seconds rather than every second.

    Every rule still runs. What changes is resolution: a condition shorter than a sample is not
    seen, and a tolerance shorter than a sample cannot bridge anything, so an episode that the
    one-second data would join up is counted as broken.
    """
    notes = []
    if r["sustainMs"] < 3 * POLL_SECONDS * 1000:
        notes.append(f"needs {_seconds(r['sustainMs'])} in breach, which is "
                     f"{max(1, r['sustainMs'] // (POLL_SECONDS * 1000))} sample(s) at ten "
                     f"seconds: short bursts are seen coarsely or not at all")
    if 0 < r["toleranceMs"] < POLL_SECONDS * 1000:
        notes.append(f"its {_seconds(r['toleranceMs'])} tolerance is shorter than one sample, so "
                     f"a single dip ends the episode")
    return "; ".join(notes) or None


DETECTORS = [
    {"id": "ftdc-long-outage", "area": "events", "severity": "critical",
     "title": "Node stopped reporting",
     "what": "The member stopped writing diagnostics for a minute or more: it was down, stalled, "
             "or the host froze.",
     "how": "A hole in the sample clock of at least 60 s. Holes within 15 minutes of each other "
            "are one incident.",
     "check": "The mongod log for that window: a restart or an election explains it; if there "
              "is nothing, the host or its volume froze.",
     "source": "big-hole/src/insights/events.ts · gapFindings"},
    {"id": "ftdc-micro-stalls", "area": "events", "severity": "warning",
     "title": "Repeated short stalls",
     "what": "The member kept pausing for a few seconds at a time — too short to be an outage, "
             "too many to be noise.",
     "how": "At least 10 holes shorter than 60 s within one incident window.",
     "check": "Host pauses: a VM being descheduled, swap, or storage that stops answering for "
              "seconds at a time.",
     "source": "big-hole/src/insights/events.ts · gapFindings"},
    {"id": "election-held", "area": "events", "severity": "warning",
     "title": "The replica set elected a new primary",
     "what": "Writes stop for the length of an election, so each one is a window in which the "
             "application could not write.",
     "how": "The replica set term went up. Elections within 30 s of each other are one event. "
            "Counted inside the report window, not over all history.",
     "check": "One around a maintenance window is expected; several without one mean members "
              "are losing contact.",
     "source": "big-hole/src/insights/events.ts · electionFindings"},
    {"id": "rolling-restart", "area": "events", "severity": "info",
     "title": "Rolling restart",
     "what": "Members restarted one after another. What maintenance, a patch or an upgrade looks "
             "like, and the explanation for the heartbeat, outage and election alerts around it.",
     "how": "serverStatus.uptime went down on two or more members, each starting within 30 "
            "minutes of the previous one coming back.",
     "check": "Whether somebody planned it: on Atlas, the project activity feed.",
     "source": "big-hole/src/insights/events.ts · restartFindings"},
    {"id": "member-restarted", "area": "events", "severity": "info",
     "title": "Member restarted",
     "what": "mongod started again on one member.",
     "how": "serverStatus.uptime went down. A new FTDC file alone is not counted: mongod also "
            "opens one when the last fills up.",
     "check": "Whether it was planned; if not, the end of the mongod log before it.",
     "source": "big-hole/src/insights/events.ts · restartFindings"},
    {"id": "alarm", "area": "events", "severity": "critical",
     "title": "An alarm counter moved",
     "what": "Counters that should never move on a healthy server — each one is an event that "
             "went wrong.",
     "how": "Any increase of one of the counters listed below.",
     "check": "The mongod log at that moment, which will say what failed and why.",
     "source": "big-hole/src/insights/events.ts · alarmFindings", "list": "alarms"},
    {"id": "setting-changed", "area": "events", "severity": "info",
     "title": "Something changed on the cluster",
     "what": "A resize, a membership change or a new MongoDB version — shown on the timeline next to what happened "
             "after it, so the two can be read together. It never claims a cause.",
     "how": "A change in one of the settings listed below. Shown as context before incidents "
            "within 72 hours.",
     "check": "Whether the behaviour after it is the change working, or the change's fault.",
     "source": "big-hole/src/insights/events.ts · changeFindings", "list": "settings"},
    {"id": "peer-outlier", "area": "events", "severity": "warning",
     "title": "One member unlike the others",
     "what": "Members of a replica set do the same work, so one far off the rest points at that "
             "host rather than at the workload.",
     "how": "One member at least 3× the median of the others on a metric listed below, above a "
            "floor that keeps near-zero values from producing ratios.",
     "check": "That host: its disk, its neighbours on the hypervisor, its configuration.",
     "source": "big-hole/src/insights/events.ts · peerFindings", "list": "peers"},
    {"id": "baseline-excursion", "area": "history", "severity": "info",
     "title": "Unusual for this cluster",
     "what": "A metric went beyond anything this cluster did in its own history — not a fixed "
             "threshold, but its own past.",
     "how": "Above the highest value held in the baseline for that metric on that member. One "
            "finding per metric per day, so a new level is said once, not every hour.",
     "check": "Whether the workload changed. A new normal is absorbed into the baseline as runs "
              "accumulate.",
     "source": "collector/anomaly.py"},
    {"id": "capacity-runway", "area": "history", "severity": "warning",
     "title": "Something will run out",
     "what": "At the rate it has been growing, a resource reaches its limit soon — the only "
             "finding that arrives before the incident.",
     "how": "Only resources with a limit the cluster itself reports (cache, connections, tickets, "
            "memory). Growth has to be steady across the whole span, not a step, and the "
            "crossing has to be near enough to matter.",
     "check": "Whether the growth is real demand or something accumulating that should not.",
     "source": "collector/runway.py"},
    {"id": "oversized-cluster", "area": "history", "severity": "info",
     "title": "Larger than its workload needs",
     "what": "Over at least a week, nothing went past half of what the cluster has — the one "
             "finding that saves money.",
     "how": "Every measured resource under 50% at its single busiest moment, on the busiest "
            "member; memory and CPU both measured; silent after any trouble in the window.",
     "check": "That the period covers the busiest time of the month before resizing.",
     "source": "collector/sizing.py"},
]


def load() -> dict:
    return json.loads(SOURCE.read_text())


def entries() -> list[dict]:
    """Every check, as one list the pages can render."""
    data = load()
    by_id = {r["id"]: r for r in data["rules"]}
    out = []
    for r in data["rules"]:
        reasoning = r["reasoning"] or (by_id[SIBLING[r["id"]]]["reasoning"]
                                       if r["id"] in SIBLING else "")
        # Paragraphs in the source comment are separated by an empty `//` line.
        reasoning = "\n\n".join(p.strip() for p in reasoning.split("\n") if p.strip())
        out.append({**r, "kind": "threshold", "area": AREA_OF.get(r["id"], "queries"),
                    "how": when_it_speaks(r), "reasoning": reasoning,
                    "ten_seconds": at_ten_seconds(r),
                    "source": "big-hole/src/insights/rules.ts"})
    for d in DETECTORS:
        out.append({**d, "kind": "detector",
                    "items": data["events"].get(d.get("list", ""), [])})
    # Settings, not events: read from the FTDC metadata by recommend.py.
    import recommend
    for c in recommend.CHECKS.values():
        out.append({"id": c.id, "kind": "config", "area": "configuration",
                    "severity": c.severity, "title": c.title, "what": c.why, "how": c.how,
                    "check": "The recommendation on the cluster page names the members and "
                             "the setting to change.",
                    "source": "collector/recommend.py"})
    return out


def anchor(rule_id: str) -> str:
    """Where a finding's rule is described: alarm counters share one entry."""
    return "alarm" if rule_id.startswith("alarm:") else rule_id


def markdown() -> str:
    items = entries()
    lines = ["# The checks", "",
             "Every check mongo-health runs, what it looks at, when it speaks and why at that "
             "threshold. Generated from the code by `collector/catalog.py`; the threshold rules "
             "come from `big-hole/src/insights/rules.ts`, reasoning included.", "",
             f"{sum(1 for e in items if e['kind'] == 'threshold')} threshold rules, "
             f"{sum(1 for e in items if e['kind'] == 'detector')} detectors and "
             f"{sum(1 for e in items if e['kind'] == 'config')} configuration checks.", ""]
    for key, name in AREAS:
        group = [e for e in items if e["area"] == key]
        if not group:
            continue
        lines += [f"## {name}", ""]
        for e in group:
            lines += [f"### {e['title']} — `{e['id']}`", "",
                      f"**Severity:** {e['severity']} · **Speaks when:** {e['how']}", ""]
            if e.get("metric"):
                lines += [f"**Metric:** `{e['metric']}`", ""]
            lines += [e["what"], ""]
            if e.get("items"):
                lines += [f"- {i['title']} — `{i['path']}`" for i in e["items"]] + [""]
            if e.get("reasoning"):
                lines += [f"**Why this threshold.** {e['reasoning']}", ""]
            lines += [f"**What to check.** {e['check']}", ""]
            if e.get("ten_seconds"):
                lines += [f"**Over a connection string (a sample every ten seconds):** "
                          f"{e['ten_seconds']}.", ""]
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--markdown", type=Path, required=True)
    args = ap.parse_args()
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text(markdown())
    print(f"{args.markdown} · {len(entries())} checks")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
