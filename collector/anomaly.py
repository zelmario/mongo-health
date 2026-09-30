"""Compare the latest window against what this cluster normally looks like.

The fixed rules ask "is this bad in absolute terms" -- more than half the ticket pool, cache
over 95%, a checkpoint past a second. Useful, and anyone can write them. What justifies
keeping a year of history is the other question: **is this unusual for this cluster**.

A ticket pool at 24 is nothing on a cluster that normally runs at 40, and an emergency on one
that has never been above 1. Same number, opposite meaning, and only the baseline can tell
them apart.

This deliberately produces `info` findings rather than warnings. An excursion from normal is a
lead, not a verdict: the cluster may simply have more traffic today. It earns a place in the
weekly summary, not an out-of-hours email.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

# A cluster needs a past before "unusual" means anything. Below this many runs the detector
# stays quiet rather than calling every new cluster anomalous for its first two days.
MIN_RUNS = 6

# How far past its own ceiling a metric must go. Calibrated in `tools/calibrar_anomalias.py`
# against the real capture: at 3x the quiet runs produce nothing and the loaded run produces
# the excursions that matter.
FACTOR = 3.0

# Relative change alone is a trap: 0.001 -> 0.01 is ten times larger and means nothing. A
# metric must also move by something worth a sentence, expressed as a fraction of the range
# this metric has ever covered on this node.
MIN_SHARE_OF_RANGE = 0.10


@dataclass(frozen=True)
class Excursion:
    node: str
    metric: str
    recent: float
    ceiling: float
    ratio: float
    runs: int

    @property
    def headline(self) -> str:
        if self.ceiling == 0:
            return f"{self.metric} moved for the first time on this node"
        return f"{self.metric} is {self.ratio:.0f}x its usual ceiling"


def load_history(path: Path, before_run: str) -> dict[tuple[str, str], list[dict]]:
    """Baseline rows from earlier runs, keyed by (node, metric).

    `before_run` excludes the run being judged. Including it would fold the excursion into
    the very ceiling it is being measured against, which is how an anomaly detector talks
    itself out of every finding it makes.
    """
    if not path.exists():
        return {}
    out: dict[tuple[str, str], list[dict]] = {}
    for line in path.read_text().splitlines():
        if not line:
            continue
        row = json.loads(line)
        if row.get("scope") != "baseline" or row.get("run", "") >= before_run:
            continue
        out.setdefault((row["node"], row["metric"]), []).append(row)
    return out


def find(nodes: list[dict], history: dict[tuple[str, str], list[dict]]) -> list[Excursion]:
    """Metrics whose latest window sits well outside this node's own history."""
    out: list[Excursion] = []

    for node in nodes:
        label = node.get("hostname") or node["node"]
        for window in node.get("recent", []):
            metric = window["metric"]
            past = history.get((node["node"], metric)) or history.get((label, metric)) or []
            if len(past) < MIN_RUNS:
                continue

            recent = window["p95"]
            if not math.isfinite(recent):
                continue

            # The ceiling is the highest p95 this node has ever recorded, not the mean. A
            # cluster's normal includes its busy hours, and comparing against an average
            # would flag every weekday morning.
            ceiling = max(row["p95"] for row in past)
            floor = min(row["min"] for row in past)
            seen_range = max(row["max"] for row in past) - floor

            if ceiling > 0:
                if recent < ceiling * FACTOR:
                    continue
                ratio = recent / ceiling
            else:
                # Never moved before. That is interesting, but only if it has now moved by
                # something comparable to the range this metric occupies elsewhere.
                if recent <= 0:
                    continue
                ratio = math.inf

            # The absolute-size guard.
            #
            # Comparing the jump against this metric's own range is only meaningful when that
            # range is itself worth something. On a metric that has only ever occupied
            # 0.001 to 0.002, a tenfold jump clears any share-of-range test trivially -- the
            # range is as tiny as the values. A test written against that case is what caught
            # this: the guard read as absolute and behaved as relative.
            #
            # So the relative test applies only above a range of 1, and everything else has to
            # reach 1 in absolute terms to be worth a sentence in a report.
            if seen_range >= 1:
                if (recent - ceiling) < seen_range * MIN_SHARE_OF_RANGE:
                    continue
            elif recent < 1:
                continue

            out.append(Excursion(node=label, metric=metric, recent=recent,
                                 ceiling=ceiling, ratio=ratio, runs=len(past)))

    # Biggest departures first; infinities (first movement ever) sort to the top.
    return sorted(out, key=lambda e: (-e.ratio if math.isfinite(e.ratio) else -1e18, e.metric))


def _chart_for(e: Excursion, nodes: list[dict], title: str) -> dict | None:
    """The excursion's series, with the ceiling it broke drawn across it.

    This is the one chart in the product that shows the claim rather than illustrating it. Every
    other rule draws a metric against a threshold somebody chose; here the line is this node's
    own history, and the gap between the two IS the finding. It is also the thing no first
    capture can produce and no competitor with a week of retention can either -- which makes it
    worth the round trip to fetch the series.
    """
    canonical = e.metric.split(" (via")[0]
    for node in nodes:
        if e.node not in (node.get("hostname"), node.get("node")):
            continue
        shape = (node.get("windowSeries") or {}).get(canonical)
        if not shape or not shape.get("t"):
            return None
        return {
            "t": shape["t"],
            "v": shape["v"],
            "series": [{"label": canonical.split(".")[-1],
                        "v": shape["v"],
                        "unit": shape.get("unit") or ""}],
            "threshold": e.ceiling if e.ceiling > 0 else None,
            # The rules' wording ("a problem above this line") would be wrong twice over: the
            # ceiling is not a limit anybody set, and being above it is unusual rather than
            # necessarily bad. Saying where the line comes from is the whole point.
            #
            # Words only -- the number is formatted where the chart is drawn, because only that
            # side knows what unit the axis ended up in. Written here it read "5.00555e+06"
            # against an axis in MiB.
            "thresholdNote": f"highest in the previous {e.runs} runs",
            # The line describes this node's past; it does not define the finding. Shading
            # every crossing of it, which is right for a rule's threshold, turned a cache that
            # idles either side of its own ceiling into a chart striped with twenty bands.
            "thresholdIsBaseline": True,
            "title": title,
            "fromMs": shape["t"][0],
            "toMs": shape["t"][-1],
        }
    return None


def as_findings(excursions: list[Excursion], window_from: int, window_to: int,
                nodes: list[dict] | None = None) -> list[dict]:
    """Shape them like every other finding, so the rest of the pipeline needs no special case."""
    findings = []
    for e in excursions:
        pretty = e.metric.split(" (via")[0].replace("serverStatus.", "")
        if e.ceiling == 0:
            what = (f"{pretty} reached {e.recent:g} in this window. Across the previous "
                    f"{e.runs} runs this node never recorded it above zero.")
        else:
            what = (f"{pretty} reached {e.recent:g} in this window, against a ceiling of "
                    f"{e.ceiling:g} across the previous {e.runs} runs — {e.ratio:.0f}x higher "
                    f"than this node has ever shown.")
        findings.append({
            "rule": "baseline-excursion",
            "title": f"Unusual for this cluster: {pretty}",
            "severity": "info",
            "node": e.node,
            "metric": e.metric,
            "episodes": 1,
            "fromMs": window_from,
            "toMs": window_to,
            "worstFromMs": window_from,
            "worstToMs": window_to,
            "secondsInState": max(0, (window_to - window_from) // 1000),
            "peak": e.recent,
            "unit": "",
            "what": what,
            "check": ("Compare against the other members: if only one node moved, look at that "
                      "host. If all of them did, the workload changed and the new level may "
                      "simply be the new normal."),
            "chart": _chart_for(e, nodes or [], f"Unusual: {pretty}"),
        })
    return findings
