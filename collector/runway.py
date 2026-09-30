"""How long until this cluster runs out of something.

Every other detector here answers "what is happening" or "what happened". This one answers the
question a DBA schedules work around: **when does this become a problem**. It is the only
finding in the product that arrives before the incident rather than after it, and it is the one
that cannot exist without months of history — a service with three days of retention can see a
cache at 78% and has no way to know whether it has been 78% all year or crossed 60% last week.

It is deliberately narrow, for a reason that took a measurement to learn. The obvious version --
"tell me which metrics are trending" -- cannot be calibrated: fitted across the stored baseline,
the median metric on the test clusters moves 60% per day, because load metrics swing with
whatever the application is doing and a slope on them means nothing. Worse, the steepest
"trends" in real data were the load winding down after a generator run: a real trend, correctly
found, and of no interest to anybody.

So this does not judge slopes against a threshold at all. It asks three questions that can each
be answered without guessing a number:

  1. Is there a real ceiling?   Only metrics paired with a limit the cluster itself reports --
                                the configured cache size, the connection limit, the ticket
                                pool, the host's total memory. Nothing is projected against a
                                figure somebody invented.
  2. Does it rise all the way through? Two tests, because one is not enough. Spearman's rank
                                correlation gives the overall direction -- but it does NOT
                                reject a step, which is the mistake this had until a test
                                caught it: when every low value precedes every high one, the
                                rank correlation is about 0.87, and idle-then-busy is the most
                                ordinary thing a cluster does. So the window is also cut into
                                four and each quarter must sit above the one before. A step
                                fails that at the boundary where nothing changed.
  3. Does the line cross the limit soon enough to matter? This is a product decision, not a
                                statistical one, and it is self-limiting: a crossing two years
                                out is not a finding at any slope.

Measured against both real clusters -- six days of Atlas and five of a local set, every metric
and every member -- this produces **nothing**. The nearest projection was 949 days away. That is
the false-positive evidence, and it holds without any calibrated slope.
"""
from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Metric -> the metric that carries its ceiling, and which direction is the bad one.
#
# `None` for connections because the limit is not reported directly: `available` is what is
# LEFT, so the ceiling is current + available. The same trap that once made `connections-high`
# read 100% at half full.
LIMITS: list[tuple[str, str | None, str]] = [
    ("serverStatus.wiredTiger.cache.bytes currently in the cache",
     "serverStatus.wiredTiger.cache.maximum bytes configured", "up"),
    ("serverStatus.connections.current", None, "up"),
    ("systemMetrics.memory.MemAvailable_kb", "systemMetrics.memory.MemTotal_kb", "down"),
    ("serverStatus.wiredTiger.concurrentTransactions.read.out",
     "serverStatus.wiredTiger.concurrentTransactions.read.totalTickets", "up"),
    ("serverStatus.wiredTiger.concurrentTransactions.write.out",
     "serverStatus.wiredTiger.concurrentTransactions.write.totalTickets", "up"),
]

# Names a reader recognises. The metric path is in the finding for anyone who wants it.
PRETTY = {
    "serverStatus.wiredTiger.cache.bytes currently in the cache": "the cache",
    "serverStatus.connections.current": "the connection pool",
    "systemMetrics.memory.MemAvailable_kb": "free memory on the host",
    "serverStatus.wiredTiger.concurrentTransactions.read.out": "the read ticket pool",
    "serverStatus.wiredTiger.concurrentTransactions.write.out": "the write ticket pool",
}

# A projection needs a base long enough that it is describing the cluster and not this morning.
# Three days rather than a run count: at one capture an hour that is 72 points, and a cluster
# whose collector was paused for a day still has to have covered real calendar time.
MIN_SPAN_DAYS = 3.0
MIN_POINTS = 24

# How straight the climb has to be. Rank correlation, so this is "does it keep going up", not
# "by how much". Measured on the two test clusters: the median series sits at 0.54 and only the
# genuinely monotone ones -- host memory recovering after a load test, on all three members at
# once -- reach 0.9.
MIN_RHO = 0.85

# ...and it has to keep going up throughout, not once. Four blocks, each above the one before by
# a fifth of the total move. Without this, a single level change passes: a step scores 0.87 on
# ranks, which is above any threshold worth setting.
BLOCKS = 4
MIN_BLOCK_SHARE = 0.20

# Beyond this the projection is arithmetic, not advice. A cluster that fills its cache in four
# months will have changed twice before then, and saying so every week is how a useful warning
# becomes furniture.
HORIZON_DAYS = 45.0

# Below this share of the limit a linear projection is extrapolating far past its evidence: a
# pool at 3% that doubles every week is still a pool at 6% next week, and the arithmetic that
# says "full in 40 days" is fitting a line to a curve. It has to already be somewhere.
MIN_SHARE = 0.35

# The trend has to be visible on most of the set. A cluster is sized as a whole and its members
# carry the same data, so real capacity pressure shows up on all of them -- while one node
# drifting on its own is a host problem, which the peer comparison already reports. This is the
# cheapest noise filter available and it costs nothing that matters.
MIN_MEMBERS = 2


def _keeps_going(points: list[tuple[float, float]], direction: str) -> bool:
    """Does every quarter sit past the one before it?

    The test that separates a trend from a step. Medians per block rather than endpoints, so one
    outlying run cannot make or break it.
    """
    n = len(points) // BLOCKS
    if n < 2:
        return False
    blocks = [statistics.median(v for _, v in points[i * n:(i + 1) * n])
              for i in range(BLOCKS)]
    move = blocks[-1] - blocks[0]
    if (move > 0) != (direction == "up") or move == 0:
        return False
    need = abs(move) * MIN_BLOCK_SHARE
    return all((b - a if direction == "up" else a - b) >= need
               for a, b in zip(blocks, blocks[1:]))


@dataclass(frozen=True)
class Runway:
    node: str
    metric: str
    pretty: str
    now: float
    limit: float
    days: float
    rho: float
    points: int
    span_days: float
    direction: str
    # What the chart needs and the prose does not: the line that was fitted, and the history it
    # was fitted to. Carried rather than re-derived, because a picture drawn from a second fit
    # is a picture that can disagree with the sentence beside it.
    slope: float = 0.0
    series: tuple[tuple[float, float], ...] = ()

    @property
    def share(self) -> float:
        return self.now / self.limit if self.limit else 0.0


def _ranks(values: list[float]) -> list[float]:
    """Ranks with ties AVERAGED.

    Breaking ties by position is not a detail: it hands a perfectly constant series a rank
    correlation of 1.0, and half the metrics with a ceiling -- the pool sizes, the host's total
    memory -- are constants. Found by measuring, when every cluster reported a flawless trend in
    its number of CPU cores.
    """
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        average = (i + j) / 2 + 1
        for k in range(i, j + 1):
            out[order[k]] = average
        i = j + 1
    return out


def spearman(points: list[tuple[float, float]]) -> float:
    """Rank correlation against time: does it keep going the same way."""
    n = len(points)
    r = _ranks([y for _, y in points])
    mean_x = (n + 1) / 2
    mean_r = sum(r) / n
    sxy = sum((i + 1 - mean_x) * (r[i] - mean_r) for i in range(n))
    sxx = sum((i + 1 - mean_x) ** 2 for i in range(n))
    syy = sum((x - mean_r) ** 2 for x in r)
    return sxy / math.sqrt(sxx * syy) if sxx > 0 and syy > 0 else 0.0


def _fit(points: list[tuple[float, float]]) -> tuple[float, float]:
    """Least squares -> (slope per day, value the line gives at the last point)."""
    n = len(points)
    mean_x = sum(x for x, _ in points) / n
    mean_y = sum(y for _, y in points) / n
    sxx = sum((x - mean_x) ** 2 for x, _ in points)
    if sxx == 0:
        return 0.0, mean_y
    slope = sum((x - mean_x) * (y - mean_y) for x, y in points) / sxx
    return slope, mean_y + slope * (points[-1][0] - mean_x)


def read_series(path: Path) -> dict[tuple[str, str], list[tuple[float, float]]]:
    """(node, metric) -> the typical second of every run, in run order.

    The p50 rather than the p95: this asks where the cluster LIVES, and a projection built on
    its worst second would be projecting the peaks, which is a different and much noisier
    question.
    """
    out: dict[tuple[str, str], list[tuple[float, float]]] = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("scope", "baseline") != "baseline":
            continue
        try:
            when = datetime.fromisoformat(row["run"].replace("Z", "+00:00")).timestamp() / 86400
        except ValueError:
            continue
        key = (row["node"], row["metric"].split(" (via")[0])
        out.setdefault(key, []).append((when, float(row.get("p50") or 0)))
    for points in out.values():
        points.sort()
    return out


def find(path: Path) -> list[Runway]:
    """Metrics whose own history projects them into their own limit, soon."""
    series = read_series(path)
    nodes = {node for node, _ in series}
    found: list[Runway] = []

    for metric, ceiling_metric, direction in LIMITS:
        for node in sorted(nodes):
            points = series.get((node, metric))
            if not points or len(points) < MIN_POINTS:
                continue
            span = points[-1][0] - points[0][0]
            if span < MIN_SPAN_DAYS:
                continue

            if ceiling_metric:
                ceiling_points = series.get((node, ceiling_metric))
                if not ceiling_points:
                    continue
                limit = statistics.median(v for _, v in ceiling_points)
            else:
                # current + available, because `available` is the remainder and not the size.
                spare = series.get((node, "serverStatus.connections.available"))
                if not spare:
                    continue
                limit = (statistics.median(v for _, v in points)
                         + statistics.median(v for _, v in spare))
            if limit <= 0:
                continue

            rho = spearman(points)
            slope, level = _fit(points)
            if level <= 0 or level > limit:
                continue

            if not _keeps_going(points, direction):
                continue

            if direction == "up":
                if rho < MIN_RHO or slope <= 0:
                    continue
                days = (limit - level) / slope
                share = level / limit
            else:
                # Falling towards exhaustion: the limit is not zero but the last tenth, where a
                # host is already swapping and the number stops being linear anyway.
                if -rho < MIN_RHO or slope >= 0:
                    continue
                floor = 0.10 * limit
                if level <= floor:
                    continue
                days = (level - floor) / -slope
                share = 1.0 - level / limit

            if not (0 < days <= HORIZON_DAYS) or share < MIN_SHARE:
                continue

            found.append(Runway(node=node, metric=metric,
                                pretty=PRETTY.get(metric, metric.split(".")[-1]),
                                now=level, limit=limit, days=days, rho=rho,
                                points=len(points), span_days=span, direction=direction,
                                slope=slope, series=tuple(points)))

    return _agreed(found)


def _agreed(found: list[Runway]) -> list[Runway]:
    """Keep only the metrics where enough members show the same thing.

    Reported once per cluster, on the member with the least room left: three copies of "you run
    out of cache in eleven days" is one piece of news printed three times, and the reader has to
    work out that it is not three problems.
    """
    by_metric: dict[str, list[Runway]] = {}
    for r in found:
        by_metric.setdefault(r.metric, []).append(r)
    out = [min(rs, key=lambda r: r.days)
           for rs in by_metric.values() if len(rs) >= MIN_MEMBERS]
    return sorted(out, key=lambda r: r.days)


def _human(value: float, metric: str) -> str:
    # `_kb` in the metric name is a lie by the time the value gets here: the reader normalises
    # host memory into bytes on the way in, and `MemTotal_kb` on this machine stores 16570290176
    # for a 16 GB host. Trusting the name divided by a further 1024 and reported a 16 GB host as
    # 15,801 GB. Found by drawing the chart, whose axis had it right, next to the sentence.
    if "bytes" in metric or "cache" in metric or metric.endswith("_kb"):
        for unit, size in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
            if value >= size:
                return f"{value / size:.1f} {unit}"
        return f"{value:.0f} bytes"
    return f"{value:,.0f}"


def _when(days: float) -> str:
    if days < 14:
        return f"about {round(days)} days"
    return f"about {round(days / 7)} weeks"


# What the ceiling IS, in words, for the line drawn across the chart. The number is formatted
# where the chart is drawn -- only that side knows what unit the axis ended up in.
CEILING_NOTE = {
    "serverStatus.wiredTiger.cache.bytes currently in the cache":
        "the cache configured on this node",
    "serverStatus.connections.current": "the connection limit",
    "systemMetrics.memory.MemAvailable_kb": "a tenth of the host's memory",
    "serverStatus.wiredTiger.concurrentTransactions.read.out": "the read ticket pool",
    "serverStatus.wiredTiger.concurrentTransactions.write.out": "the write ticket pool",
}

# FTDC counts bytes; the reader does not. Naming the unit here is what lets the axis come out in
# GiB instead of 3,500,000. Everything else is a count, and a count has no unit worth printing.
CHART_UNIT = {
    "serverStatus.wiredTiger.cache.bytes currently in the cache": "bytes",
    "systemMetrics.memory.MemAvailable_kb": "bytes",
}

# How many points to draw along the projected stretch. Enough that it reads as a line rather
# than a segment, few enough that it is not pretending to be samples.
AHEAD_POINTS = 24

# ...and a little past the crossing, because the crossing is the point of the chart and it landed
# exactly on the top right corner, where the frame cut it in half.


def _chart_for(r: Runway) -> dict | None:
    """The history, the line fitted to it, and the limit it meets -- on one time axis.

    This is the finding's argument rather than an illustration of it. The sentence says "about
    three weeks"; the only way a reader can judge that is to see how much history the line was
    fitted to and how far past the last measurement it has been carried. A projection drawn
    without that boundary is a line that looks measured all the way to the wall, which is the
    one thing this must never look like -- hence `nowMs`, and hence the fitted line being drawn
    back across the history it came from instead of starting at the last point.

    The axis runs to the crossing, so a long runway squeezes its own evidence into the left of
    the chart. That is not a flaw to correct: six days of history under a forty-day projection
    SHOULD look like six days of history under a forty-day projection.
    """
    if len(r.series) < 2:
        return None

    # The line crosses what the finding claims it crosses: the limit going up, and the last
    # tenth going down -- the same floor `find` measured the days against.
    target = r.limit if r.direction == "up" else 0.10 * r.limit
    last_day = r.series[-1][0]
    step = r.days * 1.12 / AHEAD_POINTS

    past = [x for x, _ in r.series]
    ahead = [last_day + step * (i + 1) for i in range(AHEAD_POINTS)]
    days = past + ahead

    # `now` is the fitted line at the last point, not the last reading, so the projection starts
    # where the fit is rather than on whatever the final run happened to measure.
    projected = [r.now + r.slope * (x - last_day) for x in days]
    observed = [v for _, v in r.series] + [None] * len(ahead)

    unit = CHART_UNIT.get(r.metric, "")
    return {
        "t": [round(x * 86_400_000) for x in days],
        "v": observed,
        "series": [
            {"label": "measured", "v": observed, "unit": unit},
            {"label": "at this rate", "v": projected, "unit": unit},
        ],
        "threshold": target,
        "thresholdNote": CEILING_NOTE.get(r.metric, "the limit"),
        # Not a threshold anything crossed: the crossing is in the future by construction, so
        # there is no stretch of the line to shade and nothing to outline.
        "thresholdIsForecast": True,
        "nowMs": round(last_day * 86_400_000),
        "title": f"At this rate: {r.pretty}",
        "fromMs": round(days[0] * 86_400_000),
        "toMs": round(days[-1] * 86_400_000),
    }


def as_findings(runways: list[Runway], window_from: int, window_to: int) -> list[dict]:
    """Shape them like every other finding, so nothing downstream needs a special case."""
    out = []
    for r in runways:
        if r.direction == "up":
            what = (f"{r.pretty.capitalize()} has been growing steadily for "
                    f"{round(r.span_days)} days and is now at {_human(r.now, r.metric)} of "
                    f"{_human(r.limit, r.metric)}. At this rate it reaches the limit in "
                    f"{_when(r.days)}.")
        else:
            what = (f"{r.pretty.capitalize()} has been falling steadily for "
                    f"{round(r.span_days)} days and is now {_human(r.now, r.metric)} of "
                    f"{_human(r.limit, r.metric)}. At this rate the host is down to its last "
                    f"tenth in {_when(r.days)}.")
        out.append({
            "rule": "capacity-runway",
            "title": f"At this rate, {r.pretty} runs out in {_when(r.days)}",
            # A prediction, not an event: nothing is wrong yet, and waking somebody at night for
            # something three weeks away is how a product teaches people to ignore it. It is
            # still louder than an excursion, because unlike a lead it comes with a date.
            "severity": "warning",
            "node": r.node,
            "metric": r.metric,
            "episodes": 1,
            "fromMs": window_from,
            "toMs": window_to,
            "worstFromMs": window_from,
            "worstToMs": window_to,
            # Nothing has been "in state" for any length of time: this is a projection, and
            # the window it was made in is not a duration the reader should be shown. Zero, and
            # the card leaves the fact out rather than printing "60 min in state" beside a
            # sentence about three weeks from now.
            "secondsInState": 0,
            "peak": r.now,
            "unit": "",
            "what": what,
            "check": ("Whether the growth is the workload or a leak. Data growing is expected "
                      "and answered by more room; a pool that only ever grows -- connections "
                      "that are never returned, cursors nobody closes -- is answered by fixing "
                      "the client, and adding room only moves the date."),
            "chart": _chart_for(r),
        })
    return out
