"""Tell a customer when they are paying for a cluster larger than their workload.

Every other check in the collector answers "is something wrong". This one answers "is anything
being wasted", and it is the only finding that saves the reader money rather than costing them
an afternoon. That makes it the easiest thing in the product to sell and the easiest to
discredit: advise somebody to shrink a cluster that then falls over, and nothing else in the
report will be believed again.

So the whole design is built around being wrong in one direction only.

**It reads the baseline, not the capture.** The question is not what the cluster did today, it
is what it has ever done. That lives in `baseline.jsonl`, which survives after Atlas has dropped
the raw FTDC -- and which is the reason a service with retention can make this claim at all.
Nobody with a week of history can.

**It uses the observed maximum, never a percentile.** A p95 of 40% with a daily spike to 95% is
a cluster that must not be shrunk, and a percentile hides exactly that. The maximum is the only
statistic that cannot recommend cutting into a peak it did not see.

**It stays quiet unless every resource agrees.** Memory, CPU, cache, execution tickets and
connections all have to be under half. One resource at 80% is the one that matters, and
capacity is bought as a bundle: there is no way to buy less RAM but keep the CPU.

**It reports measurements, not purchases.** It says what the workload used at its worst, in
GiB and cores, and stops there. Naming a smaller instance reads as advice and travels badly --
tiers differ in burstable versus dedicated CPU, in IOPS tied to disk size, in what a reserved
commitment already covers, and on a self-hosted cluster there is no tier to name at all.
Whoever knows their prices decides better than a rule that has only seen metrics.

**It stays quiet after trouble.** A window that produced a critical or warning finding is not a
window to draw conclusions about spare capacity from, whatever the averages say.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Below this fraction of a resource, at its worst moment ever, there is room to spare. It is how
# a DBA puts it -- "you are not even using half of it" -- and also where the arithmetic stops
# being close: a cluster peaking at 49% survives losing half its capacity with the peak still
# fitting.
SPARE_BELOW = 0.5

# No advice before this much history. A shorter window has not seen a weekly cycle, so it has
# not seen the Sunday batch or the Monday morning rush -- the two moments most likely to be the
# real peak. Seven days is the floor; it is not enough to have seen a month-end close, which is
# why the wording of the finding says how much history it is speaking from.
MIN_DAYS = 7.0

@dataclass(frozen=True)
class Resource:
    """One dimension of capacity, and how much of it was ever used."""

    name: str
    used: float
    capacity: float
    unit: str

    @property
    def fraction(self) -> float:
        return self.used / self.capacity if self.capacity > 0 else 1.0

    @property
    def spare(self) -> bool:
        return self.fraction < SPARE_BELOW


def _amount(r: "Resource") -> str:
    """The peak in the unit somebody sizes hardware in.

    "19% of memory" is a ratio and needs the capacity beside it to mean anything. "1.5 GiB of
    8 GiB" is a fact somebody can hold against a price list, a colleague, or their own plans.
    """
    if r.unit == "bytes":
        gib = 1024 ** 3
        return f"{r.used / gib:.1f} of {r.capacity / gib:.1f} GiB"
    if r.unit == "cores":
        return f"{r.used / 1000:.1f} of {r.capacity / 1000:.0f} cores"
    return f"{r.used:.0f} of {r.capacity:.0f} {r.unit}"


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("scope") == "baseline":
            out.append(row)
    return out


def _peak(rows: list[dict], metric: str, node: str, field: str = "max",
          possible: float | None = None) -> float | None:
    """The most extreme value this metric ever reached on this node.

    `field` is "max" for things where using more is the risk, and "min" for the ones stored
    inverted -- available memory is the obvious case, where the worst moment is the lowest.

    `possible` discards readings that cannot be true. It exists because of a measured artefact:
    `rate(systemMetrics.cpu.user_ms)` on the Atlas capture spikes to 380,000 ms/s -- 190 cores'
    worth on a two-core host -- at :30 past every fifth minute, with no gap in the capture and a
    normal one-second step either side. Whatever produces it, it is not the host being busy, and
    a maximum built from it would report a permanently saturated CPU and silence this advice
    forever. A reading above the physical capacity is not a measurement, so it is dropped rather
    than believed or clamped.
    """
    canonical = [r for r in rows if r["node"] == node and r["metric"].split(" (via")[0] == metric]
    if not canonical:
        return None
    values = [r[field] for r in canonical if isinstance(r.get(field), (int, float))]
    if possible is not None:
        values = [v for v in values if v <= possible]
    if not values:
        return None
    return max(values) if field == "max" else min(values)


def _days(rows: list[dict]) -> float:
    runs = {r["run"] for r in rows if r.get("run")}
    if len(runs) < 2:
        return 0.0
    try:
        delta = datetime.fromisoformat(max(runs)) - datetime.fromisoformat(min(runs))
    except ValueError:
        return 0.0
    return round(delta.total_seconds() / 86_400, 2)


def resources_for(rows: list[dict], node: str) -> list[Resource]:
    """Every dimension of capacity that can be measured for this node.

    A dimension that cannot be measured is left out rather than assumed idle, because assuming
    idle is how this ends up advising somebody to shrink on the strength of a metric that was
    never there.
    """
    out: list[Resource] = []

    total_mem = _peak(rows, "systemMetrics.memory.MemTotal_kb", node)
    free_mem = _peak(rows, "systemMetrics.memory.MemAvailable_kb", node, field="min")
    if total_mem and free_mem is not None:
        out.append(Resource("memory", total_mem - free_mem, total_mem, "bytes"))

    cores = _peak(rows, "systemMetrics.cpu.num_logical_cores", node)
    # A host cannot spend more than `cores` seconds of CPU per second. Anything above that is
    # the artefact described in `_peak`, and dropping it can only make this more cautious:
    # what is left is a smaller peak, and a smaller peak is what would let the advice speak.
    ceiling = cores * 1000.0 if cores else None
    user = _peak(rows, "rate(systemMetrics.cpu.user_ms)", node, possible=ceiling)
    system = _peak(rows, "rate(systemMetrics.cpu.system_ms)", node, possible=ceiling)
    if cores and user is not None:
        # Adding two maxima overstates the real peak -- they need not have happened at the same
        # instant -- and that is the right direction to be wrong in here. If the sum still
        # leaves the host under half, so does the truth.
        busy_ms_per_s = user + (system or 0.0)
        out.append(Resource("cpu", busy_ms_per_s, cores * 1000.0, "cores"))

    cache_used = _peak(rows, "serverStatus.wiredTiger.cache.bytes currently in the cache", node)
    cache_max = _peak(rows, "serverStatus.wiredTiger.cache.maximum bytes configured", node)
    if cache_used is not None and cache_max:
        out.append(Resource("cache", cache_used, cache_max, "bytes"))

    # Each pool against its own size, and the fuller of the two. Reads and writes draw from
    # separate pools; the sum of both against the read pool alone reported 106 of 63 tickets
    # on a real replica set, which is not a measurement of anything.
    pools = []
    for kind in ("read", "write"):
        used = _peak(rows, f"serverStatus.wiredTiger.concurrentTransactions.{kind}.out", node)
        size = _peak(rows, f"serverStatus.wiredTiger.concurrentTransactions.{kind}.totalTickets",
                     node)
        if used is not None and size:
            pools.append(Resource("concurrency", used, size, f"{kind} tickets"))
    if pools:
        out.append(max(pools, key=lambda r: r.fraction))

    current = _peak(rows, "serverStatus.connections.current", node)
    available = _peak(rows, "serverStatus.connections.available", node)
    if current is not None and available:
        out.append(Resource("connections", current, current + available, "connections"))

    return out


def advise(baseline_path: Path, nodes: list[dict], had_trouble: bool,
           window_from: int, window_to: int) -> list[dict]:
    """Zero or one finding per cluster. Silence is the common and correct answer."""
    rows = _rows(baseline_path)
    days = _days(rows)
    if days < MIN_DAYS or had_trouble or not nodes:
        return []

    # The busiest member decides. In a replica set every member is the same tier, so advice has
    # to hold for the one that works hardest -- and on a set where reads go to secondaries, that
    # is not always the primary.
    worst: dict[str, Resource] = {}
    labels = []
    for node in nodes:
        # The baseline is keyed by the node's directory, which is the hostname on Atlas and
        # anything at all on a server of your own -- `rs27017` for a member that calls itself
        # `db1`. Looked up by hostname, every self-managed cluster matched no rows and this
        # stayed silent without saying why. The hostname is only for the reader.
        key = node.get("node") or node.get("hostname")
        if not key:
            continue
        labels.append(node.get("hostname") or key)
        for resource in resources_for(rows, key):
            seen = worst.get(resource.name)
            if seen is None or resource.fraction > seen.fraction:
                worst[resource.name] = resource

    if not worst or not all(r.spare for r in worst.values()):
        return []

    memory = worst.get("memory")
    cpu = worst.get("cpu")
    if memory is None or cpu is None:
        # Without both, there is no tier to talk about: they are what a tier is.
        return []

    # Numbers, not a recommendation to buy something. Naming a smaller tier reads as advice
    # and travels badly: tiers differ in ways this cannot see -- burstable versus dedicated
    # CPU, IOPS that scale with disk size, what a reserved commitment already covers -- and it
    # says nothing at all on a self-hosted cluster, which has no tier to name.
    #
    # What we can state exactly is what the workload used at its worst, in the units somebody
    # sizes hardware in. Whoever knows their pricing and their plans is better placed to decide
    # than a rule that has only ever seen the metrics.
    parts = "; ".join(
        f"{name} {r.fraction * 100:.0f}% ({_amount(r)})" for name, r in sorted(worst.items())
    )
    what = (
        f"Across {days:.0f} days, this cluster never used more than half of anything it has. "
        f"Busiest moment observed, per resource — {parts}."
    )

    return [{
        "rule": "oversized-cluster",
        "title": "This cluster is larger than its workload needs",
        "severity": "info",
        "node": labels[0],
        "metric": "(capacity vs observed peak)",
        "episodes": 1,
        "fromMs": window_from,
        "toMs": window_to,
        "worstFromMs": window_from,
        "worstToMs": window_to,
        "secondsInState": 0,
        "peak": round(max(r.fraction for r in worst.values()) * 100, 1),
        "unit": "percent",
        "what": what,
        "check": (
            "These are peaks over the whole history, not averages, so nothing here is hidden by "
            "smoothing. What they are worth in money depends on your pricing and your plans, "
            "which is why this stops at the measurements. Before resizing, confirm the workload "
            "is not about to grow, and that the period covers your busiest time of month."
        ),
        "chart": None,
    }]
