"""When the collector is allowed to say "you are paying for more cluster than you use".

This is the one finding that costs the customer money if it is wrong — they act on it, the
cluster falls over, and every other finding in the report loses its credibility at the same
time. So most of these tests are about staying quiet, and the assertion that matters most is
that a single busy resource is enough to close the whole conversation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sizing  # noqa: E402

GB = 1024 ** 3
NODE = "n0.mongodb.net"
T0 = 1_754_000_000_000


def baseline(tmp_path: Path, *, days: float = 30.0, node: str = NODE,
             mem_total: float = 8 * GB, mem_free_min: float = 6 * GB,
             cores: float = 4, cpu_user: float = 400, cpu_system: float = 100,
             cache_used: float = 1 * GB, cache_max: float = 4 * GB,
             tickets_out: float = 3, tickets_pool: float = 128,
             conns: float = 40, conns_free: float = 1460) -> Path:
    """A baseline file describing a node with plenty of room, unless told otherwise.

    Two runs `days` apart, because the history check reads the span between the first and last
    run rather than counting rows.
    """
    rows = []
    for run in (f"2026-07-01T00:00:00+00:00",
                f"2026-07-{1 + int(days):02d}T00:00:00+00:00" if days < 28
                else "2026-07-31T00:00:00+00:00"):
        for metric, value in [
            ("systemMetrics.memory.MemTotal_kb", mem_total),
            ("systemMetrics.memory.MemAvailable_kb", mem_free_min),
            ("systemMetrics.cpu.num_logical_cores", cores),
            ("rate(systemMetrics.cpu.user_ms)", cpu_user),
            ("rate(systemMetrics.cpu.system_ms)", cpu_system),
            ("serverStatus.wiredTiger.cache.bytes currently in the cache", cache_used),
            ("serverStatus.wiredTiger.cache.maximum bytes configured", cache_max),
            ("serverStatus.wiredTiger.concurrentTransactions.read.out", tickets_out),
            ("serverStatus.wiredTiger.concurrentTransactions.write.out", 0),
            ("serverStatus.wiredTiger.concurrentTransactions.read.totalTickets", tickets_pool),
            ("serverStatus.connections.current", conns),
            ("serverStatus.connections.available", conns_free),
        ]:
            rows.append({"scope": "baseline", "run": run, "node": node, "metric": metric,
                         "min": value, "max": value, "p50": value, "p95": value, "p99": value,
                         "mean": value, "n": 100})

    path = tmp_path / "baseline.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


NODES = [{"hostname": NODE, "node": NODE}]


def advise(path: Path, trouble: bool = False) -> list[dict]:
    return sizing.advise(path, NODES, trouble, T0, T0 + 3_600_000)


# ------------------------------------------------------------------------ when it speaks

def test_an_idle_cluster_gets_the_advice(tmp_path):
    found = advise(baseline(tmp_path))
    assert len(found) == 1
    assert found[0]["rule"] == "oversized-cluster"
    assert found[0]["severity"] == "info", "saving money is not an emergency"


def test_the_advice_names_every_resource_it_checked(tmp_path):
    what = advise(baseline(tmp_path))[0]["what"]
    for resource in ("memory", "cpu", "cache", "concurrency", "connections"):
        assert resource in what, f"{resource} was checked but not shown"


def test_it_says_how_much_history_it_speaks_from(tmp_path):
    """"You are oversized" means nothing without "over how long"."""
    assert "30 days" in advise(baseline(tmp_path))[0]["what"]


# ------------------------------------------------------------------------ when it stays quiet

def test_too_little_history_says_nothing(tmp_path):
    """Six days has not seen a weekly cycle, so it has not seen the weekly peak."""
    assert advise(baseline(tmp_path, days=6.0)) == []


def test_trouble_in_the_window_closes_the_conversation(tmp_path):
    """Advising a shrink on a cluster that just broke destroys the rest of the report."""
    assert advise(baseline(tmp_path), trouble=True) == []


def test_one_busy_resource_is_enough_to_stay_quiet(tmp_path):
    """The tier is bought as a bundle: there is no way to buy less RAM but keep the CPU."""
    tight = baseline(tmp_path, mem_free_min=1 * GB)  # 7 of 8 GB used at its worst
    assert advise(tight) == []


def test_a_cpu_peak_counts_even_when_memory_is_idle(tmp_path):
    """3.6 of 4 cores at the busiest moment, on a host barely using its memory."""
    assert advise(baseline(tmp_path, cpu_user=3_000, cpu_system=600)) == []


def test_kernel_time_is_not_free(tmp_path):
    """User time alone would read as 45% and pass; with system time it is 90% and must not."""
    assert advise(baseline(tmp_path, cpu_user=1_800, cpu_system=1_800)) == []


def test_a_missing_metric_is_not_assumed_idle(tmp_path):
    """A resource that cannot be measured must not be counted as spare."""
    path = baseline(tmp_path)
    kept = [l for l in path.read_text().splitlines()
            if "num_logical_cores" not in l and "cpu.user_ms" not in l]
    path.write_text("\n".join(kept) + "\n")
    assert advise(path) == [], "no CPU reading means no tier judgement"


def test_a_cluster_with_no_baseline_says_nothing(tmp_path):
    assert advise(tmp_path / "nothing.jsonl") == []


# ------------------------------------------------------------------ measurements, not advice

def test_the_advice_gives_absolute_figures_not_only_ratios(tmp_path):
    """"19% of memory" needs the capacity beside it before anybody can act on it.

    Naming a smaller instance was tried and removed: tiers differ in ways this cannot see, and
    on a self-hosted cluster there is no tier to name. The measurement travels; the purchase
    advice does not.
    """
    what = advise(baseline(tmp_path, mem_total=8 * GB, mem_free_min=6 * GB,
                           cores=4, cpu_user=400, cpu_system=100))[0]["what"]
    assert "GiB" in what, "memory is reported as a ratio with no size"
    assert "cores" in what
    assert "2.0 of 8.0 GiB" in what


def test_it_does_not_recommend_a_product(tmp_path):
    """The finding stops at what was measured. What that is worth is the reader's call."""
    found = advise(baseline(tmp_path))[0]
    for word in ("M10", "M20", "M30", "M40", "fits in", "upgrade", "downgrade"):
        assert word not in found["what"], f"still recommending: {word}"
    assert "your pricing" in found["check"]


# --------------------------------------------------------------------------- the arithmetic

def test_the_worst_member_decides(tmp_path):
    """Every member is the same tier, so the advice has to hold for the busiest one."""
    path = baseline(tmp_path)
    busy = [json.loads(l) for l in path.read_text().splitlines() if l]
    for row in busy:
        row["node"] = "n1.mongodb.net"
        if row["metric"] == "systemMetrics.memory.MemAvailable_kb":
            row["min"] = row["max"] = 0.2 * GB   # this member is nearly out of memory
    with path.open("a") as fh:
        for row in busy:
            fh.write(json.dumps(row) + "\n")

    nodes = [{"hostname": NODE, "node": NODE}, {"hostname": "n1.mongodb.net", "node": "n1"}]
    assert sizing.advise(path, nodes, False, T0, T0 + 1000) == []


def test_memory_is_read_at_its_lowest_free_not_its_average(tmp_path):
    r = sizing.resources_for(_rows(baseline(tmp_path, mem_total=8 * GB, mem_free_min=2 * GB)),
                             NODE)
    memory = next(x for x in r if x.name == "memory")
    assert memory.used == 6 * GB
    assert not memory.spare, "75% used is not spare capacity"


def test_an_impossible_cpu_reading_is_discarded(tmp_path):
    """Measured on the real Atlas capture: 380,000 ms/s on a two-core host, every five minutes.

    Believing it would report a permanently saturated CPU and silence this advice forever, on
    every cluster. The reading is dropped, and the rest of the history still speaks.
    """
    path = baseline(tmp_path, cores=2, cpu_user=200, cpu_system=100)
    rows = [json.loads(l) for l in path.read_text().splitlines() if l]
    spike = dict(rows[0])
    spike.update({"run": "2026-07-15T00:00:00+00:00", "metric": "rate(systemMetrics.cpu.user_ms)",
                  "max": 380_000.0, "min": 380_000.0})
    with path.open("a") as fh:
        fh.write(json.dumps(spike) + "\n")

    cpu = next(r for r in sizing.resources_for(_rows(path), NODE) if r.name == "cpu")
    assert cpu.used == 300, "the spike must not become the peak"
    assert advise(path), "and the advice must still be given"


def test_a_cpu_history_that_is_all_artefact_says_nothing(tmp_path):
    """If nothing plausible survives, that is missing data -- not an idle CPU."""
    path = baseline(tmp_path, cores=2, cpu_user=380_000, cpu_system=0)
    assert not [r for r in sizing.resources_for(_rows(path), NODE) if r.name == "cpu"]
    assert advise(path) == []


def _rows(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text().splitlines() if l]
