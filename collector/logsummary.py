"""What a mongod log says about the queries that were slow, kept as shapes and never as lines.

FTDC says that collection scans happened at 23:58; the log says which ones. The `Slow query`
line (id 51803, 4.4 and later) carries the namespace, the command, the plan and what it
examined -- enough to name the index that is missing. This reads those lines and keeps, per
member and per minute, one row per query shape:

    {"m": <minute, epoch ms>, "ns": "orders.items", "op": "find",
     "shape": "{status, updatedAt ($gte)}", "plan": "COLLSCAN",
     "n": 14, "docs": 252000, "keys": 0, "ret": 70, "ms": 11200, "maxms": 1630,
     "apps": ["nightly-sync"], "rp": ["secondary"]}

Field names and operators, never values: a log written by mongod on your own servers carries
whatever the application put in its filters, and none of that is needed to find an index. The
lines themselves are not kept either -- a support bundle's log runs to gigabytes -- and only
the slow-query lines are parsed at all: the rest are skipped on a substring test.
"""
from __future__ import annotations

import gzip
import json
from datetime import datetime
from pathlib import Path

SLOW_QUERY = '"id":51803'
STARTING = '"id":4615611'          # "MongoDB starting", which names the host and port
SHAPES_PER_MINUTE = 50             # past this, a minute keeps its 50 costliest shapes


def opened(path: Path):
    """The log as text, gzipped or not."""
    with path.open("rb") as fh:
        magic = fh.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def is_log(path: Path) -> bool:
    """A mongod structured log (4.4+): its first line is a JSON object with a `t.$date`."""
    try:
        with opened(path) as fh:
            for line in fh:
                if line.strip():
                    return line.lstrip().startswith('{"t":{"$date"')
    except (OSError, EOFError, UnicodeDecodeError):
        return False
    return False


def short_host(host: str | None) -> str | None:
    """`db1.example.net:27017` -> `db1`: the name findings carry, from FTDC's own host name."""
    if not host:
        return None
    return host.split(":")[0].split(".")[0].lower() or None


def shape(value, depth: int = 0) -> str:
    """A filter's fields and operators, without its values."""
    if depth > 4:
        return "…"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value):
            sub = value[key]
            if key in ("$and", "$or", "$nor") and isinstance(sub, list):
                parts.append(f"{key}: [" + ", ".join(shape(s, depth + 1) for s in sub) + "]")
            elif key.startswith("$"):
                parts.append(key)
            elif isinstance(sub, dict) and any(str(k).startswith("$") for k in sub):
                ops = sorted(k for k in sub if str(k).startswith("$"))
                parts.append(f"{key} ({', '.join(ops)})")
            else:
                parts.append(key)
        return "{" + ", ".join(parts) + "}"
    return "?"


def pipeline_shape(stages) -> str:
    """`$match {status} | $group | $sort`: the stages, and what the first $match filters on."""
    out = []
    for stage in stages if isinstance(stages, list) else []:
        if not isinstance(stage, dict) or not stage:
            continue
        name = next(iter(stage))
        out.append(f"{name} {shape(stage[name])}" if name == "$match" else name)
    return " | ".join(out[:6]) + (" | …" if len(out) > 6 else "")


# The command's own name for what it did, in the order a command document names it first.
OPS = ("find", "aggregate", "count", "distinct", "findAndModify", "update", "delete",
       "insert", "getMore", "mapReduce")


def describe(attr: dict) -> tuple[str, str] | None:
    """(operation, shape) of one slow query, or None for what is not the application's."""
    if attr.get("isFromUserConnection") is False:
        return None   # the server's own work: session refresh, TTL, index builds
    command = attr.get("command") or {}
    if attr.get("ns", "").startswith("local.oplog"):
        return None   # secondaries tailing the oplog wait on purpose; that is not slowness
    if attr.get("ns", "").endswith(".$cmd"):
        return None   # an administrative command: no collection, nothing to index
    op = next((o for o in OPS if o in command), attr.get("type") or "command")
    if op == "getMore":
        command = attr.get("originatingCommand") or {}
        inner = next((o for o in OPS if o in command), "command")
        op = f"getMore of {inner}"
        op_base = inner
    else:
        op_base = op
    if op_base == "aggregate":
        return op, pipeline_shape(command.get("pipeline"))
    filt = command.get("filter", command.get("query", command.get("q")))
    return op, shape(filt) if isinstance(filt, dict) else ""


def summarize(path: Path) -> dict:
    """{member, first, last, slow, rows}: the slow queries of one log, minute by minute.

    `member` is the short host name from the "MongoDB starting" line, or None when the log
    begins after it (a rotated file); the caller then has to know the member another way.
    """
    member = None
    first = last = None
    slow = 0
    groups: dict[tuple, dict] = {}
    with opened(path) as fh:
        for line in fh:
            if member is None and STARTING in line:
                try:
                    a = json.loads(line).get("attr") or {}
                    member = short_host(a.get("host"))
                except ValueError:
                    pass
            if SLOW_QUERY not in line:
                continue
            try:
                doc = json.loads(line)
                at = datetime.fromisoformat(doc["t"]["$date"].replace("Z", "+00:00"))
            except (ValueError, KeyError, TypeError):
                continue
            attr = doc.get("attr") or {}
            what = describe(attr)
            if what is None:
                continue
            slow += 1
            ms = int(at.timestamp() * 1000)
            first = ms if first is None else min(first, ms)
            last = ms if last is None else max(last, ms)
            command = attr.get("command") or {}
            rp = ((command.get("$readPreference") or {}).get("mode")
                  if isinstance(command.get("$readPreference"), dict) else None)
            key = (ms // 60000 * 60000, attr.get("ns", "?"), what[0], what[1],
                   attr.get("planSummary") or "")
            g = groups.setdefault(key, {"m": key[0], "ns": key[1], "op": key[2],
                                        "shape": key[3], "plan": key[4], "n": 0, "docs": 0,
                                        "keys": 0, "ret": 0, "ms": 0, "maxms": 0,
                                        "apps": set(), "rp": set()})
            g["n"] += 1
            g["docs"] += int(attr.get("docsExamined") or 0)
            g["keys"] += int(attr.get("keysExamined") or 0)
            g["ret"] += int(attr.get("nreturned") or attr.get("nMatched") or 0)
            took = int(attr.get("durationMillis") or 0)
            g["ms"] += took
            g["maxms"] = max(g["maxms"], took)
            if attr.get("appName"):
                g["apps"].add(str(attr["appName"])[:60])
            if rp:
                g["rp"].add(rp)
    by_minute: dict[int, list] = {}
    for g in groups.values():
        by_minute.setdefault(g["m"], []).append(g)
    rows = []
    for minute in sorted(by_minute):
        kept = sorted(by_minute[minute], key=lambda g: (-g["docs"], -g["ms"]))[:SHAPES_PER_MINUTE]
        rows += [{**g, "apps": sorted(g["apps"]), "rp": sorted(g["rp"])} for g in kept]
    return {"member": member, "first": first, "last": last, "slow": slow, "rows": rows}


def store(summary: dict, logs: Path, source: str) -> Path:
    """Under `logs/<member>/<first>.json`. The same log uploaded again, longer, starts at the
    same line and so replaces itself rather than counting its queries twice."""
    target = logs / summary["member"] / f"{summary['first'] or 0}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.tmp")
    tmp.write_text(json.dumps({**summary, "source": source}))
    tmp.replace(target)
    return target


def held(logs: Path) -> list[dict]:
    """Every summary kept for a cluster."""
    out = []
    for f in sorted(logs.glob("*/*.json")) if logs.is_dir() else []:
        try:
            out.append(json.loads(f.read_text()))
        except (OSError, ValueError):
            continue
    return out


def during(summaries: list[dict], members: set[str], from_ms: int, to_ms: int) -> list[dict]:
    """The slow-query shapes of these members in this window, costliest first, merged across
    minutes: one row per (member, namespace, operation, shape, plan)."""
    merged: dict[tuple, dict] = {}
    for s in summaries:
        if s.get("member") not in members:
            continue
        for r in s.get("rows") or []:
            if not from_ms - 60_000 <= r["m"] <= to_ms:
                continue
            key = (s["member"], r["ns"], r["op"], r["shape"], r["plan"])
            g = merged.setdefault(key, {"member": s["member"], "ns": r["ns"], "op": r["op"],
                                        "shape": r["shape"], "plan": r["plan"], "n": 0,
                                        "docs": 0, "keys": 0, "ret": 0, "ms": 0, "maxms": 0,
                                        "apps": set(), "rp": set(), "first": r["m"]})
            for k in ("n", "docs", "keys", "ret", "ms"):
                g[k] += r[k]
            g["maxms"] = max(g["maxms"], r["maxms"])
            g["apps"].update(r.get("apps") or [])
            g["rp"].update(r.get("rp") or [])
            g["first"] = min(g["first"], r["m"])
    return sorted(merged.values(), key=lambda g: (-g["docs"], -g["ms"]))
