#!/usr/bin/env python3
"""Analyse what was captured: run the rules, store findings, accumulate the baseline.

Runs after `capture.py`, from the same cron entry. The split is deliberate: capturing is a
network operation that can fail for reasons of its own, analysing is pure local computation
over what is already on disk. One failing must not stop the other from running.

    python3 analyze.py --config config.json
    python3 analyze.py --config config.json --customer acme
    python3 analyze.py --config config.json --redo   # ignore what was analysed before

Writes three things per cluster, each with a different use:

    findings.jsonl   what the rules fired on -- this is what gets notified
    baseline.jsonl   percentiles per metric per run. This has to start being recorded with
                     the FIRST capture: once Atlas drops the raw data, this is all that is
                     left to later say "that is unusual for this cluster". It cannot be
                     reconstructed after the fact.
    summary.json     the current state, which is what the customer sees on screen

The engine lives in `runner/analyze.ts` and runs inside Big Hole, so that decoder, aliases
and rules all live in one place.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import anomaly
import progress
import runway
import sizing
from capture import load_clusters, record_usage
from state import State, now


def bighole_path() -> Path:
    """Where the Big Hole checkout that acts as the engine lives.

    This is **the advisor's own copy**, sitting beside the collector in the project — not a
    shared checkout of the upstream viewer. It carries the advisor's rules, so pointing this at
    a clean clone of the public repository would silently run with a smaller rule set.

    The default is relative to this file rather than to `$HOME`, so a fresh checkout works with
    no environment set. `BIGHOLE` still overrides it, for a deployment that lays things out
    differently.
    """
    fallback = Path(__file__).resolve().parent.parent / "big-hole"
    return Path(os.environ.get("BIGHOLE", fallback)).expanduser()


RUNNER = Path(__file__).resolve().parent / "runner" / "analyze.ts"


def sync_runner(repo: Path) -> Path:
    """Put this repository's runner where it can run, and return where that is.

    It has to execute from inside Big Hole's `tools/` so its imports of `../src/` resolve, and
    it used to get there by hand, with `cp`. The two copies drifted: by September the one that
    ran carried a month of changes the versioned one did not, so the file under version
    control was not the code in production. Copying on every run makes `runner/` the only
    place to edit -- a change made in `tools/` is overwritten, which is the point.
    """
    script = repo / "tools" / "analyze.ts"
    if RUNNER.exists():
        if not script.exists() or script.read_bytes() != RUNNER.read_bytes():
            shutil.copyfile(RUNNER, script)
    elif not script.exists():
        raise FileNotFoundError(
            f"{script} is missing and so is {RUNNER} — point BIGHOLE at the advisor's own checkout"
        )
    return script


def run_engine(ftdc: Path, since: str | None, timeout: int = 1800,
               daily: Path | None = None) -> dict:
    """Invoke the runner inside Big Hole and return its JSON.

    stdout is the JSON and stderr is for humans; they are kept apart so that decode progress
    cannot corrupt the output when this runs without a terminal.

    `daily` is where the per-day summaries live. With it a run decodes two days instead of
    everything held, which is what keeps its cost flat as retention grows.
    """
    repo = bighole_path()
    sync_runner(repo)

    cmd = ["npx", "vite-node", "tools/analyze.ts", "--", str(ftdc)]
    if since:
        cmd += ["--since", since]
    if daily is not None:
        cmd += ["--daily", str(daily)]

    r = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"engine failed ({r.returncode}): {r.stderr.strip()[-400:]}")
    return json.loads(r.stdout)


def finding_id(customer_id: str, cluster_id: str, f: dict) -> str:
    """Stable identity for a finding, so the same one is never reported twice.

    Built from the rule, the node and the start of the worst episode. It deliberately does
    NOT include the duration: if an episode keeps growing between two runs it is still the
    same episode, and a second email about it is exactly the noise that makes people cancel.

    The start is bucketed to the minute for the same reason. Two runs judge different windows,
    so the first sample that crosses the threshold can differ by one sampling interval, and at
    millisecond precision that produced two ids for one incident -- the customer saw the same
    ticket saturation twice, charted two different ways. A minute is safely coarse: the grouper
    already merges episodes within ten minutes of each other, so two genuinely distinct
    findings for one rule on one node are never seconds apart.
    """
    if f["rule"] == "setting-changed":
        # The metric belongs in the identity here for the same reason it does below: one rule
        # id covers five different settings, and a tier change moves memory and cache in the
        # same instant on the same node. Keyed only by rule, node and minute, those two are one
        # id -- so publishing them upserted one over the other and the report lost half of what
        # changed. Found in real data, where "the host was resized" silently replaced "the cache
        # was resized" on all three members.
        minute = int(f["worstFromMs"]) // 60_000
        raw = f"{customer_id}/{cluster_id}/{f['rule']}/{f['node']}/{f['metric']}/{minute}"
    elif f["rule"] == "baseline-excursion":
        # Excursions get one id per metric per day, not one per window.
        #
        # A level change often persists: load 600 MB into a cluster and the cache stays full,
        # the ticket pool stays wide. Every one of those is genuinely above the old ceiling,
        # and will be until enough runs pass for the baseline to absorb the new level. Keyed
        # by window, the same excursion would be reported on every run for days. Keyed by day,
        # it is said once, and said again tomorrow only if it is still true.
        day = f.get("detected_day") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        raw = f"{customer_id}/{cluster_id}/{f['rule']}/{f['node']}/{f['metric']}/{day}"
    else:
        minute = int(f["worstFromMs"]) // 60_000
        raw = f"{customer_id}/{cluster_id}/{f['rule']}/{f['node']}/{minute}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def append(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def days_of_raw_ftdc(nodes: list[dict]) -> float:
    """How far back the raw FTDC on disk goes, oldest sample to newest.

    This is what can still be opened in Big Hole and read second by second, and it is what
    the retention window buys. It *shrinks* when `prune.py` runs — see `days_observed` for
    the number that does not.
    """
    if not nodes:
        return 0.0
    first = min(n["fromMs"] for n in nodes)
    last = max(n["toMs"] for n in nodes)
    return round((last - first) / 86_400_000, 2)


def days_observed(baseline_path: Path) -> float:
    """How long this cluster has been watched, from the baseline.

    Deliberately separate from the raw window. Pruning deletes FTDC but never the baseline, so
    a cluster watched for fourteen months keeps saying fourteen months even when only the last
    twelve can be opened. Conflating the two would either overstate what can be inspected or
    understate how long the service has been running — and the second is the one the customer
    is paying for.
    """
    if not baseline_path.exists():
        return 0.0
    runs = set()
    for line in baseline_path.read_text().splitlines():
        if not line:
            continue
        try:
            runs.add(json.loads(line)["run"])
        except (json.JSONDecodeError, KeyError):
            continue
    if len(runs) < 2:
        return 0.0
    first, last = min(runs), max(runs)
    try:
        delta = datetime.fromisoformat(last) - datetime.fromisoformat(first)
    except ValueError:
        return 0.0
    return round(delta.total_seconds() / 86_400, 2)


def analyze_cluster(spec: dict, root: Path, redo: bool = False,
                    verbose: bool = True) -> dict:
    customer_id, cluster_id = spec["customer_id"], spec["cluster_id"]
    base = root / customer_id / cluster_id
    ftdc = base / "ftdc"
    state = State.load(base / "state.json", customer_id, cluster_id)

    if not ftdc.exists():
        raise FileNotFoundError(f"nothing captured yet under {ftdc}")

    pending = state.pending_analysis()
    if not pending and not redo:
        if verbose:
            print(f"[{customer_id}/{cluster_id}] no new files")
        return {"customer_id": customer_id, "cluster_id": cluster_id, "skipped": True}

    if verbose:
        print(f"[{customer_id}/{cluster_id}] {len(pending)} new file(s)")

    t0 = time.monotonic()
    # One step, not a fraction of one: the engine is a single call that either produces
    # findings or does not, and splitting it into a number would mean inventing one.
    progress.report(base, "analyse", note=f"{len(pending)} file(s)", certain=False)
    # Not just the new files: an episode can start in an old file and end in a new one, and
    # looking at them separately would either split it in two findings or lose it entirely.
    # The engine reads from a day before the last run, and takes everything older from the
    # per-day summaries in `daily/`. What bounds the noise is `--since`, which drops findings
    # that already closed before the last run.
    since = None if redo else state.last_analysis
    out = run_engine(ftdc, since, daily=base / "daily")

    stamp = now()
    nodes = out["nodes"]

    # --- excursions from this cluster's own normal ----------------------------------
    # Computed before the findings are written, using history that excludes this run: the
    # ceiling has to be what the cluster looked like *before* the window being judged.
    history = anomaly.load_history(base / "baseline.jsonl", before_run=stamp)
    # The window actually judged, not the whole capture. Falls back to the full extent on a
    # first run, when there is no `--since` and therefore no narrower window to report.
    froms = [n["recentFromMs"] for n in nodes if n.get("recentFromMs")]
    tos = [n["recentToMs"] for n in nodes if n.get("recentToMs")]
    window_from = min(froms) if froms else min((n["fromMs"] for n in nodes), default=0)
    window_to = max(tos) if tos else max((n["toMs"] for n in nodes), default=0)
    excursions = anomaly.find(nodes, history)

    # Sizing advice is judged against what the rules found in the SAME run, before anything is
    # filtered for having been reported before. A cluster that saturated its tickets an hour ago
    # is not a cluster to advise shrinking, and whether that finding is new to us has no bearing
    # on whether it happened.
    had_trouble = any(f.get("severity") in ("critical", "warning") for f in out["findings"])
    advice = sizing.advise(base / "baseline.jsonl", nodes, had_trouble, window_from, window_to)

    # What runs out, and when. Reads the same baseline file, and the same rule about history
    # applies: this run is not in it yet, so a projection is never fitted to the point it is
    # trying to predict.
    ahead = runway.as_findings(runway.find(base / "baseline.jsonl"), window_from, window_to)

    # --- findings, only the ones not seen before ------------------------------------
    already = set(state.reported_findings)
    fresh = []
    for f in (out["findings"]
              + anomaly.as_findings(excursions, window_from, window_to, nodes)
              + advice
              + ahead):
        fid = finding_id(customer_id, cluster_id, f)
        if fid in already:
            continue
        fresh.append({
            "id": fid,
            "customer_id": customer_id,
            "cluster_id": cluster_id,
            "detected_at": stamp,
            "notified_at": None,
            **f,
        })
    append(base / "findings.jsonl", fresh)
    state.reported_findings.extend(f["id"] for f in fresh)

    # --- baseline: one row per metric per run ---------------------------------------
    # Two scopes, kept apart because they answer different questions. `baseline` covers
    # everything held for the cluster and is what "normal here" is built from; `window` covers
    # only what arrived since the last run and is what gets judged against it.
    rows = [
        {
            "customer_id": customer_id,
            "cluster_id": cluster_id,
            "node": node["node"],
            "run": stamp,
            "scope": scope,
            "fromMs": node["fromMs"],
            "toMs": node["toMs"],
            **p,
        }
        for node in nodes
        for scope, series in (("baseline", node["percentiles"]), ("window", node.get("recent", [])))
        for p in series
    ]
    append(base / "baseline.jsonl", rows)

    # --- summary: what the customer sees --------------------------------------------
    ftdc_bytes = sum(f.stat().st_size for f in ftdc.rglob("metrics.*") if f.is_file())
    summary = {
        "customer_id": customer_id,
        "cluster_id": cluster_id,
        "updated_at": stamp,
        "last_capture": state.last_capture,
        "nodes": [
            {
                "node": n["node"],
                "hostname": n.get("hostname"),
                "version": n.get("version"),
                "samples": n["samples"],
                "from": datetime.fromtimestamp(n["fromMs"] / 1000, timezone.utc).isoformat(),
                "to": datetime.fromtimestamp(n["toMs"] / 1000, timezone.utc).isoformat(),
                # Over everything held. `gaps` itself only covers what this run decoded.
                "gaps": (n["gapsHeld"]["count"] if "gapsHeld" in n else len(n["gaps"])),
                "seconds_without_data": (n["gapsHeld"]["seconds"] if "gapsHeld" in n
                                         else sum(g["seconds"] for g in n["gaps"])),
            }
            for n in nodes
        ],
        "days_of_raw_ftdc": days_of_raw_ftdc(nodes),
        "days_observed": days_observed(base / "baseline.jsonl"),
        "megabytes": round(ftdc_bytes / 1024 / 1024, 1),
        "findings_new": len(fresh),
        "findings_total": len(state.reported_findings),
        "rules_evaluated": out["rulesEvaluated"],
        # A rule that fails to resolve looks exactly like a rule that found nothing. If this
        # is not empty, there is coverage the customer believes they have and do not.
        "rules_unresolved": out["rulesUnresolved"],
    }
    (base / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))

    # Chart shapes for the profile report, in their own file and overwritten each run. They
    # are neither history (the baseline is) nor small enough to belong in summary.json, which
    # gets read on every status page build.
    shapes = {n["node"]: n.get("series", {}) for n in nodes if n.get("series")}
    if shapes:
        (base / "series.json").write_text(json.dumps(shapes))

    state.mark_analyzed([f.key for f in pending])
    state.save(base / "state.json")
    progress.report(base, "done")

    measured = {
        "customer_id": customer_id,
        "cluster_id": cluster_id,
        "operation": "analyze",
        "files": len(pending),
        "findings_new": len(fresh),
        "baseline_rows": len(rows),
        "seconds": round(time.monotonic() - t0, 1),
    }
    record_usage(base, **measured)

    if verbose:
        print(
            f"  {len(fresh)} new finding(s) · {len(rows)} baseline rows · "
            f"{summary['days_of_raw_ftdc']} days of raw FTDC · {measured['seconds']}s"
        )
        for f in fresh:
            print(f"    {f['severity'].upper():8} {f['title']} [{f['node'][:26]}] "
                  f"{f['secondsInState']}s")
        if out["rulesUnresolved"]:
            print(f"  NOTE: {len(out['rulesUnresolved'])} rule(s) did not resolve:")
            for r in out["rulesUnresolved"]:
                print(f"    {r['id']}  {r['metric'][:64]}")
    return measured


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--customer", help="analyse only this customer_id")
    ap.add_argument("--redo", action="store_true",
                    help="re-analyse everything, ignoring what was analysed before")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not args.config.exists():
        print(f"{args.config} does not exist — copy config.example.json", file=sys.stderr)
        return 2
    if shutil.which("npx") is None:
        print("npx is missing: the analysis engine runs inside Big Hole", file=sys.stderr)
        return 2

    clusters = load_clusters(args.config)
    if args.customer:
        clusters = [c for c in clusters if c["customer_id"] == args.customer]
    if not clusters:
        print("no clusters to analyse", file=sys.stderr)
        return 1

    failed = 0
    for spec in clusters:
        try:
            analyze_cluster(spec, args.data, args.redo, verbose=not args.quiet)
        except Exception as e:
            # Same as in capture: one cluster failing does not stop the others, and the error
            # is loud on purpose.
            failed += 1
            print(
                f"[{spec['customer_id']}/{spec['cluster_id']}] FAILED: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
