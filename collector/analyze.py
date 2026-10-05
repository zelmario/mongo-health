#!/usr/bin/env python3
"""Analyse what was captured: run the rules, store findings, accumulate the baseline.

Runs after `capture.py`, from the same cron entry. The split is deliberate: capturing is a
network operation that can fail for reasons of its own, analysing is pure local computation
over what is already on disk. One failing must not stop the other from running.

    python3 analyze.py --config config.json
    python3 analyze.py --config config.json --cluster orders-prod
    python3 analyze.py --config config.json --redo   # ignore what was analysed before

Writes three things per cluster, each with a different use:

    findings.jsonl   what the rules fired on -- this is what gets notified
    baseline.jsonl   percentiles per metric per run. This has to start being recorded with
                     the FIRST capture: once Atlas drops the raw data, this is all that is
                     left to later say "that is unusual for this cluster". It cannot be
                     reconstructed after the fact.
    summary.json     the current state, which is what the report shows

The engine lives in `runner/analyze.ts` and runs inside Big Hole, so that decoder, aliases
and rules all live in one place.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import anomaly
import runway
import sizing
from capture import record_usage
from config import ConfigError, load_clusters
from state import State, now, timestamp_of

ANALYZING = "analyzing.json"
PROGRESS = "analyzing.progress.json"  # written by the engine as it decodes
FAILED = "analysis-failed.json"       # the last analysis failed, and how


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


# Half an hour for an hourly round, which decodes the last two days. A run with no `since` is a
# full re-analysis and decodes everything held, so its cost grows with retention: a --redo of
# Cluster1 (20 days, 1.2 GB) ran past the half hour on 2026-10-05 and left the cluster reading
# "the latest analysis failed". Still bounded, so a hung engine cannot hold the round lock for
# ever.
ROUND_TIMEOUT, FULL_TIMEOUT = 1800, 4 * 3600


def run_engine(ftdc: Path, since: str | None, timeout: int | None = None,
               daily: Path | None = None, progress: Path | None = None) -> dict:
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
    if progress is not None:
        cmd += ["--progress", str(progress.resolve())]

    if timeout is None:
        timeout = ROUND_TIMEOUT if since else FULL_TIMEOUT
    r = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"engine failed ({r.returncode}): {r.stderr.strip()[-400:]}")
    return json.loads(r.stdout)


def finding_id(cluster_id: str, f: dict) -> str:
    """Stable identity for a finding, so the same one is never reported twice.

    Built from the rule, the node and the start of the worst episode. It deliberately does
    NOT include the duration: if an episode keeps growing between two runs it is still the
    same episode, and a second email about it is exactly the noise that makes people cancel.

    The start is bucketed to the minute for the same reason. Two runs judge different windows,
    so the first sample that crosses the threshold can differ by one sampling interval, and at
    millisecond precision that produced two ids for one incident -- one ticket saturation
    reported twice, charted two different ways. A minute is safely coarse: the grouper
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
        raw = f"{cluster_id}/{f['rule']}/{f['node']}/{f['metric']}/{minute}"
    elif f["rule"] == "baseline-excursion":
        # Excursions get one id per metric per day, not one per window.
        #
        # A level change often persists: load 600 MB into a cluster and the cache stays full,
        # the ticket pool stays wide. Every one of those is genuinely above the old ceiling,
        # and will be until enough runs pass for the baseline to absorb the new level. Keyed
        # by window, the same excursion would be reported on every run for days. Keyed by day,
        # it is said once, and said again tomorrow only if it is still true.
        day = f.get("detected_day") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        raw = f"{cluster_id}/{f['rule']}/{f['node']}/{f['metric']}/{day}"
    else:
        minute = int(f["worstFromMs"]) // 60_000
        raw = f"{cluster_id}/{f['rule']}/{f['node']}/{minute}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


# What a re-analysis brings up to date on a finding already held: how it is drawn and how it
# is worded. Cluster1's rolling restart said "0.1 to 0.1 minutes" until the wording was fixed,
# and the fix reached only restarts found after it.
REFRESHED = ("chart", "title", "what", "check")


def refresh_charts(path: Path, charts: dict[str, dict]) -> None:
    """The chart and the wording of findings already held, redone by a re-analysis. Nothing
    else changes -- not when it was detected, not whether it was sent -- so a better picture of
    an old incident never becomes a second email about it. Without this, a finding kept the
    chart the engine drew the day it was found, and an improvement reached only new incidents."""
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for row in rows:
        if row.get("id") in charts:
            row.update(charts[row["id"]])
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    tmp.replace(path)


# What a re-analysis may take back. Not what depends on the history at the time it was found
# rather than on the FTDC alone: an excursion is judged against the baseline as it was then,
# sizing advice and a runway against everything held then.
NOT_RETRACTABLE = frozenset({"baseline-excursion", "oversized-cluster", "capacity-runway"})


def retract_unreproduced(base: Path, produced: set[str], nodes: list[dict], stamp: str) -> set[str]:
    """Findings held that a full re-analysis no longer produces, over data it still has.

    A redo of Cluster1 that overlapped a capture saw a node's newest file before it arrived and
    reported a 3.3-hour outage that the data does not contain; the next redo, over the complete
    files, did not produce it, and the report kept saying "At risk". Taken back only when the
    finding lies wholly inside the raw FTDC its node still holds: past retention there is
    nothing left to check it against, and a finding that cannot be checked is kept. Moved to
    retracted.jsonl with when and why, never deleted without a trace.
    """
    path = base / "findings.jsonl"
    if not path.exists():
        return set()
    extent = {}
    for n in nodes:
        for label in (n.get("hostname"), n.get("node")):
            if label:
                extent[label] = (n["fromMs"], n["toMs"])
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    keep, gone = [], []
    for row in rows:
        held = extent.get(row.get("node"))
        if (row.get("id") not in produced and row.get("rule") not in NOT_RETRACTABLE
                and held is not None
                and held[0] <= int(row["fromMs"]) and int(row["toMs"]) <= held[1]):
            gone.append(dict(row, retracted_at=stamp,
                             retracted_because="a full re-analysis of the FTDC still held "
                                               "no longer produces it"))
        else:
            keep.append(row)
    if gone:
        append(base / "retracted.jsonl", gone)
        tmp = path.with_name(f".{path.name}.tmp")
        tmp.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in keep))
        tmp.replace(path)
    return {r["id"] for r in gone}


def append(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def backfilled(pending, last_analysis: str) -> bool:
    """Whether any file waiting for analysis was opened before the window the engine re-reads.

    The engine re-reads raw FTDC from a day before `last_analysis` (see run_engine); anything
    older it takes from the daily summaries, which a file that arrived late is not in.
    """
    try:
        cutoff = datetime.fromisoformat(last_analysis.replace("Z", "+00:00")) - timedelta(days=1)
    except ValueError:
        return False
    opened = [timestamp_of(f.name) for f in pending]
    return any(t is not None and t < cutoff for t in opened)


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
    cluster_id = spec["cluster_id"]
    base = root / cluster_id
    ftdc = base / "ftdc"
    state = State.load(base / "state.json", cluster_id)

    if not ftdc.exists():
        raise FileNotFoundError(f"nothing captured yet under {ftdc}")

    pending = state.pending_analysis()
    if not pending and not redo:
        if verbose:
            print(f"[{cluster_id}] no new files")
        return {"cluster_id": cluster_id, "skipped": True}

    if verbose:
        print(f"[{cluster_id}] {len(pending)} new file(s)")
    # For the page: while this is on disk it says "Analyzing FTDC" rather than whatever the last
    # verdict was. A first upload takes minutes, and the page meanwhile said "Not being watched".
    (base / ANALYZING).write_text(json.dumps({"started": now(), "files": len(pending)}))

    t0 = time.monotonic()
    # Not just the new files: an episode can start in an old file and end in a new one, and
    # looking at them separately would either split it in two findings or lose it entirely.
    # The engine reads from a day before the last run, and takes everything older from the
    # per-day summaries in `daily/`. What bounds the noise is `--since`, which drops findings
    # that already closed before the last run.
    since = None if redo else state.last_analysis
    if since and backfilled(pending, since):
        # Files older than the last analysis arrived after it: a first Atlas capture comes
        # newest first, window by window. Read from `since`, the engine took them as already
        # summarised and judged Cluster1 on 43 hours of its 20 days. Read from the start.
        since = None
    out = run_engine(ftdc, since, daily=base / "daily", progress=base / PROGRESS)

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
    redrawn: dict[str, dict] = {}
    produced: set[str] = set()
    for f in (out["findings"]
              + anomaly.as_findings(excursions, window_from, window_to, nodes)
              + advice
              + ahead):
        fid = finding_id(cluster_id, f)
        produced.add(fid)
        if fid in already:
            if redo:
                redrawn[fid] = {k: f[k] for k in REFRESHED if f.get(k)}
            continue
        fresh.append({
            "id": fid,
            "cluster_id": cluster_id,
            "detected_at": stamp,
            "notified_at": None,
            **f,
        })
    append(base / "findings.jsonl", fresh)
    state.reported_findings.extend(f["id"] for f in fresh)
    if redrawn:
        refresh_charts(base / "findings.jsonl", redrawn)
    if redo:
        gone = retract_unreproduced(base, produced, nodes, stamp)
        state.reported_findings = [i for i in state.reported_findings if i not in gone]
        if gone and verbose:
            print(f"  {len(gone)} finding(s) no longer reproduced, retracted")

    # --- baseline: one row per metric per run ---------------------------------------
    # Two scopes, kept apart because they answer different questions. `baseline` covers
    # everything held for the cluster and is what "normal here" is built from; `window` covers
    # only what arrived since the last run and is what gets judged against it.
    rows = [
        {
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
    # A run whose files carried no metadata still knows how the member was configured: it is
    # what the previous run read. Dropping it would make the recommendations come and go.
    previous_config = {}
    if (base / "summary.json").exists():
        try:
            previous_config = {n["node"]: n["config"] for n in
                               json.loads((base / "summary.json").read_text()).get("nodes", [])
                               if n.get("config")}
        except (ValueError, KeyError):
            previous_config = {}
    summary = {
        "cluster_id": cluster_id,
        "updated_at": stamp,
        "last_capture": state.last_capture,
        "nodes": [
            {
                "node": n["node"],
                "hostname": n.get("hostname"),
                "version": n.get("version"),
                "config": n.get("config") or previous_config.get(n["node"]),
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
    # gets read on every report build.
    shapes = {n["node"]: n.get("series", {}) for n in nodes if n.get("series")}
    if shapes:
        (base / "series.json").write_text(json.dumps(shapes))

    state.mark_analyzed([f.key for f in pending])
    state.save(base / "state.json")

    measured = {
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
    ap.add_argument("--cluster", help="only this cluster id")
    ap.add_argument("--redo", action="store_true",
                    help="re-analyse everything, ignoring what was analysed before")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    with round_lock():
        return _main(args)


def round_lock():
    """The lock run.sh holds for a whole round, waited for when this runs on its own.

    An analysis loads state.json at the start and saves it at the end. A --redo of Cluster1
    started by hand between two rounds ran for sixteen minutes, a round captured six new files
    in the middle of it, and the redo's save put back the state from before them. Inside a
    round the lock is already held (ROUND_LOCK_HELD), and taking it again would wait for ever.
    """
    if os.environ.get("ROUND_LOCK_HELD"):
        return contextlib.nullcontext()

    @contextlib.contextmanager
    def held():
        path = Path(os.environ.get("LOCK") or Path(__file__).resolve().parent / ".run.lock")
        with open(path, "a") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("a collection round is running; waiting for it to finish",
                      file=sys.stderr, flush=True)
                fcntl.flock(fh, fcntl.LOCK_EX)
            yield
    return held()


def _main(args) -> int:

    if shutil.which("npx") is None:
        print("npx is missing: the analysis engine runs inside Big Hole", file=sys.stderr)
        return 2

    try:
        clusters = load_clusters(args.config)
    except ConfigError as e:
        print(e, file=sys.stderr)
        return 2
    if args.cluster:
        clusters = [c for c in clusters if c["cluster_id"] == args.cluster]
    if not clusters:
        print("no clusters to analyse", file=sys.stderr)
        return 1

    failed = 0
    for spec in clusters:
        try:
            try:
                analyze_cluster(spec, args.data, args.redo, verbose=not args.quiet)
            finally:
                for name in (ANALYZING, PROGRESS):
                    (args.data / spec["cluster_id"] / name).unlink(missing_ok=True)
            (args.data / spec["cluster_id"] / FAILED).unlink(missing_ok=True)
        except Exception as e:
            # Same as in capture: one cluster failing does not stop the others, and the error
            # is loud on purpose.
            failed += 1
            # For the page, which otherwise went on promising an analysis that had already
            # ended. Not for a cluster with nothing captured: that is waiting, not failing.
            base = args.data / spec["cluster_id"]
            if (base / "ftdc").is_dir():
                (base / FAILED).write_text(json.dumps(
                    {"at": now(), "error": f"{type(e).__name__}: {str(e)[-300:]}"}))
            print(
                f"[{spec['cluster_id']}] FAILED: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
