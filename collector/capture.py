#!/usr/bin/env python3
"""Fetch each configured cluster's new FTDC and store it.

Runs hourly from cron. Deliberately boring: download, deduplicate, store, record what
it did. All the analysis lives in `analyze.py`.

    python3 capture.py --config config.json
    python3 capture.py --config config.json --cluster orders-prod   # just one

    data/{cluster_id}/ftdc/{node}/metrics.*
    data/{cluster_id}/state.json
    data/{cluster_id}/usage.jsonl
"""
from __future__ import annotations

import argparse
import itertools
import json
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

import sources
from config import ConfigError, files_only, load_clusters
from state import State, now


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


ROSTER = "roster.json"
# Written while a source is fetching, removed when it stops. The first Atlas capture waits up to
# half an hour for the bundle, and without this the page said "Not being watched" all that time
# about a cluster added a minute before.
CAPTURING = "capturing.json"
# The last capture's error, until one succeeds. Before the first capture the page had nothing
# else to go on and said "Not being watched", after a download Atlas cut three times.
CAPTURE_FAILED = "capture-failed.json"


class CaptureMarker:
    """What a fetch is doing, on disk for the page: ordering, Atlas building, downloading.

    Rewritten when the stage changes, and within a stage at most every two seconds: a download
    reports every megabyte, and the page asks every two seconds anyway.
    """

    def __init__(self, base: Path) -> None:
        self.path = base / CAPTURING
        self.started = now()
        self.stage: str | None = None
        self.written = 0.0

    def __call__(self, stage: str, done: float = 0, total: float = 0, note: str | None = None,
                 **_) -> None:
        t = time.monotonic()
        if stage == self.stage and t - self.written < 2:
            return
        self.stage, self.written = stage, t
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{CAPTURING}.tmp")
        # `note` is the seconds Atlas has been building, the one thing known about that wait.
        elapsed = float(note) if note and str(note).isdigit() else None
        tmp.write_text(json.dumps({"started": self.started, "stage": stage, "done": done,
                                   "total": total, "elapsed": elapsed}))
        tmp.replace(self.path)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)



def write_roster(data: Path, clusters: list[dict]) -> None:
    """The clusters somebody is supposed to be watching, on disk, for the watchdog to read.

    Without it the watchdog can only see a `state.json` that stopped moving -- which is also
    what a cluster removed from the config looks like, and it would alert about that one for
    ever. The watchdog does not read the config itself: it has to keep working when the rest
    of the collector does not, and the less it depends on, the more failures it can see.

    Stale in the safe direction: if the collector stops running, the roster stops being updated
    and still lists everything that was active, so the watchdog goes on alerting. The failure it
    exists to catch cannot erase the evidence of itself.
    """
    data.mkdir(parents=True, exist_ok=True)
    payload = {
        "written_at": now(),
        "clusters": [{"cluster_id": c["cluster_id"],
                      # How the files arrive decides what the alert tells you to go and look at.
                      "source_kind": (c.get("source") or {}).get("type", "atlas")}
                     # Uploaded files and nothing more: there is no capture to stop.
                     for c in clusters if not files_only(c)],
    }
    tmp = data / f".{ROSTER}.tmp"
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
    tmp.replace(data / ROSTER)


def record_usage(base: Path, **fields) -> None:
    """One line per run: what was fetched and how long it took. Cheap now, impossible to
    reconstruct later, and the first thing to look at when a run gets slow."""
    line = {"at": now(), **fields}
    with (base / "usage.jsonl").open("a") as fh:
        fh.write(json.dumps(line, sort_keys=True) + "\n")


def capture_cluster(spec: dict, root: Path, verbose: bool = True) -> dict:
    cluster_id = spec["cluster_id"]
    base = root / cluster_id
    ftdc = base / "ftdc"
    state = State.load(base / "state.json", cluster_id)

    marker = None
    if spec["source"].get("type") in ("onprem", "mongodb"):
        # A server of your own: poller.py writes what the members report as FTDC under
        # incoming/, uploaded files are unpacked beside it member by member, and from here on
        # it is a directory like any other.
        source = sources.DirectorySource(base / "incoming")
    else:
        marker = CaptureMarker(base)
        source = sources.build(spec["source"], pending_job=state.pending_job,
                               job_estimate=state.last_job_seconds, on_progress=marker)
    # Recorded on every run rather than only at creation: a cluster can be moved from one kind
    # of source to another, and `watchdog.py` judges silence against a clock that depends on
    # this — a stale value there would judge it against the wrong one.
    state.source_kind = spec["source"].get("type", "atlas")

    # Anchored to the oldest file that could still be open, NOT to when we last captured.
    # See State.oldest_open_file: mongod appends to a file for hours, so the data written in
    # the last ten minutes can live in a file named this morning.
    since = state.oldest_open_file()
    files = source.fetch(since)
    history = isinstance(source, sources.AtlasSource) and not state.history_done
    if history:
        if state.pending_window:
            start, end, job = state.pending_window
            source.pending_window = (parse_time(start), parse_time(end))
            source.history_job = job
        if not state.files:
            # Nothing held yet: the history is the whole capture. The hourly fetch with no
            # date filter asks for everything in one bundle, which Atlas cuts at two minutes.
            # A job ordered that way by an older version is dropped for the same reason.
            source.pending_job = None
            files = iter(())
        files = itertools.chain(files, source.history(
            parse_time(state.history_before) if state.history_before else None))

    t0 = time.monotonic()
    new = skipped = new_bytes = 0
    nodes: set[str] = set()

    if verbose:
        print(f"[{cluster_id}] {source.describe()}")

    try:
        for f in files:
            size = f.path.stat().st_size
            nodes.add(f.node)

            if not state.is_new(f.node, f.name, size):
                # Same size as last time. Nothing to store, but the sighting is what proves the
                # file finished growing, which is what lets the date-filter anchor move forward.
                state.seen_unchanged(f.node, f.name, size)
                skipped += 1
                continue

            target = ftdc / f.node / f.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f.path, target)
            state.record(f.node, f.name, size)
            new += 1
            new_bytes += size
            if verbose:
                mark = "~" if f.is_interim else "+"
                print(f"  {mark} {f.node}/{f.name}  {size/1024:.0f} KB")
    finally:
        if marker is not None:
            marker.clear()
        # Written even when the run fails, and this is the point of it: a bundle we ordered and
        # could not wait out is exactly the thing a failed run has to leave behind. Losing the
        # id here means the next run orders the same bundle again and pays the same wait.
        state.pending_job = getattr(source, "pending_job", None)
        if history:
            window = source.pending_window
            state.pending_window = ([window[0].isoformat(), window[1].isoformat(),
                                     source.history_job] if window else None)
            if source.history_before:
                state.history_before = source.history_before.isoformat()
            state.history_done = source.history_done
        # Only overwritten when a job actually finished, so a run that timed out keeps the
        # previous cluster's measurement rather than replacing it with a number that describes
        # nothing.
        state.last_job_seconds = getattr(source, "job_seconds", None) or state.last_job_seconds
        state.save(base / "state.json")

    # A source that yields nothing at all is not the same as one with nothing new. It means
    # the path is wrong, the credentials lost their grant, or the cluster was renamed -- and
    # it looks exactly like a healthy quiet run unless someone says so out loud. This is the
    # same silent-failure shape as a rule that cannot resolve its metric.
    if new == 0 and skipped == 0:
        print(f"  WARNING: {source.describe()} returned no files at all — wrong path, "
              f"revoked credentials, or a renamed cluster?", file=sys.stderr)

    state.last_capture = now()
    if new:
        # Only when something arrived. This is what tells a live source from a dead one: the
        # line above moves every hour no matter what, so on its own it says we looked, not that
        # there was anything to look at.
        state.last_new_data = state.last_capture
    state.save(base / "state.json")

    summary = {
        "cluster_id": cluster_id,
        "source": source.describe(),
        "operation": "capture",
        "files_new": new,
        "files_skipped": skipped,
        "bytes_new": new_bytes,
        "nodes": len(nodes),
        "seconds": round(time.monotonic() - t0, 1),
    }
    record_usage(base, **summary)

    if verbose:
        total = sum(f.stat().st_size for f in ftdc.rglob("metrics.*") if f.is_file())
        print(
            f"  {new} new, {skipped} already stored · "
            f"{new_bytes/1024/1024:.1f} MB new · "
            f"{total/1024/1024:.1f} MB accumulated · {summary['seconds']}s"
        )
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--cluster", help="only this cluster id")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    try:
        clusters = load_clusters(args.config)
    except ConfigError as e:
        print(e, file=sys.stderr)
        return 2
    # Written before the filter and before any capture: this is the list of clusters somebody
    # is supposed to be watching, which is a different question from which ones this invocation
    # happens to touch. A partial run must not shrink it.
    if not args.cluster:
        write_roster(args.data, clusters)
    if args.cluster:
        clusters = [c for c in clusters if c["cluster_id"] == args.cluster]
    if not clusters:
        print("no clusters to capture", file=sys.stderr)
        return 1

    failed = 0
    for spec in clusters:
        base = args.data / spec["cluster_id"]
        try:
            capture_cluster(spec, args.data, verbose=not args.quiet)
            (base / CAPTURE_FAILED).unlink(missing_ok=True)
        except Exception as e:
            base.mkdir(parents=True, exist_ok=True)
            (base / CAPTURE_FAILED).write_text(json.dumps(
                {"at": now(), "error": f"{type(e).__name__}: {e}"}))
            # One cluster failing must not stop the others. In the MVP the error is loud and
            # not retried: if something breaks I want to hear about it, not have the system
            # paper over it.
            failed += 1
            print(
                f"[{spec['cluster_id']}] FAILED: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
