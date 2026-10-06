"""What has been downloaded, analysed and notified.

One JSON file per cluster, shaped like a table -- flat rows, with an identifier and
timestamps -- so that nothing has to reinterpret nested structures to read it.

It is needed from day one for a practical reason rather than a design one: without it the
same email goes out twice whenever two runs overlap.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def timestamp_of(name: str) -> datetime | None:
    """When mongod created this FTDC file, from its name.

    `metrics.2026-08-07T01-15-12Z-00000` -> 2026-08-07 01:15:12 UTC. Note this is when the
    file was *opened*, not when its last sample was written -- the gap between the two is the
    whole reason `oldest_open_file` exists. Returns None for `metrics.interim`, which carries
    no timestamp.
    """
    match = re.match(r"metrics\.(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})Z", name)
    if match is None:
        return None
    day, hh, mm, ss = match.groups()
    try:
        return datetime.fromisoformat(f"{day}T{hh}:{mm}:{ss}+00:00")
    except ValueError:
        return None


@dataclass
class SeenFile:
    """An FTDC file that is already stored, and how big it was when we stored it.

    The size is the whole point. A numbered `metrics.<timestamp>-NNNNN` file is immutable
    *after* mongod rotates away from it -- but not before: mongod keeps appending to the
    current one until it reaches its size cap, which on Atlas means roughly 10 MB and many
    hours. Treating the name as identity loses everything written after the first capture,
    and does it silently.

    Measured on a real Atlas M10: we stored 284 KB under a given name and, nine hours later,
    Atlas was still serving that same name at 8,360 KB. The analyser then reported a nine-hour
    outage on a node that had been up the whole time -- which is how the bug was found.
    """

    node: str
    name: str
    bytes: int
    seen_at: str
    analyzed_at: str | None = None
    # True once we have seen this file at the same size twice running. Only then do we know
    # our copy is its final one -- see State.oldest_open_file for why that matters.
    stable: bool = False

    @property
    def key(self) -> str:
        return f"{self.node}/{self.name}"


@dataclass
class State:
    cluster_id: str
    files: dict[str, SeenFile] = field(default_factory=dict)
    last_capture: str | None = None
    # When a run last brought something back. Separate from `last_capture` because the two
    # answer different questions and only this one means "somebody is watching": capture runs
    # every hour whatever it finds, so on a cluster that uploads to us, or one we read from a
    # directory, `last_capture` moves whether or not the source is alive.
    last_new_data: str | None = None
    last_analysis: str | None = None
    reported_findings: list[str] = field(default_factory=list)
    # How this cluster's files arrive. Recorded so that `watchdog.py` can judge silence
    # correctly without reading the config or the database -- it deliberately looks at nothing
    # but the state files and the clock, and how long is too long depends on this.
    source_kind: str | None = None
    # A bundle ordered from the provider that we did not manage to wait out. Kept because the
    # order is the slow part and it outlives the run that placed it: without this, a run that
    # times out throws away work the provider went on to finish, and the next one starts over.
    pending_job: str | None = None
    # How long the provider took to assemble the last bundle for this cluster. The only ground
    # there is for telling somebody how much of the wait is left, since the API reports a status
    # and never a percentage. Per cluster, because it scales with how much data it produces.
    last_job_seconds: float | None = None
    # The first capture of an Atlas cluster, fetched window by window (sources.AtlasSource.
    # history): the window ordered and not collected yet, the start of the oldest window
    # collected, and whether the history is complete. A run that stops halfway leaves these, and
    # the next one goes on from there instead of starting over.
    pending_window: list[str] | None = None
    history_before: str | None = None
    history_done: bool = False
    # Files `prune.py` deleted, by key, with their size then. A source that keeps offering them
    # -- an upload directory is never emptied -- would otherwise have them stored again as new:
    # dft brought back the same 22 files, 228 MB, every hour, analysed them and pruned them
    # again. Kept only while the source still offers the file (see `capture.py`).
    pruned: dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------ persistence

    @classmethod
    def load(cls, path: Path, cluster_id: str) -> "State":
        if not path.exists():
            return cls(cluster_id=cluster_id)
        raw = json.loads(path.read_text())
        return cls(
            cluster_id=raw.get("cluster_id", cluster_id),
            files={k: SeenFile(**v) for k, v in raw.get("files", {}).items()},
            last_capture=raw.get("last_capture"),
            # Seeded from the last capture when the field is absent, which is every state
            # file written before it existed. Left empty, a source that is ALREADY dead would
            # never get a first arrival timestamp and so could never be reported -- the exact
            # cluster this was built for. Inheriting the run time costs one threshold's delay
            # on the upgrade and nothing afterwards: the next run that finds nothing leaves it
            # where it is, and it starts ageing honestly.
            last_new_data=raw.get("last_new_data") or raw.get("last_capture"),
            last_analysis=raw.get("last_analysis"),
            reported_findings=raw.get("reported_findings", []),
            source_kind=raw.get("source_kind"),
            pending_job=raw.get("pending_job"),
            last_job_seconds=raw.get("last_job_seconds"),
            pending_window=raw.get("pending_window"),
            history_before=raw.get("history_before"),
            # Absent in every state written before windows existed: a cluster that already
            # holds files got its history in one bundle and is complete, and one that holds
            # none has not started.
            history_done=raw.get("history_done", bool(raw.get("files"))),
            pruned=raw.get("pruned", {}),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "cluster_id": self.cluster_id,
            "last_capture": self.last_capture,
            "last_new_data": self.last_new_data,
            "last_analysis": self.last_analysis,
            "files": {k: asdict(v) for k, v in self.files.items()},
            "reported_findings": self.reported_findings,
            "source_kind": self.source_kind,
            "pending_job": self.pending_job,
            "last_job_seconds": self.last_job_seconds,
            "pending_window": self.pending_window,
            "history_before": self.history_before,
            "history_done": self.history_done,
            "pruned": self.pruned,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body, indent=2, sort_keys=True))
        tmp.replace(path)  # atomic: an interrupted run cannot leave half a state file

    # ------------------------------------------------------------------ queries

    def is_new(self, node: str, name: str, size: int) -> bool:
        """Is this file worth storing?

        One rule, no special cases: store it if we have not seen it, or if its size *changed*.

        Changed, not grew. `metrics.interim` is a buffer of samples not yet flushed to the
        numbered file, so it **shrinks** every time mongod flushes -- observed on Atlas going
        from 62 KB down to 46 KB. A grew-only test never refetches it after the first shrink,
        so the copy on disk freezes at some past moment while the cluster moves on. That
        produces a capture whose newest file is stale by hours, which is both wrong and
        invisible.

        Numbered files only ever grow, so `!=` costs nothing there and states the real
        invariant: we hold a faithful copy exactly when the size matches.
        """
        seen = self.files.get(f"{node}/{name}")
        return seen is None or size != seen.bytes

    def record(self, node: str, name: str, size: int) -> None:
        key = f"{node}/{name}"
        previous = self.files.get(key)
        unchanged = previous is not None and previous.bytes == size
        self.files[key] = SeenFile(
            node=node,
            name=name,
            bytes=size,
            seen_at=now(),
            # If the file changed, whatever was analysed before no longer covers all of it.
            analyzed_at=previous.analyzed_at if unchanged else None,
            stable=unchanged,
        )

    def seen_unchanged(self, node: str, name: str, size: int) -> None:
        """Record that a file we already hold came back at the same size.

        `capture.py` skips storing it, but the observation still matters: two sightings at
        one size is what promotes a file to stable, and only stable files stop holding the
        date-filter anchor back.
        """
        existing = self.files.get(f"{node}/{name}")
        if existing is not None and existing.bytes == size:
            existing.stable = True

    def oldest_open_file(self) -> datetime | None:
        """Timestamp of the oldest file whose copy we cannot yet prove is complete.

        This is what a date filter has to be anchored to, and it is not the same as "when we
        last captured". Atlas filters by the timestamp in the file *name*, and mongod appends
        to a file for hours after creating it -- so the file holding the last ten minutes of
        metrics may be named from this morning. Filtering from `now - 6h` asks for a window
        that excludes the very file the new data is in.

        The anchor is the oldest *unstable* file across all nodes, not simply the newest file
        of each. The difference only shows up at rotation, and it is the difference between
        keeping a file's tail and losing it:

            we capture file A on every node, complete up to that moment
            all three nodes roll over to file B
            next run, anchoring on "newest per node" gives B's timestamp
            A now falls outside the filter, and whatever mongod appended to A between our
            last capture and its rotation is gone for good

        The members of a replica set start together, so their files roll over together --
        this is the normal case, not a corner one. Anchoring on the oldest file we have not
        yet seen twice at the same size keeps A in the window for exactly one more run, which
        is when we find out whether it grew.

        Returns None when nothing is stored yet, which means "do not filter at all".
        """
        candidates: dict[str, datetime] = {}
        closed = self._closed_when_stored()
        for f in self.files.values():
            when = timestamp_of(f.name)
            if when is None:
                continue  # the interim carries no timestamp and is always served anyway
            if f.stable or f.key in closed:
                continue  # proven complete: it cannot need fetching again
            current = candidates.get(f.node)
            if current is None or when < current:
                candidates[f.node] = when

        if candidates:
            return min(candidates.values())

        # Everything is stable, which happens on a quiet cluster between rotations. Fall back
        # to the newest file per node: there is nothing older that could still need fetching.
        newest: dict[str, datetime] = {}
        for f in self.files.values():
            when = timestamp_of(f.name)
            if when is None:
                continue
            current = newest.get(f.node)
            if current is None or when > current:
                newest[f.node] = when
        return min(newest.values()) if newest else None

    # Files stored within this of each other came in the same capture: one window of a first
    # capture lands in seconds, and the hourly ones are an hour apart.
    SAME_CAPTURE_SECONDS = 600

    def _closed_when_stored(self) -> set[str]:
        """Files that already had a newer file beside them when they were stored.

        mongod opens a new file only after closing the last, so a file that arrived together
        with a newer one from the same node was complete when we copied it. Without this, the
        126 files of Cluster1's first capture, each seen once, held the anchor at 12 Sep, and
        every hourly capture asked Atlas for the whole history again -- which Atlas cuts.
        """
        by_node: dict[str, list[tuple[datetime, datetime, str]]] = {}
        for f in self.files.values():
            opened = timestamp_of(f.name)
            try:
                stored = datetime.fromisoformat(f.seen_at.replace("Z", "+00:00"))
            except (AttributeError, ValueError):
                continue
            if opened is not None:
                by_node.setdefault(f.node, []).append((opened, stored, f.key))
        closed = set()
        for files in by_node.values():
            files.sort()
            earliest_after = None  # the earliest a newer file of this node was stored
            for opened, stored, key in reversed(files):
                if earliest_after is not None and \
                        (earliest_after - stored).total_seconds() <= self.SAME_CAPTURE_SECONDS:
                    closed.add(key)
                earliest_after = stored if earliest_after is None else min(earliest_after, stored)
        return closed

    def pending_analysis(self) -> list[SeenFile]:
        return [f for f in self.files.values() if f.analyzed_at is None]

    def mark_analyzed(self, keys: list[str]) -> None:
        stamp = now()
        for key in keys:
            if key in self.files:
                self.files[key].analyzed_at = stamp
        self.last_analysis = stamp
