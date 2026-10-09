#!/usr/bin/env python3
"""Poll clusters connected by connection string, and write what they report as FTDC.

    python3 poller.py --config config.json --data data

For every cluster whose source is `{"type": "mongodb", "uri": "mongodb://..."}`: find its
members, connect to each directly with the same credentials, and ask it for `getDiagnosticData`
every `interval` seconds (ten unless the cluster says otherwise). The samples are written as FTDC under `data/<cluster>/incoming/<member>/`, where
the hourly capture picks them up like any directory of FTDC.

One user, created once on the primary, is enough: the replica set replicates it to every member.
It needs `clusterMonitor` and nothing more:

    db.getSiblingDB("admin").createUser({user: "mongo-health", pwd: passwordPrompt(),
      roles: [{role: "clusterMonitor", db: "admin"}]})

Runs for ever. The config is re-read every minute, so a cluster added from the page starts being
polled without a restart, and members are re-discovered every five, so a member added, removed
or renamed is followed.
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bson
from bson.codec_options import CodecOptions
from bson.raw_bson import RawBSONDocument
from pymongo import MongoClient
from pymongo import uri_parser

import config
import ftdcwrite
from ftdcfiles import member_dir

INTERVAL = 10            # seconds between samples, per member, unless the cluster sets `interval`
INTERVALS = (1, 2, 5, 10)  # what the add page offers
# Every connection asks for it: a sample is 221 KB of BSON and 33 KB compressed (measured on a
# PSMDB 8.0 replica set), which is the difference between 2.9 and 19.6 GB a day per member at
# one a second. The server accepts zlib by default; a URI naming its own compressors keeps them.
COMPRESSORS = "zlib"
DISCOVER_EVERY = 300     # seconds between re-reading the member list
RELOAD_EVERY = 60        # seconds between re-reading the config
TIMEOUT_MS = 10_000
RAW = CodecOptions(document_class=RawBSONDocument)

# The first chunk of a member's life is written after this many samples instead of the usual
# five minutes' worth, so the first evaluation of a newly connected cluster waits a minute.
FIRST_CHUNK = 6

# Where the poller says which holes in a member's samples are its own: it was stopped, not the
# member. Every rebuild of the app restarts it, and each restart read as "Node stopped
# reporting" on every connected cluster (17:25-17:27 on the first clean install). The runner
# drops the gaps inside these intervals (runner/analyze.ts, --unwatched).
UNWATCHED = "unwatched.jsonl"


def uptime_of(raw: bytes) -> float | None:
    """mongod's serverStatus.uptime in one getDiagnosticData sample, in seconds.

    At the top of the sample before 8.0, inside a role section (common, shard...) from 8.0 on.
    """
    try:
        doc = bson.decode(raw)
    except Exception:
        return None
    for d in (doc, *(v for v in doc.values() if isinstance(v, dict))):
        status = d.get("serverStatus")
        if isinstance(status, dict) and isinstance(status.get("uptime"), (int, float)):
            return float(status["uptime"])
    return None


def client_for(uri: str, host: str | None = None) -> MongoClient:
    """A client for the whole set, or -- with `host` -- one connected straight to that member,
    with the credentials and options of the original connection string."""
    parsed = uri_parser.parse_uri(uri)
    compress = {} if "compressors" in {k.lower() for k in parsed["options"]} \
        else {"compressors": COMPRESSORS}
    if host is None:
        return MongoClient(uri, serverSelectionTimeoutMS=TIMEOUT_MS, appname="mongo-health",
                           **compress)
    options = {k: v for k, v in parsed["options"].items()
               if k.lower() not in ("replicaset", "directconnection", "readpreference",
                                    "loadbalanced")}
    return MongoClient(host=host, directConnection=True, username=parsed["username"],
                       password=parsed["password"], serverSelectionTimeoutMS=TIMEOUT_MS,
                       appname="mongo-health", **compress, **options)


def discover(uri: str) -> dict:
    """The members of the set the connection string points at, as they name themselves.

    Returns {"members": [...], "kind": "replica set" | "standalone" | "sharded"}. Arbiters are
    left out: they hold no data and have nothing to measure.
    """
    with client_for(uri) as c:
        hello = c.admin.command("hello")
    if hello.get("msg") == "isdbgrid":
        return {"kind": "sharded", "members": []}
    if "setName" in hello:
        members = list(hello.get("hosts", [])) + list(hello.get("passives", []))
        return {"kind": "replica set", "members": members, "set": hello["setName"]}
    host = uri_parser.parse_uri(uri)["nodelist"][0]
    return {"kind": "standalone", "members": [f"{host[0]}:{host[1]}"]}


def check(uri: str) -> dict:
    """Everything the "test connection" button reports: what was found, and per member whether
    it answered and whether the user may read its diagnostics."""
    result = {"ok": False, "kind": None, "members": [], "error": None}
    try:
        found = discover(uri)
    except Exception as e:  # the message is the user's to read, whatever it is
        result["error"] = f"{type(e).__name__}: {e}"
        return result
    result["kind"] = found["kind"]
    if found["kind"] == "sharded":
        result["error"] = ("This is a mongos. This version watches replica sets only, so a "
                           "sharded cluster cannot be added as a whole yet.")
        return result
    for host in found["members"]:
        row = {"host": host, "ok": False, "version": None, "error": None}
        try:
            with client_for(uri, host) as c:
                row["version"] = c.admin.command("buildInfo").get("version")
                raw = c.admin.command("getDiagnosticData", codec_options=RAW)["data"].raw
                # What one sample costs on the wire, for the page to price each interval with
                # this cluster's own numbers rather than an example's.
                row["sample_bytes"] = len(raw)
                row["compressed_bytes"] = len(zlib.compress(raw, 6))
                row["ok"] = True
        except Exception as e:
            text = str(e)
            row["error"] = ("the user cannot read diagnostics here — it needs the "
                            "clusterMonitor role" if "not authorized" in text.lower()
                            else f"{type(e).__name__}: {text[:200]}")
        result["members"].append(row)
    result["ok"] = bool(result["members"]) and all(m["ok"] for m in result["members"])
    return result


def chunk_for(interval: int) -> int:
    """Samples per chunk: five minutes of them, as mongod does at its one a second."""
    return max(ftdcwrite.CHUNK_SAMPLES, 300 // interval)


class MemberPoller(threading.Thread):
    def __init__(self, uri: str, host: str, out: Path, stop: threading.Event, status: dict,
                 interval: int = INTERVAL, resume_from: datetime | None = None,
                 unwatched: Path | None = None):
        super().__init__(daemon=True, name=f"poll {host}")
        self.uri, self.host, self.out, self.stop, self.status = uri, host, out, stop, status
        self.interval = interval
        # The newest sample a previous run of the poller wrote for this member, and where to say
        # that the hole from there to this run's first sample was the poller's.
        self.resume_from, self.unwatched = resume_from, unwatched

    def own_gap(self, raw: bytes, now: datetime) -> dict | None:
        """The hole since the previous run, recorded as the poller's own, unless mongod
        restarted inside it: then the member was down too, and its outage is real."""
        start, self.resume_from = self.resume_from, None
        if start is None or self.unwatched is None:
            return None
        gap = (now - start).total_seconds()
        if gap <= 2 * self.interval:
            return None
        up = uptime_of(raw)
        if up is not None and up < gap:
            return None
        record = {"member": member_dir(self.host), "from": start.isoformat(),
                  "to": now.isoformat(), "uptime": up}
        self.unwatched.parent.mkdir(parents=True, exist_ok=True)
        with self.unwatched.open("a") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def run(self) -> None:
        client = None
        writer = None
        chunk = FIRST_CHUNK
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                if client is None:
                    client = client_for(self.uri, self.host)
                    writer = ftdcwrite.Writer(self.out, lambda: self._metadata(client),
                                              chunk_samples=chunk_for(self.interval))
                data = client.admin.command("getDiagnosticData", codec_options=RAW)["data"]
                if "start" not in data:
                    # A mongod that has just started has no sample of its own yet and answers
                    # {}. Written, that was a chunk with no fields, and the decoder dropped the
                    # whole file: everything the member said after a real restart, unread.
                    self.stop.wait(max(0.0, self.interval - (time.monotonic() - started)))
                    continue
                raw = data.raw
                taken = datetime.now(timezone.utc)
                writer.add(raw, at=taken)
                if self.resume_from is not None:
                    self.own_gap(raw, taken)
                if len(writer.samples) >= chunk:
                    writer.flush()
                    chunk = chunk_for(self.interval)
                self._status_ok(writer)
            except Exception as e:
                self.status[self.host] = {**self.status.get(self.host, {}),
                                          "error": f"{type(e).__name__}: {str(e)[:200]}"}
                # What was read before the error is kept. A new writer took the old one's place
                # unflushed, and up to five minutes of samples before an outage went with it.
                if writer is not None:
                    try:
                        writer.flush()
                    except OSError:
                        pass
                    writer = None
                if client is not None:
                    client.close()
                client = None
            self.stop.wait(max(0.0, self.interval - (time.monotonic() - started)))
        if writer is not None:
            writer.flush()
            self._status_ok(writer)
        if client is not None:
            client.close()

    def _status_ok(self, writer) -> None:
        written = writer.written_through or (self.status.get(self.host) or {}).get("last_written")
        self.status[self.host] = {
            "last_sample": datetime.now(timezone.utc).isoformat(),
            "last_written": written.isoformat() if isinstance(written, datetime) else written,
            "error": None}

    @staticmethod
    def _metadata(client: MongoClient) -> dict:
        """What mongod writes at the top of its own FTDC files, and what the report reads the
        host name, the version and the configuration from."""
        doc = {}
        for command in ("buildInfo", "getCmdLineOpts", "hostInfo"):
            try:
                doc[command] = client.admin.command(command)
            except Exception:
                pass
        return doc


class ClusterPoller:
    def __init__(self, cluster_id: str, uri: str, data: Path, interval: int = INTERVAL):
        self.cluster_id, self.uri, self.interval = cluster_id, uri, interval
        # Shared with uploaded files for the same members; see ftdcfiles.py.
        self.base = data / cluster_id / "incoming"
        self.members: dict[str, tuple[MemberPoller, threading.Event]] = {}
        self.status: dict = {}
        # Where the previous run stopped writing each member, from the status it left behind.
        self.previous = previous_writes(self.base / "status.json")
        self.discovered_at = 0.0
        self.kind = None
        self.error = None

    def tick(self) -> None:
        if time.monotonic() < self.discovered_at:
            return
        self.discovered_at = time.monotonic() + DISCOVER_EVERY
        try:
            found = discover(self.uri)
            self.kind, self.error = found["kind"], None
        except Exception as e:
            # Tried again in a minute rather than on the next tick: a cluster that is down
            # should not be hammered every five seconds by the tool watching it.
            self.discovered_at = time.monotonic() + 60
            self.error = f"{type(e).__name__}: {str(e)[:200]}"
            return
        if found["kind"] == "sharded":
            self.error = "this is a mongos: this version watches replica sets only"
            return
        wanted = set(found["members"])
        for host in list(self.members):
            if host not in wanted:
                self.members.pop(host)[1].set()
        for host in wanted - set(self.members):
            stop = threading.Event()
            t = MemberPoller(self.uri, host, self.base / member_dir(host), stop, self.status,
                             self.interval, resume_from=self.previous.pop(host, None),
                             unwatched=self.base.parent / UNWATCHED)
            t.start()
            self.members[host] = (t, stop)

    def write_status(self) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        tmp = self.base / ".status.json.tmp"
        tmp.write_text(json.dumps({"kind": self.kind, "error": self.error,
                                   "members": self.status}, indent=2, sort_keys=True))
        tmp.replace(self.base / "status.json")

    def stop(self) -> None:
        for t, event in self.members.values():
            event.set()
        for t, _ in self.members.values():
            t.join(timeout=self.interval * 2 + TIMEOUT_MS / 1000)


def previous_writes(status_path: Path) -> dict[str, datetime]:
    """Per member, the newest sample a previous run wrote to disk.

    `last_written`, not `last_sample`: a sample still in memory when the poller was killed never
    reached a file, so the hole in the data starts at the last one written. A status from before
    `last_written` existed was left by a poller that never flushed on the way out, so its
    `last_sample` is taken back by the most a chunk holds, five minutes.

    A member that was failing when the poller stopped is left out: the hole may be the member's.
    """
    try:
        members = json.loads(status_path.read_text()).get("members") or {}
    except (OSError, ValueError, AttributeError):
        return {}
    out = {}
    for host, m in members.items():
        if not isinstance(m, dict) or m.get("error"):
            continue
        try:
            if m.get("last_written"):
                out[host] = datetime.fromisoformat(m["last_written"])
            elif m.get("last_sample"):
                out[host] = datetime.fromisoformat(m["last_sample"]) - timedelta(seconds=300)
        except (TypeError, ValueError):
            continue
    return out


def targets(config_path: Path) -> dict[str, str]:
    try:
        clusters = config.load_clusters(config_path)
    except config.ConfigError:
        return {}
    return {c["cluster_id"]: (c["source"]["uri"], int(c["source"].get("interval") or INTERVAL))
            for c in clusters
            if c["source"].get("type") in ("onprem", "mongodb") and c["source"].get("uri")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    args = ap.parse_args()

    running: dict[str, ClusterPoller] = {}
    # `docker compose stop` sends SIGTERM. Left to the default, the samples of the chunk in
    # memory, up to five minutes of them at 10 s, died with the process.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        return _poll(args, running)
    finally:
        for p in running.values():
            p.stop()
            p.write_status()


def _poll(args, running: dict) -> int:
    print(f"polling every {INTERVAL}s unless a cluster says otherwise; config re-read every "
          f"{RELOAD_EVERY}s", flush=True)
    while True:
        wanted = targets(args.config)
        for cid in list(running):
            if cid not in wanted or (running[cid].uri, running[cid].interval) != wanted[cid]:
                running.pop(cid).stop()
                print(f"[{cid}] stopped", flush=True)
        for cid, (uri, interval) in wanted.items():
            if cid not in running:
                running[cid] = ClusterPoller(cid, uri, args.data, interval)
                print(f"[{cid}] started, a sample every {interval}s", flush=True)
        deadline = time.monotonic() + RELOAD_EVERY
        while time.monotonic() < deadline:
            for p in running.values():
                p.tick()
                p.write_status()
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
