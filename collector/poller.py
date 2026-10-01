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
import sys
import threading
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path

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
                 interval: int = INTERVAL):
        super().__init__(daemon=True, name=f"poll {host}")
        self.uri, self.host, self.out, self.stop, self.status = uri, host, out, stop, status
        self.interval = interval

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
                raw = client.admin.command("getDiagnosticData", codec_options=RAW)["data"].raw
                writer.add(raw)
                if len(writer.samples) >= chunk:
                    writer.flush()
                    chunk = chunk_for(self.interval)
                self.status[self.host] = {"last_sample": datetime.now(timezone.utc).isoformat(),
                                          "error": None}
            except Exception as e:
                self.status[self.host] = {**self.status.get(self.host, {}),
                                          "error": f"{type(e).__name__}: {str(e)[:200]}"}
                if client is not None:
                    client.close()
                client = None
            self.stop.wait(max(0.0, self.interval - (time.monotonic() - started)))
        if writer is not None:
            writer.flush()
        if client is not None:
            client.close()

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
                             self.interval)
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
