#!/usr/bin/env python3
"""Poll clusters connected by connection string, and write what they report as FTDC.

    python3 poller.py --config config.json --data data

For every cluster whose source is `{"type": "mongodb", "uri": "mongodb://..."}`: find its
members, connect to each directly with the same credentials, and ask it for `getDiagnosticData`
every ten seconds. The samples are written as FTDC under `data/<cluster>/poll/<member>/`, where
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
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from bson.codec_options import CodecOptions
from bson.raw_bson import RawBSONDocument
from pymongo import MongoClient
from pymongo import uri_parser

import config
import ftdcwrite

INTERVAL = 10            # seconds between samples, per member
DISCOVER_EVERY = 300     # seconds between re-reading the member list
RELOAD_EVERY = 60        # seconds between re-reading the config
TIMEOUT_MS = 10_000
RAW = CodecOptions(document_class=RawBSONDocument)

# The first chunk of a member's life is written after this many samples instead of the usual
# five minutes' worth, so the first evaluation of a newly connected cluster waits a minute.
FIRST_CHUNK = 6


def member_dir(host: str) -> str:
    """A member's directory name. `db1:27017` -> `db1_27017`: the colon is legal on Linux but
    not everywhere this data may be copied to."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


def client_for(uri: str, host: str | None = None) -> MongoClient:
    """A client for the whole set, or -- with `host` -- one connected straight to that member,
    with the credentials and options of the original connection string."""
    if host is None:
        return MongoClient(uri, serverSelectionTimeoutMS=TIMEOUT_MS, appname="mongo-health")
    parsed = uri_parser.parse_uri(uri)
    options = {k: v for k, v in parsed["options"].items()
               if k.lower() not in ("replicaset", "directconnection", "readpreference",
                                    "loadbalanced")}
    return MongoClient(host=host, directConnection=True, username=parsed["username"],
                       password=parsed["password"], serverSelectionTimeoutMS=TIMEOUT_MS,
                       appname="mongo-health", **options)


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
        result["error"] = ("This is a mongos: sharded clusters are not supported yet. Connect "
                           "to each shard's replica set, and the config servers, on their own.")
        return result
    for host in found["members"]:
        row = {"host": host, "ok": False, "version": None, "error": None}
        try:
            with client_for(uri, host) as c:
                row["version"] = c.admin.command("buildInfo").get("version")
                c.admin.command("getDiagnosticData")
                row["ok"] = True
        except Exception as e:
            text = str(e)
            row["error"] = ("the user cannot read diagnostics here — it needs the "
                            "clusterMonitor role" if "not authorized" in text.lower()
                            else f"{type(e).__name__}: {text[:200]}")
        result["members"].append(row)
    result["ok"] = bool(result["members"]) and all(m["ok"] for m in result["members"])
    return result


class MemberPoller(threading.Thread):
    def __init__(self, uri: str, host: str, out: Path, stop: threading.Event, status: dict):
        super().__init__(daemon=True, name=f"poll {host}")
        self.uri, self.host, self.out, self.stop, self.status = uri, host, out, stop, status

    def run(self) -> None:
        client = None
        writer = None
        chunk = FIRST_CHUNK
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                if client is None:
                    client = client_for(self.uri, self.host)
                    writer = ftdcwrite.Writer(self.out, lambda: self._metadata(client))
                raw = client.admin.command("getDiagnosticData", codec_options=RAW)["data"].raw
                writer.add(raw)
                if len(writer.samples) >= chunk:
                    writer.flush()
                    chunk = ftdcwrite.CHUNK_SAMPLES
                self.status[self.host] = {"last_sample": datetime.now(timezone.utc).isoformat(),
                                          "error": None}
            except Exception as e:
                self.status[self.host] = {**self.status.get(self.host, {}),
                                          "error": f"{type(e).__name__}: {str(e)[:200]}"}
                if client is not None:
                    client.close()
                client = None
            self.stop.wait(max(0.0, INTERVAL - (time.monotonic() - started)))
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
    def __init__(self, cluster_id: str, uri: str, data: Path):
        self.cluster_id, self.uri = cluster_id, uri
        self.base = data / cluster_id / "poll"
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
            self.error = "sharded clusters are not supported yet"
            return
        wanted = set(found["members"])
        for host in list(self.members):
            if host not in wanted:
                self.members.pop(host)[1].set()
        for host in wanted - set(self.members):
            stop = threading.Event()
            t = MemberPoller(self.uri, host, self.base / member_dir(host), stop, self.status)
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
            t.join(timeout=INTERVAL * 2)


def targets(config_path: Path) -> dict[str, str]:
    try:
        clusters = config.load_clusters(config_path)
    except config.ConfigError:
        return {}
    return {c["cluster_id"]: c["source"]["uri"] for c in clusters
            if c["source"].get("type") == "mongodb" and c["source"].get("uri")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    args = ap.parse_args()

    running: dict[str, ClusterPoller] = {}
    print(f"polling every {INTERVAL}s; config re-read every {RELOAD_EVERY}s", flush=True)
    while True:
        wanted = targets(args.config)
        for cid in list(running):
            if cid not in wanted or running[cid].uri != wanted[cid]:
                running.pop(cid).stop()
                print(f"[{cid}] stopped", flush=True)
        for cid, uri in wanted.items():
            if cid not in running:
                running[cid] = ClusterPoller(cid, uri, args.data)
                print(f"[{cid}] started", flush=True)
        deadline = time.monotonic() + RELOAD_EVERY
        while time.monotonic() < deadline:
            for p in running.values():
                p.tick()
                p.write_status()
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
