"""FTDC files somebody hands over: unpack them, and work out which member each one belongs to.

The upload on the add page takes whatever is easiest to produce -- a .tar.gz of a
diagnostic.data, a .zip of three of them, a bare metrics file -- and this turns it into one
directory per member, named the way poller.py names the same member. That is what lets files
uploaded once and samples polled from then on land in the same place: one member, one history,
not the same host twice with two baselines.

A member's name is read from the data itself, not from how the archive happens to be laid out:
FTDC samples carry replSetGetStatus, and the member marked `self` is this one, under the name
the replica set knows it by -- the same name `hello` reports, which is what the poller uses.
A standalone falls back to the host name and port in the file's metadata.
"""
from __future__ import annotations

import re
import shutil
import struct
import tarfile
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

import bson

import sources


def member_dir(host: str) -> str:
    """A member's directory name. `db1:27017` -> `db1_27017`: the colon is legal on Linux but
    not everywhere this data may be copied to."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


def _documents(path: Path):
    """The BSON documents of an FTDC file, stopping quietly at a truncated tail."""
    with path.open("rb") as fh:
        try:
            yield from bson.decode_file_iter(fh)
        except Exception:
            return


def _reference(doc: dict) -> dict | None:
    """The reference sample at the start of a metric chunk: plain BSON after the length."""
    try:
        payload = zlib.decompress(bytes(doc["data"])[4:])
        length = struct.unpack_from("<i", payload, 0)[0]
        return bson.decode(payload[:length])
    except Exception:
        return None


def describe(path: Path) -> dict:
    """{member, from, to} for one FTDC file, as far as its contents say."""
    member = None
    first = last = None
    metadata = {}
    for doc in _documents(path):
        if doc.get("type") == 0:
            metadata = doc.get("doc") or {}
        elif doc.get("type") == 1:
            at = doc.get("_id")
            if isinstance(at, datetime):
                at = at.replace(tzinfo=at.tzinfo or timezone.utc)
                first = first or at
                last = at
            if member is None:
                ref = _reference(doc) or {}
                me = [m.get("name") for m in (ref.get("replSetGetStatus") or {}).get("members", [])
                      if m.get("self")]
                member = me[0] if me else None
    if member is None and metadata:
        host = ((metadata.get("hostInfo") or {}).get("system") or {}).get("hostname")
        port = ((((metadata.get("getCmdLineOpts") or {}).get("parsed") or {}).get("net") or {})
                .get("port", 27017))
        member = f"{host}:{port}" if host else None
    return {"member": member, "from": first, "to": last}


def _unpack(archive: Path, into: Path) -> None:
    """Whatever arrived, as files under `into`: a zip, a tar in any compression, or a single
    FTDC file. Nothing is allowed to land outside `into`."""
    into.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(archive):
        root = into.resolve()
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                dest = (root / info.filename).resolve()
                if dest != root and root not in dest.parents:
                    raise ValueError(f"refusing {info.filename!r}: it points outside the upload")
                if not info.is_dir():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(info) as src, dest.open("wb") as out:
                        shutil.copyfileobj(src, out)
        return
    if tarfile.is_tarfile(archive):
        with tarfile.open(archive) as t:
            sources.extract(t, into)
        return
    # Not an archive: a bare metrics file, if it reads as one.
    if describe(archive)["from"] is None:
        raise ValueError("this is neither an archive nor an FTDC file")
    shutil.copy(archive, into / "metrics.uploaded-00000")


def receive(archive: Path, staging: Path) -> list[dict]:
    """Unpack an upload into `staging/<member>/`, and say what was found, member by member."""
    raw = staging / "raw"
    _unpack(archive, raw)
    found: dict[str, dict] = {}
    files = [p for p in raw.rglob("metrics.*") if p.is_file()]
    if not files:
        raise ValueError("no FTDC files in it — it needs the metrics.* files from a "
                         "diagnostic.data directory")
    for path in files:
        info = describe(path)
        if info["from"] is None:
            continue
        name = info["member"] or path.parent.name
        target = staging / "members" / member_dir(name)
        target.mkdir(parents=True, exist_ok=True)
        # Two members' files can share a name -- they are named by time -- so a clash keeps both.
        dest = target / path.name
        if dest.exists():
            dest = target / f"{path.name}.{len(list(target.iterdir()))}"
        shutil.move(str(path), dest)
        entry = found.setdefault(name, {"member": name, "files": 0, "bytes": 0,
                                        "from": info["from"], "to": info["to"]})
        entry["files"] += 1
        entry["bytes"] += dest.stat().st_size
        entry["from"] = min(entry["from"], info["from"])
        entry["to"] = max(entry["to"], info["to"])
    shutil.rmtree(raw, ignore_errors=True)
    if not found:
        raise ValueError("the metrics files in it could not be read as FTDC")
    return sorted(found.values(), key=lambda e: e["member"])


def adopt(staging: Path, incoming: Path) -> None:
    """Move received members into a cluster's incoming directory, next to what the poller
    writes for the same members.

    A file already there is replaced when the new copy is larger, or is `metrics.interim`.
    mongod keeps appending to its newest file, so a second upload carries the same name with
    more in it -- and keeping the first copy dropped exactly the hours the upload was for.
    """
    members = staging / "members"
    for member in (members.iterdir() if members.exists() else []):
        target = incoming / member.name
        target.mkdir(parents=True, exist_ok=True)
        for f in member.iterdir():
            dest = target / f.name
            if (not dest.exists() or f.name == "metrics.interim"
                    or f.stat().st_size > dest.stat().st_size):
                shutil.move(str(f), dest)
    shutil.rmtree(staging, ignore_errors=True)


def members_of(base: Path) -> set[str]:
    """The members a cluster already holds files for, by directory name."""
    return {d.name for sub in ("ftdc", "incoming") if (base / sub).is_dir()
            for d in (base / sub).iterdir() if d.is_dir()}
