"""Write real FTDC from the samples getDiagnosticData returns.

`getDiagnosticData` hands back, over the wire, the very document mongod writes to its own FTDC
every second. Writing those documents out as FTDC files -- the same format, readable by the same
decoder -- is what lets a cluster connected by connection string go through capture, analysis
and the report exactly like one whose files are read from disk. Nothing downstream has to know
where the samples came from.

The format, as the Big Hole decoder reads it (big-hole/docs/ftdc-format.md):

    file    = metadata document (type 0), then metric chunks (type 1), concatenated BSON
    chunk   = {_id: start time, type: 1, data: binary}
    data    = uint32 uncompressed length, then zlib( reference sample BSON
                                                    uint32 metrics count
                                                    uint32 deltas count
                                                    deltas: uvarint, column by column )

Three things that are easy to get wrong, all mirrored from big-hole/src/ftdc/flatten.ts:

  - doubles are delta-encoded as their IEEE-754 bit pattern, not their value;
  - a BSON Timestamp is TWO columns: seconds * 1000, then `<key>.inc`;
  - deltas are unsigned varints holding a wrapped signed int64 (no zigzag), and a zero delta
    is followed by the count of further zeros.

The sample is walked as the raw BSON the server sent, not as decoded Python values: a Python
int does not remember whether it was an int32 or an int64, and the type of each column is part
of the format.
"""
from __future__ import annotations

import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

import bson
from bson.binary import Binary

MASK = (1 << 64) - 1

# Samples per chunk. mongod uses 300 at one a second; at one every ten seconds, 30 is five
# minutes -- the most a capture can lag behind the poller, since a chunk reaches the file whole.
CHUNK_SAMPLES = 30

# A new file, with fresh metadata, after this long or this size. mongod rotates at 10 MB.
FILE_SECONDS = 6 * 3600
FILE_BYTES = 10 * 1024 * 1024


# ------------------------------------------------------------------ reading raw BSON

def _cstring(b: bytes, p: int) -> tuple[str, int]:
    end = b.index(b"\x00", p)
    return b[p:end].decode("utf-8", "replace"), end + 1


def _value_size(b: bytes, t: int, p: int) -> int:
    if t in (0x01, 0x09, 0x11, 0x12):          # double, datetime, timestamp, int64
        return 8
    if t == 0x10:                               # int32
        return 4
    if t == 0x08:                               # bool
        return 1
    if t in (0x06, 0x0A, 0x7F, 0xFF):           # undefined, null, max/min key
        return 0
    if t == 0x07:                               # ObjectId
        return 12
    if t == 0x13:                               # Decimal128
        return 16
    if t in (0x02, 0x0D, 0x0E):                 # string, code, symbol
        return 4 + struct.unpack_from("<i", b, p)[0]
    if t in (0x03, 0x04, 0x0F):                 # document, array, code with scope
        return struct.unpack_from("<i", b, p)[0]
    if t == 0x05:                               # binary
        return 4 + 1 + struct.unpack_from("<i", b, p)[0]
    if t == 0x0B:                               # regex: two cstrings
        _, q = _cstring(b, p)
        _, q = _cstring(b, q)
        return q - p
    if t == 0x0C:                               # DBPointer
        return 4 + struct.unpack_from("<i", b, p)[0] + 12
    raise ValueError(f"unknown BSON type 0x{t:02x} at offset {p}")


def _walk(b: bytes, t: int, p: int, key: str, out: list) -> None:
    """Append (key, type, uint64 value) for every metric under this value, in document order."""
    if t == 0x01:
        out.append((key, "double", struct.unpack_from("<Q", b, p)[0]))
    elif t == 0x10:
        out.append((key, "int32", struct.unpack_from("<i", b, p)[0] & MASK))
    elif t == 0x12:
        out.append((key, "int64", struct.unpack_from("<Q", b, p)[0]))
    elif t == 0x09:
        out.append((key, "datetime", struct.unpack_from("<Q", b, p)[0]))
    elif t == 0x08:
        out.append((key, "bool", 1 if b[p] == 1 else 0))
    elif t == 0x11:
        inc, seconds = struct.unpack_from("<II", b, p)
        out.append((key, "int64", seconds * 1000))
        out.append((f"{key}.inc", "int64", inc))
    elif t == 0x03:
        _walk_document(b, p, key, out)
    elif t == 0x04:
        end = p + struct.unpack_from("<i", b, p)[0]
        q, idx = p + 4, 0
        while q < end - 1:
            et = b[q]
            _, q = _cstring(b, q + 1)
            _walk(b, et, q, f"{key}.{idx}", out)
            q += _value_size(b, et, q)
            idx += 1


def _walk_document(b: bytes, start: int, prefix: str, out: list) -> None:
    end = start + struct.unpack_from("<i", b, start)[0]
    p = start + 4
    while p < end - 1:
        t = b[p]
        key, p = _cstring(b, p + 1)
        _walk(b, t, p, f"{prefix}.{key}" if prefix else key, out)
        p += _value_size(b, t, p)


def flatten(raw: bytes) -> list[tuple[str, str, int]]:
    out: list = []
    _walk_document(raw, 0, "", out)
    return out


# ------------------------------------------------------------------------ encoding

def _uvarint(n: int, out: bytearray) -> None:
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return


def encode_chunk(reference: bytes, samples: list[list[int]], start: datetime) -> bytes:
    """One type-1 chunk document. `samples[0]` is the reference sample's own values."""
    columns = len(samples[0])
    deltas = bytearray()
    for m in range(columns):
        j = 1
        while j < len(samples):
            d = (samples[j][m] - samples[j - 1][m]) & MASK
            if d == 0:
                run = 1
                while j + run < len(samples) and samples[j + run][m] == samples[j + run - 1][m]:
                    run += 1
                _uvarint(0, deltas)
                _uvarint(run - 1, deltas)
                j += run
            else:
                _uvarint(d, deltas)
                j += 1
    payload = reference + struct.pack("<II", columns, len(samples) - 1) + bytes(deltas)
    data = struct.pack("<I", len(payload)) + zlib.compress(payload)
    return bson.encode({"_id": start, "type": 1, "data": Binary(data)})


def encode_metadata(doc: dict, at: datetime) -> bytes:
    return bson.encode({"_id": at, "type": 0, "doc": doc})


# ---------------------------------------------------------------------- the writer

class Writer:
    """Samples in, FTDC files out, for one member.

    A chunk holds samples with the same schema -- the same metrics, of the same types, in the
    same order. When the schema changes (a collection appears in the oplog stats, a counter
    grows past int32) the chunk is closed and a new one starts, which is what mongod does too.
    """

    def __init__(self, directory: Path, metadata, clock=lambda: datetime.now(timezone.utc),
                 chunk_samples: int = CHUNK_SAMPLES):
        self.directory = Path(directory)
        self.chunk_samples = chunk_samples
        self.metadata = metadata      # called at every new file: buildInfo, hostInfo...
        self.clock = clock
        self.path: Path | None = None
        self.opened: datetime | None = None
        self.reference: bytes | None = None
        self.schema: list[tuple[str, str]] | None = None
        self.samples: list[list[int]] = []
        self.started: datetime | None = None

    def add(self, raw: bytes) -> None:
        flat = flatten(raw)
        schema = [(k, t) for k, t, _ in flat]
        if self.schema is not None and schema != self.schema:
            self.flush()
        if self.schema is None:
            self.reference, self.schema, self.started = raw, schema, self.clock()
        self.samples.append([v for _, _, v in flat])
        if len(self.samples) >= self.chunk_samples:
            self.flush()

    def flush(self) -> None:
        if not self.samples:
            return
        chunk = encode_chunk(self.reference, self.samples, self.started)
        now = self.clock()
        if (self.path is None or not self.path.exists()
                or (now - self.opened).total_seconds() >= FILE_SECONDS
                or self.path.stat().st_size + len(chunk) > FILE_BYTES):
            self._new_file(now, self.started)
        # One write of a whole document: a reader can see a file end mid-chunk only while the
        # write is in flight, and the decoder treats a truncated tail as normal.
        with self.path.open("ab") as fh:
            fh.write(chunk)
        self.samples, self.reference, self.schema, self.started = [], None, None, None

    def _new_file(self, now: datetime, first: datetime) -> None:
        # Named for its first sample, as mongod names its files: the capture reads that name as
        # when the file begins.
        self.directory.mkdir(parents=True, exist_ok=True)
        name = "metrics." + first.strftime("%Y-%m-%dT%H-%M-%SZ") + "-00000"
        self.path = self.directory / name
        self.opened = now
        self.path.write_bytes(encode_metadata(self.metadata(), now))
