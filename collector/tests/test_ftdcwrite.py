"""FTDC written from getDiagnosticData samples must read back exactly, through the real decoder."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bson
import pytest
from bson.int64 import Int64
from bson.timestamp import Timestamp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ftdcwrite  # noqa: E402

T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
BIGHOLE = Path(__file__).resolve().parents[2] / "big-hole"


def sample(i: int, **extra) -> bytes:
    """A sample shaped like getDiagnosticData's: nested documents, arrays, every numeric type."""
    return bson.encode({
        "start": T0 + timedelta(seconds=10 * i),
        "serverStatus": {
            "host": "db1",                              # a string: no column
            "uptimeMillis": Int64(1_000_000 + 10_000 * i),
            "connections": {"current": 40 + (i % 3)},    # int32
            "opLatencies": {"reads": {"latency": Int64(5 * i)}},
            "wiredTiger": {"cache": {"fill ratio": 0.25 + i / 1000}},   # double
            "ok": True,
        },
        "replSetGetStatus": {
            "members": [{"optime": {"ts": Timestamp(1_790_000_000 + i, i % 5)}},
                        {"optime": {"ts": Timestamp(1_790_000_000 + i, 0)}}],
        },
        **extra,
    })


# --------------------------------------------------------------------- flattening

def test_columns_follow_the_ftdc_rules():
    cols = {k: t for k, t, _ in ftdcwrite.flatten(sample(0))}
    assert "serverStatus.host" not in cols, "strings carry no metric"
    assert cols["serverStatus.uptimeMillis"] == "int64"
    assert cols["serverStatus.connections.current"] == "int32"
    assert cols["serverStatus.wiredTiger.cache.fill ratio"] == "double"
    assert cols["serverStatus.ok"] == "bool"
    assert cols["start"] == "datetime"
    # A Timestamp is two columns, and forgetting the second shifts every column after it.
    assert "replSetGetStatus.members.0.optime.ts" in cols
    assert "replSetGetStatus.members.0.optime.ts.inc" in cols
    assert "replSetGetStatus.members.1.optime.ts.inc" in cols


def test_a_timestamp_is_seconds_in_milliseconds_then_the_increment():
    values = {k: v for k, _, v in ftdcwrite.flatten(sample(3))}
    assert values["replSetGetStatus.members.0.optime.ts"] == (1_790_000_003) * 1000
    assert values["replSetGetStatus.members.0.optime.ts.inc"] == 3


def test_a_double_is_carried_as_its_bit_pattern():
    import struct
    values = {k: v for k, _, v in ftdcwrite.flatten(sample(0))}
    bits = values["serverStatus.wiredTiger.cache.fill ratio"]
    assert struct.unpack("<d", struct.pack("<Q", bits))[0] == 0.25


def test_a_negative_int32_wraps_to_its_64_bit_pattern():
    values = {k: v for k, _, v in ftdcwrite.flatten(bson.encode({"x": -1}))}
    assert values["x"] == (1 << 64) - 1


# ------------------------------------------------------------------------ writing

def write(tmp: Path, samples: list[bytes]) -> Path:
    clock = iter(T0 + timedelta(seconds=10 * i) for i in range(10_000))
    w = ftdcwrite.Writer(tmp / "db1", lambda: {"hostInfo": {"system": {"hostname": "db1"}},
                                               "buildInfo": {"version": "8.0.3"}},
                         clock=lambda: next(clock))
    for s in samples:
        w.add(s)
    w.flush()
    return next((tmp / "db1").iterdir())


def documents(path: Path) -> list[dict]:
    return list(bson.decode_file_iter(path.open("rb")))


def test_a_file_starts_with_metadata_then_chunks(tmp_path):
    docs = documents(write(tmp_path, [sample(i) for i in range(40)]))
    assert docs[0]["type"] == 0 and docs[0]["doc"]["buildInfo"]["version"] == "8.0.3"
    assert [d["type"] for d in docs[1:]] == [1, 1], "30 samples, then the other 10"


def test_a_change_of_schema_starts_a_new_chunk(tmp_path):
    samples = [sample(0), sample(1), sample(2, extra={"new": 1}), sample(3, extra={"new": 2})]
    docs = documents(write(tmp_path, samples))
    assert [d["type"] for d in docs] == [0, 1, 1]


def test_the_file_is_named_like_mongods(tmp_path):
    path = write(tmp_path, [sample(0)])
    assert path.name == "metrics.2026-09-30T12-00-00Z-00000"


# ------------------------------------------------------- through the real decoder

DECODE = """
import { readFileSync } from 'node:fs';
import { decodeFTDC, readMetadata } from '../src/ftdc/index.js';
const bytes = new Uint8Array(readFileSync(process.argv[2]));
const out: Record<string, number[]> = {};
for (const c of decodeFTDC(bytes))
  c.keys.forEach((k, i) => (out[k] ??= []).push(...Array.from(c.columns[i]!)));
console.log(JSON.stringify({ meta: readMetadata(bytes)?.hostname, out }));
"""


@pytest.mark.skipif(shutil.which("npx") is None or not (BIGHOLE / "node_modules").exists(),
                    reason="needs the engine installed to decode with it")
def test_what_is_written_decodes_to_the_same_values(tmp_path):
    """The only test that matters in the end: the decoder the analysis uses reads back exactly
    what was sampled, column for column, across chunk boundaries and zero runs."""
    samples = [sample(i) for i in range(45)]
    path = write(tmp_path, samples)
    script = BIGHOLE / "tools" / "_decode_test.ts"
    script.write_text(DECODE)
    try:
        r = subprocess.run(["npx", "vite-node", str(script), "--", str(path)], cwd=BIGHOLE,
                           capture_output=True, text=True, timeout=180)
    finally:
        script.unlink()
    got = json.loads(r.stdout.strip().splitlines()[-1])
    assert got["meta"] == "db1"
    import struct
    for key, kind, _ in ftdcwrite.flatten(samples[0]):
        expected = [dict((k, v) for k, _, v in ftdcwrite.flatten(s))[key] for s in samples]
        if kind == "double":
            expected = [struct.unpack("<d", struct.pack("<Q", v))[0] for v in expected]
        elif kind == "int32":
            expected = [v - (1 << 64) if v >= 1 << 63 else v for v in expected]
        assert got["out"][key] == expected, key
