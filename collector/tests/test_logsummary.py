"""The mongod log, read for its slow queries: shapes kept, values and lines never."""
from __future__ import annotations

import gzip
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import logsummary  # noqa: E402


def line(at: str, attr: dict, id_=51803, msg="Slow query") -> str:
    return json.dumps({"t": {"$date": at}, "s": "I", "c": "COMMAND", "id": id_,
                       "ctx": "conn1", "msg": msg, "attr": attr}, separators=(",", ":"))


STARTING = line("2026-10-01T16:28:43.727+00:00",
                {"pid": 1, "port": 27017, "host": "db1.example.net"}, 4615611, "MongoDB starting")


def scan(at: str, **over) -> str:
    attr = {"type": "command", "ns": "shop.orders", "appName": "nightly-sync",
            "command": {"find": "orders", "filter": {"status": "open", "total": {"$gt": 100}},
                        "$db": "shop", "$readPreference": {"mode": "secondary"}},
            "planSummary": "COLLSCAN", "keysExamined": 0, "docsExamined": 20_000,
            "nreturned": 3, "durationMillis": 900}
    attr.update(over)
    return line(at, attr)


def write(tmp: Path, lines: list[str], gz: bool = False) -> Path:
    path = tmp / ("mongod.log.gz" if gz else "mongod.log")
    text = "\n".join(lines) + "\n"
    if gz:
        with gzip.open(path, "wt") as fh:
            fh.write(text)
    else:
        path.write_text(text)
    return path


def test_a_filter_keeps_its_fields_and_operators_and_drops_its_values():
    assert logsummary.shape({"status": "open", "total": {"$gt": 100}, "email": "a@b.c"}) == \
        "{email, status, total ($gt)}"
    assert logsummary.shape({"$or": [{"a": 1}, {"b": {"$in": [1, 2]}}]}) == \
        "{$or: [{a}, {b ($in)}]}"


def test_slow_queries_are_grouped_by_minute_and_shape(tmp_path):
    log = write(tmp_path, [STARTING, scan("2026-10-01T20:58:15.000+00:00"),
                           scan("2026-10-01T20:58:40.000+00:00", durationMillis=1600),
                           scan("2026-10-01T20:59:05.000+00:00")], gz=True)
    s = logsummary.summarize(log)
    assert s["member"] == "db1" and s["slow"] == 3
    first = s["rows"][0]
    assert (first["ns"], first["op"], first["shape"], first["plan"]) == \
        ("shop.orders", "find", "{status, total ($gt)}", "COLLSCAN")
    assert first["n"] == 2 and first["docs"] == 40_000 and first["maxms"] == 1600
    assert first["apps"] == ["nightly-sync"] and first["rp"] == ["secondary"]
    assert "open" not in json.dumps(s), "no value from a filter survives"


def test_the_servers_own_work_and_oplog_tailing_are_not_the_applications():
    assert logsummary.describe({"isFromUserConnection": False, "ns": "config.system.sessions",
                                "command": {"createIndexes": "x"}}) is None
    assert logsummary.describe({"ns": "local.oplog.rs", "command": {"getMore": 1}}) is None
    assert logsummary.describe({"ns": "admin.$cmd", "command": {"replSetGetStatus": 1}}) is None


def test_a_getmore_is_shaped_by_the_query_that_opened_it():
    op, shape = logsummary.describe({"ns": "shop.orders", "command": {"getMore": 5},
                                     "originatingCommand": {"find": "orders",
                                                            "filter": {"sku": "x"}}})
    assert (op, shape) == ("getMore of find", "{sku}")


def test_an_aggregation_is_shaped_by_its_stages():
    op, shape = logsummary.describe({"ns": "shop.orders", "command": {
        "aggregate": "orders", "pipeline": [{"$match": {"status": "open"}}, {"$group": {}},
                                            {"$sort": {"n": -1}}]}})
    assert (op, shape) == ("aggregate", "$match {status} | $group | $sort")


def test_a_longer_copy_of_the_same_log_replaces_itself(tmp_path):
    lines = [STARTING, scan("2026-10-01T20:58:15.000+00:00")]
    first = logsummary.store(logsummary.summarize(write(tmp_path, lines)), tmp_path / "logs", "a")
    lines.append(scan("2026-10-01T21:10:00.000+00:00"))
    again = logsummary.store(logsummary.summarize(write(tmp_path, lines)), tmp_path / "logs", "a")
    assert first == again and len(logsummary.held(tmp_path / "logs")) == 1


def test_an_incident_sees_its_members_and_its_window_only(tmp_path):
    log = write(tmp_path, [STARTING, scan("2026-10-01T20:58:15.000+00:00"),
                           scan("2026-10-01T23:00:00.000+00:00")])
    held = [logsummary.summarize(log)]
    at = lambda h, m: int(datetime(2026, 10, 1, h, m, tzinfo=timezone.utc).timestamp() * 1000)  # noqa: E731
    rows = logsummary.during(held, {"db1"}, at(20, 58), at(21, 0))
    assert len(rows) == 1 and rows[0]["n"] == 1
    assert logsummary.during(held, {"db2"}, at(20, 58), at(21, 0)) == []


def test_only_structured_logs_are_logs(tmp_path):
    assert logsummary.is_log(write(tmp_path, [STARTING]))
    (tmp_path / "notes.txt").write_text("hello\n")
    assert not logsummary.is_log(tmp_path / "notes.txt")


def test_a_log_taken_from_syslog_or_journald_is_read_through_its_prefix(tmp_path):
    """How a real support bundle's 2.6 GB log arrived: every line behind a syslog prefix."""
    prefix = "Jul 15 06:52:31 ip-172-19-100-152.eu-west-1.compute.internal mongo[3731]: "
    log = write(tmp_path, [prefix + STARTING, prefix + scan("2026-10-01T20:58:15.000+00:00")])
    assert logsummary.is_log(log)
    s = logsummary.summarize(log)
    assert s["member"] == "db1" and s["slow"] == 1


def test_a_change_stream_is_named_as_one_not_as_a_scanning_aggregate():
    op, shape = logsummary.describe({"ns": "zero.customers", "command": {"getMore": 1},
                                     "originatingCommand": {"aggregate": "customers", "pipeline": [
                                         {"$_internalChangeStreamOplogMatch": {}},
                                         {"$_internalChangeStreamUnwindTransaction": {}}]}})
    assert (op, shape) == ("getMore of change stream", "")
