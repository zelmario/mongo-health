"""The poller: how often each cluster is read, and what each read costs on the wire."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config  # noqa: E402
import poller  # noqa: E402


def write(tmp_path, clusters) -> Path:
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"clusters": clusters}))
    return cfg


def test_each_cluster_is_read_at_its_own_interval(tmp_path):
    cfg = write(tmp_path, [
        {"id": "fast", "source": {"type": "onprem", "uri": "mongodb://a/", "interval": 1}},
        {"id": "usual", "source": {"type": "onprem", "uri": "mongodb://b/"}},
        {"id": "files", "source": {"type": "onprem"}},
    ])
    assert poller.targets(cfg) == {"fast": ("mongodb://a/", 1), "usual": ("mongodb://b/", 10)}


def test_a_chunk_holds_five_minutes_whatever_the_interval():
    """At one a second, thirty samples a chunk was a file written every thirty seconds."""
    assert poller.chunk_for(1) == 300
    assert poller.chunk_for(5) == 60
    assert poller.chunk_for(10) == 30


@pytest.fixture
def clients(monkeypatch):
    made = []
    monkeypatch.setattr(poller, "MongoClient", lambda *a, **kw: made.append(kw) or object())
    return made


def test_every_connection_asks_for_compression(clients):
    """221 KB a sample in BSON, 33 KB compressed: measured on a PSMDB 8.0 replica set."""
    poller.client_for("mongodb://u:p@db1,db2/?replicaSet=rs0")
    poller.client_for("mongodb://u:p@db1,db2/?replicaSet=rs0", "db2:27017")
    assert [kw.get("compressors") for kw in clients] == ["zlib", "zlib"]


def test_a_uri_that_names_its_compressors_keeps_them(clients):
    poller.client_for("mongodb://u:p@db1/?compressors=zlib&zlibCompressionLevel=9", "db1:27017")
    assert clients[0]["compressors"] == ["zlib"] and clients[0]["zlibcompressionlevel"] == 9


def test_an_interval_outside_one_to_sixty_seconds_is_refused(tmp_path):
    cfg = write(tmp_path, [{"id": "x", "source": {"type": "onprem", "uri": "mongodb://a/",
                                                  "interval": 0}}])
    with pytest.raises(config.ConfigError, match="interval"):
        config.load(cfg)
