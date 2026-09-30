"""Signing up a cluster: finding it, naming it correctly, and not breaking what is there.

The name is the fragile part. `logCollectionJobs` needs the internal replica set name, and
every obvious place to look for it is wrong: `replicaSetName` on the cluster document comes
back empty, and the hostnames read `…shard-00-00` while the set is `…shard-0`. The only
reliable source is the connection string, and a test that pins that is cheaper than
rediscovering it against a live account.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import onboard  # noqa: E402
from onboard import add_to_config, discover  # noqa: E402

SRV = ("mongodb://cluster0-shard-00-00.abcde.mongodb.net:27017,"
       "cluster0-shard-00-01.abcde.mongodb.net:27017/"
       "?ssl=true&authSource=admin&replicaSet=atlas-pua8zf-shard-0")


class FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload

    def raise_for_status(self):
        pass


def atlas_cluster(name="Cluster0", conn=SRV, tier="M10", autoscale=False,
                  state="IDLE") -> dict:
    return {
        "name": name, "mongoDBVersion": "8.0.29", "stateName": state,
        "connectionStrings": {"standard": conn} if conn else {},
        "providerSettings": {"instanceSizeName": tier, "regionName": "SA_EAST_1"},
        "autoScaling": {"compute": {"enabled": autoscale}},
    }


def stub(monkeypatch, clusters):
    monkeypatch.setattr(onboard.requests, "get",
                        lambda url, **kw: FakeResponse({"results": clusters}))


# ---------------------------------------------------------------------- naming the cluster

def test_replica_set_comes_from_the_connection_string(monkeypatch):
    stub(monkeypatch, [atlas_cluster()])
    found = discover("g", "pub", "priv")
    assert found[0]["replica_set"] == "atlas-pua8zf-shard-0"


def test_the_replica_set_is_not_derived_from_hostnames(monkeypatch):
    """Hostnames say `shard-00-00`; the set is `shard-0`. Deriving it produces a job that fails."""
    stub(monkeypatch, [atlas_cluster()])
    assert discover("g", "pub", "priv")[0]["replica_set"] != "atlas-pua8zf-shard-00"


def test_a_cluster_with_no_connection_string_is_flagged_not_guessed(monkeypatch):
    """M0 free tiers expose none, and cannot be collected from at all.

    Returning None lets the caller skip it with a reason instead of building a broken job.
    """
    stub(monkeypatch, [atlas_cluster(name="sandbox", conn=None, tier="M0")])
    assert discover("g", "pub", "priv")[0]["replica_set"] is None


def test_autoscaling_is_reported(monkeypatch):
    """It contaminates the baseline's first rows, and those cannot be recomputed.

    A read-only key cannot turn it off, so the only thing left is to say it loudly.
    """
    stub(monkeypatch, [atlas_cluster(autoscale=True)])
    assert discover("g", "pub", "priv")[0]["autoscaling"] is True


def test_every_cluster_in_the_project_is_listed(monkeypatch):
    stub(monkeypatch, [atlas_cluster(name="a"), atlas_cluster(name="b")])
    assert [c["name"] for c in discover("g", "pub", "priv")] == ["a", "b"]


def test_a_wrong_project_says_which_call_lists_the_right_one(monkeypatch):
    """401 here almost always means the id came from the console URL, not from the API.

    The raw Atlas error does not say that, and it cost an hour the first time.
    """
    class Unauthorized(FakeResponse):
        status_code = 401

    monkeypatch.setattr(onboard.requests, "get", lambda url, **kw: Unauthorized({}))
    with pytest.raises(RuntimeError, match=r"groups"):
        discover("g", "pub", "priv")


# ----------------------------------------------------------------------------- the config

def test_a_new_customer_is_added(tmp_path: Path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"customers": []}))
    added = add_to_config(cfg, "acme", ["a@x"], "g", "pub", "priv",
                          [{"name": "c1", "replica_set": "rs1"}], 14)
    assert added == 1
    written = json.loads(cfg.read_text())
    assert written["customers"][0]["id"] == "acme"
    assert written["customers"][0]["retention_days"] == 14
    assert written["customers"][0]["clusters"][0]["source"]["replica_set"] == "rs1"


def test_an_existing_customer_keeps_their_clusters(tmp_path: Path):
    """Onboarding a second cluster must not wipe the first."""
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"customers": [
        {"id": "acme", "notify": ["a@x"], "clusters": [{"id": "old", "source": {}}]}]}))
    add_to_config(cfg, "acme", ["a@x"], "g", "pub", "priv",
                  [{"name": "new", "replica_set": "rs2"}], 365)
    ids = [c["id"] for c in json.loads(cfg.read_text())["customers"][0]["clusters"]]
    assert ids == ["old", "new"]


def test_signing_up_the_same_cluster_twice_is_harmless(tmp_path: Path):
    """Re-running onboarding must not duplicate it, or the cron would capture it twice."""
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"customers": []}))
    clusters = [{"name": "c1", "replica_set": "rs1"}]
    add_to_config(cfg, "acme", [], "g", "pub", "priv", clusters, 14)
    added = add_to_config(cfg, "acme", [], "g", "pub", "priv", clusters, 14)
    assert added == 0
    assert len(json.loads(cfg.read_text())["customers"][0]["clusters"]) == 1


def test_the_config_is_not_world_readable(tmp_path: Path):
    """It holds private keys for every customer's project."""
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"customers": []}))
    add_to_config(cfg, "acme", [], "g", "pub", "priv",
                  [{"name": "c1", "replica_set": "rs1"}], 14)
    assert cfg.stat().st_mode & 0o077 == 0, "no access for group or others"


def test_a_missing_config_is_created(tmp_path: Path):
    """First onboarding on a fresh install must not require a file to exist first."""
    cfg = tmp_path / "config.json"
    add_to_config(cfg, "acme", [], "g", "pub", "priv",
                  [{"name": "c1", "replica_set": "rs1"}], 14)
    assert cfg.exists()
