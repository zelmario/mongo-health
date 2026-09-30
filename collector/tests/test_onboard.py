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
import config  # noqa: E402
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

KEYS = {"public_key": "pub", "private_key": "priv"}


def test_a_cluster_is_added(tmp_path: Path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"clusters": []}))
    added = add_to_config(cfg, ["a@x"], "g", [{"name": "c1", "replica_set": "rs1"}], KEYS)
    assert added == 1
    written = json.loads(cfg.read_text())
    assert written["notify"] == ["a@x"]
    assert written["clusters"][0]["id"] == "c1"
    assert written["clusters"][0]["source"]["replica_set"] == "rs1"


def test_what_onboarding_writes_is_a_valid_config(tmp_path: Path):
    """The file has one reader, and it is strict; the writer must not be looser than it."""
    cfg = tmp_path / "config.json"
    add_to_config(cfg, ["a@x"], "g", [{"name": "c1", "replica_set": "rs1"}], KEYS)
    assert [c["cluster_id"] for c in config.load_clusters(cfg)] == ["c1"]


def test_keys_from_the_environment_stay_out_of_the_file(tmp_path: Path):
    """Somebody who put the key in the environment chose not to have it on disk."""
    cfg = tmp_path / "config.json"
    add_to_config(cfg, [], "g", [{"name": "c1", "replica_set": "rs1"}], None)
    source = json.loads(cfg.read_text())["clusters"][0]["source"]
    assert "public_key" not in source and "private_key" not in source


def test_existing_clusters_and_settings_are_kept(tmp_path: Path):
    """Onboarding a second cluster must not wipe the first, nor who is notified."""
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"notify": ["first@x"], "clusters": [{"id": "old", "source": {}}]}))
    add_to_config(cfg, ["second@x"], "g", [{"name": "new", "replica_set": "rs2"}], KEYS)
    written = json.loads(cfg.read_text())
    assert [c["id"] for c in written["clusters"]] == ["old", "new"]
    assert written["notify"] == ["first@x"]


def test_signing_up_the_same_cluster_twice_is_harmless(tmp_path: Path):
    """Re-running onboarding must not duplicate it, or the cron would capture it twice."""
    cfg = tmp_path / "config.json"
    clusters = [{"name": "c1", "replica_set": "rs1"}]
    add_to_config(cfg, [], "g", clusters, KEYS)
    added = add_to_config(cfg, [], "g", clusters, KEYS)
    assert added == 0
    assert len(json.loads(cfg.read_text())["clusters"]) == 1


def test_the_config_is_not_world_readable(tmp_path: Path):
    """It can hold the private key."""
    cfg = tmp_path / "config.json"
    add_to_config(cfg, [], "g", [{"name": "c1", "replica_set": "rs1"}], KEYS)
    assert cfg.stat().st_mode & 0o077 == 0, "no access for group or others"


def test_onboarding_ends_with_the_first_evaluation(tmp_path, monkeypatch, capsys):
    """The last thing on screen after onboarding is the answer, not a path to a file."""
    import onboard

    monkeypatch.setenv("ATLAS_PUBLIC_KEY", "pub")
    monkeypatch.setenv("ATLAS_PRIVATE_KEY", "priv")
    monkeypatch.setattr(onboard, "discover", lambda *a: [
        {"name": "c1", "replica_set": "rs1", "tier": "M10", "version": "8.0",
         "state": "IDLE", "autoscaling": False}])
    # Capture and analysis are their own programs with their own tests; here they succeed
    # and leave nothing behind, which is a cluster with nothing captured yet.
    monkeypatch.setattr(onboard, "run", lambda cmd, quiet: True)
    monkeypatch.setattr(sys, "argv", ["onboard", "--config", str(tmp_path / "config.json"),
                                      "--data", str(tmp_path / "data"),
                                      "--site", str(tmp_path / "site"), "--group-id", "g"])
    assert onboard.main() == 0
    out = capsys.readouterr().out
    assert "c1: Not being watched" in out
    assert (tmp_path / "site" / "c1" / "index.html").exists()
