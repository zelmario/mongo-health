"""The configuration file: one reader, strict, and the defaults it applies."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config  # noqa: E402
from config import ConfigError  # noqa: E402

EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.json"


def write(tmp: Path, cfg: dict) -> Path:
    path = tmp / "config.json"
    path.write_text(json.dumps(cfg))
    return path


def atlas(**extra) -> dict:
    return {"type": "atlas", "group_id": "g", "replica_set": "rs0", **extra}


@pytest.fixture(autouse=True)
def no_secrets_in_the_environment(monkeypatch):
    for name in ("ATLAS_PUBLIC_KEY", "ATLAS_PRIVATE_KEY", "SMTP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------------------ what is accepted

def test_the_example_is_a_valid_config():
    """The file people copy first must load, or the first thing they see is a traceback."""
    ids = [c["cluster_id"] for c in config.load_clusters(EXAMPLE)]
    assert ids == ["orders-prod", "rs-staging"]


def test_a_missing_file_says_what_to_do(tmp_path):
    with pytest.raises(ConfigError, match="config.example.json"):
        config.load(tmp_path / "config.json")


def test_broken_json_is_a_config_error(tmp_path):
    (tmp_path / "config.json").write_text("{")
    with pytest.raises(ConfigError, match="not valid JSON"):
        config.load(tmp_path / "config.json")


def test_clusters_are_required(tmp_path):
    with pytest.raises(ConfigError, match='"clusters"'):
        config.load(write(tmp_path, {"notify": []}))


@pytest.mark.parametrize("bad", ["", "../etc", "a/b", ".hidden", "x" * 64, 7, None])
def test_a_cluster_id_must_be_safe_as_a_directory(tmp_path, bad):
    """It becomes a directory under data/: a slash or a leading dot must not get that far."""
    with pytest.raises(ConfigError, match='"id"'):
        config.load(write(tmp_path, {"clusters": [{"id": bad, "source": atlas()}]}))


def test_a_cluster_id_used_twice_is_refused(tmp_path):
    """Two clusters with one id would share a data directory and overwrite each other's state."""
    cfg = {"clusters": [{"id": "a", "source": atlas()}, {"id": "a", "source": atlas()}]}
    with pytest.raises(ConfigError, match="used twice"):
        config.load(write(tmp_path, cfg))


def test_a_cluster_without_a_source_is_refused(tmp_path):
    with pytest.raises(ConfigError, match='"source"'):
        config.load(write(tmp_path, {"clusters": [{"id": "a"}]}))


# --------------------------------------------------------------------------- the defaults

def test_a_cluster_inherits_the_top_level_settings(tmp_path):
    cfg = {"notify": ["team@x"], "retention_days": 120, "clusters": [{"id": "a", "source": atlas()}]}
    (c,) = config.load_clusters(write(tmp_path, cfg))
    assert c["notify"] == ["team@x"]
    assert c["retention_days"] == 120
    assert c["mute"] == []


def test_a_cluster_can_override_them(tmp_path):
    """Regression: the old loader dropped a cluster's own retention_days, so the example's
    promise that it could be set per cluster was false and every cluster got the global one."""
    cfg = {"notify": ["team@x"], "retention_days": 120, "clusters": [
        {"id": "a", "source": atlas(), "notify": ["a@x"], "retention_days": 30,
         "mute": ["connection-storm"]}]}
    (c,) = config.load_clusters(write(tmp_path, cfg))
    assert c["notify"] == ["a@x"]
    assert c["retention_days"] == 30
    assert c["mute"] == ["connection-storm"]


def test_retention_has_a_default(tmp_path):
    (c,) = config.load_clusters(write(tmp_path, {"clusters": [{"id": "a", "source": atlas()}]}))
    assert c["retention_days"] == config.DEFAULT_RETENTION_DAYS


# ------------------------------------------------------------------------------- secrets

def test_atlas_keys_can_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_PUBLIC_KEY", "envpub")
    monkeypatch.setenv("ATLAS_PRIVATE_KEY", "envpriv")
    (c,) = config.load_clusters(write(tmp_path, {"clusters": [{"id": "a", "source": atlas()}]}))
    assert (c["source"]["public_key"], c["source"]["private_key"]) == ("envpub", "envpriv")


def test_a_key_in_the_file_wins_over_the_environment(tmp_path, monkeypatch):
    """Two projects need two keys; the environment can only hold one."""
    monkeypatch.setenv("ATLAS_PUBLIC_KEY", "envpub")
    monkeypatch.setenv("ATLAS_PRIVATE_KEY", "envpriv")
    source = atlas(public_key="filepub", private_key="filepriv")
    (c,) = config.load_clusters(write(tmp_path, {"clusters": [{"id": "a", "source": source}]}))
    assert c["source"]["public_key"] == "filepub"


def test_a_directory_source_gets_no_atlas_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_PUBLIC_KEY", "envpub")
    cfg = {"clusters": [{"id": "a", "source": {"type": "directory", "path": "/x"}}]}
    (c,) = config.load_clusters(write(tmp_path, cfg))
    assert "public_key" not in c["source"]


def test_the_smtp_password_can_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "envsecret")
    assert config.smtp({"smtp": {"host": "h"}})["password"] == "envsecret"
    assert config.smtp({"smtp": {"host": "h", "password": "file"}})["password"] == "file"
    assert config.smtp({}) is None
