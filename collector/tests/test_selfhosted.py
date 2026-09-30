"""Capturing from a customer's own servers rather than from Atlas.

The Atlas path is the one that gets exercised daily, so it is the one that stays working by
accident. This one has to be held in place deliberately: a self-hosted customer is a customer
whose data never touches an Atlas API, and everything downstream — decode, rules, baseline,
reports — has to be reached the same way.

Verified end to end by hand against a real mongod 8.0 capture and against a three-node set laid
out as `host/27017/diagnostic.data`; these keep the parts of that which can run in a second.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capture import capture_cluster  # noqa: E402
from sources import SSHSource, build  # noqa: E402

# A real diagnostic.data directory to read; the test skips without one.
SAMPLE = Path(os.environ.get("BIGHOLE_SAMPLE_FTDC", "/nonexistent"))


def spec(path: Path, node: str | None = None) -> dict:
    source = {"type": "directory", "path": str(path)}
    if node:
        source["node"] = node
    return {"customer_id": "acme", "cluster_id": "own", "notify": [], "source": source}


# ------------------------------------------------------------------ the directory path

@pytest.mark.skipif(not SAMPLE.exists(), reason="no local mongod capture to read")
def test_a_local_diagnostic_data_is_captured_like_any_other(tmp_path):
    """No Atlas anywhere: a directory on disk, and the same files land in the same layout."""
    result = capture_cluster(spec(SAMPLE, "mongo-prod-1.acme.internal"), tmp_path)

    assert result["files_new"] >= 1
    stored = list((tmp_path / "acme" / "own" / "ftdc").rglob("metrics.*"))
    assert stored, "nothing was written where the analyser will look for it"
    assert all(p.stat().st_size > 0 for p in stored)


@pytest.mark.skipif(not SAMPLE.exists(), reason="no local mongod capture to read")
def test_capturing_twice_brings_nothing_new(tmp_path):
    """The incremental logic is the source's, not Atlas's — a directory must honour it too."""
    capture_cluster(spec(SAMPLE), tmp_path)
    again = capture_cluster(spec(SAMPLE), tmp_path)
    assert again["files_new"] == 0


def test_a_replica_set_is_one_directory_per_member(tmp_path):
    """What a customer hands over: one directory per host, named after the host."""
    for member in ("alpha.internal", "beta.internal", "gamma.internal"):
        d = tmp_path / "given" / member / "27017" / "diagnostic.data"
        d.mkdir(parents=True)
        (d / "metrics.2026-08-05T12-00-00Z-00000").write_bytes(b"not real ftdc, but a file")

    files = list(build({"type": "directory", "path": str(tmp_path / "given")}).fetch(None))
    assert sorted({f.node for f in files}) == ["alpha.internal", "beta.internal",
                                               "gamma.internal"]


# ------------------------------------------------------------------------- the ssh path

def test_ssh_pulls_with_the_identity_and_yields_what_arrived(tmp_path, monkeypatch):
    """`fetch` had never been executed by a test — only its description.

    Nothing here talks to a real host: the point is the command that would be run, and that
    whatever lands in the temporary directory is handed on with the host as the node name.
    """
    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        # scp would drop the files into the last argument.
        landing = Path(cmd[-1])
        (landing / "metrics.2026-08-05T12-00-00Z-00000").write_bytes(b"x")
        (landing / "metrics.interim").write_bytes(b"y")
        (landing / "something-else.log").write_bytes(b"z")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    source = SSHSource("db1.acme.internal", "/var/lib/mongo/diagnostic.data/",
                       user="readonly", identity="/keys/acme")
    files = list(source.fetch(datetime(2026, 8, 1, tzinfo=timezone.utc)))

    assert seen["cmd"][0] == "scp"
    assert "-i" in seen["cmd"] and "/keys/acme" in seen["cmd"]
    assert "readonly@db1.acme.internal:/var/lib/mongo/diagnostic.data/metrics.*" in seen["cmd"]
    assert seen["kwargs"].get("check") is True, "a failed copy must not look like an empty one"

    assert {f.name for f in files} == {"metrics.2026-08-05T12-00-00Z-00000", "metrics.interim"}
    assert {f.node for f in files} == {"db1.acme.internal"}


def test_ssh_without_a_user_still_builds_a_target(monkeypatch):
    """Plenty of setups carry the user in ~/.ssh/config instead."""
    seen: dict = {}
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: seen.setdefault("cmd", cmd) and None
                        or subprocess.CompletedProcess(cmd, 0))
    list(SSHSource("db1.acme.internal", "/data/diagnostic.data").fetch(None))
    assert "db1.acme.internal:/data/diagnostic.data/metrics.*" in seen["cmd"]
    assert "-i" not in seen["cmd"]


def test_a_failing_copy_raises_rather_than_reporting_nothing(monkeypatch):
    """Silence is how a broken collector looks exactly like a healthy cluster."""
    def boom(cmd, **kwargs):
        raise subprocess.CalledProcessError(255, cmd)

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(subprocess.CalledProcessError):
        list(SSHSource("db1", "/data").fetch(None))
