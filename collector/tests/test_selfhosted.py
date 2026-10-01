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

class FakeAttr:
    def __init__(self, name, size):
        self.filename, self.st_size = name, size


class FakeSession:
    """What sftp.connect returns, over a dict of remote files."""

    def __init__(self, files):
        self.files, self.closed, self.got = files, False, []
        self.sftp = self

    def listdir_attr(self, path):
        return [FakeAttr(n, len(b)) for n, b in self.files.items()]

    def getfo(self, remote, buf):
        self.got.append(remote.rsplit("/", 1)[-1])
        buf.write(self.files[remote.rsplit("/", 1)[-1]])

    def close(self):
        self.closed = True


REMOTE = {
    "metrics.2026-08-01T00-00-00Z-00000": b"old",
    "metrics.2026-08-05T12-00-00Z-00000": b"open",
    "metrics.interim": b"tail",
    "something-else.log": b"z",
}


def ssh(hosts=("db1", "db2")):
    return SSHSource(list(hosts), "/var/lib/mongo/diagnostic.data/", "mongo-health-ftdc",
                     "/keys/acme", "/keys/known_hosts")


def test_ssh_downloads_only_what_may_have_changed(monkeypatch):
    """From the oldest file that may still grow, plus the interim file -- not the directory."""
    import sftp
    sessions = {}
    monkeypatch.setattr(sftp, "connect", lambda host, port, user, key, known, learn=False:
                        sessions.setdefault(host, FakeSession(REMOTE)))
    files = list(ssh().fetch(datetime(2026, 8, 5, 12, tzinfo=timezone.utc)))
    assert {(f.node, f.name) for f in files} == {
        (h, n) for h in ("db1", "db2")
        for n in ("metrics.2026-08-05T12-00-00Z-00000", "metrics.interim")}
    assert all(s.closed for s in sessions.values())


def test_ssh_takes_everything_on_the_first_run(monkeypatch):
    import sftp
    monkeypatch.setattr(sftp, "connect", lambda *a, **k: FakeSession(REMOTE))
    names = {f.name for f in ssh(["db1"]).fetch(None)}
    assert names == {n for n in REMOTE if n.startswith("metrics.")}


def test_one_member_down_still_reads_the_others_then_fails_the_run(monkeypatch):
    """Silence is how a broken collector looks exactly like a healthy cluster."""
    import sftp

    def connect(host, *a, **k):
        if host == "db2":
            raise TimeoutError()
        return FakeSession(REMOTE)

    monkeypatch.setattr(sftp, "connect", connect)
    got = []
    with pytest.raises(RuntimeError, match="db2: no answer on the SSH port"):
        for f in ssh(["db1", "db2", "db3"]).fetch(None):
            got.append(f.node)
    assert set(got) == {"db1", "db3"}


def test_an_unknown_host_key_is_refused_after_the_cluster_was_added(tmp_path):
    """A capture never learns a key: a changed one is what a man in the middle looks like."""
    import paramiko
    import sftp
    key = tmp_path / "id"
    sftp.generate_key(key, "test")
    with pytest.raises(Exception) as e:
        # Nothing listens on port 9: refused either way, but never with AutoAddPolicy.
        sftp.connect("127.0.0.1", 9, "u", key, tmp_path / "known_hosts")
    assert not (tmp_path / "known_hosts").exists()
    assert not isinstance(e.value, paramiko.BadHostKeyException)


def test_a_generated_key_is_private_and_loads(tmp_path):
    import sftp
    key = tmp_path / "keys" / "prod_ed25519"
    line = sftp.generate_key(key, "mongo-health:prod")
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    assert line.startswith("ssh-ed25519 ") and line.endswith(" mongo-health:prod")
    assert sftp.public_line(key, "mongo-health:prod") == line


def test_host_entries_carry_the_ssh_port():
    import sftp
    assert sftp.split_host("db1") == ("db1", 22)
    assert sftp.split_host("db1:2222") == ("db1", 2222)
    assert sftp.split_host("[fe80::1]:2222") == ("fe80::1", 2222)
    assert sftp.member_name("db1.acme.internal:2222") == "db1.acme.internal"
