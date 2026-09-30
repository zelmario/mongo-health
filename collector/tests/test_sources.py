"""Where FTDC comes from, and the shape every source has to present.

The abstraction exists because accepting non-Atlas clusters later changes the interface, and
that was worth deciding before there was a second source rather than after. These tests hold
that contract: whatever the transport, the rest of the pipeline receives the same thing.

`DirectorySource` is exercised for real against files on disk, because it is also what the
capture tests use as a stand-in — if it drifted, those tests would be verifying a fiction.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sources import (AtlasSource, DirectorySource, FTDCFile, SSHSource,  # noqa: E402
                     build, node_from_path)

NAME = "metrics.2026-08-07T01-15-12Z-00000"


# ------------------------------------------------------------------------- the file itself

def test_only_the_interim_is_marked_as_such():
    """The one mutable file by name. Everything else is identified by size instead."""
    assert FTDCFile("n0", "metrics.interim", Path("/x")).is_interim
    assert not FTDCFile("n0", NAME, Path("/x")).is_interim


# --------------------------------------------------------------------------- the factory

def test_build_dispatches_on_type():
    assert isinstance(build({"type": "directory", "path": "/x"}), DirectorySource)
    assert isinstance(build({"type": "ssh", "host": "h", "path": "/x"}), SSHSource)
    assert isinstance(build({"type": "atlas", "group_id": "g", "replica_set": "rs",
                             "public_key": "p", "private_key": "k"}), AtlasSource)


def test_atlas_is_the_default():
    """Existing configs predate the `type` field, and must keep working."""
    assert isinstance(build({"group_id": "g", "replica_set": "rs",
                             "public_key": "p", "private_key": "k"}), AtlasSource)


def test_an_unknown_type_fails_loudly():
    """A typo must not fall through to a source that silently returns nothing.

    That would look exactly like a healthy cluster with no new data.
    """
    with pytest.raises(ValueError, match="unknown source type"):
        build({"type": "carrier-pigeon"})


def test_every_source_describes_itself():
    """The description lands in logs and usage records, so it has to identify the cluster."""
    assert "atlas" in build({"type": "atlas", "group_id": "g60", "replica_set": "rs1",
                             "public_key": "p", "private_key": "k"}).describe()
    assert "rs1" in build({"type": "atlas", "group_id": "g60", "replica_set": "rs1",
                           "public_key": "p", "private_key": "k"}).describe()
    assert "/mnt/x" in build({"type": "directory", "path": "/mnt/x"}).describe()
    assert "db1" in build({"type": "ssh", "host": "db1", "path": "/x"}).describe()


def test_a_description_never_leaks_the_private_key():
    """It goes to logs and to usage.jsonl, neither of which is treated as a secret."""
    described = build({"type": "atlas", "group_id": "g", "replica_set": "rs",
                       "public_key": "pub", "private_key": "SECRET"}).describe()
    assert "SECRET" not in described


# ------------------------------------------------------------------- reading a directory

def test_directory_source_finds_every_node(tmp_path: Path):
    for node in ("n0", "n1"):
        d = tmp_path / node / "27017" / "diagnostic.data"
        d.mkdir(parents=True)
        (d / NAME).write_bytes(b"x")
    found = list(DirectorySource(tmp_path).fetch(None))
    assert {f.node for f in found} == {"n0", "n1"}


def test_plain_node_directories_are_separate_nodes(tmp_path: Path):
    """Regression: without a `diagnostic.data` in the path every file took the root's name, so
    a three-node set was stored as one node and its three interims overwrote each other."""
    for node in ("rs27017", "rs27018", "rs27019"):
        d = tmp_path / node
        d.mkdir()
        (d / NAME).write_bytes(b"x")
        (d / "metrics.interim").write_bytes(b"x")
    found = list(DirectorySource(tmp_path).fetch(None))
    assert len(found) == 6
    assert {f.node for f in found} == {"rs27017", "rs27018", "rs27019"}


def test_files_at_the_root_are_one_node_named_after_it(tmp_path: Path):
    (tmp_path / NAME).write_bytes(b"x")
    assert [f.node for f in DirectorySource(tmp_path).fetch(None)] == [tmp_path.name]


def test_directory_source_ignores_anything_else(tmp_path: Path):
    """A bundle carries logs and metadata beside the metrics files."""
    d = tmp_path / "n0" / "27017" / "diagnostic.data"
    d.mkdir(parents=True)
    (d / NAME).write_bytes(b"x")
    (d / "mongodb.log").write_bytes(b"x")
    (tmp_path / "README.txt").write_bytes(b"x")
    assert [f.name for f in DirectorySource(tmp_path).fetch(None)] == [NAME]


def test_directory_source_can_be_told_the_node_name(tmp_path: Path):
    """A single mongod has no host directory to infer one from."""
    d = tmp_path / "diagnostic.data"
    d.mkdir(parents=True)
    (d / NAME).write_bytes(b"x")
    found = list(DirectorySource(tmp_path, single_node="db1").fetch(None))
    assert found[0].node == "db1"


def test_an_empty_directory_yields_nothing_without_failing(tmp_path: Path):
    """Not an error here: `capture.py` is what decides that yielding nothing is worth a warning."""
    assert list(DirectorySource(tmp_path).fetch(None)) == []


# -------------------------------------------------------------------------- node naming

def test_port_directories_are_seen_through():
    p = Path("/x/host-a/27017/diagnostic.data/" + NAME)
    assert node_from_path(p, "fallback") == "host-a"


def test_a_non_numeric_parent_is_the_node():
    p = Path("/x/host-a/diagnostic.data/" + NAME)
    assert node_from_path(p, "fallback") == "host-a"


def test_diagnostic_data_at_the_root_falls_back():
    """Nothing above it to name the node with, so the caller's default stands."""
    assert node_from_path(Path("diagnostic.data/" + NAME), "fallback") == "fallback"
