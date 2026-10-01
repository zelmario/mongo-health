"""Configuration recommendations: each one fires on what it names, and nothing fires on a
cluster configured the way MongoDB asks -- which is what Atlas's metadata looks like."""
from __future__ import annotations

from datetime import date

import recommend

TODAY = date(2026, 10, 1)

# Cluster1's real metadata, as the runner extracts it: the reference for "nothing to say".
ATLAS = {"allocator": "tcmalloc-google", "auth": "enabled", "bindIp": "0.0.0.0",
         "cacheSizeGB": 0.5, "cores": 2, "dataFs": "xfs", "dataMountPoint": "/srv/mongodb",
         "dbPath": "/srv/mongodb/n0", "fdSoft": 1048576, "internalAuth": True, "memMB": 1846,
         "overcommit": 1, "rseqDisabled": True, "rseqPresent": True,
         "thpDefrag": "defer+madvise", "thpEnabled": "always", "thpMaxPtesNone": 0,
         "tlsMode": "requireTLS", "version": "8.0.34", "writeConcernSource": "global",
         "writeConcernW": "majority"}


def cluster(*overrides: dict, hosts=("db1", "db2", "db3")) -> list[dict]:
    """Three members on three hosts; overrides apply to members in order (one dict: all)."""
    nodes = []
    for i, host in enumerate(hosts):
        change = overrides[i] if len(overrides) > 1 else (overrides[0] if overrides else {})
        nodes.append({"node": host, "hostname": host,
                      "config": {**ATLAS, "hostname": host, **change}})
    return nodes


def ids(nodes, today=TODAY) -> set[str]:
    return {r.id for r in recommend.evaluate(nodes, today)}


def test_a_cluster_configured_like_atlas_has_nothing_to_hear():
    assert recommend.evaluate(cluster(), TODAY) == []


def test_nothing_is_said_without_configuration():
    assert recommend.evaluate([{"node": "a"}, {"node": "b"}], TODAY) == []


def test_a_version_past_its_end_of_life():
    recs = recommend.evaluate(cluster({"version": "6.0.20"}), TODAY)
    [r] = [r for r in recs if r.id == "version-end-of-life"]
    assert r.severity == "warning" and "31 Jul 2025" in r.what
    assert len(r.members) == 3, "one recommendation naming three members, not three"


def test_seven_is_still_supported_in_2026():
    """7.0's end of life moved to August 2027. The date in our heads was a year early."""
    assert "version-end-of-life" not in ids(cluster({"version": "7.0.39", "allocator": "tcmalloc"}))


def test_an_end_of_life_coming_up_is_a_heads_up():
    recs = recommend.evaluate(cluster({"version": "7.0.39"}), date(2027, 5, 1))
    [r] = [r for r in recs if r.id == "version-end-of-life"]
    assert r.severity == "info"


def test_three_members_on_one_machine():
    """mongod appends the port to its hostname: asusnueva, asusnueva:27018, asusnueva:27019."""
    nodes = cluster(hosts=("asusnueva", "asusnueva:27018", "asusnueva:27019"))
    [r] = [r for r in recommend.evaluate(nodes, TODAY) if r.id == "members-share-a-host"]
    assert r.what == "Every member reports the host asusnueva."
    assert len(r.members) == 3


def test_a_smaller_member():
    assert "unequal-members" in ids(cluster({}, {}, {"memMB": 900}))
    assert "unequal-members" not in ids(cluster({}, {}, {"memMB": 1700}))


def test_mixed_versions():
    assert "mixed-versions" in ids(cluster({}, {}, {"version": "8.0.30"}))


def test_thp_follows_the_allocator_not_the_version():
    # 8.0 with tcmalloc-google wants always; 'never' -- the old advice -- is now wrong.
    assert "transparent-huge-pages" in ids(cluster({"thpEnabled": "never"}))
    # The older tcmalloc wants it off, and only 'always' is a problem: madvise is fine.
    old = {"allocator": "tcmalloc", "version": "7.0.39"}
    assert "transparent-huge-pages" in ids(cluster({**old, "thpEnabled": "always"}))
    assert "transparent-huge-pages" not in ids(cluster({**old, "thpEnabled": "madvise"}))
    # The kernel's own spelling.
    assert "transparent-huge-pages" in ids(cluster({"thpEnabled": "[never] madvise always"}))


def test_thp_details_under_tcmalloc_google():
    recs = recommend.evaluate(cluster({"thpDefrag": "madvise", "thpMaxPtesNone": 511}), TODAY)
    [r] = [r for r in recs if r.id == "transparent-huge-pages"]
    assert r.severity == "info" and "defrag" in r.what and "511" in r.what


def test_rseq_left_to_glibc():
    assert "glibc-rseq" in ids(cluster({"rseqDisabled": False}))


def test_open_files_at_mongods_own_line():
    assert "ulimits-low" in ids(cluster({"fdSoft": 1024}))
    assert "ulimits-low" not in ids(cluster({"fdSoft": 65535}))
    assert "ulimits-low" not in ids(cluster({"fdSoft": -1})), "-1 is unlimited"


def test_several_mongods_each_taking_half_of_memory():
    # No cacheSizeGB: each takes half of (RAM - 1 GB), three of them 150% of the host.
    nodes = cluster({"cacheSizeGB": None, "memMB": 16384},
                    hosts=("box", "box:27018", "box:27019"))
    for n in nodes:
        n["config"].pop("cacheSizeGB")
    [r] = [r for r in recommend.evaluate(nodes, TODAY) if r.id == "cache-too-large"]
    assert "3 mongods" in r.what


def test_open_to_the_network_without_auth():
    found = ids(cluster({"auth": None, "internalAuth": None}))
    assert "open-without-auth" in found


def test_a_keyfile_is_authorization():
    assert "open-without-auth" not in ids(cluster({"auth": None, "internalAuth": True}))


def test_localhost_without_auth_is_a_test_box_not_a_hole():
    found = ids(cluster({"auth": None, "internalAuth": None, "tlsMode": None,
                         "bindIp": "127.0.0.1"}))
    assert not found & {"open-without-auth", "open-without-tls"}


def test_ext4_under_the_data():
    assert "filesystem-not-xfs" in ids(cluster({"dataFs": "ext4"}))
    assert "filesystem-not-xfs" not in ids(cluster({"dataFs": None}))


def test_write_concern_lowered_on_purpose():
    assert "write-concern-w1" in ids(cluster({"writeConcernW": 1}))
    # Implicit w:1 is what a pre-5.0-style arbiter set gets by itself; not a choice made.
    assert "write-concern-w1" not in ids(cluster({"writeConcernW": 1,
                                                 "writeConcernSource": "implicit"}))


def test_every_recommendation_has_a_documented_check():
    nodes = cluster({"version": "6.0.1", "thpEnabled": "never", "fdSoft": 10, "dataFs": "ext4",
                     "auth": None, "internalAuth": None, "tlsMode": None, "overcommit": 2,
                     "rseqDisabled": False, "writeConcernW": 1},
                    hosts=("h", "h:27018", "h:27019"))
    for r in recommend.evaluate(nodes, TODAY):
        assert r.why, r.id
