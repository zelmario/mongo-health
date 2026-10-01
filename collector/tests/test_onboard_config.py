"""The first evaluation prints the recommendations under the verdict."""
from __future__ import annotations

import json

import onboard
import recommend


def write(tmp_path, nodes):
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "summary.json").write_text(json.dumps({"nodes": nodes}))


def test_the_recommendations_follow_the_verdict(tmp_path):
    cfg = {"hostname": "box", "version": "8.0.34", "allocator": "tcmalloc-google",
           "thpEnabled": "always", "thpDefrag": "defer+madvise", "fdSoft": 1024}
    write(tmp_path, [{"node": "box", "hostname": "box", "config": cfg}])
    out = onboard.configuration_lines("c", tmp_path, recommend)
    assert "1 recommendation" in out
    assert "[warning] Open-file limit below MongoDB's minimum" in out


def test_a_clean_cluster_is_told_so(tmp_path):
    write(tmp_path, [{"node": "box", "hostname": "box", "config": {"version": "8.0.34"}}])
    assert "nothing to change" in onboard.configuration_lines("c", tmp_path, recommend)


def test_no_configuration_read_means_no_claim(tmp_path):
    write(tmp_path, [{"node": "box", "hostname": "box"}])
    assert onboard.configuration_lines("c", tmp_path, recommend) == ""
