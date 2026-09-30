"""The catalog of checks must describe the checks that actually run."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import catalog  # noqa: E402

BIGHOLE = Path(__file__).resolve().parents[2] / "big-hole"
DOCS = Path(__file__).resolve().parents[2] / "docs" / "rules.md"


@pytest.mark.skipif(shutil.which("npx") is None or not (BIGHOLE / "node_modules").exists(),
                    reason="needs the engine installed to regenerate the rules")
def test_rules_json_is_what_the_engine_has_today():
    """Change a threshold in rules.ts and forget to regenerate, and this fails -- rather than
    the catalog quietly describing a rule that no longer runs."""
    r = subprocess.run(["npx", "vite-node", "tools/rule-catalog.ts"], cwd=BIGHOLE,
                       capture_output=True, text=True, timeout=180)
    fresh = json.loads(r.stdout)
    assert fresh == catalog.load(), (
        "collector/rules.json is stale: regenerate it with\n"
        "  cd big-hole && npx vite-node tools/rule-catalog.ts > ../collector/rules.json")


def test_the_markdown_in_the_repository_is_current():
    assert DOCS.read_text() == catalog.markdown(), (
        "docs/rules.md is stale: regenerate it with\n"
        "  cd collector && python3 catalog.py --markdown ../docs/rules.md")


def test_every_rule_that_can_fire_has_an_entry():
    ids = {e["id"] for e in catalog.entries()}
    engine = {r["id"] for r in catalog.load()["rules"]}
    produced_elsewhere = {"ftdc-long-outage", "ftdc-micro-stalls", "election-held",
                          "setting-changed", "peer-outlier", "baseline-excursion",
                          "capacity-runway", "oversized-cluster"}
    assert engine | produced_elsewhere <= ids
    assert catalog.anchor("alarm:serverStatus.metrics.repl.initialSync.failedAttempts") in ids


def test_every_threshold_rule_is_placed_in_an_area():
    unplaced = [r["id"] for r in catalog.load()["rules"] if r["id"] not in catalog.AREA_OF]
    assert unplaced == [], "add them to catalog.AREA_OF"


def test_every_threshold_rule_says_why():
    """The whole claim of the catalog is that no number is a guess."""
    silent = [e["id"] for e in catalog.entries() if e["kind"] == "threshold" and not e["reasoning"]]
    assert silent == []


def test_the_condition_reads_as_a_sentence():
    e = next(e for e in catalog.entries() if e["id"] == "read-tickets-saturated")
    assert e["how"] == "≥ 50% for 60 s, dips of up to 15 s tolerated"


def test_what_ten_second_samples_change_is_said_where_it_matters():
    by = {e["id"]: e for e in catalog.entries()}
    assert "shorter than one sample" in by["command-latency-high"]["ten_seconds"]
    assert by["cache-full"]["ten_seconds"] is None
