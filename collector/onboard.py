#!/usr/bin/env python3
"""Sign up a cluster: find it, pull everything Atlas still has, and profile it.

    python3 onboard.py --group-id 60ad… --notify you@example.com
    python3 onboard.py --group-id 60ad… --cluster orders-prod   # just one

The key comes from ATLAS_PUBLIC_KEY / ATLAS_PRIVATE_KEY, or from --public-key / --private-key;
only the second way writes it into the config.

The point is to see something the same day. Atlas holds 3 to 10 days of FTDC
right now, and the moment a read-only key reaches it that history is kept — so the
first run pulls **all of it** rather than starting from zero and waiting a week for
the graphs to mean anything.

That single fetch is small: measured at 0.6 GB for an idle three-node cluster, 1.4 GB under
real traffic.

What it does, in order:

  1. asks the project which clusters exist, and what each one's replica set is called
  2. writes them into the config, so the cron picks them up from then on
  3. captures with no date filter -- everything Atlas is holding
  4. analyses it, which fills the baseline with a real starting point rather than one sample
  5. evaluates it, and writes the report with the verdict (see report.py and verdict.py)

Steps 3 to 5 are the same code the cron runs. Onboarding is not a separate pipeline, it is the
normal one with the date filter turned off.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.auth import HTTPDigestAuth

import config

BASE = "https://cloud.mongodb.com/api/atlas/v1.0"


def discover(group_id: str, public_key: str, private_key: str) -> list[dict]:
    """Every cluster in the project, with the name the log endpoint actually needs.

    The replica set name is the awkward part. `replicaSetName` on the cluster document comes
    back empty, and the hostnames are no help either -- they read `…shard-00-00` while the set
    is `…shard-0`. The only reliable source is the `replicaSet=` parameter of the standard
    connection string.
    """
    auth = HTTPDigestAuth(public_key, private_key)
    r = requests.get(f"{BASE}/groups/{group_id}/clusters", auth=auth,
                     headers={"Accept": "application/json"}, timeout=60)
    if r.status_code == 401:
        raise RuntimeError(
            "Atlas rejected the key for this project. `GET /api/atlas/v1.0/groups` lists the "
            "ones it can reach — the id in the console URL is not always the right one."
        )
    r.raise_for_status()

    out = []
    for c in r.json().get("results", []):
        conn = (c.get("connectionStrings") or {}).get("standard", "")
        match = re.search(r"replicaSet=([^&\s]+)", conn)
        provider = c.get("providerSettings") or {}
        # Replica sets only in this version. A sharded cluster's standard string points at the
        # mongos and carries no replicaSet=, so it was already left out -- but it said "M0/Flex",
        # which is the wrong reason, and the reason is what the person acts on.
        sharded = c.get("clusterType") in ("SHARDED", "GEOSHARDED")
        out.append({
            "name": c["name"],
            "replica_set": None if sharded else (match.group(1) if match else None),
            "sharded": sharded,
            "version": c.get("mongoDBVersion"),
            "tier": provider.get("instanceSizeName"),
            "region": provider.get("regionName"),
            "state": c.get("stateName"),
            # Reported so the operator can act on it. Autoscaling contaminates the baseline
            # from its very first row, and that row cannot be recomputed later.
            "autoscaling": bool((c.get("autoScaling") or {}).get("compute", {}).get("enabled")),
        })
    return out


def add_to_config(path: Path, notify: list[str], group_id: str, clusters: list[dict],
                  keys: dict | None = None) -> int:
    """Merge the discovered clusters into the config, leaving existing ones alone.

    `keys` are written into each source only when given. Keys that came from the environment
    stay there: writing them out would put a secret into a file the user chose to keep clean.
    """
    cfg = json.loads(path.read_text()) if path.exists() else {}
    cfg.setdefault("notify", notify)
    cfg.setdefault("clusters", [])

    added = 0
    for c in clusters:
        if any(existing["id"] == c["name"] for existing in cfg["clusters"]):
            continue
        source = {"type": "atlas", "group_id": group_id, "replica_set": c["replica_set"]}
        source.update(keys or {})
        cfg["clusters"].append({"id": c["name"], "source": source})
        added += 1

    path.write_text(json.dumps(cfg, indent=2) + "\n")
    path.chmod(0o600)  # it may hold private keys, and it names every cluster
    return added


def run(cmd: list[str], quiet: bool) -> bool:
    r = subprocess.run(cmd, capture_output=quiet, text=True)
    if r.returncode != 0 and quiet:
        print((r.stderr or r.stdout or "").strip()[-400:], file=sys.stderr)
    return r.returncode == 0


def configuration_lines(cluster_id: str, data: Path, recommend) -> str:
    """The recommendations under the verdict: the first evaluation is the one moment somebody
    reads everything, and a setting found now is fixed before it becomes an incident."""
    summary_path = data / cluster_id / "summary.json"
    if not summary_path.exists():
        return ""
    nodes = json.loads(summary_path.read_text()).get("nodes", [])
    if not any(n.get("config") for n in nodes):
        return ""
    recs = recommend.evaluate(nodes, datetime.now(timezone.utc).date())
    if not recs:
        return "\n  configuration: nothing to change"
    out = [f"\n  configuration: {len(recs)} recommendation{'s' if len(recs) != 1 else ''}"]
    for r in recs:
        out.append(f"    [{r.severity}] {r.title}\n      {r.fix}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--site", type=Path, default=Path("site"), help="where the report is written")
    ap.add_argument("--group-id", required=True, help="the Atlas project id")
    ap.add_argument("--public-key", help="default: $ATLAS_PUBLIC_KEY")
    ap.add_argument("--private-key", help="default: $ATLAS_PRIVATE_KEY")
    ap.add_argument("--cluster", action="append",
                    help="only this cluster; repeat for several. Default: all in the project")
    ap.add_argument("--notify", action="append", default=[],
                    help="where findings go, when the config does not say yet")
    ap.add_argument("--discover-only", action="store_true",
                    help="list what is there and change nothing")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    public_key = args.public_key or os.environ.get("ATLAS_PUBLIC_KEY")
    private_key = args.private_key or os.environ.get("ATLAS_PRIVATE_KEY")
    if not (public_key and private_key):
        print("no API key: set ATLAS_PUBLIC_KEY and ATLAS_PRIVATE_KEY, or pass "
              "--public-key and --private-key", file=sys.stderr)
        return 2
    # Only a key typed on the command line goes into the file; see add_to_config.
    keys = ({"public_key": public_key, "private_key": private_key}
            if args.public_key and args.private_key else None)

    print(f"looking at project {args.group_id}")
    try:
        found = discover(args.group_id, public_key, private_key)
    except Exception as e:
        print(f"could not list clusters: {e}", file=sys.stderr)
        return 1

    if not found:
        print("the project has no clusters", file=sys.stderr)
        return 1

    for c in found:
        flags = []
        if c["autoscaling"]:
            flags.append("AUTOSCALING ON")
        if c["state"] != "IDLE":
            flags.append(c["state"])
        if c.get("sharded"):
            flags.append("sharded — replica sets only in this version")
        elif not c["replica_set"]:
            flags.append("no replica set name — cannot collect")
        print(f"  {c['name']:24} {c['tier'] or '?':6} {c['version'] or '?':9} "
              f"{c['replica_set'] or '—':26} {' · '.join(flags)}")

    wanted = [c for c in found if not args.cluster or c["name"] in args.cluster]
    wanted = [c for c in wanted if c["replica_set"]]
    if not wanted:
        print("nothing to sign up", file=sys.stderr)
        return 1

    if any(c["autoscaling"] for c in wanted):
        # Worth stopping over. A tier change mid-capture rescales every metric, and the
        # baseline's first rows are the ones that cannot be recomputed later.
        print("\n  WARNING: autoscaling is on. Turn it off before the baseline builds up,")
        print("           or its earliest rows will mix two different machines.")

    if args.discover_only:
        return 0

    added = add_to_config(args.config, args.notify, args.group_id, wanted, keys)
    print(f"\n  {added} cluster(s) added to {args.config}")

    # The bootstrap itself: capture with no `--since`, which is what capture.py does for a
    # cluster it has never seen. Everything Atlas holds comes down in one go.
    print("\npulling everything Atlas still holds — this is the slow part")
    ok = all([run(["python3", "capture.py", "--config", str(args.config), "--data",
                   str(args.data), "--cluster", c["name"]], args.quiet) for c in wanted])
    if not ok:
        print("the first capture failed; the cluster is configured, so the cron will retry",
              file=sys.stderr)
        return 1

    print("\nanalysing")
    if not all([run(["python3", "analyze.py", "--config", str(args.config), "--data",
                     str(args.data), "--cluster", c["name"]], args.quiet) for c in wanted]):
        return 1

    # The first evaluation, over everything Atlas still held. Printed as well as written: the
    # answer to "is it healthy?" should be the last thing on the screen after onboarding, not a
    # file somebody has to know to open.
    print("\nthe first evaluation")
    import report  # noqa: PLC0415 -- matplotlib is slow to import, and only needed here

    import recommend  # noqa: PLC0415

    rows = report.build(config.load_clusters(args.config), args.data, args.site)
    for r in rows:
        if r["id"] in {c["name"] for c in wanted}:
            print(f"\n  {r['id']}: {r['verdict'].label}\n  {r['verdict'].reason}")
            print(configuration_lines(r["id"], args.data, recommend))
    print(f"\n  the full report: {args.site / 'index.html'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
