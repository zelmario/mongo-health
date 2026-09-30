#!/usr/bin/env python3
"""Sign up a cluster: find it, pull everything Atlas still has, and profile it.

    python3 onboard.py --customer acme --group-id 60ad… --public-key … --private-key …
    python3 onboard.py --customer acme --group-id 60ad… --cluster orders-prod   # just one

The point is that a new customer sees something the same day. Atlas holds 3 to 10 days of FTDC
right now, and the moment they hand over a read-only key that history becomes theirs — so the
first run pulls **all of it** rather than starting from zero and asking them to wait a week for
the graphs to mean anything.

That single fetch is also the cheapest part of the service: measured at 0.6 GB for an idle
three-node cluster, 1.4 GB under real traffic. It costs almost nothing and it is the whole
first impression.

What it does, in order:

  1. asks the project which clusters exist, and what each one's replica set is called
  2. writes them into the config, so the cron picks them up from then on
  3. captures with no date filter -- everything Atlas is holding
  4. analyses it, which fills the baseline with a real starting point rather than one sample
  5. writes the profile report (see profile.py)

Steps 3 to 5 are the same code the cron runs. Onboarding is not a separate pipeline, it is the
normal one with the date filter turned off.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import requests
from requests.auth import HTTPDigestAuth

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
        out.append({
            "name": c["name"],
            "replica_set": match.group(1) if match else None,
            "version": c.get("mongoDBVersion"),
            "tier": provider.get("instanceSizeName"),
            "region": provider.get("regionName"),
            "state": c.get("stateName"),
            # Reported so the operator can act on it. Autoscaling contaminates the baseline
            # from its very first row, and that row cannot be recomputed later.
            "autoscaling": bool((c.get("autoScaling") or {}).get("compute", {}).get("enabled")),
        })
    return out


def add_to_config(path: Path, customer: str, notify: list[str], group_id: str,
                  public_key: str, private_key: str, clusters: list[dict],
                  retention_days: int) -> int:
    """Merge the discovered clusters into the config, leaving existing ones alone."""
    cfg = json.loads(path.read_text()) if path.exists() else {"customers": []}
    cfg.setdefault("customers", [])

    customer_entry = next((c for c in cfg["customers"] if c["id"] == customer), None)
    if customer_entry is None:
        customer_entry = {"id": customer, "notify": notify, "clusters": [],
                          "retention_days": retention_days}
        cfg["customers"].append(customer_entry)
    customer_entry.setdefault("clusters", [])

    added = 0
    for c in clusters:
        if any(existing["id"] == c["name"] for existing in customer_entry["clusters"]):
            continue
        customer_entry["clusters"].append({
            "id": c["name"],
            "source": {
                "type": "atlas",
                "group_id": group_id,
                "replica_set": c["replica_set"],
                "public_key": public_key,
                "private_key": private_key,
            },
        })
        added += 1

    path.write_text(json.dumps(cfg, indent=2) + "\n")
    path.chmod(0o600)  # it holds private keys
    return added


def run(cmd: list[str], quiet: bool) -> bool:
    r = subprocess.run(cmd, capture_output=quiet, text=True)
    if r.returncode != 0 and quiet:
        print((r.stderr or r.stdout or "").strip()[-400:], file=sys.stderr)
    return r.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--customer", required=True)
    ap.add_argument("--group-id", required=True)
    ap.add_argument("--public-key", required=True)
    ap.add_argument("--private-key", required=True)
    ap.add_argument("--cluster", action="append",
                    help="only this cluster; repeat for several. Default: all in the project")
    ap.add_argument("--notify", action="append", default=[],
                    help="where findings go for this customer")
    ap.add_argument("--retention-days", type=int, default=14,
                    help="free tier keeps 14 days; paid keeps more")
    ap.add_argument("--discover-only", action="store_true",
                    help="list what is there and change nothing")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    print(f"looking at project {args.group_id}")
    try:
        found = discover(args.group_id, args.public_key, args.private_key)
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
        if not c["replica_set"]:
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

    added = add_to_config(args.config, args.customer, args.notify, args.group_id,
                          args.public_key, args.private_key, wanted, args.retention_days)
    print(f"\n  {added} cluster(s) added to {args.config}, retention {args.retention_days} d")

    # The bootstrap itself: capture with no `--since`, which is what capture.py does for a
    # cluster it has never seen. Everything Atlas holds comes down in one go.
    print("\npulling everything Atlas still holds — this is the slow part")
    ok = run(["python3", "capture.py", "--config", str(args.config), "--data", str(args.data),
              "--customer", args.customer], args.quiet)
    if not ok:
        print("the first capture failed; the cluster is configured, so the cron will retry",
              file=sys.stderr)
        return 1

    print("\nanalysing")
    if not run(["python3", "analyze.py", "--config", str(args.config), "--data", str(args.data),
                "--customer", args.customer], args.quiet):
        return 1

    print("\nwriting the profile")
    for c in wanted:
        run(["python3", "profile.py", "--data", str(args.data), "--customer", args.customer,
             "--cluster", c["name"], "--out", f"profile-{args.customer}-{c['name']}.html"],
            args.quiet)

    return 0


if __name__ == "__main__":
    sys.exit(main())
