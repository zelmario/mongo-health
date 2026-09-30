#!/usr/bin/env python3
"""Drop raw FTDC past its retention, and keep everything that cannot be rebuilt.

    python3 prune.py --config config.json              # says what it would delete
    python3 prune.py --config config.json --apply      # actually deletes

**Deleting is opt-in.** Without `--apply` this only reports. Retention is the thing being
sold, so an over-eager prune destroys the product itself, and there is no undo.

## What goes and what stays

Measured on a real three-node cluster: raw FTDC runs about 58 MB per day, some 20.5 GB a
year, while the baseline is around 55 MB a year. The raw data is roughly **420x** the derived
data, so it is the only thing worth deleting and the derived data is not worth thinking about.

    ftdc/*/metrics.*    pruned past the retention window
    baseline.jsonl      never   -- percentiles cannot be recomputed once the raw data is gone
    findings.jsonl      never   -- what was reported, and when
    usage.jsonl         never   -- what each customer cost
    state.json          entries for pruned files are dropped, so it does not grow forever

Compression was considered and rejected: FTDC chunks are already zlib-compressed internally,
so gzip buys 1%.

## What retention means for the customer

Two different numbers, and conflating them would misrepresent the service:

  - **history observed** — how far back the baseline goes. Never shrinks, because pruning
    does not touch it. This is what "we have watched this cluster for 14 months" means.
  - **raw FTDC available** — how far back a capture can actually be opened in Big Hole and
    read second by second. This is what the retention window buys, and it does shrink.

`status.py` shows both for this reason.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from capture import load_clusters
from state import State, timestamp_of

DEFAULT_RETENTION_DAYS = 365


def retention_for(spec: dict, cfg: dict) -> int:
    """Days of raw FTDC to keep, most specific setting wins.

    Per cluster, then per customer, then the global default. Retention is what is being paid
    for, so it belongs in the same place as the rest of the customer's configuration rather
    than in a constant here.
    """
    if "retention_days" in spec:
        return int(spec["retention_days"])
    for customer in cfg.get("customers", []):
        if customer["id"] == spec["customer_id"] and "retention_days" in customer:
            return int(customer["retention_days"])
    return int(cfg.get("retention_days", DEFAULT_RETENTION_DAYS))


def prunable(ftdc: Path, cutoff: datetime) -> tuple[list[Path], list[str]]:
    """Files older than the cutoff, and the reasons some were spared.

    Two things are never pruned regardless of age:

      - `metrics.interim`, which is the live buffer.
      - the newest numbered file of each node, because mongod may still be appending to it.
        Its *name* can be hours or days old while its contents are current -- that gap is
        exactly what made the capture lose data before, and deleting the active file would
        be a worse version of the same mistake.
    """
    doomed: list[Path] = []
    spared: list[str] = []

    for node_dir in sorted(p for p in ftdc.iterdir() if p.is_dir()):
        numbered = sorted(
            (f for f in node_dir.glob("metrics.*") if timestamp_of(f.name) is not None),
            key=lambda f: timestamp_of(f.name),  # type: ignore[arg-type]
        )
        if not numbered:
            continue
        newest = numbered[-1]
        for f in numbered:
            when = timestamp_of(f.name)
            if when is None or when >= cutoff:
                continue
            if f == newest:
                spared.append(f"{node_dir.name}/{f.name} (newest of its node, may still be open)")
                continue
            doomed.append(f)
    return doomed, spared


def prune_cluster(spec: dict, cfg: dict, root: Path, apply: bool,
                  verbose: bool = True) -> dict:
    customer_id, cluster_id = spec["customer_id"], spec["cluster_id"]
    base = root / customer_id / cluster_id
    ftdc = base / "ftdc"
    if not ftdc.exists():
        return {"customer_id": customer_id, "cluster_id": cluster_id, "skipped": True}

    days = retention_for(spec, cfg)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    doomed, spared = prunable(ftdc, cutoff)
    freed = sum(f.stat().st_size for f in doomed)

    if verbose:
        held = sum(f.stat().st_size for f in ftdc.rglob("metrics.*") if f.is_file())
        print(f"[{customer_id}/{cluster_id}] retention {days} d "
              f"(before {cutoff.date()}) · holding {held/1048576:.0f} MB")
        for f in doomed:
            print(f"  - {f.parent.name}/{f.name}  {f.stat().st_size/1048576:.1f} MB")
        for reason in spared:
            print(f"  = kept {reason}")
        if not doomed:
            print("  nothing past retention")

    if apply and doomed:
        state = State.load(base / "state.json", customer_id, cluster_id)
        for f in doomed:
            f.unlink()
            # Drop it from the state too. Otherwise the file list grows forever, and a stale
            # entry would make `is_new` claim we still hold something we deleted.
            state.files.pop(f"{f.parent.name}/{f.name}", None)
        state.save(base / "state.json")
        if verbose:
            print(f"  deleted {len(doomed)} file(s), freed {freed/1048576:.0f} MB")

    return {
        "customer_id": customer_id,
        "cluster_id": cluster_id,
        "operation": "prune",
        "retention_days": days,
        "files": len(doomed),
        "bytes": freed,
        "applied": bool(apply and doomed),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--customer", help="prune only this customer_id")
    ap.add_argument("--apply", action="store_true",
                    help="actually delete; without this it only reports")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not args.config.exists():
        print(f"{args.config} does not exist — copy config.example.json", file=sys.stderr)
        return 2

    cfg = json.loads(args.config.read_text())
    clusters = load_clusters(args.config)
    if args.customer:
        clusters = [c for c in clusters if c["customer_id"] == args.customer]

    total_files = total_bytes = 0
    failed = 0
    for spec in clusters:
        try:
            r = prune_cluster(spec, cfg, args.data, args.apply, verbose=not args.quiet)
            total_files += r.get("files", 0)
            total_bytes += r.get("bytes", 0)
        except Exception as e:
            failed += 1
            print(f"[{spec['customer_id']}/{spec['cluster_id']}] FAILED: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)

    if not args.quiet:
        verb = "freed" if args.apply else "would free"
        print(f"\n{verb} {total_bytes/1048576:.0f} MB across {total_files} file(s)"
              + ("" if args.apply else " — pass --apply to do it"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
