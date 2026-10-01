"""The configuration file: what to watch, who to tell, and how to send the mail.

    {
      "notify": ["you@example.com"],
      "retention_days": 365,
      "report_url": "https://mongo-reports.example.com",
      "smtp": {"host": "smtp.example.com", "port": 587, "from": "collector@example.com",
               "user": "collector@example.com"},
      "clusters": [
        {"id": "orders-prod",
         "source": {"type": "atlas", "group_id": "...", "replica_set": "atlas-abc123-shard-0"}},
        {"id": "rs-staging", "notify": ["staging@example.com"], "retention_days": 90,
         "source": {"type": "directory", "path": "/mnt/ftdc/rs-staging"}}
      ]
    }

A cluster's `notify`, `mute` and `retention_days` override the top-level ones.

Secrets do not have to live in the file. `ATLAS_PUBLIC_KEY` and `ATLAS_PRIVATE_KEY` fill in an
Atlas source that has no key of its own, and `SMTP_PASSWORD` fills in the SMTP password -- so the
file can be committed to a private repo, or mounted into a container, without carrying either.

Everything that reads the configuration reads it through here. It used to be parsed in five
places, and one of them quietly dropped the per-cluster retention the example promised.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

DEFAULT_RETENTION_DAYS = 365

# A cluster id becomes a directory name and part of every finding id, so it is held to what is
# safe as both. Anchored at both ends; no dots leading anywhere.
CLUSTER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


class ConfigError(ValueError):
    """The file cannot be used as it is. The message says what to change."""


def load(path: Path) -> dict:
    """Read and check the file. Raises ConfigError with the reason, never a KeyError later."""
    try:
        cfg = json.loads(Path(path).read_text())
    except FileNotFoundError:
        raise ConfigError(f"{path} does not exist — copy config.example.json") from None
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path} is not valid JSON: {e}") from None
    if not isinstance(cfg, dict):
        raise ConfigError(f"{path}: expected an object at the top level")

    clusters = cfg.get("clusters")
    if not isinstance(clusters, list):
        raise ConfigError(f'{path}: needs a "clusters" list, even an empty one')
    seen = set()
    for i, cluster in enumerate(clusters):
        where = f"{path}: clusters[{i}]"
        if not isinstance(cluster, dict):
            raise ConfigError(f"{where} is not an object")
        cid = cluster.get("id")
        if not isinstance(cid, str) or not CLUSTER_ID.match(cid):
            raise ConfigError(f'{where}: "id" must be letters, digits, ".", "_" or "-", '
                              f"starting with a letter or digit (got {cid!r})")
        if cid in seen:
            raise ConfigError(f'{where}: the id "{cid}" is used twice')
        seen.add(cid)
        if not isinstance(cluster.get("source"), dict):
            raise ConfigError(f'{where} ("{cid}"): needs a "source"')
        interval = cluster["source"].get("interval")
        if interval is not None and (not isinstance(interval, int) or not 1 <= interval <= 60):
            raise ConfigError(f'{where} ("{cid}"): "interval" is seconds between samples, '
                              f"a whole number from 1 to 60 (got {interval!r})")
        days = cluster.get("retention_days")
        if days is not None and (not isinstance(days, int) or days < 1):
            raise ConfigError(f'{where} ("{cid}"): "retention_days" is a whole number of days '
                              f"(got {days!r})")
    return cfg


def _source(spec: dict) -> dict:
    source = dict(spec)
    if source.get("type", "atlas") == "atlas":
        source.setdefault("public_key", os.environ.get("ATLAS_PUBLIC_KEY", ""))
        source.setdefault("private_key", os.environ.get("ATLAS_PRIVATE_KEY", ""))
    return source


def files_only(spec: dict) -> bool:
    """A cluster that is only the files somebody uploaded, with no connection to send more.

    Its newest sample ageing is not silence: nothing promised data after it. The report judges
    it as of that sample, and the watchdog leaves it alone.
    """
    source = spec.get("source") or {}
    return source.get("type") == "onprem" and not source.get("uri")


def clusters(cfg: dict) -> list[dict]:
    """Every configured cluster, with the top-level defaults already applied."""
    out = []
    for cluster in cfg["clusters"]:
        out.append({
            "cluster_id": cluster["id"],
            "source": _source(cluster["source"]),
            "notify": cluster.get("notify", cfg.get("notify", [])),
            # Rules this cluster does not want emails about. They are still detected and still
            # in the report; only the email is skipped.
            "mute": cluster.get("mute", []),
            "retention_days": int(cluster.get("retention_days",
                                              cfg.get("retention_days", DEFAULT_RETENTION_DAYS))),
            # Where `site/` is served, if anywhere. The emails link into it when it is set.
            "report_url": (cfg.get("report_url") or "").rstrip("/") or None,
        })
    return out


def load_clusters(path: Path) -> list[dict]:
    return clusters(load(path))


def smtp(cfg: dict) -> dict | None:
    """The SMTP block, with the password from the environment when the file has none."""
    block = cfg.get("smtp")
    if not block:
        return None
    block = dict(block)
    if not block.get("password") and os.environ.get("SMTP_PASSWORD"):
        block["password"] = os.environ["SMTP_PASSWORD"]
    return block
