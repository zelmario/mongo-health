"""Incidents somebody has dealt with, and what they said about it.

    data/<cluster>/resolved.json    {finding id: {"note": ..., "at": ISO time}}

Keyed by finding, not by incident: an incident is assembled from findings at read time and has
no identity of its own, so marking one resolved marks every finding in it. If the same thing
happens again it arrives as new findings with new ids, and is news again -- while the old ones
still count as earlier occurrences, because resolving takes an incident out of the report, not
out of the history.

The note is the point. Anyone can keep a list of closed alerts; what is worth opening six
months later is "added an index on orders.customer_id", next to the incident that caused it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

NAME = "resolved.json"
NOTE_LIMIT = 500


def load(base: Path) -> dict[str, dict]:
    """Tolerant: a truncated file must not take the report down with it."""
    try:
        data = json.loads((base / NAME).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save(base: Path, data: dict) -> None:
    tmp = base / f".{NAME}.tmp"
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    tmp.replace(base / NAME)


def resolve(base: Path, ids: list[str], note: str = "", now: datetime | None = None) -> None:
    data = load(base)
    at = (now or datetime.now(timezone.utc)).isoformat()
    for fid in ids:
        data[fid] = {"note": note.strip()[:NOTE_LIMIT], "at": at}
    _save(base, data)


def reopen(base: Path, ids: list[str]) -> None:
    data = load(base)
    for fid in ids:
        data.pop(fid, None)
    _save(base, data)


def is_resolved(group, done: dict[str, dict]) -> dict | None:
    """The resolution that covers this incident, if any member of it was marked."""
    return next((done[m["id"]] for m in group.members if m["id"] in done), None)
