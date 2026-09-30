"""How far along a capture is, written to disk where a page can read it.

A first capture takes minutes, and without this the only thing anyone could see was a sentence
that never changed. This is the file that lets a page say more than "wait".

Two decisions are the whole design:

**The number comes from the run, not from a timer.** Every phase below reports what it actually
knows -- bytes of a known total, files of a counted set -- and the percentage is derived from
that. Where nothing is known, it says so rather than inventing movement: see `BUILD`.

**It is a file, not a table.** `capture.py` runs on installs with no database at all, and it
stays that way.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

NAME = "progress.json"


@dataclass(frozen=True)
class Phase:
    key: str
    label: str
    start: int
    end: int


# The order a capture goes through, and the share of the bar each one owns. The shares are not
# measurements -- they are how much of the wait each phase typically is, on the one real cluster
# we have timed: ordering is instant, Atlas assembling the bundle is most of it, the download is
# minutes on a fast link, and storing and analysing are seconds each.
PHASES = (
    Phase("order", "Asking Atlas for the data", 0, 3),
    Phase("build", "Atlas is assembling the bundle", 3, 55),
    Phase("download", "Downloading it", 55, 82),
    Phase("store", "Storing what is new", 82, 90),
    Phase("analyse", "Looking for what went wrong", 90, 99),
    Phase("done", "Done", 100, 100),
)

BY_KEY = {p.key: p for p in PHASES}


def report(base: Path, phase: str, *, done: float | None = None, total: float | None = None,
           note: str | None = None, certain: bool = True) -> None:
    """Record where the run is. Cheap enough to call in a loop; never raises.

    `done`/`total` are whatever this phase counts -- bytes, files -- and are what moves the bar
    inside the phase. `certain` is False when the fraction is an estimate rather than a count,
    which is the difference the page has to be able to show.
    """
    p = BY_KEY.get(phase)
    if p is None:
        return
    fraction = 0.0
    if total:
        fraction = max(0.0, min(1.0, float(done or 0) / float(total)))
    body = {
        "phase": p.key,
        "label": p.label,
        "percent": round(p.start + (p.end - p.start) * fraction),
        "done": done,
        "total": total,
        "note": note,
        "certain": bool(certain),
        "at": time.time(),
    }
    try:
        base.mkdir(parents=True, exist_ok=True)
        tmp = base / (NAME + ".tmp")
        tmp.write_text(json.dumps(body, sort_keys=True))
        tmp.replace(base / NAME)          # atomic: a reader never sees half a file
    except OSError:
        # Progress is decoration. A disk that cannot take it must not take the capture down
        # with it -- the capture is the part the customer is paying for.
        pass


def read(base: Path) -> dict | None:
    try:
        body = json.loads((base / NAME).read_text())
    except (OSError, ValueError):
        return None
    return body if isinstance(body, dict) else None
