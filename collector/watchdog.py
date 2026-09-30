#!/usr/bin/env python3
"""Notice when the collector stops, and say so out loud.

    python3 watchdog.py --config config.json --data data          # report only
    python3 watchdog.py --config config.json --data data --send   # email the alert

A monitoring service that dies quietly is worse than no monitoring service. Whoever
believes their cluster is watched, the status page keeps showing the last good run, and the
silence reads as "nothing is wrong" instead of "nobody is looking". That is the failure this
guards against, and it is the one failure the collector cannot report about itself.

## Why this is a separate program

`status.py` already shows a stale cluster — but `status.py` is run **by the collector**. If the
cron stops firing, the page is never regenerated, so it freezes displaying the last healthy
state. A dead collector produces a page that actively asserts everything is fine.

So this reads only two things: the state files on disk, and the clock. It imports nothing from
the analysis path and needs neither Node nor Big Hole. It can run from a
different cron entry, a different user, or a different machine pointed at the same storage —
and the further away it runs, the more failures it can see.

## What it cannot see

Running on the same box, it will not notice the box being off. That is what the heartbeat in
`run.sh` is for: an outbound ping to an external service that alerts when the pings stop. The
two together cover both halves — this one catches "the collector is broken", the heartbeat
catches "the machine is gone".
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import smtplib
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import config


# The cron runs hourly. One missed run is routine — a slow Atlas job, a long first capture, a
# run that took the lock and held it — so the threshold is four of them: past any reboot or
# maintenance window, and still a quarter of the blind spot the six-hourly cron needed.
# Same threshold the status page uses, so the two never disagree.
STALE_AFTER_HOURS = 4


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def roster(data: Path) -> dict[str, dict] | None:
    """Which clusters are supposed to be capturing, as the collector last understood it.

    Keyed by cluster id. A cluster taken out of the config drops off the roster on the
    next run, so its data can stay on disk without the watchdog alerting about it for ever.

    `None` when there is no roster file: older data directories predate it, and absence means
    "watch everything I can see".

    Unreadable is treated the same as absent. This program's whole job is to still work when
    other things are broken, and refusing to run because one JSON file is truncated would make
    it the fragile part of the system it exists to watch.
    """
    path = data / "roster.json"
    try:
        entries = json.loads(path.read_text())["clusters"]
        return {e["cluster_id"]: e for e in entries}
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None


def check(data: Path, now: datetime, hours: int) -> list[dict]:
    """One entry per cluster that has stopped reporting, worst first.

    Deliberately reads `state.json` rather than `summary.json`: state is written by the
    capture step, so it moves even on a run where the analysis failed. A cluster capturing
    fine but failing to analyse is a different problem, and it should not be reported as a
    dead collector.
    """
    watched = roster(data)
    problems = []
    for state_path in sorted(data.glob("*/state.json")):
        key = state_path.parent.name
        if watched is not None:
            if key not in watched:
                # Paused, deleted, or its key was revoked. Its capture stopping is the intended
                # outcome, not a fault, and the data stays on disk — so the state file goes on
                # ageing for ever and would alert for ever.
                continue
        try:
            state = json.loads(state_path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            problems.append({
                "cluster": state_path.parent.name,
                "hours": None,
                "why": f"state file unreadable: {type(e).__name__}",
            })
            continue

        # Judged on when data ARRIVED, not on when we last looked. The capture step runs every
        # hour and stamps `last_capture` whatever it found, so on a cluster that uploads to us
        # -- or one we read out of a directory -- that timestamp moves while the source is
        # stone dead, and only our own collector stopping could ever be caught.
        #
        # Measured on rs-local on 20/08: the local replica set had been down for 29 hours,
        # capture had run 29 times, the operator alert stayed quiet and the page went on saying
        # "4.9 days watched". Falls back to `last_capture` for states written before the field
        # existed, so an upgrade does not turn every cluster into an alarm.
        last_run = parse_iso(state.get("last_capture"))
        last = parse_iso(state.get("last_new_data")) or last_run
        if last is None:
            # Configured but never captured. Real, but not the same alarm as one that stopped.
            problems.append({
                "cluster": state.get("cluster_id", state_path.parent.name),
                "hours": None,
                "why": "never captured",
            })
            continue

        allowed = hours
        age = (now - last).total_seconds() / 3600
        if age > allowed:
            # The reason names the expectation as well as the fact. "3 h ago" is alarming for a
            # cluster that pushes every ten minutes and unremarkable for one polled hourly, and
            # whoever reads the alert should not have to remember which is which.
            why = f"no new data for {age:.0f} h"
            # Which end stopped. The run being fresh while the data is old puts it at the
            # source; both being old puts it here, and those are different mornings.
            if last_run and (now - last_run).total_seconds() / 3600 <= allowed:
                why += " — capture is running, so the source stopped, moved or went empty"
            else:
                why += f" — and capture has not run for {(now - last_run).total_seconds() / 3600:.0f} h" \
                       if last_run else " — and capture has never run"
            problems.append({
                "cluster": state.get("cluster_id", state_path.parent.name),
                "hours": age,
                # The arrival, not the run. The email quotes this next to "26 hours ago", and
                # quoting the run put a timestamp from four minutes earlier under a sentence
                # about a day of silence -- a contradiction the reader sees before anything
                # else. It is also what makes a second outage after a recovery a new outage.
                "last_data": state.get("last_new_data") or state.get("last_capture"),
                "source_kind": state.get("source_kind"),
                "why": why,
            })

    return sorted(problems, key=lambda p: -(p["hours"] or 1e9))


def compose(problems: list[dict], recipients: list[str], sender: str,
            now: datetime) -> EmailMessage:
    worst = problems[0]
    subject = (f"[collector] {worst['cluster']} has stopped capturing"
               if len(problems) == 1
               else f"[collector] {len(problems)} clusters have stopped capturing")

    lines = [
        "The collector has not captured for one or more clusters.",
        "",
        "This is about the collector, not about the clusters themselves: they may be",
        "perfectly healthy. What it means is that nobody is currently watching them,",
        "and that the status page is showing the last run rather than the present.",
        "",
    ]
    for p in problems:
        lines.append(f"  {p['cluster']} — {p['why']}")
    lines += [
        "",
        "Where to look, in order:",
        "  1. did cron fire?            grep the collector's logs/run-YYYY-MM.log",
        "  2. did a step fail?          the log names the failing step and its exit code",
        "  3. is the API key still valid?  a revoked key fails every run identically",
        "  4. is the lock stuck?        a killed run can leave .run.lock held",
        "",
        f"Checked at {now.strftime('%d %b %Y %H:%M UTC')}.",
    ]

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content("\n".join(lines))
    return msg


# The outages the operator has already been told about. This program holds no state at all
# otherwise, and that is on purpose -- but "once per outage" cannot be answered without
# remembering, and an hourly email for three days is how an alert teaches people to filter it.
NOTIFIED = "watchdog-notified.json"


@contextlib.contextmanager
def only_one_reporter(data: Path):
    """Hold the right to send, or yield False and send nothing.

    This program was designed to hold no state and no lock, and for a long time it needed
    neither. Remembering which outages have already been reported changed that: the sequence is
    read the file, decide, send, write it back, and two copies of that running at once both read
    "not told yet" and both send.

    Not hypothetical. Two instances started within the same second on 22/08 -- systemd catching
    up missed runs after the machine had been asleep -- and the only reason nobody was emailed
    twice is that one happened to finish before the other read the file.

    Non-blocking on purpose. A watchdog that waits on a lock is a watchdog that can hang, and
    this is the program whose whole promise is to still work when other things do not. If
    somebody else holds it, they are already doing the job: say nothing and let them.
    """
    path = data / f".{NOTIFIED}.lock"
    try:
        handle = path.open("w")
    except OSError:
        # Unwritable directory. The alert matters more than the deduplication, so carry on
        # alone rather than fall silent because of a permissions problem.
        yield True
        return
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        yield True
    finally:
        handle.close()


def read_outages(data: Path) -> dict:
    """Tolerant on purpose, exactly like `roster`: a truncated JSON file must not stop the
    program whose job is to work when other things are broken. The cost of forgetting is one
    repeated email; the cost of refusing to run is the silence this exists to break."""
    try:
        return json.loads((data / NOTIFIED).read_text())
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


def write_outages(data: Path, outages: dict) -> None:
    tmp = data / f".{NOTIFIED}.tmp"
    tmp.write_text(json.dumps(outages, indent=2, sort_keys=True))
    tmp.replace(data / NOTIFIED)


def send(msg: EmailMessage, smtp: dict) -> None:
    with smtplib.SMTP(smtp["host"], int(smtp.get("port", 587)), timeout=60) as server:
        if smtp.get("starttls", True):
            server.starttls()
        if smtp.get("user"):
            server.login(smtp["user"], smtp["password"])
        server.send_message(msg)



# How long before the same alert is worth repeating to the operator.
#
# It used to go out on every run, which was harmless while the only thing it could report was a
# collector that had stopped -- rare, and fixed within the hour. Since it also reports a dead
# SOURCE, an outage can last for days: a replica set that is switched off produces
# an identical email every hour until somebody acts, and the fourth one is already being
# filtered. A day is long enough not to nag and short enough that an ignored outage keeps
# coming back.
#
# It is a floor on repeats, not on news: any change to the set of affected clusters sends
# immediately, because that is a different situation and not a reminder of the same one.
REMIND_AFTER_HOURS = 24


def _signature(problems: list[dict]) -> list[str]:
    """What the alert is about, in a form two runs can be compared by.

    The arrival timestamp is part of it: a cluster that recovered and stopped again is a new
    outage, not the old one still running, and it must not be swallowed as a repeat.
    """
    return sorted(f"{p['cluster']}@{p.get('last_data') or p['why']}"
                  for p in problems)


def worth_repeating(data: Path, problems: list[dict], now: datetime) -> tuple[bool, dict]:
    """Whether to send the operator alert now, and the state to write back if it is sent."""
    outages = read_outages(data)
    before = outages.get("operator") or {}
    signature = _signature(problems)

    if before.get("signature") != signature:
        return True, {**outages, "operator": {"signature": signature,
                                              "told_at": now.isoformat()}}

    told_at = parse_iso(before.get("told_at"))
    if told_at is None or (now - told_at).total_seconds() / 3600 >= REMIND_AFTER_HOURS:
        return True, {**outages, "operator": {"signature": signature,
                                              "told_at": now.isoformat()}}
    return False, outages


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--hours", type=int, default=STALE_AFTER_HOURS)
    ap.add_argument("--to", action="append", default=[],
                    help="who to alert; defaults to smtp.operator, then to the config's notify")
    ap.add_argument("--send", action="store_true")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    if not args.data.exists():
        # The data directory itself being gone is the loudest possible signal, and the one
        # case where finding nothing must not be read as finding nothing wrong.
        print(f"ALARM: {args.data} does not exist — nothing has ever been captured",
              file=sys.stderr)
        return 1

    problems = check(args.data, now, args.hours)

    # Read raw and forgiving, not through config.load: a config that no longer validates must
    # not be what silences the program that reports on everything else being broken.
    try:
        cfg = json.loads(args.config.read_text())
    except (OSError, json.JSONDecodeError):
        cfg = {}
    smtp = config.smtp(cfg) or {}

    # Deciding and remembering are one step, and two copies of this program can run at once:
    # systemd catches up missed runs, and a machine that was asleep wakes several at a time.
    with only_one_reporter(args.data) as mine:
        if not mine:
            # Not an error, and not silence either: whoever holds the lock is doing exactly
            # this, and the exit code still says something is wrong.
            print("another watchdog is already reporting — leaving it to that one")
            return 1

        if not problems:
            # Counted over what is actually being watched, not over every directory on disk. A
            # paused cluster leaves its data behind, so counting folders would report an all-clear
            # over more clusters than anybody is checking -- reassurance about work not done.
            watched = roster(args.data)
            on_disk = {p.parent.name for p in args.data.glob("*/state.json")}
            total = len(on_disk if watched is None else on_disk & set(watched))
            idle = len(on_disk) - total
            note = f" ({idle} paused or no longer collected)" if idle else ""
            print(f"all {total} cluster(s) captured within the last {args.hours} h{note}")
            return 0

        print(f"{len(problems)} cluster(s) not capturing:")
        for p in problems:
            print(f"  {p['cluster']} — {p['why']}")

        if not args.send:
            print("\nnot sent (pass --send to alert)")
            return 1

        recipients = args.to or ([smtp["operator"]] if smtp.get("operator") else
                                 list(cfg.get("notify") or []))
        if not recipients:
            print('no recipient: pass --to, or set "notify" in the config', file=sys.stderr)
            return 1

        repeat, state = worth_repeating(args.data, problems, now)
        if not repeat:
            # Silent, and it still exits non-zero: the cron's own mail is the net underneath this
            # program, and pretending the run was clean because we already said so would remove it.
            print(f"\nalready alerted {', '.join(recipients)} about this, within the last "
                  f"{REMIND_AFTER_HOURS} h")
            return 1

        send(compose(problems, recipients, smtp.get("from", "collector@localhost"), now), smtp)
        write_outages(args.data, state)
        print(f"\nalerted {', '.join(recipients)}")
        return 1  # non-zero on purpose: this ran because something is wrong


if __name__ == "__main__":
    sys.exit(main())
