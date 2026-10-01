#!/usr/bin/env python3
"""The weekly note that goes out when nothing happened.

    python3 digest.py --config config.json --data data            # writes to outbox
    python3 digest.py --config config.json --data data --send

A normal day here is silence: no findings, no email. That is the product working, and it is also
how a customer forgets they are paying for it. The cancellation does not come from a bad week,
it comes from a quiet quarter and somebody reviewing the invoices.

So once a week, one short message that says the two things silence cannot:

  · what the week held — incidents if there were any, and plainly none if there were not
  · **how much history is now yours**, against the three days Atlas keeps

That second number is the whole subscription made visible. It only grows, it cannot be
reconstructed if collection stops, and it is the thing a customer would be buying back at full
price if they cancelled and returned in a month.

Deliberately not a report. No charts, no tables, no per-metric anything: this competes for
attention with a full inbox, and a weekly message somebody skims for four seconds has to be
worth those four seconds or it becomes the noise it exists to prevent.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

import mailheaders
import recommend
import config
from group import group as group_findings, moments
from state import now

ATLAS_DAYS = 3

TEXT = {
    "subject_quiet": "[{cluster}] a quiet week",
    "subject_busy": "[{cluster}] {n} incident(s) this week",
    "quiet": "Nothing crossed a threshold on {cluster} this week. Every check ran; none fired.",
    "busy": "{n} thing(s) worth a look on {cluster} this week.",
    "history": "You now hold {days} of diagnostic history for this cluster. Atlas keeps about "
               "{atlas} days and deletes the rest, so {extra} of it exists only here.",
    # A cluster in its first days has nothing beyond what Atlas still holds, and saying "0 days
    # exist only here" deflates the exact argument this message is for. The truth then is about
    # the direction, not the amount.
    "history_new": "You now hold {days} of diagnostic history for this cluster. Atlas keeps "
                   "about {atlas} days and then deletes it; from here on, what it drops stays "
                   "with you.",
    # The one thing in the product that saves the reader money rather than costing them an
    # afternoon, and it has nowhere else to go: sizing advice only fires when the window had NO
    # trouble, and a run whose findings are all informational sends no mail. Two correct
    # decisions that between them mean it would never reach anybody. A quiet week is exactly
    # when it is true and exactly when there is room to say it.
    # A self-managed cluster has no Atlas deleting anything: mongod itself rotates its FTDC
    # directory when it reaches a size limit. No number of days here, because that depends on
    # the limit and the sampling rate, and a made-up figure is worse than none.
    "history_self": "You now hold {days} of diagnostic history for this cluster. mongod keeps "
                    "its own diagnostic data only up to a size limit and deletes the oldest; "
                    "what it drops stays here.",
    "spare": "And one thing that is not a problem: {what}",
    # Settings stay true until somebody changes them, so they come back every week -- the
    # weekly note is the one place a standing fact can repeat without becoming an alarm.
    "config": "How it is configured, against what MongoDB recommends:",
    "config_more": "  … and {n} more on the cluster page",
    "footer": "mongo-health · one note a week, whether or not anything happened.",
}


# How stale a sizing conclusion may be before it stops being worth repeating. It is a standing
# statement about the cluster rather than an event, so it does not belong to a week -- but one
# from a month ago describes a workload that may have changed.
SPARE_FRESH_DAYS = 14


def spare_capacity(findings: list[dict], now_ms: int) -> dict | None:
    """The most recent still-current statement that this cluster is larger than it needs."""
    recent = [f for f in findings
              if f.get("rule") == "oversized-cluster"
              and int(f.get("worstFromMs") or 0) >= now_ms - SPARE_FRESH_DAYS * 86_400_000]
    return max(recent, key=lambda f: int(f["worstFromMs"])) if recent else None


def week_of(findings: list[dict], since_ms: int) -> list[dict]:
    """Findings whose worst moment falls in the last seven days."""
    return [f for f in findings if int(f.get("worstFromMs") or 0) >= since_ms]


def read_findings(base: Path) -> list[dict]:
    path = base / "findings.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def read_summary(base: Path) -> dict:
    path = base / "summary.json"
    return json.loads(path.read_text()) if path.exists() else {}


# Warnings only, and few: a weekly note that lists every informational nit is skimmed past,
# and then so are the warnings in it.
CONFIG_LINES = 3


def compose(cluster_id: str, incidents: list, days_held: float, recipients: list[str],
            sender: str, spare: dict | None = None,
            recommendations: list | None = None, atlas: bool = True) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = (TEXT["subject_busy"].format(cluster=cluster_id, n=len(incidents))
                      if incidents else TEXT["subject_quiet"].format(cluster=cluster_id))

    extra = max(0.0, days_held - ATLAS_DAYS)

    def days(v: float) -> str:
        """"1 days" is the kind of detail that makes a reader trust the numbers less."""
        n = round(v)
        return "1 day" if n == 1 else f"{n} days"
    lines = [
        TEXT["busy"].format(n=len(incidents), cluster=cluster_id) if incidents
        else TEXT["quiet"].format(cluster=cluster_id),
        "",
    ]
    for m in incidents[:5]:
        lines.append(f"  [{m.severity.upper()}] {m.groups[0].headline()}")
    if len(incidents) > 5:
        lines.append(f"  … and {len(incidents) - 5} more")
    if incidents:
        lines.append("")
    if spare is not None:
        # Its own paragraph rather than a line in the incident list. Buried among "things worth
        # a look" it reads as another problem, and it is the opposite of one.
        lines += [TEXT["spare"].format(what=spare.get("what", "")), ""]
    warnings = [r for r in recommendations or [] if r.severity == "warning"]
    if warnings:
        lines.append(TEXT["config"])
        lines += [f"  - {r.title}. {r.fix}" for r in warnings[:CONFIG_LINES]]
        if len(warnings) > CONFIG_LINES:
            lines.append(TEXT["config_more"].format(n=len(warnings) - CONFIG_LINES))
        lines.append("")
    lines += [
        (TEXT["history_self"].format(days=days(days_held)) if not atlas
         else TEXT["history"].format(days=days(days_held), atlas=ATLAS_DAYS, extra=days(extra))
         if round(extra) >= 1
         else TEXT["history_new"].format(days=days(days_held), atlas=ATLAS_DAYS)),
        "",
        TEXT["footer"],
    ]
    msg.set_content("\n".join(lines))
    return mailheaders.stamp(msg, sender,
                             unsubscribe=f"unsubscribe@{mailheaders.sender_domain(sender)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--outbox", type=Path, default=Path("outbox"))
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--to", help="override every recipient")
    args = ap.parse_args()

    try:
        cfg = config.load(args.config)
    except config.ConfigError as e:
        print(e, file=sys.stderr)
        return 2
    smtp = config.smtp(cfg)
    sender = (smtp or {}).get("from", "collector@localhost")
    since_ms = int((datetime.now(timezone.utc) - timedelta(days=7)).timestamp() * 1000)

    sent = 0
    for spec in config.clusters(cfg):
        base = args.data / spec["cluster_id"]
        summary = read_summary(base)
        if not summary:
            # Nothing has been captured yet. A weekly note about a cluster that has never
            # reported would be the service congratulating itself for doing nothing.
            continue

        incidents = moments(group_findings(week_of(read_findings(base), since_ms)))
        days_held = float(summary.get("days_of_raw_ftdc") or 0)
        recipients = [args.to] if args.to else spec.get("notify") or []
        if not recipients:
            continue

        all_findings = read_findings(base)
        msg = compose(spec["cluster_id"], incidents, days_held, recipients, sender,
                      spare=spare_capacity(all_findings, int(datetime.now(timezone.utc)
                                                             .timestamp() * 1000)),
                      recommendations=recommend.evaluate(summary.get("nodes", []),
                                                         datetime.now(timezone.utc).date()),
                      atlas=(spec.get("source") or {}).get("type", "atlas") == "atlas")
        if args.send and smtp:
            import smtplib
            with smtplib.SMTP(smtp["host"], int(smtp.get("port", 587)), timeout=60) as server:
                if smtp.get("starttls", True):
                    server.starttls()
                if smtp.get("user"):
                    server.login(smtp["user"], smtp["password"])
                server.send_message(msg)
            print(f"[{spec['cluster_id']}] sent to {recipients[0]}")
        else:
            folder = args.outbox / spec['cluster_id']
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / f"digest-{now().replace(':', '').replace('-', '')}.eml"
            target.write_bytes(bytes(msg))
            print(f"[{spec['cluster_id']}] -> {target}")
        sent += 1

    print(f"{sent} digest(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
