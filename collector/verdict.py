"""One answer to "is my cluster healthy?", and the sentence that justifies it.

Everything else on a cluster's page is evidence. This is the conclusion, and it is the first
thing read, so it is deliberately simple enough to predict: whoever reads "needs attention"
should be able to say why without opening anything.

    unwatched   no data is arriving, so nothing below describes the present
    at_risk     something critical happened in the last day
    attention   something critical or worth a look happened in the last week, or a resource is
                forecast to run out
    healthy     none of that, over however much history was checked

Only critical and warning findings move it. Informational ones -- a setting that changed, spare
capacity, an unusual-but-harmless reading -- are context, and a verdict that turned amber on
every resize would be read as noise within a week.

Judged on when a finding ENDED, not when it started: a saturation that began six days ago and is
still going is happening now.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from group import group as group_findings, moments

HOUR_MS = 3_600_000
AT_RISK_HOURS = 24
ATTENTION_DAYS = 7

LABELS = {
    "unwatched": "Not being watched",
    "at_risk": "At risk",
    "attention": "Needs attention",
    "healthy": "Healthy",
}


@dataclass
class Verdict:
    state: str                     # one of LABELS
    reason: str                    # one sentence, the "why"
    evidence: list = field(default_factory=list)   # the moments that decided it, worst first

    @property
    def label(self) -> str:
        return LABELS[self.state]


def _ago(ms: int, now_ms: int) -> str:
    hours = (now_ms - ms) / HOUR_MS
    if hours < 1:
        return "in the last hour"
    if hours < 48:
        n = int(hours)
        return f"{n} hour{'s' if n != 1 else ''} ago"
    n = int(hours // 24)
    return f"{n} days ago"


def _describe(found: list, now_ms: int, window: str) -> str:
    """The worst moment by name, and how many more there are."""
    worst = found[0]
    line = f"{worst.headline()}, {_ago(worst.to_ms, now_ms)}"
    rest = len(found) - 1
    if rest:
        line += f" — and {rest} more incident{'s' if rest != 1 else ''} in the last {window}"
    return line + "."


def evaluate(findings: list[dict], now: datetime, silent_hours: float | None,
             captured: bool, days_held: float) -> Verdict:
    """The verdict for one cluster.

    `silent_hours` is how long data has not been arriving, when that is past what is allowed
    (see report.silent_hours); `days_held` is how much history the checks ran over.
    """
    if not captured:
        return Verdict("unwatched", "Nothing has been captured from this cluster yet.")
    if silent_hours is not None:
        span = (f"{silent_hours / 24:.0f} days" if silent_hours >= 48
                else f"{silent_hours:.0f} hours")
        return Verdict("unwatched",
                       f"No data has arrived for {span}, so nothing here describes the cluster "
                       f"as it is now.")

    now_ms = int(now.timestamp() * 1000)
    serious = [f for f in findings if f.get("severity") in ("critical", "warning")]
    recent = moments(group_findings(
        [f for f in serious if int(f["toMs"]) >= now_ms - ATTENTION_DAYS * 24 * HOUR_MS]))

    def order(m):
        # Critical first, then the most recent: the thing to read first is the worst thing that
        # is closest to now.
        return ({"critical": 0, "warning": 1}.get(m.severity, 2), -m.to_ms)

    critical_today = sorted((m for m in recent if m.severity == "critical"
                             and m.to_ms >= now_ms - AT_RISK_HOURS * HOUR_MS), key=order)
    if critical_today:
        return Verdict("at_risk", _describe(critical_today, now_ms, "day"), critical_today)

    if recent:
        ranked = sorted(recent, key=order)
        return Verdict("attention", _describe(ranked, now_ms, "week"), ranked)

    held = (f"{days_held:.0f} days" if days_held >= 2 else
            f"{days_held * 24:.0f} hours" if days_held > 0 else "the history held")
    return Verdict("healthy",
                   f"Nothing critical or worth a look in the last {ATTENTION_DAYS} days. "
                   f"Every check ran over {held} of history.")
