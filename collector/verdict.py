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

# Findings that are listed but do not decide the verdict alone when they are this short, in
# seconds, on one member. Packet loss is the case: Cluster1 read "Needs attention" for 45 s of
# TCP retransmissions on one member, the only time in 22 days, while the server never noticed.
# The rule keeps its 30 s sustain because a 41 s injected loss is exactly what it must catch;
# what changes is only how loudly a lone blip speaks. Two members at once is not a blip: that
# is what they share, and it still counts.
BRIEF = {"packets-retransmitted": 60}

LABELS = {
    "unwatched": "Not being watched",
    "pending": "Not checked yet",
    "analyzing": "Analyzing FTDC",
    "waiting": "Waiting for the first data",
    "capturing": "Collecting the FTDC",
    "capture_failed": "Capture failed",
    "failed": "Analysis failed",
    # Uploaded files and nothing more. Never "At risk" or "Healthy": those describe a cluster
    # as it is now, and these describe a capture that ended.
    "files_problems": "Problems found in the FTDC",
    "files_clean": "Nothing found in the FTDC",
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


def _ago(ms: int, now_ms: int, archive: bool = False) -> str:
    hours = (now_ms - ms) / HOUR_MS
    if hours < 1:
        return "in the last hour of the FTDC" if archive else "in the last hour"
    if hours < 48:
        n = int(hours)
        span = f"{n} hour{'s' if n != 1 else ''}"
    else:
        span = f"{int(hours // 24)} days"
    return f"{span} before the FTDC ends" if archive else f"{span} ago"


def _describe(found: list, now_ms: int, window: str, archive: bool = False) -> str:
    """The worst moment by name, and how many more there are."""
    worst = found[0]
    line = f"{worst.headline()}, {_ago(worst.to_ms, now_ms, archive)}"
    rest = len(found) - 1
    if rest:
        tail = f"in its last {window}" if archive else f"in the last {window}"
        line += f" — and {rest} more incident{'s' if rest != 1 else ''} {tail}"
    return line + "."


def _brief_and_alone(f: dict, findings: list[dict]) -> bool:
    """A short episode of a BRIEF rule with no other member showing the same within a minute."""
    limit = BRIEF.get(f.get("rule"))
    if limit is None or (f.get("secondsInState") or 0) >= limit:
        return False
    lo, hi = int(f["fromMs"]) - 60_000, int(f["toMs"]) + 60_000
    return not any(o is not f and o.get("rule") == f["rule"] and o.get("node") != f.get("node")
                   and int(o["fromMs"]) <= hi and int(o["toMs"]) >= lo for o in findings)


def evaluate(findings: list[dict], now: datetime, silent_hours: float | None,
             captured: bool, days_held: float, analysed: bool = True,
             ends: datetime | None = None, analyzing: dict | None = None,
             arriving: dict | None = None, failed: dict | None = None,
             capturing: dict | None = None, capture_failed: dict | None = None) -> Verdict:
    """The verdict for one cluster.

    `silent_hours` is how long data has not been arriving, when that is past what is allowed
    (see report.silent_hours); `days_held` is how much history the checks ran over; `analysed`
    is whether any analysis has run over what was captured.

    `ends` is set for a cluster that is only files somebody handed over, with nothing sending
    more: the newest sample in them. Nobody promised data after it, so its age is not silence,
    and the files are judged as of that moment. Judged against the clock instead, a capture
    with 31 incidents in it read "Not being watched" a day after it was taken.

    `analyzing` is set while an analysis is running over new files: what it is reading.

    `arriving` is what the poller says about a cluster with nothing captured yet: the members it
    is reading, or the error that stops it. A cluster added a minute ago read "Not being
    watched" until its first capture, while its samples were already coming in.

    `capturing` is what a first fetch is doing (see capture.CaptureMarker). On Atlas that fetch
    took 38 minutes for 20 days of an M10, and the page called the cluster unwatched all along.
    One sentence for every stage: the fetch builds and downloads a window of history after
    another, and the progress bar under this says which.
    """
    if not captured and capturing:
        return Verdict("capturing", "Collecting everything Atlas still holds for this cluster, "
                                    "newest first: from a few days to several weeks of FTDC. "
                                    "On an M10 with 20 days it took 38 minutes. The analysis "
                                    "starts when it lands.")
    if not captured and capture_failed:
        # Before the first capture, the error is the only thing known about the cluster.
        return Verdict("capture_failed", f"The first capture failed: {capture_failed.get('error')}"
                                         f". It is tried again on the next round, within the "
                                         f"hour. On Atlas the bundle already built is kept, so "
                                         f"only the download is repeated.")
    if not captured:
        if arriving and arriving.get("error"):
            return Verdict("unwatched", f"The collector cannot read this cluster: "
                                        f"{arriving['error']}")
        if arriving and arriving.get("uploaded"):
            # An upload read "Samples are arriving from 3 members" as if something sent them.
            n = arriving["members"]
            return Verdict("pending", f"Files from {n} member{'s' if n != 1 else ''} have "
                                      f"arrived, but no check has run over them yet. This page "
                                      f"updates when the analysis finishes.")
        if arriving and arriving.get("members"):
            n = arriving["members"]
            return Verdict("waiting", f"Samples are arriving from {n} member"
                                      f"{'s' if n != 1 else ''}. The first capture and "
                                      f"analysis run within a few minutes.")
        return Verdict("unwatched", "Nothing has been captured from this cluster yet.")
    if analyzing:
        n = analyzing.get("files") or 0
        if analyzing.get("whole"):
            what = "all the FTDC held"
        else:
            # The engine reads from a day before the last analysis, so the bar under this counts
            # more files than arrived: 16 against 6 on an hourly Cluster1 round.
            what = (f"{n} new file{'s' if n != 1 else ''}" if n else "the new files") \
                + " and the day before them"
        return Verdict("analyzing", f"Reading {what}. This page updates when the analysis "
                                    f"finishes.")
    # Files and no analysis has no findings either, and read as "Healthy" for the minutes a
    # first analysis takes: a clean bill of health from checks that had not run.
    if not analysed and failed:
        return Verdict("failed", f"The analysis of the files received failed, so no check has "
                                 f"run over them: {failed.get('error')}. It is tried again "
                                 f"on the next round.")
    if not analysed:
        return Verdict("pending", "Files have arrived, but no check has run over them yet. "
                                  "This page updates when the analysis finishes.")
    archive = ends is not None
    if archive:
        now = ends
    elif silent_hours is not None:
        span = (f"{silent_hours / 24:.0f} days" if silent_hours >= 48
                else f"{silent_hours:.0f} hours")
        return Verdict("unwatched",
                       f"No data has arrived for {span}, so nothing here describes the cluster "
                       f"as it is now.")

    now_ms = int(now.timestamp() * 1000)
    serious = [f for f in findings if f.get("severity") in ("critical", "warning")]
    # Still on the page, still in the incident list; just not the reason for the verdict.
    blips = [f for f in serious if _brief_and_alone(f, findings)
             and int(f["toMs"]) >= now_ms - ATTENTION_DAYS * 24 * HOUR_MS]
    serious = [f for f in serious if not any(f is b for b in blips)]
    aside = (f" {len(blips)} brief network blip{'s' if len(blips) != 1 else ''} on a single "
             f"member {'is' if len(blips) == 1 else 'are'} listed below." if blips else "")
    # A rolling restart is information on its own, but when it is what the serious signals
    # came from, it is what the verdict should name first: "members not answering" on Cluster1
    # was the restart Atlas did, and said alone it read as an outage.
    restarts = [f for f in findings if f.get("rule") == "rolling-restart"]
    recent = [m for m in moments(group_findings(
        [f for f in serious + restarts
         if int(f["toMs"]) >= now_ms - ATTENTION_DAYS * 24 * HOUR_MS]))
        if any(g.severity in ("critical", "warning") for g in m.groups)]

    def order(m):
        # Critical first, then the most recent: the thing to read first is the worst thing that
        # is closest to now.
        return ({"critical": 0, "warning": 1}.get(m.severity, 2), -m.to_ms)

    critical_today = sorted((m for m in recent if m.severity == "critical"
                             and m.to_ms >= now_ms - AT_RISK_HOURS * HOUR_MS), key=order)
    # Said once, after the finding: which moment "the last day" means, and what keeps it going.
    upto = (f" Judged on the FTDC provided, which ends {ends:%d %b %Y %H:%M} UTC. Upload newer "
            f"files from this page to bring it up to date." if archive else "")
    if archive:
        if recent:
            ranked = sorted(recent, key=order)
            return Verdict("files_problems", _describe(ranked, now_ms, "week", archive) + upto,
                           ranked)
        held = f"{days_held:.0f} days" if days_held >= 2 else f"{days_held * 24:.0f} hours"
        return Verdict("files_clean", f"Nothing critical or worth a look in the last "
                                      f"{ATTENTION_DAYS} days of the FTDC. Every check ran over "
                                      f"{held} of history.{aside}{upto}")

    if critical_today:
        return Verdict("at_risk", _describe(critical_today, now_ms, "day"), critical_today)

    if recent:
        ranked = sorted(recent, key=order)
        return Verdict("attention", _describe(ranked, now_ms, "week"), ranked)

    held = (f"{days_held:.0f} days" if days_held >= 2 else
            f"{days_held * 24:.0f} hours" if days_held > 0 else "the history held")
    return Verdict("healthy",
                   f"Nothing critical or worth a look in the last {ATTENTION_DAYS} days. "
                   f"Every check ran over {held} of history.{aside}")
