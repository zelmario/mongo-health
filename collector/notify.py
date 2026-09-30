#!/usr/bin/env python3
"""Send what was found: one email per cluster, with the chart of each finding.

Runs after `analyze.py`, last in the cron entry.

    python3 notify.py --config config.json                 # writes to outbox/, sends nothing
    python3 notify.py --config config.json --send          # actually sends
    python3 notify.py --config config.json --to me@x.com   # override the recipient

**Sending is opt-in.** The default writes the message to `outbox/` and marks nothing, so a
mistake costs a file rather than an email to a customer. An email cannot be recalled, and the
one failure mode this product cannot survive is being a source of noise -- so the safe thing
is the default and the irreversible thing needs saying out loud.

One email per cluster rather than per finding: three findings from one incident is one thing
that happened, and three emails about it is the noise that gets a service muted.

The chart is drawn here from the points `analyze.py` stored with each finding, rather than by
screenshotting the app. Everything was already decoded when the finding was made, and a chart
for an email wants the one metric that fired with its window marked -- not a dashboard with
eleven other panels around it. The link to Big Hole is what takes the reader to the full view.
"""
from __future__ import annotations

import argparse
import json
from urllib.parse import quote
import smtplib
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import make_msgid

import mailheaders
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no display in a cron job
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

import config  # noqa: E402
from group import group as group_findings, moments, name_nodes, subject_for  # noqa: E402
from state import now  # noqa: E402

# ---------------------------------------------------------------------------- strings

TEXT = {
    "subject_one": "[{cluster}] {title}",
    "subject_many": "[{cluster}] {n} findings",
    "heading": "What we found",
    "intro_one": "One thing worth looking at on {cluster}.",
    "intro_many": "{n} things worth looking at on {cluster}.",
    "and_more": "{n} more, in the report.",
    "open": "See the whole incident",
    "open_all": "Open {cluster} in the report",
    "window": "Worst window",
    "duration": "Time in state",
    "node": "Node",
    "episodes": "Episodes",
    "check": "What to check",
    "history_note": "You have {days} days of history for this cluster. Atlas keeps about {atlas}.",
    "footer": "Big Hole · you are receiving this because this cluster is being monitored.",
    "no_chart": "This finding is the absence of data, not a value — there is no series to plot.",
}

ATLAS_DAYS = 3

# Same palette as the report, so an email and the page look like one product.
INK = "#171b20"
INK_SOFT = "#5b666f"
EDGE = "#d3d8dd"
SIGNAL = "#c8500f"
SEVERITY_COLOR = {"critical": "#a32b22", "warning": "#9a6206", "info": "#5b666f"}


def read_pending(base: Path) -> list[dict]:
    path = base / "findings.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    return [r for r in rows if r.get("notified_at") is None]


def mark_notified(base: Path, ids: set[str], stamp: str) -> None:
    """Rewrite findings.jsonl with the sent ones marked.

    Append-only everywhere else, rewritten here because a finding's notified state is the one
    field that changes after the fact. Written to a temporary file and renamed, so an
    interrupted run cannot truncate the record of what was already sent.
    """
    path = base / "findings.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    for r in rows:
        if r["id"] in ids:
            r["notified_at"] = stamp
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n")
    tmp.replace(path)


def draw_chart(finding: dict, out: Path) -> bool:
    """One finding, one chart: the metric that fired, with its window and threshold marked."""
    chart = finding.get("chart")
    if not chart or not chart.get("t"):
        return False

    times = [datetime.fromtimestamp(ms / 1000, timezone.utc) for ms in chart["t"]]
    values = chart["v"]
    colour = SEVERITY_COLOR.get(finding["severity"], INK)

    # A forecast is the one finding that has not happened yet, and this renderer -- the plain
    # one, for email -- assumes throughout that it has: it shades the worst episode, labels the
    # limit "threshold", and puts clock times on the axis. All three are wrong for a projection
    # that spans weeks, so the three are answered here. Everything else in the mail's charts is
    # left exactly as it was; only this shape needed the second line.
    forecast = bool(chart.get("thresholdIsForecast"))

    fig, ax = plt.subplots(figsize=(7.2, 2.6), dpi=150)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    if not forecast:
        # The worst episode, shaded. This is what the email is about; everything either side is
        # context so the reader can see the shape arrive and recede.
        worst_from = datetime.fromtimestamp(finding["worstFromMs"] / 1000, timezone.utc)
        worst_to = datetime.fromtimestamp(finding["worstToMs"] / 1000, timezone.utc)
        ax.axvspan(worst_from, worst_to, color=colour, alpha=0.10, zorder=1)

    if chart.get("threshold") is not None:
        # "threshold 1.07374e+09" is a number the reader has to decode before they can see what
        # it is. When the chart says what its line is, say that instead.
        ax.axhline(chart["threshold"], color=SIGNAL, linewidth=1, linestyle=(0, (4, 3)),
                   zorder=2,
                   label=chart.get("thresholdNote") or f"threshold {chart['threshold']:g}")

    # NaNs stay as NaNs: matplotlib breaks the line there, which is the honest rendering of a
    # gap in the capture. Joining across it would draw data that was never collected.
    ax.plot(times, values, color=colour, linewidth=1.3, zorder=3, solid_capstyle="round",
            label="measured" if forecast else None)

    if forecast:
        # The projection, and the point past which nothing was measured. Without both, this is a
        # solid line reaching a limit -- which is a claim the finding does not make.
        for extra in (chart.get("series") or [])[1:]:
            ax.plot(times, extra["v"], color=INK_SOFT, linewidth=1.0, linestyle=(0, (5, 2)),
                    zorder=2, label=extra.get("label") or None)
        if chart.get("nowMs"):
            at = datetime.fromtimestamp(chart["nowMs"] / 1000, timezone.utc)
            ax.axvline(at, color=INK_SOFT, linewidth=0.8, linestyle=(0, (2, 3)), zorder=2)
            ax.annotate("now", xy=(at, 0.02), xycoords=("data", "axes fraction"),
                        xytext=(3, 0), textcoords="offset points",
                        fontsize=7, color=INK_SOFT, ha="left", va="bottom", zorder=4)

    if ax.get_legend_handles_labels()[1]:
        ax.legend(loc="upper left", frameon=False, fontsize=7,
                  labelcolor=INK_SOFT if forecast else SIGNAL, handlelength=1.6)

    ax.set_ylabel(finding.get("unit", ""), fontsize=7, color=INK_SOFT)
    ax.tick_params(labelsize=7, colors=INK_SOFT, length=3, width=0.6)
    # Clock times on an axis six weeks wide repeat "00:00" across the whole chart. The span
    # decides, not the rule: everything the mail draws today is an hour long except this.
    spans_days = (chart["t"][-1] - chart["t"][0]) > 2 * 86_400_000
    ax.xaxis.set_major_formatter(
        mdates.DateFormatter("%d %b" if spans_days else "%H:%M", tz=timezone.utc))
    ax.margins(x=0)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(EDGE)
        ax.spines[side].set_linewidth(0.8)
    ax.grid(axis="y", color=EDGE, linewidth=0.5, alpha=0.6)
    ax.set_axisbelow(True)

    fig.tight_layout(pad=0.6)
    fig.savefig(out, format="png", facecolor="white")
    plt.close(fig)
    return True


def when_ms(ms: float) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%d %b %Y %H:%M UTC")


def esc(value) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# How many incidents get the full treatment in an email.
#
# Not a layout choice. A capture of a bad day produced 37 findings, and an email carrying one
# chart each would be several megabytes of PNGs that nobody scrolls to the end of. The mail is
# an alert -- it exists to make somebody open the report -- so it carries the worst few in full
# and names the rest.
DETAILED_IN_MAIL = 5


def duration(seconds: int) -> str:
    """A length of time the way somebody says it out loud.

    "16158s" is a number to convert; "4.5 h" is a fact. The mail is read on a phone by
    somebody deciding whether this needs them now.
    """
    seconds = int(seconds or 0)
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def incident_url(site: str | None, finding_id: str) -> str | None:
    """Where the report page for this finding lives, when the site is served somewhere.

    `report_url` is unset on an install that only reads its report from disk, and then the
    email carries no links rather than links that go nowhere: a dead link in an email about a
    broken cluster is its own small betrayal. Any member of an incident has a page -- the site
    leaves a redirect for each -- so the id of whichever finding the email grouped on is enough.
    """
    return f"{site}/incidents/{quote(str(finding_id), safe='')}.html" if site else None


def render_html(cluster_id: str, incidents: list, cids: dict[str, str],
                days: float | None, context: dict | None = None,
                site: str | None = None) -> str:

    blocks = []
    for m in incidents[:DETAILED_IN_MAIL]:
        # What somebody changed shortly before this moment. Two dates and no verdict: the
        # product does not say one caused the other, because the reader is the one who knows
        # what they changed and why, and a wrong accusation costs more than a missing hint.
        changed = ""
        antes = (context or {}).get(m.from_ms, [])
        if antes:
            filas = "".join(
                f'<li><b>{esc(c["title"])}</b> — {esc(when_ms(c["worstFromMs"]))}</li>'
                for c in antes)
            changed = (
                f'<p style="margin:.7rem 0 0;padding:.5rem .7rem;background:#f2f4f6;'
                f'border-left:2px solid {EDGE};font:12px/1.5 -apple-system,system-ui,'
                f'sans-serif;color:{INK_SOFT};">'
                f'<b style="color:{INK};text-transform:uppercase;letter-spacing:.05em;'
                f'font-size:11px;">Changed shortly before this</b>'
                f'<ul style="margin:.3rem 0 0;padding-left:1.1rem;">{filas}</ul></p>')
        g = m.groups[0]
        f = g.worst
        colour = SEVERITY_COLOR.get(f["severity"], INK)
        cid = cids.get(f["id"])
        # Every node's chart and every earlier time are on the report page. The email is the
        # alert; it is not trying to be the report.
        url = incident_url(site, f["id"])
        more = (f'<p style="margin:14px 0 0;font:600 14px/1.5 -apple-system,system-ui,'
                f'sans-serif;"><a href="{esc(url)}" style="color:{SIGNAL};">'
                f'{TEXT["open"]} →</a></p>' if url else "")
        chart_html = (
            f'<img src="cid:{cid}" alt="{esc(f["metric"])}" '
            f'style="width:100%;max-width:640px;height:auto;display:block;margin:14px 0;">'
            if cid else
            f'<p style="margin:12px 0;color:{INK_SOFT};font-size:13px;font-style:italic;">'
            f'{TEXT["no_chart"]}</p>'
        )
        blocks.append(f"""
        <tr><td style="padding:22px 0;border-top:1px solid {EDGE};">
          <div style="font:600 11px/1 -apple-system,system-ui,sans-serif;
                      letter-spacing:.08em;text-transform:uppercase;color:{colour};">
            {esc(f["severity"])}</div>
          <h2 style="margin:6px 0 8px;font:600 19px/1.3 -apple-system,system-ui,sans-serif;
                     color:{INK};">{esc(m.headline())}</h2>
          <p style="margin:0;font:15px/1.55 -apple-system,system-ui,sans-serif;color:{INK};">
            {esc(f["what"])}</p>
          {chart_html}
          <table cellpadding="0" cellspacing="0" style="margin:4px 0 14px;
                 font:13px/1.7 -apple-system,system-ui,sans-serif;color:{INK_SOFT};">
            <tr><td style="padding-right:18px;">{TEXT["node"]}</td>
                <td style="color:{INK};font-family:ui-monospace,Menlo,monospace;">
                  {esc(name_nodes(g.nodes))}</td></tr>
            <tr><td style="padding-right:18px;">{TEXT["window"]}</td>
                <td style="color:{INK};">{when_ms(f["worstFromMs"])}</td></tr>
            {f'''<tr><td style="padding-right:18px;">{TEXT["duration"]}</td>
                <td style="color:{INK};">{duration(g.seconds_in_state)} on the worst-affected
                node</td></tr>''' if g.seconds_in_state else ""}
          </table>
          <p style="margin:0;font:13px/1.6 -apple-system,system-ui,sans-serif;color:{INK_SOFT};">
            <b style="color:{INK};">{TEXT["check"]}:</b> {esc(f["check"])}</p>
          {changed}
          {more}
        </td></tr>""")

    # Everything past the detailed few gets one line, so the reader knows what is waiting
    # rather than discovering later that the email showed a fifth of it.
    rest = incidents[DETAILED_IN_MAIL:]
    if rest:
        items = "".join(
            f'<li style="margin:0 0 4px;">'
            + (f'<a href="{esc(incident_url(site, m.groups[0].worst["id"]))}" '
               f'style="color:{INK};">{esc(m.headline())}</a>' if site
               else esc(m.headline()))
            + f' <span style="color:{INK_SOFT};">· {when_ms(m.from_ms)}</span></li>'
            for m in rest)
        blocks.append(f"""
        <tr><td style="padding:22px 0;border-top:1px solid {EDGE};">
          <h2 style="margin:0 0 10px;font:600 15px/1.3 -apple-system,system-ui,sans-serif;
                     color:{INK};">{esc(TEXT["and_more"].format(n=len(rest)))}</h2>
          <ul style="margin:0;padding-left:18px;
                     font:14px/1.6 -apple-system,system-ui,sans-serif;color:{INK};">
            {items}
          </ul>
        </td></tr>""")

    intro = (TEXT["intro_one"] if len(incidents) == 1 else TEXT["intro_many"]).format(
        n=len(incidents), cluster=esc(cluster_id))

    # After the findings rather than before them: whoever opened this wants to know what
    # happened first. Bordered instead of filled because many mail clients drop backgrounds.
    open_all = ""
    if site:
        open_all = (
            f'<p style="margin:22px 0 0;"><a href="{esc(site)}/index.html" '
            f'style="display:inline-block;padding:9px 16px;border:1px solid {SIGNAL};'
            f'color:{SIGNAL};text-decoration:none;'
            f'font:600 14px/1 -apple-system,system-ui,sans-serif;">'
            f'{esc(TEXT["open_all"].format(cluster=cluster_id))}</a></p>')
    history = ""
    if days:
        banked = f'<b style="color:{SIGNAL}">{days:.0f}</b>'
        note = TEXT["history_note"].format(days=banked, atlas=ATLAS_DAYS)
        history = (
            f'<p style="margin:16px 0 0;font:13px/1.6 -apple-system,system-ui,sans-serif;'
            f'color:{INK_SOFT};">{note}</p>'
        )

    return f"""<!doctype html>
<html><body style="margin:0;padding:24px 16px;background:#eef0f2;">
<table cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:680px;margin:0 auto;background:#fff;
              border:1px solid {EDGE};border-left:3px solid {SIGNAL};">
  <tr><td style="padding:26px 28px 0;">
    <div style="font:600 11px/1 -apple-system,system-ui,sans-serif;letter-spacing:.1em;
                text-transform:uppercase;color:{INK_SOFT};">{esc(cluster_id)}</div>
    <h1 style="margin:8px 0 6px;font:600 24px/1.25 -apple-system,system-ui,sans-serif;
               color:{INK};">{TEXT["heading"]}</h1>
    <p style="margin:0;font:15px/1.55 -apple-system,system-ui,sans-serif;color:{INK_SOFT};">
      {intro}</p>
  </td></tr>
  <tr><td style="padding:0 28px;"><table cellpadding="0" cellspacing="0" width="100%">
    {"".join(blocks)}
  </table></td></tr>
  <tr><td style="padding:0 28px 26px;">
    {open_all}
    {history}
    <p style="margin:22px 0 0;padding-top:16px;border-top:1px solid {EDGE};
              font:12px/1.5 -apple-system,system-ui,sans-serif;color:#8b959d;">
      {TEXT["footer"]}</p>
  </td></tr>
</table>
</body></html>"""


# Same window the web report uses. The two must agree: an email that mentions a resize and a
# page that does not, for the same incident, is the product contradicting itself.
CHANGE_CONTEXT_HOURS = 72


def changes_before(all_findings: list[dict], before_ms: int) -> list[dict]:
    """Settings that moved on this cluster shortly before a moment, most recent per setting.

    Read from every finding on record rather than from what is pending: the change that
    explains tonight's incident may well have been written to disk days ago, and by then it is
    no longer pending anything. It is context, and context does not expire when it is read.
    """
    window = before_ms - CHANGE_CONTEXT_HOURS * 3_600_000
    seen: dict[str, dict] = {}
    for f in all_findings:
        if f.get("rule") != "setting-changed":
            continue
        at = int(f.get("worstFromMs") or 0)
        if not (window <= at < before_ms):
            continue
        best = seen.get(f["title"])
        if best is None or at > int(best["worstFromMs"]):
            seen[f["title"]] = f
    return sorted(seen.values(), key=lambda f: -int(f["worstFromMs"]))


def render_text(cluster_id: str, incidents: list, context: dict | None = None,
                site: str | None = None) -> str:
    """The plain-text half. Not a courtesy: some people read mail in a terminal."""
    lines = [f"{cluster_id} — {len(incidents)} incident(s)", ""]
    for m in incidents[:DETAILED_IN_MAIL]:
        g = m.groups[0]
        f = g.worst
        lines += [
            f"[{m.severity.upper()}] {m.headline()}",
            f"  {f['what']}",
            f"  {TEXT['node']}: {name_nodes(g.nodes)}",
            f"  {TEXT['window']}: {when_ms(f['worstFromMs'])} · "
            f"{duration(g.seconds_in_state)} on the worst-affected node",
            f"  {TEXT['check']}: {f['check']}",
        ]
        for c in (context or {}).get(m.from_ms, []):
            lines.append(f"  Changed before this: {c['title']} — {when_ms(c['worstFromMs'])}")
        # The URL in full, on its own line: a terminal mail client will not hide it behind
        # words, and this half of the message is read by people who copy links by hand.
        if site:
            lines.append(f"  {incident_url(site, f['id'])}")
        lines.append("")
    rest = incidents[DETAILED_IN_MAIL:]
    if rest:
        lines.append(TEXT["and_more"].format(n=len(rest)))
        lines += [f"  {when_ms(m.from_ms)}  {m.headline()}" for m in rest]
        lines.append("")
    if site:
        lines += [TEXT["open_all"].format(cluster=cluster_id) + f": {site}/index.html", ""]
    lines.append(TEXT["footer"])
    return "\n".join(lines)


def build_message(cluster_id: str, findings: list[dict], recipients: list[str],
                  sender: str, work: Path, days: float | None,
                  all_findings: list[dict] | None = None,
                  site: str | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    # Grouped by symptom, so the subject counts incidents rather than findings. Six findings
    # from one bad afternoon are one bad afternoon, and "15 findings" is a subject nobody opens.
    groups = group_findings(findings)
    incidents = moments(groups)
    msg["Subject"] = subject_for(cluster_id, incidents)

    # One chart per group, drawn from its worst member: three identical charts of the same
    # symptom on three nodes is the same noise as three emails about it.
    charts: list[tuple[str, Path]] = []
    cids: dict[str, str] = {}
    for f in [m.groups[0].worst for m in incidents[:DETAILED_IN_MAIL]]:
        png = work / f"{f['id']}.png"
        if draw_chart(f, png):
            cid = make_msgid(domain=mailheaders.sender_domain(sender))
            cids[f["id"]] = cid[1:-1]  # cid: reference drops the angle brackets
            charts.append((cid, png))

    context = {m.from_ms: changes_before(all_findings or findings, m.from_ms)
               for m in incidents}
    msg.set_content(render_text(cluster_id, incidents, context, site))
    msg.add_alternative(render_html(cluster_id, incidents, cids, days, context, site),
                        subtype="html")

    html_part = msg.get_payload()[1]
    for cid, png in charts:
        html_part.add_related(png.read_bytes(), maintype="image", subtype="png", cid=cid)

    # The headers a filter reads before it reads anything else. `unsubscribe` points at a real
    # inbox rather than a URL -- see mailheaders for why a half-built one-click link is worse
    # than none.
    domain = mailheaders.sender_domain(sender)
    return mailheaders.stamp(msg, sender, unsubscribe=f"unsubscribe@{domain}")


def notify_cluster(spec: dict, root: Path, outbox: Path, send: bool,
                   override_to: str | None, smtp: dict | None, verbose: bool = True) -> int:
    cluster_id = spec["cluster_id"]
    base = root / cluster_id

    pending = read_pending(base)

    # Rules switched off for this cluster. Filtered here, at the last step before
    # an email is composed, so that muting changes exactly one thing: whether we write. The
    # findings were still detected, still stored, and still appear in the report marked as
    # muted -- a monitoring product that hides what it found is lying to the person paying it
    # to look. What it stops is the part that arrives in somebody's inbox at 3am.
    #
    # They are marked as notified along with everything else below, rather than left pending for
    # ever: un-muting a rule should start telling you about what happens NEXT, not deliver a
    # month of backlog the moment you change your mind.
    muted = set(spec.get("mute") or [])
    silenced = [f for f in pending if f.get("rule") in muted]
    if silenced:
        pending = [f for f in pending if f.get("rule") not in muted]
        if verbose:
            print(f"[{cluster_id}] {len(silenced)} finding(s) muted "
                  f"({', '.join(sorted({f['rule'] for f in silenced}))})")
        # Marked here rather than on the way out, because what happens to them does not depend
        # on the rest. Doing it at the end missed the path where everything left over is
        # informational: that branch returns early, so the muted findings stayed pending for
        # ever and every hourly run printed the same "N finding(s) muted" line.
        mark_notified(base, {f["id"] for f in silenced}, now())
        if not pending:
            return 0
    # Context does not send mail on its own. A configuration change is something somebody chose
    # -- a resize, a member added -- and telling them what they just did is the noise that
    # teaches people to filter this address. It still travels in the message when there IS
    # something to report, which is the whole point of detecting it: "the cache was halved on
    # the 14th" is worth reading beside "eviction has been stalling since the 14th", and worth
    # nothing on its own.
    #
    # The findings stay pending rather than being marked notified, so the first real incident
    # carries whatever context accumulated before it.
    if pending and all(f.get("severity") == "info" for f in pending):
        if verbose:
            print(f"[{cluster_id}] {len(pending)} informational finding(s), "
                  f"nothing worth an email yet")
        return 0
    if not pending:
        if verbose:
            print(f"[{cluster_id}] nothing pending")
        return 0

    recipients = [override_to] if override_to else spec.get("notify") or []
    if not recipients:
        print(f"[{cluster_id}] {len(pending)} pending but no recipient "
              f"configured — skipping", file=sys.stderr)
        return 0

    days = None
    summary_path = base / "summary.json"
    if summary_path.exists():
        days = json.loads(summary_path.read_text()).get("days_of_history")

    work = outbox / cluster_id
    work.mkdir(parents=True, exist_ok=True)
    sender = (smtp or {}).get("from", "bighole@localhost")
    # Every finding on record, not just the pending ones: the resize that explains tonight's
    # incident was written days ago and stopped being pending the moment it was read past.
    everything = [json.loads(line)
                  for line in (base / "findings.jsonl").read_text().splitlines() if line]
    site = f"{spec['report_url']}/{quote(cluster_id, safe='')}" if spec.get("report_url") else None
    msg = build_message(cluster_id, pending, recipients, sender, work, days, everything, site)

    if not send:
        # Stamped rather than a fixed `message.eml`: an outbox that silently overwrites
        # leaves one file whose name says nothing about when it was written or whether it
        # still reflects reality. A stale message claiming three findings, sitting next to a
        # cluster that currently has none, is exactly the confusion worth avoiding.
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = work / f"{stamp}.eml"
        target.write_bytes(bytes(msg))
        if verbose:
            print(f"[{cluster_id}] {len(pending)} finding(s) -> {target}")
            print("  not sent (pass --send to actually deliver)")
        return 0

    if not smtp:
        raise RuntimeError("--send needs an \"smtp\" block in the config")

    host, port = smtp["host"], int(smtp.get("port", 587))
    with smtplib.SMTP(host, port, timeout=60) as server:
        if smtp.get("starttls", True):
            server.starttls()
        if smtp.get("user"):
            server.login(smtp["user"], smtp["password"])
        server.send_message(msg)

    mark_notified(base, {f["id"] for f in pending}, now())
    if verbose:
        print(f"[{cluster_id}] sent {len(pending)} finding(s) "
              f"to {', '.join(recipients)}")
    return len(pending)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--outbox", type=Path, default=Path("outbox"))
    ap.add_argument("--cluster", help="only this cluster id")
    ap.add_argument("--to", help="send everything to this address instead")
    ap.add_argument("--send", action="store_true",
                    help="actually deliver; without this the message is only written to disk")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    try:
        cfg = config.load(args.config)
    except config.ConfigError as e:
        print(e, file=sys.stderr)
        return 2
    smtp = config.smtp(cfg)
    clusters = config.clusters(cfg)
    if args.cluster:
        clusters = [c for c in clusters if c["cluster_id"] == args.cluster]

    sent = failed = 0
    for spec in clusters:
        try:
            sent += notify_cluster(spec, args.data, args.outbox, args.send,
                                   args.to, smtp, verbose=not args.quiet)
        except Exception as e:
            failed += 1
            print(f"[{spec['cluster_id']}] FAILED: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)

    if not args.quiet and args.send:
        print(f"{sent} finding(s) delivered")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
