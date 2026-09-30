"""The email: what it claims, and what it must never do on its own.

Two kinds of assertion here, and they carry different weight.

The first is about content. An email is the only part of this product most customers will ever
see, so "the subject counts incidents rather than findings" is a product requirement, not a
formatting preference — it is the difference between a message that gets opened and one that
becomes a filter rule.

The second is about restraint. Sending is irreversible: `--send` must be the only path that
delivers anything, and nothing may be marked as notified unless it actually went out.
Otherwise a failed send silently swallows the finding forever.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from notify import build_message, draw_chart, mark_notified, read_pending  # noqa: E402

T0 = 1_754_000_000_000
HOUR = 3_600_000


def a_finding(fid="f1", rule="memory-low", node="n0", severity="critical",
              title="Host running out of memory", chart=True, notified=None,
              at=None) -> dict:
    inicio = T0 if at is None else at
    return {
        "id": fid, "customer_id": "acme", "cluster_id": "prod",
        "detected_at": "2026-08-09T12:00:00+00:00", "notified_at": notified,
        "rule": rule, "title": title, "severity": severity,
        "node": f"{node}.abcde.mongodb.net", "metric": "pct(a,b)", "episodes": 1,
        "fromMs": inicio, "toMs": inicio + HOUR,
        "worstFromMs": inicio, "worstToMs": inicio + HOUR,
        "secondsInState": 600, "peak": 95, "unit": "percent",
        "what": "Available memory is low.", "check": "Look at the cache size.",
        "chart": ({"t": [inicio + i * 1000 for i in range(60)],
                   "v": [float(i) for i in range(60)],
                   "threshold": 20, "fromMs": inicio, "toMs": inicio + HOUR} if chart else None),
    }


def text_of(msg) -> str:
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            return part.get_payload(decode=True).decode()
    return ""


def html_of(msg) -> str:
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            return part.get_payload(decode=True).decode()
    return ""


# ------------------------------------------------------------------------ what it claims

def test_one_symptom_across_nodes_is_one_subject_line(tmp_path: Path):
    """Six nodes with the same problem is one problem, described by its scope.

    "on 6 nodes" is the right kind of six: it says how wide the incident is, not how many
    rows a database happens to hold.
    """
    findings = [a_finding(fid=f"f{i}", node=f"n{i}") for i in range(6)]
    subject = build_message("prod", findings, ["a@x"], "c@x", tmp_path, days=30.0)["Subject"]
    assert "on 6 nodes" in subject
    assert "finding" not in subject.lower()


def test_subject_counts_incidents_not_findings(tmp_path: Path):
    """Nine findings from three problems at the same time read as ONE incident.

    The first real email said "15 findings", which is a subject nobody opens. Nine is no
    better. Three problems that started together are one bad moment with three signals — and
    the subject says so without ever mentioning nine.
    """
    findings = [a_finding(fid=f"{r}{n}", rule=f"rule-{r}", title=f"Problem {r}", node=f"n{n}")
                for r in range(3) for n in range(3)]
    subject = build_message("prod", findings, ["a@x"], "c@x", tmp_path, days=30.0)["Subject"]
    assert "9" not in subject, "counted the findings"
    assert "2 other signals" in subject, "one moment, three signals"


def test_subject_counts_separate_moments_separately(tmp_path: Path):
    """Three problems hours apart are three incidents, and the subject counts them."""
    findings = [a_finding(fid=f"m{i}", rule=f"rule-{i}", title=f"Problem {i}",
                          at=T0 + i * 6 * HOUR)
                for i in range(3)]
    subject = build_message("prod", findings, ["a@x"], "c@x", tmp_path, days=30.0)["Subject"]
    assert "2 more" in subject


def test_a_long_list_is_capped_in_the_mail(tmp_path: Path):
    """The mail is an alert, not the report.

    One chart per incident on a bad day is several megabytes of PNGs nobody scrolls through,
    so the worst few go in full and the rest are named.
    """
    import notify

    findings = [a_finding(fid=f"m{i}", rule=f"rule-{i}", title=f"Problem {i}",
                          at=T0 + i * 6 * HOUR)
                for i in range(notify.DETAILED_IN_MAIL + 4)]
    msg = build_message("prod", findings, ["a@x"], "c@x", tmp_path, days=30.0)

    charts = sum(1 for part in msg.walk() if part.get_content_type().startswith("image/"))
    assert charts <= notify.DETAILED_IN_MAIL, "an unbounded number of charts went out"

    body = "".join(part.get_payload(decode=True).decode()
                   for part in msg.walk() if part.get_content_type() == "text/plain")
    assert "4 more, in the report" in body, "the rest were dropped silently"


def test_subject_names_a_lone_incident(tmp_path: Path):
    msg = build_message("prod", [a_finding()], ["a@x"], "c@x", tmp_path, days=None)
    assert "Host running out of memory" in msg["Subject"]
    assert "prod" in msg["Subject"]


def test_one_chart_per_incident_not_per_node(tmp_path: Path):
    """Three identical charts of one symptom on three nodes is the same noise as three emails."""
    findings = [a_finding(fid=f"f{i}", node=f"n{i}") for i in range(3)]
    msg = build_message("prod", findings, ["a@x"], "c@x", tmp_path, days=None)
    images = [p for p in msg.walk() if p.get_content_type() == "image/png"]
    assert len(images) == 1


def test_the_body_names_every_affected_node(tmp_path: Path):
    """The subject counts, the body enumerates: the reader needs to know where to look."""
    findings = [a_finding(fid=f"f{i}", node=f"n{i}") for i in range(3)]
    body = text_of(build_message("prod", findings, ["a@x"], "c@x", tmp_path, days=None))
    assert all(f"n{i}" in body for i in range(3))


def test_a_gap_finding_says_why_it_has_no_chart(tmp_path: Path):
    """Its evidence is the absence of data. Drawing a line there would invent the data.

    Saying nothing would instead look like a bug in the report.
    """
    f = a_finding(rule="ftdc-long-outage", title="Node stopped reporting", chart=False)
    html = html_of(build_message("prod", [f], ["a@x"], "c@x", tmp_path, days=None))
    assert "absence of data" in html


def test_both_plain_text_and_html_are_present(tmp_path: Path):
    """Some people read mail in a terminal, and an HTML-only alert is unreadable there."""
    msg = build_message("prod", [a_finding()], ["a@x"], "c@x", tmp_path, days=None)
    kinds = {p.get_content_type() for p in msg.walk()}
    assert "text/plain" in kinds and "text/html" in kinds


def test_history_is_mentioned_when_known(tmp_path: Path):
    """The quiet sales argument: what you have that Atlas no longer does."""
    html = html_of(build_message("prod", [a_finding()], ["a@x"], "c@x", tmp_path, days=47.0))
    assert "47" in html


def test_charts_are_referenced_by_cid(tmp_path: Path):
    """Inline images, not attachments: an attachment does not render in the message body."""
    msg = build_message("prod", [a_finding()], ["a@x"], "c@x", tmp_path, days=None)
    html = html_of(msg)
    cids = [p["Content-ID"].strip("<>") for p in msg.walk()
            if p.get_content_type() == "image/png"]
    assert cids and all(f"cid:{c}" in html for c in cids)


# ------------------------------------------------------------------------ what it must not do

def test_only_unnotified_findings_are_pending(tmp_path: Path):
    """Deduplication's last line of defence, right before the irreversible step."""
    path = tmp_path / "findings.jsonl"
    path.write_text("\n".join(json.dumps(f) for f in [
        a_finding(fid="new"),
        a_finding(fid="old", notified="2026-08-08T00:00:00+00:00"),
    ]))
    assert [f["id"] for f in read_pending(tmp_path)] == ["new"]


def test_marking_notified_preserves_everything_else(tmp_path: Path):
    """Rewriting the file must not lose findings that were not part of this send."""
    path = tmp_path / "findings.jsonl"
    path.write_text("\n".join(json.dumps(f) for f in [
        a_finding(fid="a"), a_finding(fid="b"), a_finding(fid="c")]))

    mark_notified(tmp_path, {"a", "c"}, "2026-08-09T13:00:00+00:00")

    rows = {json.loads(l)["id"]: json.loads(l)["notified_at"]
            for l in path.read_text().splitlines() if l}
    assert rows["a"] and rows["c"]
    assert rows["b"] is None
    assert len(rows) == 3, "no finding may be dropped by the rewrite"


def test_marking_leaves_no_temporary_file(tmp_path: Path):
    """The rewrite is atomic: a crash mid-write must not truncate the record of what was sent."""
    path = tmp_path / "findings.jsonl"
    path.write_text(json.dumps(a_finding(fid="a")))
    mark_notified(tmp_path, {"a"}, "2026-08-09T13:00:00+00:00")
    assert not (tmp_path / "findings.tmp").exists()
    assert json.loads(path.read_text().strip())["notified_at"]


def test_missing_findings_file_is_not_an_error(tmp_path: Path):
    """A cluster that never had a finding is the normal case, not a failure."""
    assert read_pending(tmp_path) == []


# ------------------------------------------------------------------------------- the chart

def test_chart_is_drawn_when_there_are_points(tmp_path: Path):
    out = tmp_path / "c.png"
    assert draw_chart(a_finding(), out) is True
    assert out.stat().st_size > 1000


def test_no_chart_without_points(tmp_path: Path):
    out = tmp_path / "c.png"
    assert draw_chart(a_finding(chart=False), out) is False
    assert not out.exists()


# --------------------------------------------------------------- the way back to the report

def a_message(tmp_path: Path, findings=None):
    return build_message("prod", findings or [a_finding()], ["ops@example.com"],
                         "bighole@localhost", tmp_path, days=9.4)


def test_a_collector_with_no_web_app_sends_no_links(tmp_path: Path, monkeypatch):
    """Self-hosted, no web: a dead link in an email about a broken cluster is a small betrayal."""
    monkeypatch.delenv("BIGHOLE_PUBLIC_URL", raising=False)
    msg = a_message(tmp_path)

    assert "href=" not in html_of(msg)
    assert "Open prod in Big Hole" not in text_of(msg)


# ------------------------------------------------------- context does not send mail alone

def _cluster_with(tmp_path: Path, findings: list[dict]) -> tuple[dict, Path, Path]:
    base = tmp_path / "acme" / "prod"
    base.mkdir(parents=True)
    (base / "findings.jsonl").write_text(
        "".join(json.dumps(f) + "\n" for f in findings))
    return ({"customer_id": "acme", "cluster_id": "prod", "notify": ["dba@x"]},
            tmp_path, tmp_path / "outbox")


def _finding(severity: str, rule: str, ident: str) -> dict:
    return {"id": ident, "rule": rule, "title": "t", "severity": severity, "node": "db1",
            "fromMs": 1_786_000_000_000, "toMs": 1_786_000_060_000,
            "worstFromMs": 1_786_000_000_000, "worstToMs": 1_786_000_060_000,
            "secondsInState": 60, "what": "w", "check": "c", "metric": "m",
            "notified_at": None}


def test_a_resize_on_its_own_sends_nothing(tmp_path: Path):
    """Telling somebody what they just did is the noise that gets an address filtered.

    A configuration change is a decision, not a fault. It is detected so it can sit beside a
    real incident — "the cache was halved on the 14th" next to "eviction has been stalling
    since the 14th" — and on its own it is worth nothing.
    """
    from notify import notify_cluster

    spec, root, outbox = _cluster_with(tmp_path, [_finding("info", "setting-changed", "a")])
    notify_cluster(spec, root, outbox, send=False, override_to=None, smtp=None, verbose=False)

    assert not list(outbox.rglob("*.eml"))


def test_the_resize_still_travels_with_a_real_incident(tmp_path: Path):
    """And this is why it is detected at all."""
    from notify import notify_cluster

    # Three days earlier, which is the case this exists for: the change is its own moment in
    # the report, named, instead of being folded into the incident's "and N other signals".
    contexto = _finding("info", "setting-changed", "a")
    contexto["title"] = "The cache was resized"
    for k in ("fromMs", "toMs", "worstFromMs", "worstToMs"):
        contexto[k] -= 3 * 86_400_000
    spec, root, outbox = _cluster_with(tmp_path, [
        contexto,
        _finding("critical", "read-tickets-saturated", "b"),
    ])
    notify_cluster(spec, root, outbox, send=False, override_to=None, smtp=None, verbose=False)

    sent = list(outbox.rglob("*.eml"))
    assert len(sent) == 1
    # Read as a message rather than as bytes: the body is encoded, so a substring search over
    # the raw file passes or fails on the transfer encoding rather than on the content.
    import email, email.policy
    body = email.message_from_bytes(sent[0].read_bytes(), policy=email.policy.default)
    text = "".join(part.get_content() for part in body.walk()
                   if part.get_content_type() == "text/plain")
    assert "cache was resized" in text


def test_context_stays_pending_until_something_happens(tmp_path: Path):
    """Not marked as notified, so the first real incident carries what accumulated before it."""
    from notify import notify_cluster, read_pending

    spec, root, outbox = _cluster_with(tmp_path, [_finding("info", "setting-changed", "a")])
    notify_cluster(spec, root, outbox, send=False, override_to=None, smtp=None, verbose=False)

    assert len(read_pending(root / "acme" / "prod")) == 1


def test_the_email_names_what_changed_before_the_incident(tmp_path: Path):
    """The line the whole feature exists for, in the half a customer reads first.

    A resize on its own sends nothing; beside an incident it is the first thing anybody would
    want to know, and it has to be in the email rather than only behind a link — the email is
    what gets read on a phone at the moment somebody decides whether this needs them.
    """
    from notify import notify_cluster
    import email, email.policy

    cambio = _finding("info", "setting-changed", "a")
    cambio["title"] = "The cache was resized"
    cambio["metric"] = "serverStatus.wiredTiger.cache.maximum bytes configured"
    for k in ("fromMs", "toMs", "worstFromMs", "worstToMs"):
        cambio[k] -= 2 * 86_400_000
    cambio["notified_at"] = "2026-08-14T00:00:00+00:00"   # ya reportado antes, sigue siendo contexto

    spec, root, outbox = _cluster_with(tmp_path, [
        cambio, _finding("critical", "read-tickets-saturated", "b"),
    ])
    notify_cluster(spec, root, outbox, send=False, override_to=None, smtp=None, verbose=False)

    sent = list(outbox.rglob("*.eml"))[0]
    body = email.message_from_bytes(sent.read_bytes(), policy=email.policy.default)
    text = "".join(p.get_content() for p in body.walk()
                   if p.get_content_type() == "text/plain")
    assert "Changed before this" in text
    assert "cache was resized" in text


def test_a_change_from_last_month_is_not_dragged_in(tmp_path: Path):
    """Past three days it stops being context and starts being the product insinuating a cause.

    Measured, not guessed: with a two-week window one resize decorated 23 of the next 24
    incidents on a real cluster, and a line that appears on everything is one nobody reads.
    """
    from notify import notify_cluster
    import email, email.policy

    viejo = _finding("info", "setting-changed", "a")
    viejo["title"] = "The cache was resized"
    for k in ("fromMs", "toMs", "worstFromMs", "worstToMs"):
        viejo[k] -= 30 * 86_400_000
    viejo["notified_at"] = "2026-07-01T00:00:00+00:00"

    spec, root, outbox = _cluster_with(tmp_path, [
        viejo, _finding("critical", "read-tickets-saturated", "b"),
    ])
    notify_cluster(spec, root, outbox, send=False, override_to=None, smtp=None, verbose=False)

    sent = list(outbox.rglob("*.eml"))[0]
    body = email.message_from_bytes(sent.read_bytes(), policy=email.policy.default)
    text = "".join(p.get_content() for p in body.walk()
                   if p.get_content_type() == "text/plain")
    assert "Changed before this" not in text


# ------------------------------------------------------------------- rules somebody muted

import notify  # noqa: E402

def test_a_muted_rule_sends_no_email(tmp_path, monkeypatch):
    """The alternative to offering this is not a quieter product: it is a customer who filters
    the address, and then the message that mattered is filtered too."""
    base = tmp_path / "acme" / "prod"
    base.mkdir(parents=True)
    (base / "findings.jsonl").write_text(json.dumps({
        "id": "f1", "rule": "cache-full", "severity": "critical", "title": "Cache full",
        "node": "n1", "fromMs": 0, "toMs": 1000, "worstFromMs": 0, "worstToMs": 1000,
        "secondsInState": 1, "what": "", "check": "", "notified_at": None}) + "\n")

    sent = notify.notify_cluster(
        {"customer_id": "acme", "cluster_id": "prod", "notify": ["a@b.test"],
         "mute": ["cache-full"]},
        tmp_path, tmp_path / "outbox", send=False, override_to=None, smtp=None, verbose=False)

    assert sent == 0
    # And it does not come back on every run for ever.
    rows = [json.loads(l) for l in (base / "findings.jsonl").read_text().splitlines() if l]
    assert rows[0]["notified_at"] is not None


def test_muting_one_rule_does_not_silence_the_others(tmp_path):
    """The failure that would make this worse than useless: asking for quiet about one thing and
    getting quiet about everything."""
    base = tmp_path / "acme" / "prod"
    base.mkdir(parents=True)
    (base / "findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in [
        {"id": "f1", "rule": "cache-full", "severity": "critical", "title": "Cache full",
         "node": "n1", "fromMs": 0, "toMs": 1000, "worstFromMs": 0, "worstToMs": 1000,
         "secondsInState": 1, "what": "", "check": "", "notified_at": None},
        {"id": "f2", "rule": "replication-lag", "severity": "critical", "title": "Lag",
         "node": "n1", "fromMs": 0, "toMs": 1000, "worstFromMs": 0, "worstToMs": 1000,
         "secondsInState": 1, "what": "", "check": "", "notified_at": None}]))

    notify.notify_cluster(
        {"customer_id": "acme", "cluster_id": "prod", "notify": ["a@b.test"],
         "mute": ["cache-full"]},
        tmp_path, tmp_path / "outbox", send=False, override_to=None, smtp=None, verbose=False)

    written = list((tmp_path / "outbox").rglob("*.eml"))
    assert len(written) == 1, "the one that was not muted still goes out"
    body = written[0].read_text()
    assert "Lag" in body and "Cache full" not in body


def test_muted_findings_are_settled_even_when_the_rest_is_only_context(tmp_path):
    """The path that was missed. Everything left over being informational returns early, so the
    muted findings stayed pending for ever and every hourly run printed the same line about
    them -- the exact noise muting exists to remove.
    """
    base = tmp_path / "acme" / "prod"
    base.mkdir(parents=True)
    (base / "findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in [
        {"id": "f1", "rule": "cache-full", "severity": "critical", "title": "Cache full",
         "node": "n1", "fromMs": 0, "toMs": 1000, "worstFromMs": 0, "worstToMs": 1000,
         "secondsInState": 1, "what": "", "check": "", "notified_at": None},
        {"id": "f2", "rule": "setting-changed", "severity": "info", "title": "Cache resized",
         "node": "n1", "fromMs": 0, "toMs": 1000, "worstFromMs": 0, "worstToMs": 1000,
         "secondsInState": 1, "what": "", "check": "", "notified_at": None}]))

    notify.notify_cluster(
        {"customer_id": "acme", "cluster_id": "prod", "notify": ["a@b.test"],
         "mute": ["cache-full"]},
        tmp_path, tmp_path / "outbox", send=False, override_to=None, smtp=None, verbose=False)

    rows = {r["id"]: r for r in
            (json.loads(l) for l in (base / "findings.jsonl").read_text().splitlines() if l)}
    assert rows["f1"]["notified_at"] is not None, "muted: settled"
    assert rows["f2"]["notified_at"] is None, "context: still waiting for something to travel with"
