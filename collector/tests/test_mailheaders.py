"""The headers that decide whether any of this arrives.

Everything the product produces leaves by email, and mail that fails a filter does not bounce:
it is filed away, and the customer concludes the tool found nothing rather than that it never
came. That is the same shape as the two failures this project has already had — silence that
looks exactly like good news — which is why these are worth pinning down.
"""
from __future__ import annotations

import sys
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import mailheaders  # noqa: E402

SENDER = "Collector <collector@example.com>"


def a_message() -> EmailMessage:
    m = EmailMessage()
    m["From"] = SENDER
    m["To"] = "dba@example.com"
    m["Subject"] = "[prod] Read ticket pool saturated"
    m.set_content("…")
    return m


def test_the_message_id_is_at_the_sending_domain():
    """It used to be absent, so Python invented one from the local hostname.

    Mail from `collector@example.com` went out announcing itself as coming from `dbhost`,
    which is a mismatch that costs reputation for no reason at all.
    """
    m = mailheaders.stamp(a_message(), SENDER)
    assert m["Message-ID"].endswith("@example.com>")


def test_a_date_is_always_present():
    """Required by RFC 5322. `send_message` adds one; the outbox path writes bytes directly
    and was producing messages without it."""
    assert mailheaders.stamp(a_message(), SENDER)["Date"]


def test_automated_mail_says_so():
    """RFC 3834. Without it a customer's out-of-office replies to a robot, and in the worst
    case the two of them keep going."""
    assert mailheaders.stamp(a_message(), SENDER)["Auto-Submitted"] == "auto-generated"


def test_alerts_carry_a_way_to_stop_them():
    """The header filters most want on recurring mail, and the honest thing besides: an alert
    nobody can turn off is the noise that ends subscriptions."""
    m = mailheaders.stamp(a_message(), SENDER, unsubscribe="unsubscribe@example.com")
    assert m["List-Unsubscribe"] == "<mailto:unsubscribe@example.com>"


def test_a_message_somebody_asked_for_has_nothing_to_unsubscribe_from():
    """A password reset is not a subscription, and offering to end one is nonsense."""
    assert "List-Unsubscribe" not in mailheaders.stamp(a_message(), SENDER)


def test_it_never_overwrites_what_a_caller_set():
    """A caller that set something meant it, and this runs after them."""
    m = a_message()
    m["Message-ID"] = "<mine@example.org>"
    assert mailheaders.stamp(m, SENDER)["Message-ID"] == "<mine@example.org>"


def test_a_broken_sender_does_not_crash_the_send():
    """Misconfiguration must degrade, not stop the mail: a message with an odd Message-ID still
    arrives, and one that was never built does not."""
    m = mailheaders.stamp(a_message(), "not-an-address")
    assert m["Message-ID"].endswith("@localhost>")
