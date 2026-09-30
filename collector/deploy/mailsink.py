#!/usr/bin/env python3
"""An SMTP server that delivers to a directory instead of to the internet.

    python3 deploy/mailsink.py --port 1025 --out outbox/delivered

For a machine that is being treated as the deployment box without being one yet. The collector
refuses `--send` without an `smtp` block, and the point of `--send` is not the sending: it is
that a delivered finding is *marked* as delivered, so the next hourly run reports what is new
rather than the same incident for ever. Pointing it at a sink exercises that path honestly,
and the mail lands somewhere it can be read.

Deliberately not a feature of the product. On the real server this is replaced by a real host
in the `smtp` block, and nothing else changes.
"""
from __future__ import annotations

import argparse
import asyncio
import email
import email.policy
import re
from datetime import datetime, timezone
from pathlib import Path

from aiosmtpd.controller import Controller


def slug(value: str) -> str:
    """A filename that cannot escape the output directory."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)[:80] or "unknown"


class Sink:
    def __init__(self, out: Path) -> None:
        self.out = out
        self.out.mkdir(parents=True, exist_ok=True)

    async def handle_DATA(self, server, session, envelope):
        message = email.message_from_bytes(envelope.content, policy=email.policy.default)
        when = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        # The recipient in the name, because the question asked of this directory is almost
        # always "did anything go to that address".
        to = slug(envelope.rcpt_tos[0] if envelope.rcpt_tos else "nobody")
        path = self.out / f"{when}-{to}.eml"
        # Never overwrite: two findings delivered in the same second are two mails.
        n = 2
        while path.exists():
            path = self.out / f"{when}-{to}-{n}.eml"
            n += 1
        path.write_bytes(envelope.content)
        print(f"{path.name}  to={envelope.rcpt_tos}  subject={message['Subject']!r}",
              flush=True)
        return "250 Message accepted for delivery"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1025)
    ap.add_argument("--out", type=Path, default=Path("outbox/delivered"))
    args = ap.parse_args()

    controller = Controller(Sink(args.out.resolve()), hostname=args.host, port=args.port)
    controller.start()
    print(f"listening on {args.host}:{args.port}, writing to {args.out.resolve()}", flush=True)
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
