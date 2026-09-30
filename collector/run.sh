#!/usr/bin/env bash
# One cron entry: capture, analyse, rebuild the report, notify.
#
#   ./run.sh                    # nothing irreversible: no email sent, nothing deleted
#   ./run.sh --send             # also deliver the email
#   ./run.sh --send --prune     # also delete raw FTDC past its retention
#   ./run.sh --cluster orders-prod --send
#
# Install as:
#
#   5 * * * *  cd /srv/collector && ./run.sh --send
#
# Nothing here is clever on purpose. It runs four commands in order, refuses to run twice at
# once, records what happened, and exits non-zero if any step failed so that cron's own
# mail-on-failure does its job. A collector that dies quietly is worse than one that never
# ran, because the report would keep showing yesterday's clean bill of health.

# No `-e`: a failing step must not abort the rest. If Atlas is unreachable, capture fails but
# analysing what is already on disk, refreshing the page and sending pending findings are all
# still worth doing -- and the page is where "the collector stopped capturing" becomes visible.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 2

CONFIG="${CONFIG:-config.json}"
DATA="${DATA:-data}"
OUTBOX="${OUTBOX:-outbox}"
SITE="${SITE:-site}"
LOG_DIR="${LOG_DIR:-logs}"
LOCK="${LOCK:-.run.lock}"

# Outbound heartbeat. Optional, and the only part of this that survives the machine itself
# dying: a watchdog running here cannot report that "here" is switched off. Point HEARTBEAT_URL
# at any service that alerts when pings stop (healthchecks.io, Cronitor and friends all take a
# plain GET, and append /fail for an explicit failure).
HEARTBEAT_URL="${HEARTBEAT_URL:-}"

ping_heartbeat() {  # $1: "" for success, "/fail" for failure
  [ -n "$HEARTBEAT_URL" ] || return 0
  curl -fsS -m 10 --retry 3 "${HEARTBEAT_URL}${1:-}" -o /dev/null 2>/dev/null \
    || say "  heartbeat ping failed (the run itself was unaffected)"
}

SEND=""
PRUNE=""
PASSTHROUGH=()
for arg in "$@"; do
  case "$arg" in
    --send) SEND="--send" ;;
    --prune) PRUNE="--apply" ;;
    *) PASSTHROUGH+=("$arg") ;;
  esac
done

mkdir -p "$LOG_DIR"
# One log file per month: rotation without logrotate, and a year of history is a handful of
# files rather than a decision anyone has to make.
LOG="$LOG_DIR/run-$(date -u +%Y-%m).log"

say() { printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }

# ---------------------------------------------------------------------- preconditions

if [ ! -f "$CONFIG" ]; then
  say "FATAL: $CONFIG is missing — copy config.example.json"
  ping_heartbeat /fail
  exit 2
fi
if ! command -v npx >/dev/null 2>&1; then
  say "FATAL: npx is missing — the analysis engine runs inside Big Hole"
  ping_heartbeat /fail
  exit 2
fi

# The advisor's own copy, beside the collector. Not a shared checkout of the
# public viewer: this one carries the advisor's rules.
BIGHOLE_DIR="${BIGHOLE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/big-hole}"
# The runner itself is copied into tools/ by analyze.py on every run; what has to exist is
# the Big Hole it runs inside.
if [ ! -d "$BIGHOLE_DIR/src/insights" ]; then
  say "FATAL: $BIGHOLE_DIR is not the advisor's Big Hole (no src/insights) — set BIGHOLE"
  exit 2
fi
export BIGHOLE="$BIGHOLE_DIR"

# A run can outlast the hour before the next one: a first capture pulls days of history,
# and the first analysis of a cluster decodes everything held to build its daily summaries. Two overlapping runs would fight over
# state.json and could send the same finding twice, so the second one steps aside and waits
# for the next slot rather than queueing behind the first.
exec 9>"$LOCK"
if ! flock -n 9; then
  say "another run is still going (lock: $LOCK) — skipping this slot"
  exit 0
fi

# ------------------------------------------------------------------------------- steps

failed=()

step() {
  local name="$1"; shift
  say "→ $name"
  if "$@" >>"$LOG" 2>&1; then
    say "  $name ok"
  else
    local code=$?
    say "  $name FAILED (exit $code)"
    failed+=("$name")
  fi
}

say "=== run starting${SEND:+ (delivery enabled)}${PRUNE:+ (pruning enabled)} ==="

step capture python3 capture.py --config "$CONFIG" --data "$DATA" "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"
step analyze python3 analyze.py --config "$CONFIG" --data "$DATA" "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"
step report python3 report.py --config "$CONFIG" --data "$DATA" --out "$SITE"

# Notify runs last and only reads what analyse committed, so it is safe even when an earlier
# step failed: without new findings it has nothing pending and says so.
step notify python3 notify.py --config "$CONFIG" --data "$DATA" --outbox "$OUTBOX" \
  ${SEND:+"$SEND"} "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"

# Pruning goes after everything else so a run always analyses and reports on the widest data
# it has, and only then drops what is past retention. Like --send, deleting is opt-in: without
# --prune this reports what it would remove and removes nothing.
step prune python3 prune.py --config "$CONFIG" --data "$DATA" \
  ${PRUNE:+"$PRUNE"} "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"

# ------------------------------------------------------------------------------ result

if [ ${#failed[@]} -eq 0 ]; then
  ping_heartbeat
  say "=== run finished, all steps ok ==="
  exit 0
fi

# Report the failure explicitly rather than staying silent. Silence would eventually raise the
# alarm anyway, but only after the grace period -- and a run that failed loudly should not have
# to wait that long to be noticed.
ping_heartbeat /fail
say "=== run finished with ${#failed[@]} failed step(s): ${failed[*]} ==="
say "    see $LOG"
exit 1
