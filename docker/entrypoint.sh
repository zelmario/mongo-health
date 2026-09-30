#!/usr/bin/env bash
# What the container does, by the first argument.
#
#   schedule            (default) run once now, then on the schedule in docker/crontab
#   run                 one collection round: capture, analyse, report, notify, prune
#   onboard ...         add Atlas clusters to the config and pull everything Atlas still holds
#   serve               the report, with the forms to add clusters and mark incidents fixed
#   poll                read clusters connected by connection string, every ten seconds
#   report | watchdog | digest ...   one of those on its own
#   anything else       executed as given, e.g. `bash`
#
# Email goes out only when the config has an "smtp" block. Without one, messages are written to
# the outbox volume instead, so a fresh install runs cleanly rather than failing every hour
# over mail it was never told how to send.
set -euo pipefail
cd /app/collector

# Run as whoever owns ./config on the host, so that a config written by `onboard` is theirs to
# edit, and one they wrote is readable here. The data volumes are Docker's own and follow along.
# A root-owned ./config means the host runs Docker as root; then so does this.
if [ "$(id -u)" = 0 ]; then
  owner="$(stat -c %u:%g /etc/bighole)"
  if [ "${owner%%:*}" != 0 ]; then
    # Recursively only when the owner changed: months of FTDC is gigabytes, and walking it on
    # every start would make each hourly run wait for it.
    for dir in /var/lib/bighole/data /var/lib/bighole/site; do
      [ "$(stat -c %u:%g "$dir")" = "$owner" ] || chown -R "$owner" "$dir"
    done
    export HOME=/tmp
    exec setpriv --reuid "${owner%%:*}" --regid "${owner##*:}" --clear-groups "$0" "$@"
  fi
fi

mkdir -p "$(dirname "$DATA")" "$DATA" "$OUTBOX" "$LOG_DIR" "$MPLCONFIGDIR"

has_smtp() {
  python3 - "$CONFIG" <<'PY' 2>/dev/null
import json, sys
try:
    sys.exit(0 if json.load(open(sys.argv[1])).get("smtp") else 1)
except Exception:
    sys.exit(1)
PY
}

send_flag() { has_smtp && echo "--send" || true; }

need_config() {
  if [ ! -f "$CONFIG" ]; then
    cat >&2 <<MSG
No config at $CONFIG.

Copy config.example.json to ./config/config.json and fill it in, or add Atlas clusters with:

  docker compose run --rm collector onboard --group-id <your Atlas project id>
MSG
    exit 2
  fi
}

cmd="${1:-schedule}"
[ $# -gt 0 ] && shift

case "$cmd" in
  schedule)
    # A first round straight away, so the report has something in it minutes after
    # `docker compose up` rather than at the next :05. The lock in run.sh keeps it from
    # overlapping the scheduled one if it runs long. With no config yet the schedule still
    # starts: the first cluster is usually added from the page, and the next round picks it up.
    [ -f "$CONFIG" ] && ./run.sh $(send_flag) --prune &
    exec supercronic -passthrough-logs /app/docker/crontab
    ;;
  run)
    if [ ! -f "$CONFIG" ]; then
      echo "no clusters yet — add one at http://localhost:8080/add"
      exit 0
    fi
    exec ./run.sh $(send_flag) --prune "$@"
    ;;
  onboard)
    # onboard.py starts a new file when there is none; an empty one it would fail to parse.
    [ -s "$CONFIG" ] || rm -f "$CONFIG"
    exec python3 onboard.py --config "$CONFIG" --data "$DATA" --site "$SITE" "$@"
    ;;
  serve)
    # Starts without a config: adding the first cluster from the page is what creates it.
    exec python3 server.py --config "$CONFIG" --data "$DATA" --site "$SITE" --bind 0.0.0.0 \
      --port 8080 "$@"
    ;;
  poll)
    # Starts without a config too, and picks up clusters as they are added.
    exec python3 poller.py --config "$CONFIG" --data "$DATA" "$@"
    ;;
  report)
    need_config
    exec python3 report.py --config "$CONFIG" --data "$DATA" --out "$SITE" "$@"
    ;;
  watchdog)
    exec python3 watchdog.py --config "$CONFIG" --data "$DATA" $(send_flag) "$@"
    ;;
  digest)
    need_config
    exec python3 digest.py --config "$CONFIG" --data "$DATA" --outbox "$OUTBOX" $(send_flag) "$@"
    ;;
  *)
    exec "$cmd" "$@"
    ;;
esac
