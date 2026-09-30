#!/usr/bin/env bash
# Does the sending domain have what a filter looks for before trusting its mail?
#
#   ./deploy/check-mail-dns.sh                 # reads BIGHOLE_MAIL_FROM
#   ./deploy/check-mail-dns.sh example.com
#
# Everything this product produces leaves by email, and mail that fails these checks does not
# bounce -- it is quietly filed in spam. The customer sees nothing and concludes the tool found
# nothing, which is the same failure this project has already met twice: silence that looks
# exactly like good news.
#
# So it is checked here rather than discovered from a customer saying "I never get anything".
# Exits non-zero if SPF or DMARC are missing, because those two are the difference between
# "might be delivered" and "will probably not be".
set -uo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  FROM="${BIGHOLE_MAIL_FROM:-}"
  DOMAIN="${FROM##*@}"
  DOMAIN="${DOMAIN%>}"
fi
[ -n "$DOMAIN" ] || { echo "usage: $0 <domain>, or set BIGHOLE_MAIL_FROM" >&2; exit 2; }

command -v dig >/dev/null || { echo "dig is not installed" >&2; exit 2; }

problems=0
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  MISSING  %s\n' "$*"; problems=$((problems + 1)); }
note() { printf '  note  %s\n' "$*"; }

echo "checking mail DNS for $DOMAIN"

# ---- SPF: which servers are allowed to send as this domain.
SPF="$(dig +short TXT "$DOMAIN" | tr -d '"' | grep -i '^v=spf1' | head -1)"
if [ -n "$SPF" ]; then
  ok "SPF · $SPF"
  case "$SPF" in
    *"+all"*) note "SPF ends in +all, which authorises the entire internet — that is no SPF" ;;
    *"~all"*|*"-all"*) ;;
    *) note "SPF has no ~all or -all, so it says nothing about senders not listed" ;;
  esac
else
  bad "SPF — without it, mail claiming to be from $DOMAIN has nothing vouching for it"
fi

# ---- DMARC: what a receiver should do when SPF and DKIM disagree, and where to report.
DMARC="$(dig +short TXT "_dmarc.$DOMAIN" | tr -d '"' | grep -i '^v=DMARC1' | head -1)"
if [ -n "$DMARC" ]; then
  ok "DMARC · $DMARC"
  case "$DMARC" in
    *"rua="*) ;;
    *) note "DMARC has no rua= address, so nobody ever sees the reports that say what is failing" ;;
  esac
else
  bad "DMARC — Gmail and Yahoo require it from anything sending at volume"
fi

# ---- DKIM: the signature itself. The selector is chosen by whoever sends, so this cannot be
# discovered -- only checked against the ones people actually use.
found=""
for selector in "${BIGHOLE_DKIM_SELECTOR:-}" default google mail smtp s1 s2 selector1 k1 mandrill; do
  [ -n "$selector" ] || continue
  if [ -n "$(dig +short TXT "$selector._domainkey.$DOMAIN" | head -1)" ]; then
    found="$selector"
    break
  fi
done
if [ -n "$found" ]; then
  ok "DKIM · selector '$found' publishes a key"
else
  note "no DKIM key found at the usual selectors. It may exist under one this script does not"
  note "guess — set BIGHOLE_DKIM_SELECTOR. If it does not exist, SPF alone will not carry you."
fi

echo
if [ "$problems" -gt 0 ]; then
  echo "$problems record(s) missing — see deploy/mail-dns.md for exactly what to publish"
  exit 1
fi
echo "the sending domain is set up"
