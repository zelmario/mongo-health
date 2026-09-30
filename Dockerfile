# The collector and the engine it runs, in one image.
#
#   docker compose up -d                  # collect every hour, serve the report on :8080
#   docker compose run --rm collector onboard --group-id <atlas project id>
#
# Python runs the collector; Node runs the Big Hole engine the analysis happens in. Both are
# needed on every run, so they share an image rather than talking over a network.

FROM node:20-bookworm-slim

# supercronic runs the schedule: cron made for containers, logging to stdout and passing the
# environment through. Pinned by version and checksum (computed from the release download on
# 2026-09-30), so a rebuild cannot silently pick up a different binary.
ARG SUPERCRONIC=v0.2.49
ARG TARGETARCH
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 python3-venv ca-certificates curl \
        util-linux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) sum=a53ae236602c7338aba3fbaff40bda6300eae3b9fedb8261eb06cfe3724430c1 ;; \
      arm64) sum=02aa0cb229ba09050cba6638059dadb9eedc2276632ea43d6a57a2f8c1629dd5 ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/supercronic \
      "https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC}/supercronic-linux-${TARGETARCH:-amd64}"; \
    echo "${sum}  /usr/local/bin/supercronic" | sha256sum -c -; \
    chmod +x /usr/local/bin/supercronic; \
    apt-get purge -y curl; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY collector/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# The files belong to an unprivileged user. Which user the collector then runs as is decided
# when the container starts -- see docker/entrypoint.sh -- because it has to match whoever owns
# the ./config directory on the host, and the image cannot know that.
RUN useradd --uid 10001 --create-home bighole \
 && mkdir -p /app /var/lib/bighole/data /var/lib/bighole/site /etc/bighole \
 && chown bighole:bighole /app /var/lib/bighole /var/lib/bighole/data /var/lib/bighole/site \
      /etc/bighole
USER bighole

# The engine's dependencies first, against the lockfile, so editing source does not reinstall
# them. The development ones are needed: the analysis runs through vite-node. No browsers --
# playwright is there for the viewer's own tests, not for anything the collector does.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
COPY --chown=bighole:bighole big-hole/package.json big-hole/package-lock.json /app/big-hole/
RUN cd /app/big-hole && npm ci --no-audit --no-fund && npm cache clean --force

COPY --chown=bighole:bighole big-hole /app/big-hole
COPY --chown=bighole:bighole collector /app/collector
COPY --chown=bighole:bighole docker/entrypoint.sh docker/crontab /app/docker/

# The three places a run writes inside the engine: analyze.py copies the runner into tools/,
# vite-node keeps its cache under node_modules/.vite, and vite bundles its config into a
# temporary file beside vite.config.ts. Writable by whichever user runs it; the files already
# there stay read-only to everybody else.
RUN mkdir -p /app/big-hole/node_modules/.vite && chmod 1777 /app/big-hole /app/big-hole/tools \
      /app/big-hole/node_modules/.vite

# Starts as root only to pick the user; the entrypoint drops to it before doing anything else.
USER root

ENV CONFIG=/etc/bighole/config.json \
    DATA=/var/lib/bighole/data/clusters \
    OUTBOX=/var/lib/bighole/data/outbox \
    LOG_DIR=/var/lib/bighole/data/logs \
    LOCK=/var/lib/bighole/data/.run.lock \
    SITE=/var/lib/bighole/site \
    BIGHOLE=/app/big-hole \
    MPLCONFIGDIR=/tmp/matplotlib \
    PYTHONUNBUFFERED=1 \
    TZ=UTC

WORKDIR /app/collector
VOLUME ["/var/lib/bighole/data", "/var/lib/bighole/site"]
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["schedule"]
