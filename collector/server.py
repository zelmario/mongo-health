#!/usr/bin/env python3
"""The report, served, with the few things that need somewhere to write.

    python3 server.py --config config.json --data data --site site --port 8080

Serves the static site the collector builds, exactly as a plain web server would, and adds:

    GET  /add                   add a cluster: on Atlas, or on your own servers
    POST /add/atlas             list the clusters in an Atlas project
    POST /add/atlas/pick        add the chosen ones, and start their first capture
    POST /add/onprem/upload     receive FTDC files: an archive, unpacked member by member
    POST /add/onprem            a connection string (tested first), uploaded files, or both
    POST /add/onprem/confirm    add it once the connection test passed
    POST /<cluster>/resolve     mark an incident as fixed, with an optional note
    POST /<cluster>/reopen      put it back

Standard library only: this is a handful of forms on a machine the user controls, and every
dependency is one more thing to keep patched on a box that holds API keys.

**Who can use it.** Bound to localhost by docker-compose, like the report before it. Every POST
must come from a page this server served (its Origin or Referer names this host), so a web page
elsewhere cannot make the browser add a cluster or close an incident behind the user's back.
Set UI_PASSWORD and every request needs it too -- for anybody who puts this on a network.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import config
import ftdcfiles
import onboard
import resolutions

HERE = Path(__file__).resolve().parent

# Discovered Atlas projects waiting for the user to pick clusters, by a one-time token. Kept in
# memory rather than round-tripped through the form, so a private key never travels back to the
# browser once it has been sent. Short-lived: a pick after ten minutes starts again.
PENDING: dict[str, tuple[float, dict]] = {}
PENDING_TTL = 600

# One rebuild at a time: two browsers clicking at once must not write the site concurrently.
REBUILD = threading.Lock()


def esc(v) -> str:
    return (str(v).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


class App:
    def __init__(self, config_path: Path, data: Path, site: Path, password: str | None,
                 start_capture=None, clock=None):
        self.config_path = config_path
        self.data = data
        self.site = site
        self.password = password
        # How a first capture is started. A parameter so tests can see it was asked for without
        # starting one.
        self.start_capture = start_capture or self._start_capture
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    # ---------------------------------------------------------------- effects

    def rebuild(self) -> None:
        """The site, rebuilt so the page the user is sent back to shows what they just did."""
        import report  # noqa: PLC0415 -- matplotlib is slow to import; not needed to serve

        with REBUILD:
            try:
                clusters = config.load_clusters(self.config_path)
            except config.ConfigError:
                clusters = []
            report.build(clusters, self.data, self.site, self.clock())

    def _start_capture(self, cluster_id: str, delay: int = 0) -> None:
        """A full collection round in the background. The lock in run.sh keeps it from colliding
        with another round; LOCK_WAIT makes it wait for that one rather than skip, because
        skipping left a cluster added a minute after another at "0 MB" until the next hour."""
        env = dict(os.environ, CONFIG=str(self.config_path), DATA=str(self.data),
                   SITE=str(self.site), LOCK_WAIT="1")
        # Behind an Atlas first fetch that wait is most of an hour, and the page promised "a
        # few minutes". Said to the report, which names what it waits for; capture.py clears it
        # when the cluster's turn comes.
        try:
            with self._round_lock():
                pass
        except RoundRunning:
            base = self.data / cluster_id
            base.mkdir(parents=True, exist_ok=True)
            (base / "queued.json").write_text(json.dumps(
                {"since": self.clock().isoformat()}))
        command = [str(HERE / "run.sh"), "--cluster", cluster_id]
        if delay:
            command = ["sh", "-c", f'sleep {int(delay)}; exec "$0" "$@"', *command]
        subprocess.Popen(command, cwd=HERE, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)

    def add_entry(self, entry: dict) -> None:
        """One cluster into the config, written aside and renamed so the collector never reads
        half a file."""
        cfg = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
        cfg.setdefault("clusters", [])
        if any(c.get("id") == entry["id"] for c in cfg["clusters"]):
            raise ValueError(f'there is already a cluster called "{entry["id"]}"')
        cfg["clusters"].append(entry)
        tmp = self.config_path.with_name(f".{self.config_path.name}.tmp")
        tmp.write_text(json.dumps(cfg, indent=2) + "\n")
        tmp.chmod(0o600)
        tmp.replace(self.config_path)
        config.load(self.config_path)  # refuse to leave behind a config that does not load

    def update_entry(self, cluster_id: str, **fields) -> None:
        """Fields of one cluster, written the same way as an added one."""
        cfg = json.loads(self.config_path.read_text())
        entry = next(c for c in cfg["clusters"] if c.get("id") == cluster_id)
        entry.update(fields)
        tmp = self.config_path.with_name(f".{self.config_path.name}.tmp")
        tmp.write_text(json.dumps(cfg, indent=2) + "\n")
        tmp.chmod(0o600)
        tmp.replace(self.config_path)
        config.load(self.config_path)

    def remove_entry(self, cluster_id: str, delete_data: bool) -> None:
        """One cluster out of the config, its pages with it, and its data if asked.

        The data is kept unless asked: an Atlas cluster's FTDC is gone from Atlas within days,
        so what is held here is the only copy, and the baseline cannot be rebuilt from anything.
        Deleting waits for no round: it refuses while one runs, rather than pull files out from
        under an analysis that is reading them.
        """
        cfg = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
        kept = [c for c in cfg.get("clusters", []) if c.get("id") != cluster_id]
        if len(kept) == len(cfg.get("clusters", [])):
            raise KeyError(cluster_id)
        gone = next(c for c in cfg["clusters"] if c.get("id") == cluster_id)
        with self._round_lock() if delete_data else _nothing():
            cfg["clusters"] = kept
            tmp = self.config_path.with_name(f".{self.config_path.name}.tmp")
            tmp.write_text(json.dumps(cfg, indent=2) + "\n")
            tmp.chmod(0o600)
            tmp.replace(self.config_path)
            if delete_data:
                shutil.rmtree(self.data / cluster_id, ignore_errors=True)
        # Without its config entry the report no longer builds these, and they would stay
        # reachable for ever, describing a cluster nobody is looking at.
        shutil.rmtree(self.site / cluster_id, ignore_errors=True)
        # Its SFTP key and confirmed host keys, when they sit in config/keys under the names
        # given to them there. Credentials, not data: kept, they would let this machine into
        # the hosts with nothing left to use them. A key kept anywhere else is not ours.
        keys = (self.config_path.parent / "keys").resolve()
        made = {keys / f"{cluster_id}_ed25519", keys / f"{cluster_id}.known_hosts"}
        for field in ("identity", "known_hosts"):
            held = (gone.get("source") or {}).get(field)
            if held and Path(held).resolve() in made:
                Path(held).unlink(missing_ok=True)

    def _round_lock(self):
        """The lock run.sh holds for a whole round, taken without waiting."""
        return _flock(Path(os.environ.get("LOCK") or HERE / ".run.lock"))


class RoundRunning(Exception):
    """A collection round holds the lock."""


class _flock:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self):
        self.fh = open(self.path, "a")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.fh.close()
            raise RoundRunning() from None
        return self

    def __exit__(self, *exc) -> None:
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


class _nothing:
    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


def remove_page(cluster_id: str, held_mb: float, error: str = "") -> str:
    """The confirmation: what goes, what can stay, and that the data is the only copy."""
    held = (f"{held_mb:.0f} MB" if held_mb >= 1 else "less than 1 MB") if held_mb else "nothing"
    return page(f"Remove {cluster_id} · mongo-health", f"""
    <p><a href="/{esc(cluster_id)}/index.html" class="back">← {esc(cluster_id)}</a></p>
    <h1>Remove {esc(cluster_id)}?</h1>
    {flash(error)}
    <form method="post" action="/remove/{esc(cluster_id)}">
      <input type="hidden" name="confirm" value="{esc(cluster_id)}">
      <div class="card">
        <p>It stops being collected and analysed, leaves the report, and no more email is sent
          about it.</p>
        <label class="pick">
          <input type="checkbox" name="delete_data" value="1">
          <span>Also delete everything held for it: {esc(held)} of FTDC, the findings and the
            baseline. <b>This cannot be undone.</b> For a cluster on Atlas, the FTDC held here
            is the only copy left.</span>
        </label>
        <p class="hint">Left unticked, the data stays on disk, and adding a cluster with the
          same name later picks it up again.</p>
      </div>
      <button type="submit">Remove {esc(cluster_id)}</button>
      <a href="/{esc(cluster_id)}/index.html" class="back" style="margin-left:1rem">Cancel</a>
    </form>""")


def page(title: str, body: str) -> str:
    """The same frame and stylesheet as the report, so a form does not feel like another
    product."""
    import report  # noqa: PLC0415

    return report.layout(title, body, "/", datetime.now(timezone.utc))


CREATE_USER = ('db.getSiblingDB("admin").createUser({user: "mongo-health", '
               'pwd: passwordPrompt(),\n  roles: [{role: "clusterMonitor", db: "admin"}]})')

# Uploads larger than this are refused before a byte is written: a diagnostic.data holds at
# most ~200 MB per member by default, so this is room for a large replica set and no more.
UPLOAD_LIMIT = 4 * 1024 ** 3


def flash(error: str) -> str:
    return f'<div class="flash">{esc(error)}</div>' if error else ""


RETENTION_CHOICES = [(30, "1 month"), (60, "2 months"), (90, "3 months"), (180, "6 months"),
                     (365, "1 year")]
DEFAULT_RETENTION = 90


def retention_field(selected: int = DEFAULT_RETENTION) -> str:
    """How long the raw files are kept. Asked when a cluster is added, because the answer is
    disk, and only the person adding it knows how much of that there is."""
    choices = list(RETENTION_CHOICES)
    if selected not in dict(choices):
        # Set by hand in config.json to something the page does not offer: shown as it is, so
        # saving the page unchanged does not quietly change it.
        choices.append((selected, f"{selected} days, as set in the config"))
    options = "".join(
        f'<option value="{days}"{" selected" if days == selected else ""}>{label}</option>'
        for days, label in choices)
    return f"""
        <label for="retention_days">Keep the raw FTDC for</label>
        <select id="retention_days" name="retention_days">{options}</select>
        <p class="hint">Files older than this are deleted. The findings, the incidents and the
          baseline of what is normal for the cluster are kept for good, so its history outlives
          the files. FTDC from mongod takes about 20 MB a member a day when idle, several times
          that under load.</p>"""


def retention_from(value: str, keep: int | None = None) -> int:
    """The days chosen, if the page offered them. `keep` is a value from the config that the
    page shows as it is, and so may come back."""
    try:
        days = int(value)
    except (TypeError, ValueError):
        return keep or DEFAULT_RETENTION
    return days if days in dict(RETENTION_CHOICES) or days == keep else (keep or DEFAULT_RETENTION)


def settings_page(cluster_id: str, current: int, held: dict, error: str = "") -> str:
    import report  # noqa: PLC0415

    holding = (f"It holds {held['files']} files, {held['mb']:.0f} MB, from "
               f"{held['oldest']:%d %b %Y}." if held.get("oldest") else
               "It holds no raw FTDC yet.")
    return page(f"{cluster_id} settings · mongo-health", f"""
    <p><a href="/{esc(cluster_id)}/index.html" class="back">← {esc(cluster_id)}</a></p>
    <h1>{esc(cluster_id)}</h1>
    {flash(error)}
    <form method="post" action="/settings/{esc(cluster_id)}">
      <div class="card">
        {retention_field(current)}
        <p class="hint">Now: {esc(report.retention_label(current))}. {esc(holding)}</p>
      </div>
      <button type="submit">Save</button>
      <a href="/{esc(cluster_id)}/index.html" class="back" style="margin-left:1rem">Cancel</a>
    </form>""")


def shorten_page(cluster_id: str, days: int, doomed: dict, atlas: bool) -> str:
    import report  # noqa: PLC0415

    gone = (" Atlas no longer holds files that old, so nothing can bring them back."
            if atlas else "")
    return page(f"Shorten {cluster_id} · mongo-health", f"""
    <p><a href="/settings/{esc(cluster_id)}" class="back">← back</a></p>
    <h1>Keep {esc(cluster_id)} for {esc(report.retention_label(days))}?</h1>
    <div class="card">
      <p>{doomed['files']} files, {doomed['mb']:.0f} MB of raw FTDC from
        {doomed['oldest']:%d %b %Y} to {doomed['newest']:%d %b %Y}, are deleted at the next
        round, within the hour. <b>This cannot be undone.</b>{esc(gone)}</p>
      <p class="hint">The findings, the incidents and the baseline stay. What goes is the
        ability to open those days second by second.</p>
    </div>
    <form method="post" action="/settings/{esc(cluster_id)}">
      <input type="hidden" name="retention_days" value="{days}">
      <input type="hidden" name="confirm" value="{esc(cluster_id)}">
      <button type="submit">Keep {esc(report.retention_label(days))} and delete them</button>
      <a href="/settings/{esc(cluster_id)}" class="back" style="margin-left:1rem">Cancel</a>
    </form>""")


def interval_field(result: dict) -> str:
    """How often to read it, priced with this cluster's own sample, measured while testing."""
    import poller  # noqa: PLC0415

    members = [m for m in result["members"] if m.get("compressed_bytes")]
    if not members:
        return f'<input type="hidden" name="interval" value="{poller.INTERVAL}">'
    each = max(m["compressed_bytes"] for m in members)
    rows = []
    for seconds in poller.INTERVALS:
        per_day = each * 86400 / seconds / 1e9
        total = per_day * len(members)
        note = "  · the default" if seconds == poller.INTERVAL else ""
        rows.append(f"""
        <label class="pick">
          <input type="radio" name="interval" value="{seconds}"
                 {"checked" if seconds == poller.INTERVAL else ""}>
          <span>Every {seconds} s <span class="meta">· {per_day:.2f} GB a day per member,
            {total:.2f} GB for all {len(members)}{note}</span></span>
        </label>""")
    return f"""
      <h2>How often to read it</h2>
      <div class="card">
        {''.join(rows)}
        <p class="hint">Each read is one <code>getDiagnosticData</code>, which hands over the
          sample mongod already took for its own FTDC: no extra work on the server, the cost is
          the network. Measured here: one sample is {each / 1024:.0f} KB compressed. A value
          that moves and comes back between two reads (a ticket pool emptied for three
          seconds) is only seen at one a second.</p>
      </div>"""


def choose_page() -> str:
    """The ways in, none of which asks for anything to be installed or changed on a database
    host: an Atlas API key, a folder this machine already sees, or a monitoring user."""
    return page("Add a cluster · mongo-health", """
    <p><a href="/index.html" class="back">← all clusters</a></p>
    <h1>Add a cluster</h1>
    <div class="doors">
      <a class="door" href="/add/atlas">
        <b>On Atlas</b>
        <span>An API key with read-only access to the project. Everything Atlas still holds
          comes down straight away.</span>
      </a>
      <a class="door recommended" href="/add/files">
        <b>On your own servers: upload its FTDC</b>
        <span>Recommended. Each member's <code>diagnostic.data</code> as an archive: one
          sample a second and every day mongod kept, with nothing installed or changed on the
          hosts. Upload newer files whenever you want it brought up to date.</span>
      </a>
      <a class="door" href="/add/onprem">
        <b>On your own servers: connect to it</b>
        <span>A monitoring user, read every 10 seconds unless you choose otherwise, so it keeps
          collecting by itself; the next page prices each interval. Spikes shorter than the
          interval can be missed.</span>
      </a>
      <a class="door" href="/add/folder">
        <b>From a folder on this machine</b>
        <span>A <code>diagnostic.data</code> this machine can already see: a local mongod,
          a mounted share, or wherever something else copies the files.</span>
      </a>
    </div>""")


def folder_page(error: str = "", name: str = "", path: str = "",
                retention: int = DEFAULT_RETENTION) -> str:
    return page("Add a cluster from a folder · mongo-health", f"""
    <p><a href="/add" class="back">← back</a></p>
    <h1>Add a cluster from a folder</h1>
    {flash(error)}
    <p class="lede">For a <code>diagnostic.data</code> this machine can already see. It is read
      once an hour, like every other source.</p>
    <form method="post" action="/add/folder">
      <div class="card">
        <label for="f_id">Name</label>
        <input id="f_id" name="id" type="text" required placeholder="orders-prod"
               value="{esc(name)}">
        <label for="f_path">Folder</label>
        <input id="f_path" name="path" type="text" required placeholder="/mnt/ftdc/orders-prod"
               value="{esc(path)}">
        <p class="hint">Either one member's <code>diagnostic.data</code>, or a folder with one
          subfolder per member (<code>db1/</code>, <code>db2/</code>, …). The members are
          recognised from the files, so the names do not matter.</p>
        {retention_field(retention)}
      </div>
      <button type="submit">Check the folder</button>
    </form>
    <h2>Running in Docker</h2>
    <p>The folder has to be visible inside the containers, read-only. Add it to a
      <code>docker-compose.override.yml</code> next to <code>docker-compose.yml</code>, for the
      <code>collector</code> and the <code>ui</code>, then run <code>docker compose up -d</code>:</p>
    <pre class="snippet">services:
  collector:
    volumes:
      - /var/lib/mongo/diagnostic.data:/mnt/ftdc/local:ro
  ui:
    volumes:
      - /var/lib/mongo/diagnostic.data:/mnt/ftdc/local:ro</pre>
    <p>and enter <code>/mnt/ftdc/local</code> above. The containers run as the owner of
      <code>./config</code>, and mongod writes its files readable by itself only (umask 077),
      so that user needs a read grant. On the host, as root:</p>
    <pre class="snippet">U=$(stat -c %u ./config)                 # run from the mongo-health directory
DIAG=/var/lib/mongo/diagnostic.data
setfacl -m u:$U:x "$(dirname "$DIAG")"
setfacl -m u:$U:rx "$DIAG"
setfacl -d -m u:$U:r "$DIAG"           # and the files mongod creates from now on
setfacl -m u:$U:r "$DIAG"/metrics.*</pre>""")


def folder_found_page(token: str, name: str, path: str, members: list[dict]) -> str:
    rows = "".join(
        f'<tr><td class="num">{esc(m["member"] or "?")}</td><td>{m["files"]} files, '
        f'{m["mb"]} MB</td><td>{esc(m["span"])}</td></tr>' for m in members)
    return page(f"Check {name} · mongo-health", f"""
    <p><a href="/add/folder" class="back">← back</a></p>
    <h1>{esc(name)}</h1>
    <p class="capacity-line" data-state="spare">Found {len(members)} member{'s' if len(members) != 1 else ''}
      in <code>{esc(path)}</code>.</p>
    <div class="scroll"><table><thead><tr><th>Member</th><th></th><th>History</th></tr></thead>
      <tbody>{rows}</tbody></table></div>
    <form method="post" action="/add/folder/confirm">
      <input type="hidden" name="token" value="{esc(token)}">
      <button type="submit">Add {esc(name)}</button>
    </form>""")


def atlas_page(error: str = "", env_keys: bool = False) -> str:
    # Always asked for. Hiding the fields when a key sits in the environment made the page look
    # as if Atlas needed no key at all, and left no way to add a project that needs another one.
    required = "" if env_keys else "required"
    return page("Add an Atlas cluster · mongo-health", f"""
    <p><a href="/add" class="back">← back</a></p>
    <h1>Add a cluster on Atlas</h1>
    {flash(error)}
    <div class="card">
      <form method="post" action="/add/atlas">
        <label for="group_id">Project ID</label>
        <input id="group_id" name="group_id" type="text" required autocomplete="off"
               placeholder="24 hexadecimal characters, from Project Settings">
        <label for="public_key">Public key</label>
        <input id="public_key" name="public_key" type="text" {required} autocomplete="off">
        <label for="private_key">Private key</label>
        <input id="private_key" name="private_key" type="password" {required}
               autocomplete="off">
        <p class="hint">An API key with Project Read Only on this project, and nothing more.
          {'Leave both empty to use the key in <code>.env</code>. ' if env_keys else ''}A key
          typed here is written to your config file, which only you can read.</p>
        <button type="submit">List its clusters</button>
      </form>
    </div>""")


# How a DBA packs a member's files, on the member. Read-only, one-off, nothing left behind.
PACK = """sudo tar czf "$(hostname)-ftdc.tgz" -C /var/lib/mongo diagnostic.data \\
    -C /var/log/mongodb mongod.log
# dbPath elsewhere?  grep dbPath /etc/mongod.conf   (Ubuntu: /var/lib/mongodb)
# log elsewhere?     grep -A3 systemLog /etc/mongod.conf  (RHEL: /var/log/mongo)"""


def drop_zone() -> str:
    """Where FTDC archives are dropped. Each is uploaded as it lands and described back --
    which members, which days -- before anything is added."""
    return f"""
      <div class="card">
        <div class="drop" id="drop" tabindex="0">
          <b>Drop FTDC files here</b>
          <span>A .tar.gz, .tgz, .tar or .zip of each member's <code>diagnostic.data</code> —
            one member or all of them, in one archive or several — or
            <label for="file" class="link">choose them</label>. Add the member's
            <code>mongod.log</code> too, in the archive or on its own, and each incident says
            which queries were slow while it happened.</span>
          <input id="file" type="file" multiple
                 accept=".gz,.tgz,.tar,.zip,.log,application/gzip,application/zip,text/plain">
        </div>
        <div id="uploads"></div>
        <p class="hint">On each member, as a user that can read mongod's files:</p>
        <pre class="snippet">{esc(PACK)}</pre>
        <p class="hint">Members are recognised from the files themselves, so the names and the
          layout inside the archive do not matter.</p>
      </div>"""


def files_page(error: str = "", name: str = "", retention: int = DEFAULT_RETENTION) -> str:
    """The recommended way in for a cluster of your own: the FTDC mongod already writes."""
    return page("Add a cluster from its FTDC files · mongo-health", f"""
    <p><a href="/add" class="back">← back</a></p>
    <h1>Add a cluster from its FTDC files</h1>
    {flash(error)}
    <p class="lede">One sample a second, and every day mongod has kept: the same data Atlas
      hands over. Nothing is installed or changed on the hosts. Upload newer files from the
      cluster's page whenever you want it brought up to date.</p>
    <form method="post" action="/add/onprem" id="onprem">
      <input type="hidden" name="from" value="files">
      <div class="card">
        <label for="m_id">Name</label>
        <input id="m_id" name="id" type="text" required placeholder="orders-prod"
               value="{esc(name)}">
        {retention_field(retention)}
      </div>
      {drop_zone()}
      <button type="submit" id="continue">Add the cluster</button>
    </form>
    <script>{UPLOAD_JS}</script>""")


def more_files_page(cluster_id: str, error: str = "", unknown: list[str] | None = None,
                    tokens: list[str] | None = None) -> str:
    """More files for a cluster already here. Overlapping what it holds is fine: what it has
    is skipped, and what grew since is taken."""
    confirm = ""
    if unknown:
        hidden = "".join(f'<input type="hidden" name="upload" value="{esc(t)}">'
                         for t in tokens or [])
        confirm = f"""
    <div class="card">
      <p>These members are new to {esc(cluster_id)}: <code>{esc(", ".join(unknown))}</code>.
        If the files are from another cluster, they would be judged as part of this one.</p>
      <form method="post" action="/files/{esc(cluster_id)}">
        {hidden}
        <input type="hidden" name="confirm" value="{esc(cluster_id)}">
        <button type="submit">Add them to {esc(cluster_id)}</button>
        <a href="/files/{esc(cluster_id)}" class="back" style="margin-left:1rem">Cancel</a>
      </form>
    </div>"""
    return page(f"Add FTDC files to {cluster_id} · mongo-health", f"""
    <p><a href="/{esc(cluster_id)}/index.html" class="back">← {esc(cluster_id)}</a></p>
    <h1>Add FTDC files to {esc(cluster_id)}</h1>
    {flash(error)}
    {confirm}
    <p class="lede">Files it already holds are skipped, and the one mongod was still writing
      is taken again with what it gained. They are analysed straight away.</p>
    <form method="post" action="/files/{esc(cluster_id)}" id="onprem">
      {drop_zone()}
      <button type="submit" id="continue">Add the files</button>
    </form>
    <script>{UPLOAD_JS}</script>""")


def onprem_page(error: str = "", name: str = "", uri: str = "",
                retention: int = DEFAULT_RETENTION) -> str:
    """A connection string, files, or both. The files are dropped onto the page and uploaded
    straight away, so what they contain -- which members, which days -- is known before the
    cluster is added."""
    return page("Add a cluster on your own servers · mongo-health", f"""
    <p><a href="/add" class="back">← back</a></p>
    <h1>Add a cluster on your own servers</h1>
    {flash(error)}
    <form method="post" action="/add/onprem" id="onprem">
      <div class="card">
        <label for="m_id">Name</label>
        <input id="m_id" name="id" type="text" required placeholder="orders-prod"
               value="{esc(name)}">
        {retention_field(retention)}
      </div>

      <h2>Connect to it <span class="optional">— to keep collecting from now on</span></h2>
      <div class="card">
        <label for="uri">Connection string</label>
        <input id="uri" name="uri" type="password" autocomplete="off"
               placeholder="mongodb://mongo-health:…@db1,db2,db3/?replicaSet=rs0"
               value="{esc(uri)}">
        <p class="hint">Any member, all of them, or a <code>mongodb+srv://</code> address — the
          rest are found on their own. It needs one user with the clusterMonitor role, created
          once on the primary; the set copies it to every member:</p>
        <pre class="snippet">{esc(CREATE_USER)}</pre>
      </div>

      <h2>Add its history <span class="optional">— the days before today</span></h2>
      {drop_zone()}

      <p class="hint">Either one is enough; both is best — the files bring the past, the
        connection keeps it going.</p>
      <button type="submit" id="continue">Continue</button>
    </form>
    <script>{UPLOAD_JS}</script>""")


# Plain JavaScript, no library: upload each dropped file with progress, show what it contained,
# and remember its token for the form.
UPLOAD_JS = r"""
(function () {
  const drop = document.getElementById('drop'), input = document.getElementById('file');
  const list = document.getElementById('uploads'), form = document.getElementById('onprem');
  // Leaving the page aborts an upload still in flight, and the form then goes without its
  // token: the cluster is added with none of the history that was dropped on it.
  const button = document.getElementById('continue');
  let pending = 0;
  function settle(delta) {
    pending += delta;
    button.disabled = pending > 0;
    button.textContent = pending > 0 ? 'Waiting for ' + pending + ' upload(s)…' : 'Continue';
  }
  form.addEventListener('submit', (e) => { if (pending > 0) e.preventDefault(); });
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  function upload(file) {
    const row = document.createElement('div');
    row.className = 'upload';
    row.innerHTML = '<b>' + esc(file.name) + '</b> <span class="meta">uploading…</span>' +
                    '<div class="use-bar" style="--w:0%"></div>';
    list.appendChild(row);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/add/onprem/upload');
    xhr.setRequestHeader('X-Filename', encodeURIComponent(file.name));
    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      row.querySelector('.use-bar').style.setProperty('--w', (100 * e.loaded / e.total).toFixed(0) + '%');
      // The bytes are there, but the server still unpacks and reads the archive before it answers.
      if (e.loaded === e.total) row.querySelector('.meta').textContent = 'reading the files…';
    };
    xhr.onloadend = () => settle(-1);
    xhr.onload = () => {
      let r = {};
      try { r = JSON.parse(xhr.responseText); } catch (e) { r = { error: 'The server did not answer as expected.' }; }
      if (r.error) {
        row.querySelector('.meta').textContent = r.error;
        row.classList.add('failed');
        return;
      }
      row.querySelector('.use-bar').remove();
      const logs = r.logs || [];
      row.querySelector('.meta').textContent = r.members.length + ' member(s) found' +
        (logs.length ? ', ' + logs.length + ' log(s)' : '');
      const ul = document.createElement('ul');
      ul.innerHTML = r.members.map((m) => '<li><code>' + esc(m.member) + '</code> — ' + esc(m.from) +
        ' to ' + esc(m.to) + ', ' + m.files + ' file(s), ' + m.mb + ' MB</li>').join('') +
        logs.map((g) => g.member
          ? '<li>log <code>' + esc(g.log) + '</code> for <code>' + esc(g.member) + '</code> — ' +
            g.slow + ' slow queries' + (g.from ? ', ' + esc(g.from) + ' to ' + esc(g.to) : '') + '</li>'
          : '<li class="failed">log <code>' + esc(g.log) + '</code>: which member it is from ' +
            'cannot be told (it starts after mongod did); upload it in one archive with that ' +
            'member\'s diagnostic.data</li>').join('');
      row.appendChild(ul);
      const token = document.createElement('input');
      token.type = 'hidden'; token.name = 'upload'; token.value = r.token;
      form.appendChild(token);
    };
    xhr.onerror = () => { row.querySelector('.meta').textContent = 'The upload failed.'; row.classList.add('failed'); };
    settle(+1);
    xhr.send(file);
  }
  const take = (files) => Array.from(files).forEach(upload);
  input.addEventListener('change', () => take(input.files));
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => take(e.dataTransfer.files));
})();
"""


def tested_page(token: str, name: str, result: dict, uploads: list[dict]) -> str:
    rows = "".join(
        f"""<tr><td class="num">{esc(m['host'])}</td><td>{esc(m.get('version') or '—')}</td>
            <td style="color:var({'--ok' if m['ok'] else '--bad'})">
              {'reads diagnostics' if m['ok'] else esc(m['error'])}</td></tr>"""
        for m in result["members"])
    history = ""
    if uploads:
        history = (f'<p class="hint">Plus the history from the files: '
                   f'{len(uploads)} member(s), '
                   f'{esc(min(u["from"] for u in uploads))} to '
                   f'{esc(max(u["to"] for u in uploads))}.</p>')
    if result["ok"]:
        verdict = (f'<p class="capacity-line" data-state="spare">Found a {esc(result["kind"])} '
                   f'of {len(result["members"])} member(s), and every one answers.</p>')
        action = f"""
      {history}
      <form method="post" action="/add/onprem/confirm">
        <input type="hidden" name="token" value="{esc(token)}">
        {interval_field(result)}
        <button type="submit">Add {esc(name)}</button>
      </form>
      <p class="hint">Samples start arriving in a minute; the first evaluation follows.</p>"""
    else:
        verdict = (f'<p class="capacity-line" data-state="tight">'
                   f'{esc(result["error"] or "Not every member can be read yet.")}</p>')
        action = ('<p class="hint">Fix what is marked above and try again. A member that says '
                  'it needs clusterMonitor has the user but not the role; one that does not '
                  'answer may not be reachable from here under the name it gives itself.</p>'
                  f'<pre class="snippet">{esc(CREATE_USER)}</pre>'
                  '<p><a href="/add/onprem">← back to the form</a></p>')
    table = (f'<div class="scroll"><table><thead><tr><th>Member</th><th>Version</th>'
             f'<th></th></tr></thead><tbody>{rows}</tbody></table></div>' if rows else "")
    return page("Test the connection · mongo-health", f"""
    <p><a href="/add/onprem" class="back">← back</a></p>
    <h1>{esc(name)}</h1>
    {verdict}
    {table}
    {action}""")


def pick_page(token: str, group_id: str, found: list[dict], already: set[str]) -> str:
    rows = []
    for c in found:
        usable = bool(c.get("replica_set"))
        taken = c["name"] in already
        note = ("already added" if taken else
                "" if usable else
                "sharded: this version watches replica sets only" if c.get("sharded") else
                "no replica set name, so it cannot be collected (M0/Flex)")
        rows.append(f"""
        <label class="pick">
          <input type="checkbox" name="cluster" value="{esc(c['name'])}"
                 {'checked' if usable and not taken else ''}
                 {'disabled' if taken or not usable else ''}>
          <b>{esc(c['name'])}</b> <span class="meta">{esc(c.get('tier') or '?')} ·
            MongoDB {esc(c.get('version') or '?')}{' · ' + esc(note) if note else ''}</span>
        </label>""")
    return page("Choose clusters · mongo-health", f"""
    <p><a href="/add/atlas" class="back">← back</a></p>
    <h1>Clusters in project {esc(group_id)}</h1>
    <div class="card">
      <form method="post" action="/add/atlas/pick">
        <input type="hidden" name="token" value="{esc(token)}">
        {''.join(rows)}
        {retention_field()}
        <p class="hint">Adding one pulls everything Atlas still holds for it, from a few days to
          several weeks, newest first. On an M10 with 20 days that took 38 minutes; the page shows
          the cluster straight away and fills in when the data lands.</p>
        <button type="submit">Add the selected</button>
      </form>
    </div>""")


class Handler(SimpleHTTPRequestHandler):
    app: App  # set on the subclass made in serve()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.app.site), **kwargs)

    def log_message(self, fmt, *args):  # quieter than the default, one line per request
        sys.stderr.write(f"ui  {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n")

    # ------------------------------------------------------------ guards

    def _authorized(self) -> bool:
        if not self.app.password:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                _, _, given = base64.b64decode(header[6:]).decode().partition(":")
            except (ValueError, UnicodeDecodeError):
                given = ""
            if hmac.compare_digest(given, self.app.password):
                return True
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="mongo-health"')
        self.end_headers()
        return False

    def _same_origin(self) -> bool:
        """A form posted from a page this server served names this host in Origin (or, from
        older browsers, Referer). Anything else is another site making the browser post."""
        host = self.headers.get("Host", "")
        source = self.headers.get("Origin") or self.headers.get("Referer") or ""
        return bool(host) and urlsplit(source).netloc == host

    def _html(self, text: str, status: int = 200) -> None:
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, to: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", to)
        self.end_headers()

    def _form(self) -> dict[str, list[str]]:
        length = min(int(self.headers.get("Content-Length") or 0), 64 * 1024)
        return parse_qs(self.rfile.read(length).decode(errors="replace"), keep_blank_values=True)

    # ------------------------------------------------------------ routes

    def do_GET(self):
        if not self._authorized():
            return
        path = urlsplit(self.path).path
        env_keys = bool(os.environ.get("ATLAS_PUBLIC_KEY"))
        pages = {"/add": choose_page, "/add/atlas": lambda: atlas_page(env_keys=env_keys),
                 "/add/onprem": onprem_page, "/add/folder": folder_page,
                 "/add/files": files_page}
        if path in pages:
            return self._html(pages[path]())
        m = re.fullmatch(r"/progress/([^/]+)", path)
        if m and config.CLUSTER_ID.match(m.group(1)):
            return self._progress(m.group(1))
        m = re.fullmatch(r"/files/([^/]+)", path)
        if m:
            if not self._takes_files(m.group(1)):
                return self._html("<p>No cluster by that name takes uploaded files.</p>", 404)
            return self._html(more_files_page(m.group(1)))
        m = re.fullmatch(r"/settings/([^/]+)", path)
        if m:
            entry = self._entry(m.group(1))
            if entry is None:
                return self._html("<p>There is no cluster by that name.</p>", 404)
            return self._html(settings_page(m.group(1), self._retention_of(entry),
                                            self._held(m.group(1))))
        m = re.fullmatch(r"/remove/([^/]+)", path)
        if m:
            if not self._configured(m.group(1)):
                return self._html("<p>There is no cluster by that name.</p>", 404)
            return self._html(remove_page(m.group(1), self._held_mb(m.group(1))))
        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_HEAD(self):
        if self._authorized():
            super().do_HEAD()

    def do_POST(self):
        if not self._authorized():
            return
        if not self._same_origin():
            return self._html("<p>Refused: this form did not come from this page.</p>", 403)
        path = urlsplit(self.path).path
        if path == "/add/onprem/upload":
            return self._upload()
        form = self._form()
        one = lambda k: (form.get(k) or [""])[0].strip()  # noqa: E731

        m = re.fullmatch(r"/([^/]+)/(resolve|reopen)", path)
        if m and config.CLUSTER_ID.match(m.group(1)):
            base = self.app.data / m.group(1)
            ids = [i for i in one("ids").split(",") if re.fullmatch(r"[0-9a-f]{1,64}", i)]
            if not base.is_dir() or not ids:
                return self._html("<p>Nothing to mark.</p>", 400)
            if m.group(2) == "resolve":
                resolutions.resolve(base, ids, one("note"))
            else:
                resolutions.reopen(base, ids)
            self.app.rebuild()
            back = urlsplit(self.headers.get("Referer") or "").path or f"/{m.group(1)}/"
            return self._redirect(back)

        m = re.fullmatch(r"/files/([^/]+)", path)
        if m:
            return self._more_files(m.group(1), form.get("upload") or [], one("confirm"))
        m = re.fullmatch(r"/settings/([^/]+)", path)
        if m:
            return self._settings(m.group(1), one("retention_days"), one("confirm"))
        m = re.fullmatch(r"/remove/([^/]+)", path)
        if m:
            return self._remove(m.group(1), one("confirm"), one("delete_data") == "1")

        if path == "/add/folder":
            return self._folder(one("id"), one("path"), retention_from(one("retention_days")))
        if path == "/add/folder/confirm":
            return self._folder_confirm(one("token"))

        if path == "/add/atlas":
            return self._discover(one("group_id"), one("public_key"), one("private_key"))
        if path == "/add/atlas/pick":
            return self._pick(one("token"), form.get("cluster") or [],
                              retention_from(one("retention_days")))
        if path == "/add/onprem":
            return self._onprem(one("id"), one("uri"), form.get("upload") or [],
                                retention_from(one("retention_days")), one("from"))
        if path == "/add/onprem/confirm":
            return self._onprem_confirm(one("token"), one("interval"))
        return self._html("<p>Not found.</p>", 404)

    def _discover(self, group_id: str, public_key: str, private_key: str):
        # A key typed into the form is for this project and goes to its config entry; with the
        # fields left empty, the one in the environment is used and stays there.
        typed = ({"public_key": public_key, "private_key": private_key}
                 if public_key and private_key else {})
        public_key = public_key or os.environ.get("ATLAS_PUBLIC_KEY", "")
        private_key = private_key or os.environ.get("ATLAS_PRIVATE_KEY", "")
        env_keys = bool(os.environ.get("ATLAS_PUBLIC_KEY"))
        if not re.fullmatch(r"[0-9a-f]{24}", group_id):
            return self._html(atlas_page("A project ID is 24 hexadecimal characters.", env_keys),
                              400)
        if not (public_key and private_key):
            return self._html(atlas_page("An API key is needed: both halves of it.", env_keys),
                              400)
        try:
            found = onboard.discover(group_id, public_key, private_key)
        except Exception as e:
            return self._html(atlas_page(f"Atlas did not answer as expected: {e}", env_keys), 502)
        now = time.time()
        for token in [t for t, (at, _) in PENDING.items() if now - at > PENDING_TTL]:
            PENDING.pop(token, None)
        token = secrets.token_urlsafe(16)
        PENDING[token] = (now, {"group_id": group_id, "found": found, "keys": typed})
        try:
            already = {c["cluster_id"] for c in config.load_clusters(self.app.config_path)}
        except config.ConfigError:
            already = set()
        return self._html(pick_page(token, group_id, found, already))

    def _pick(self, token: str, names: list[str], retention: int = DEFAULT_RETENTION):
        at, pending = PENDING.pop(token, (0, None))
        if pending is None or time.time() - at > PENDING_TTL or "found" not in pending:
            return self._redirect("/add/atlas")
        chosen = [c for c in pending["found"] if c["name"] in names and c.get("replica_set")]
        added = []
        for c in chosen:
            source = {"type": "atlas", "group_id": pending["group_id"],
                      "replica_set": c["replica_set"], **pending["keys"]}
            try:
                self.app.add_entry({"id": c["name"], "retention_days": retention,
                                    "source": source})
                added.append(c["name"])
            except (ValueError, config.ConfigError):
                continue
        # Started before the rebuild: when the round has to wait, the launcher says so in
        # queued.json, and the page drawn now is the one that has to say it.
        for name in added:
            self.app.start_capture(name)
        self.app.rebuild()
        return self._redirect(f"/{added[0]}/index.html" if len(added) == 1 else "/index.html")

    # --------------------------------------------------------------- on-premise

    def _staging(self, token: str) -> Path:
        return self.app.data / ".staging" / token

    def _upload(self):
        """One dropped file, streamed to disk, unpacked, and described member by member. Answers
        JSON for the page's script; the token it returns travels with the form."""
        def answer(body: dict, status: int = 200):
            data = json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        length = int(self.headers.get("Content-Length") or 0)
        if not 0 < length <= UPLOAD_LIMIT:
            return answer({"error": "Nothing arrived, or more than 4 GB."}, 413)
        # Staging older than a day is somebody's abandoned form.
        root = self.app.data / ".staging"
        for old in (root.iterdir() if root.exists() else []):
            if time.time() - old.stat().st_mtime > 86_400:
                shutil.rmtree(old, ignore_errors=True)
        token = secrets.token_hex(12)
        staging = self._staging(token)
        staging.mkdir(parents=True)
        archive = staging / "upload"
        with archive.open("wb") as out:
            left = length
            while left:
                block = self.rfile.read(min(left, 1 << 20))
                if not block:
                    break
                out.write(block)
                left -= len(block)
        try:
            # The name it was dropped with, for what the page says back; never used as a path.
            dropped = re.sub(r"[^A-Za-z0-9._-]", "_",
                             unquote(self.headers.get("X-Filename") or ""))[-80:] or None
            members = ftdcfiles.receive(archive, staging, dropped)
        except Exception as e:
            shutil.rmtree(staging, ignore_errors=True)
            return answer({"error": str(e)}, 400)
        finally:
            archive.unlink(missing_ok=True)
        day = lambda ms: datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%d %b %Y")  # noqa: E731
        return answer({"token": token, "members": [
            {"member": m["member"], "files": m["files"], "mb": round(m["bytes"] / 1048576),
             "from": f"{m['from']:%d %b %Y}", "to": f"{m['to']:%d %b %Y}"} for m in members],
            "logs": [{"log": g["log"], "member": g["member"], "slow": g["slow"],
                      "from": day(g["from"]) if g["from"] else None,
                      "to": day(g["to"]) if g["to"] else None}
                     for g in ftdcfiles.received_logs(staging)]})

    def _uploads(self, tokens: list[str]) -> list[dict]:
        """What the tokens on the form stand for, ignoring any that are not ours. A token that
        brought only mongod logs shows up as {"token", "member", "log": True}."""
        found = []
        for token in tokens:
            if not re.fullmatch(r"[0-9a-f]{24}", token):
                continue
            for g in ftdcfiles.received_logs(self._staging(token)):
                if g["member"]:
                    found.append({"token": token, "member": g["member"], "log": True})
            members = self._staging(token) / "members"
            for m in (members.iterdir() if members.exists() else []):
                files = [f for f in m.iterdir() if f.is_file()]
                spans = [ftdcfiles.describe(f) for f in files[:1] + files[-1:]]
                found.append({"token": token, "member": m.name,
                              "from": min(s["from"] for s in spans if s["from"]),
                              "to": max(s["to"] for s in spans if s["to"])})
        return found

    def _takes_files(self, cluster_id: str) -> bool:
        """Uploaded files land in `incoming/`, which only an on-premise source reads."""
        entry = self._entry(cluster_id)
        return bool(entry) and (entry.get("source") or {}).get("type") == "onprem"

    def _more_files(self, cluster_id: str, tokens: list[str], confirm: str):
        if not self._takes_files(cluster_id):
            return self._html("<p>No cluster by that name takes uploaded files.</p>", 404)
        uploads = self._uploads(tokens)
        if not uploads:
            return self._html(more_files_page(
                cluster_id, "Drop at least one FTDC archive, and wait for it to finish "
                            "uploading."), 400)
        base = self.app.data / cluster_id
        held = ftdcfiles.members_of(base)
        # Only FTDC members are compared: a log names its member by host, the FTDC directories
        # by the name the replica set gives it, and the two rarely look alike.
        unknown = sorted({u["member"] for u in uploads if not u.get("log")} - held)
        # A cluster with no members yet has nothing to be mixed up with.
        if held and unknown and confirm != cluster_id:
            return self._html(more_files_page(cluster_id, unknown=unknown,
                                              tokens=sorted({u["token"] for u in uploads})))
        for token in sorted({u["token"] for u in uploads}):
            ftdcfiles.adopt(self._staging(token), base / "incoming")
        self.app.start_capture(cluster_id)
        return self._redirect(f"/{cluster_id}/index.html")

    def _onprem(self, cluster_id: str, uri: str, tokens: list[str],
                retention: int = DEFAULT_RETENTION, origin: str = ""):
        if origin == "files":
            again = lambda msg: self._html(files_page(msg, cluster_id, retention), 400)  # noqa: E731
        else:
            again = lambda msg: self._html(onprem_page(msg, cluster_id, uri, retention), 400)  # noqa: E731
        if not config.CLUSTER_ID.match(cluster_id):
            return again("A name is letters, digits, dots, dashes or underscores.")
        uploads = [u for u in self._uploads(tokens) if not u.get("log")]
        if origin == "files" and not uploads:
            return again("Drop at least one FTDC archive, and wait for it to finish uploading. "
                         "A mongod log can come with it, not instead of it.")
        if not uri and not uploads:
            return again("Give it a connection string, some FTDC files, or both.")
        if uri and not uri.startswith(("mongodb://", "mongodb+srv://")):
            return again("A connection string starts with mongodb:// or mongodb+srv://.")
        pending = {"id": cluster_id, "uri": uri,
                   "uploads": sorted({u["token"] for u in self._uploads(tokens)}),
                   "retention_days": retention}
        if not uri:
            return self._finish(pending)
        import poller  # noqa: PLC0415 -- pymongo is only needed once somebody connects

        result = poller.check(uri)
        token = ""
        if result["ok"]:
            token = secrets.token_urlsafe(16)
            PENDING[token] = (time.time(), pending)
        return self._html(tested_page(token, cluster_id, result, uploads))

    # ---------------------------------------------------------------- folder

    def _folder(self, cluster_id: str, path_text: str, retention: int = DEFAULT_RETENTION):
        if not config.CLUSTER_ID.match(cluster_id):
            return self._html(folder_page("A name is letters, digits, dots, dashes or "
                                          "underscores.", cluster_id, path_text), 400)
        if self._configured(cluster_id):
            return self._html(folder_page(f'There is already a cluster called "{cluster_id}".',
                                          cluster_id, path_text), 400)
        root = Path(path_text)
        if not root.is_absolute() or not root.is_dir():
            return self._html(folder_page(
                f"{path_text} is not a folder this machine can see. In Docker, mount it as shown "
                f"below and use the path inside the container.", cluster_id, path_text), 400)
        try:
            members = self._folder_members(root)
        except PermissionError:
            return self._html(folder_page(
                f"{path_text} is there but cannot be read: the read grant below is missing.",
                cluster_id, path_text), 400)
        if not members:
            return self._html(folder_page(f"No metrics files in {path_text} or in the folders "
                                          f"directly under it.", cluster_id, path_text), 400)
        token = secrets.token_urlsafe(16)
        PENDING[token] = (time.time(), {"folder": str(root), "id": cluster_id,
                                        "single": members[0]["single"],
                                        "retention_days": retention})
        return self._html(folder_found_page(token, cluster_id, str(root), members))

    @staticmethod
    def _folder_members(root: Path) -> list[dict]:
        """One row per member: the folder itself when it holds the files, else each subfolder."""
        from state import timestamp_of

        def one(d: Path, single: bool) -> dict | None:
            files = sorted(p for p in d.glob("metrics.*") if p.is_file())
            if not files:
                return None
            spans = [ftdcfiles.describe(f) for f in dict.fromkeys([files[-1], files[0]])]
            first = min([s["from"] for s in spans if s.get("from")]
                        + [t for t in [timestamp_of(files[0].name)] if t], default=None)
            last = max((s["to"] for s in spans if s.get("to")), default=None)
            return {"member": next((s["member"] for s in spans if s.get("member")), None),
                    "files": len(files), "single": single,
                    "mb": round(sum(f.stat().st_size for f in files) / 1024 ** 2, 1),
                    "span": (f"{first:%d %b %Y} to {last:%d %b %Y}" if first and last else "")}

        here = one(root, True)
        if here:
            return [here]
        return [m for d in sorted(root.iterdir()) if d.is_dir() and (m := one(d, False))]

    def _folder_confirm(self, token: str):
        at, pending = PENDING.pop(token, (0, None))
        if pending is None or time.time() - at > PENDING_TTL or "folder" not in pending:
            return self._redirect("/add/folder")
        source = {"type": "directory", "path": pending["folder"]}
        if pending["single"]:
            # One member's diagnostic.data: named after the member, not after the folder,
            # which is always called "diagnostic.data".
            members = self._folder_members(Path(pending["folder"]))
            source["node"] = ftdcfiles.member_dir(members[0]["member"] or pending["id"])
        try:
            self.app.add_entry({"id": pending["id"], "retention_days": pending["retention_days"],
                                "source": source})
        except (ValueError, config.ConfigError) as e:
            return self._html(folder_page(str(e), pending["id"], pending["folder"]), 400)
        self.app.start_capture(pending["id"])
        self.app.rebuild()
        return self._redirect(f"/{pending['id']}/index.html")

    def _progress(self, cluster_id: str):
        """How far an analysis of this cluster has got, for the page's progress bar."""
        import report  # noqa: PLC0415

        base = self.app.data / cluster_id
        now = self.app.clock()
        body: dict = {"analyzing": report.analyzing(base, now) is not None}
        if body["analyzing"]:
            try:
                body.update(json.loads((base / "analyzing.progress.json").read_text()))
            except (OSError, ValueError):
                pass  # started, but the engine has not decoded a file yet
        elif (fetch := report.capturing(base, now)) is not None:
            # A first fetch from Atlas: "analyzing" is what the page's script polls on, so the
            # bar keeps moving through the capture and into the analysis after it.
            body.update({"analyzing": True, **{k: fetch.get(k) for k in
                                               ("stage", "done", "total", "elapsed", "ago")}})
        elif (report.read_json(base / "state.json") or {}).get("last_capture") \
                and not (base / "summary.json").exists() \
                and not (base / "analysis-failed.json").exists():
            # Captured, and the analysis has not started: the minute between the two.
            body.update({"analyzing": True, "stage": "queued"})
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _entry(self, cluster_id: str) -> dict | None:
        if not config.CLUSTER_ID.match(cluster_id) or not self.app.config_path.exists():
            return None
        cfg = json.loads(self.app.config_path.read_text())
        return next((c for c in cfg.get("clusters", []) if c.get("id") == cluster_id), None)

    def _retention_of(self, entry: dict) -> int:
        """As the collector resolves it: the cluster's, the config's, or the built-in default."""
        cfg = json.loads(self.app.config_path.read_text())
        return int(entry.get("retention_days", cfg.get("retention_days",
                                                       config.DEFAULT_RETENTION_DAYS)))

    def _held(self, cluster_id: str, days: int | None = None) -> dict:
        """The raw FTDC held, or with `days` what pruning to that many would delete -- by the
        same rule prune.py applies, so the page cannot promise a different number."""
        import prune  # noqa: PLC0415
        from state import timestamp_of  # noqa: PLC0415

        ftdc = self.app.data / cluster_id / "ftdc"
        if not ftdc.is_dir():
            return {"files": 0, "mb": 0.0}
        if days is None:
            files = [f for f in ftdc.rglob("metrics.*") if f.is_file()]
        else:
            files = prune.prunable(ftdc, self.app.clock() - timedelta(days=days))[0]
        stamps = sorted(t for f in files if (t := timestamp_of(f.name)))
        return {"files": len(files), "mb": sum(f.stat().st_size for f in files) / 1024 ** 2,
                "oldest": stamps[0] if stamps else None,
                "newest": stamps[-1] if stamps else None}

    def _settings(self, cluster_id: str, value: str, confirm: str):
        entry = self._entry(cluster_id)
        if entry is None:
            return self._html("<p>There is no cluster by that name.</p>", 404)
        current = self._retention_of(entry)
        days = retention_from(value, keep=current)
        if days < current and confirm != cluster_id:
            doomed = self._held(cluster_id, days)
            if doomed["files"]:
                atlas = (entry.get("source") or {}).get("type", "atlas") == "atlas"
                return self._html(shorten_page(cluster_id, days, doomed, atlas))
        self.app.update_entry(cluster_id, retention_days=days)
        self.app.rebuild()
        return self._redirect(f"/{cluster_id}/index.html")

    def _configured(self, cluster_id: str) -> bool:
        if not config.CLUSTER_ID.match(cluster_id) or not self.app.config_path.exists():
            return False
        cfg = json.loads(self.app.config_path.read_text())
        return any(c.get("id") == cluster_id for c in cfg.get("clusters", []))

    def _held_mb(self, cluster_id: str) -> float:
        base = self.app.data / cluster_id
        return sum(p.stat().st_size for p in base.rglob("*") if p.is_file()) / 1024 ** 2 \
            if base.is_dir() else 0.0

    def _remove(self, cluster_id: str, confirm: str, delete_data: bool):
        if not self._configured(cluster_id):
            return self._html("<p>There is no cluster by that name.</p>", 404)
        # The name comes back from the confirmation page: a post that skipped it removes nothing.
        if confirm != cluster_id:
            return self._redirect(f"/remove/{cluster_id}")
        try:
            self.app.remove_entry(cluster_id, delete_data)
        except RoundRunning:
            return self._html(remove_page(
                cluster_id, self._held_mb(cluster_id),
                "A collection round is running right now and may be reading this cluster's "
                "files. Nothing was removed; try again in a minute."), 409)
        self.app.rebuild()
        return self._redirect("/index.html")

    def _onprem_confirm(self, token: str, interval: str = ""):
        import poller  # noqa: PLC0415

        at, pending = PENDING.pop(token, (0, None))
        if pending is None or time.time() - at > PENDING_TTL or "uploads" not in pending:
            return self._redirect("/add/onprem")
        try:
            seconds = int(interval)
        except ValueError:
            seconds = poller.INTERVAL
        pending["interval"] = seconds if seconds in poller.INTERVALS else poller.INTERVAL
        return self._finish(pending)

    def _finish(self, pending: dict):
        source = {"type": "onprem", **({"uri": pending["uri"]} if pending["uri"] else {})}
        if pending["uri"] and pending.get("interval"):
            source["interval"] = pending["interval"]
        retention = pending.get("retention_days", DEFAULT_RETENTION)
        try:
            self.app.add_entry({"id": pending["id"], "retention_days": retention,
                                "source": source})
        except (ValueError, config.ConfigError) as e:
            return self._html(onprem_page(str(e), pending["id"], pending["uri"], retention), 400)
        incoming = self.app.data / pending["id"] / "incoming"
        for token in pending["uploads"]:
            ftdcfiles.adopt(self._staging(token), incoming)
        # Uploaded history is there to capture now. A connection alone has nothing until the
        # poller finds the cluster, within a minute, and writes its first samples a minute later.
        self.app.start_capture(pending["id"], delay=0 if pending["uploads"] else 150)
        self.app.rebuild()
        return self._redirect(f"/{pending['id']}/index.html")


def serve(app: App, bind: str, port: int) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"app": app})
    return ThreadingHTTPServer((bind, port), handler)


def report_stage(marker: Path) -> str:
    try:
        return "capturing:" + str(json.loads(marker.read_text()).get("stage"))
    except (OSError, ValueError, AttributeError):
        return "capturing"


def watch_analyses(app: App, every: float = 5.0) -> None:
    """Rebuild the pages when an analysis starts or ends.

    The collector rebuilds them only after the whole round, so for the minutes a first upload
    takes to analyse the page went on showing what it showed before -- "Not being watched".
    """
    seen: set = set()
    while True:
        now_ = set()
        for p in app.data.glob("*/analyzing.json"):
            try:
                now_.add((p.parent.name, p.stat().st_mtime))
            except OSError:
                continue  # it finished between the listing and the look
        # A fetch, by stage and not by time: a download rewrites its marker every two seconds,
        # and the page only words the stage.
        for p in app.data.glob("*/capturing.json"):
            now_.add((p.parent.name, (report_stage(p))))
        if now_ != seen:
            seen = now_
            try:
                app.rebuild()
            except Exception as e:  # noqa: BLE001 -- the server must keep serving
                print(f"rebuild after an analysis changed failed: {e}", flush=True)
        time.sleep(every)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("config.json"))
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--site", type=Path, default=Path("site"))
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    args.site.mkdir(parents=True, exist_ok=True)
    app = App(args.config, args.data, args.site, os.environ.get("UI_PASSWORD") or None)
    # Rebuilt on every start, not only when missing: after an upgrade the pages on disk were
    # written by the previous version, and would go on offering whatever it offered (or did not)
    # until the next collection round. In the background, so the server answers straight away.
    threading.Thread(target=app.rebuild, daemon=True).start()
    threading.Thread(target=watch_analyses, args=(app,), daemon=True).start()
    httpd = serve(app, args.bind, args.port)
    print(f"serving {args.site} on http://{args.bind}:{args.port} "
          f"({'password required' if app.password else 'no password'}) · "
          f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
