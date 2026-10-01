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
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

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
        with the scheduled one; if that one is running, the next hour picks the new cluster up."""
        env = dict(os.environ, CONFIG=str(self.config_path), DATA=str(self.data),
                   SITE=str(self.site))
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


def choose_page() -> str:
    """Two doors, because the two are different conversations: Atlas needs an API key and
    nothing on your servers; a server of your own needs a user on it, or its files."""
    return page("Add a cluster · mongo-health", """
    <p><a href="/index.html" class="back">← all clusters</a></p>
    <h1>Add a cluster</h1>
    <div class="doors">
      <a class="door" href="/add/atlas">
        <b>On Atlas</b>
        <span>An API key with read-only access to the project. Everything Atlas still holds
          comes down straight away.</span>
      </a>
      <a class="door" href="/add/onprem">
        <b>On your own servers</b>
        <span>A connection string with a monitoring user, the FTDC files you already have, or
          both.</span>
      </a>
    </div>""")


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


def onprem_page(error: str = "", name: str = "", uri: str = "") -> str:
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
      </div>

      <h2>Connect to it <span class="optional">— to keep watching from now on</span></h2>
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
      <div class="card">
        <div class="drop" id="drop" tabindex="0">
          <b>Drop FTDC files here</b>
          <span>A .tar.gz, .tgz, .tar or .zip of each member's <code>diagnostic.data</code> —
            one member or all of them, in one archive or several — or
            <label for="file" class="link">choose them</label>.</span>
          <input id="file" type="file" multiple
                 accept=".gz,.tgz,.tar,.zip,application/gzip,application/zip">
        </div>
        <div id="uploads"></div>
        <p class="hint">mongod keeps them in <code>diagnostic.data</code> under its
          <code>dbPath</code>. Members are recognised from the files themselves, so the layout
          inside the archive does not matter.</p>
      </div>

      <p class="hint">Either one is enough; both is best — the files bring the past, the
        connection keeps it going.</p>
      <button type="submit">Continue</button>
    </form>
    <script>{UPLOAD_JS}</script>""")


# Plain JavaScript, no library: upload each dropped file with progress, show what it contained,
# and remember its token for the form.
UPLOAD_JS = r"""
(function () {
  const drop = document.getElementById('drop'), input = document.getElementById('file');
  const list = document.getElementById('uploads'), form = document.getElementById('onprem');
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
      if (e.lengthComputable) row.querySelector('.use-bar').style.setProperty('--w', (100 * e.loaded / e.total).toFixed(0) + '%');
    };
    xhr.onload = () => {
      let r = {};
      try { r = JSON.parse(xhr.responseText); } catch (e) { r = { error: 'The server did not answer as expected.' }; }
      if (r.error) {
        row.querySelector('.meta').textContent = r.error;
        row.classList.add('failed');
        return;
      }
      row.querySelector('.use-bar').remove();
      row.querySelector('.meta').textContent = r.members.length + ' member(s) found';
      const ul = document.createElement('ul');
      ul.innerHTML = r.members.map((m) => '<li><code>' + esc(m.member) + '</code> — ' + esc(m.from) +
        ' to ' + esc(m.to) + ', ' + m.files + ' file(s), ' + m.mb + ' MB</li>').join('');
      row.appendChild(ul);
      const token = document.createElement('input');
      token.type = 'hidden'; token.name = 'upload'; token.value = r.token;
      form.appendChild(token);
    };
    xhr.onerror = () => { row.querySelector('.meta').textContent = 'The upload failed.'; row.classList.add('failed'); };
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
        <p class="hint">Adding one pulls everything Atlas still holds for it — usually 3 to 10
          days. Atlas takes up to half an hour to prepare that the first time; the page shows the
          cluster straight away and fills in when the data lands.</p>
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
                 "/add/onprem": onprem_page}
        if path in pages:
            return self._html(pages[path]())
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

        if path == "/add/atlas":
            return self._discover(one("group_id"), one("public_key"), one("private_key"))
        if path == "/add/atlas/pick":
            return self._pick(one("token"), form.get("cluster") or [])
        if path == "/add/onprem":
            return self._onprem(one("id"), one("uri"), form.get("upload") or [])
        if path == "/add/onprem/confirm":
            return self._onprem_confirm(one("token"))
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

    def _pick(self, token: str, names: list[str]):
        at, pending = PENDING.pop(token, (0, None))
        if pending is None or time.time() - at > PENDING_TTL or "found" not in pending:
            return self._redirect("/add/atlas")
        chosen = [c for c in pending["found"] if c["name"] in names and c.get("replica_set")]
        added = []
        for c in chosen:
            source = {"type": "atlas", "group_id": pending["group_id"],
                      "replica_set": c["replica_set"], **pending["keys"]}
            try:
                self.app.add_entry({"id": c["name"], "source": source})
                added.append(c["name"])
            except (ValueError, config.ConfigError):
                continue
        self.app.rebuild()
        for name in added:
            self.app.start_capture(name)
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
            members = ftdcfiles.receive(archive, staging)
        except Exception as e:
            shutil.rmtree(staging, ignore_errors=True)
            return answer({"error": str(e)}, 400)
        finally:
            archive.unlink(missing_ok=True)
        return answer({"token": token, "members": [
            {"member": m["member"], "files": m["files"], "mb": round(m["bytes"] / 1048576),
             "from": f"{m['from']:%d %b %Y}", "to": f"{m['to']:%d %b %Y}"} for m in members]})

    def _uploads(self, tokens: list[str]) -> list[dict]:
        """What the tokens on the form stand for, ignoring any that are not ours."""
        found = []
        for token in tokens:
            if not re.fullmatch(r"[0-9a-f]{24}", token):
                continue
            members = self._staging(token) / "members"
            for m in (members.iterdir() if members.exists() else []):
                files = [f for f in m.iterdir() if f.is_file()]
                spans = [ftdcfiles.describe(f) for f in files[:1] + files[-1:]]
                found.append({"token": token, "member": m.name,
                              "from": min(s["from"] for s in spans if s["from"]),
                              "to": max(s["to"] for s in spans if s["to"])})
        return found

    def _onprem(self, cluster_id: str, uri: str, tokens: list[str]):
        if not config.CLUSTER_ID.match(cluster_id):
            return self._html(onprem_page("A name is letters, digits, dots, dashes or "
                                          "underscores.", cluster_id, uri), 400)
        uploads = self._uploads(tokens)
        if not uri and not uploads:
            return self._html(onprem_page("Give it a connection string, some FTDC files, or "
                                          "both.", cluster_id, uri), 400)
        if uri and not uri.startswith(("mongodb://", "mongodb+srv://")):
            return self._html(onprem_page("A connection string starts with mongodb:// or "
                                          "mongodb+srv://.", cluster_id, uri), 400)
        pending = {"id": cluster_id, "uri": uri, "uploads": sorted({u["token"] for u in uploads})}
        if not uri:
            return self._finish(pending)
        import poller  # noqa: PLC0415 -- pymongo is only needed once somebody connects

        result = poller.check(uri)
        token = ""
        if result["ok"]:
            token = secrets.token_urlsafe(16)
            PENDING[token] = (time.time(), pending)
        return self._html(tested_page(token, cluster_id, result, uploads))

    def _onprem_confirm(self, token: str):
        at, pending = PENDING.pop(token, (0, None))
        if pending is None or time.time() - at > PENDING_TTL or "uploads" not in pending:
            return self._redirect("/add/onprem")
        return self._finish(pending)

    def _finish(self, pending: dict):
        source = {"type": "onprem", **({"uri": pending["uri"]} if pending["uri"] else {})}
        try:
            self.app.add_entry({"id": pending["id"], "source": source})
        except (ValueError, config.ConfigError) as e:
            return self._html(onprem_page(str(e), pending["id"], pending["uri"]), 400)
        incoming = self.app.data / pending["id"] / "incoming"
        for token in pending["uploads"]:
            ftdcfiles.adopt(self._staging(token), incoming)
        self.app.rebuild()
        # Uploaded history is there to capture now. A connection alone has nothing until the
        # poller finds the cluster, within a minute, and writes its first samples a minute later.
        self.app.start_capture(pending["id"], delay=0 if pending["uploads"] else 150)
        return self._redirect(f"/{pending['id']}/index.html")


def serve(app: App, bind: str, port: int) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"app": app})
    return ThreadingHTTPServer((bind, port), handler)


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
    httpd = serve(app, args.bind, args.port)
    print(f"serving {args.site} on http://{args.bind}:{args.port} "
          f"({'password required' if app.password else 'no password'}) · "
          f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
