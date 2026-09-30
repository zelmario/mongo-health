#!/usr/bin/env python3
"""The report, served, with the few things that need somewhere to write.

    python3 server.py --config config.json --data data --site site --port 8080

Serves the static site the collector builds, exactly as a plain web server would, and adds:

    GET  /add                   add a cluster: an Atlas project, or a directory of FTDC
    POST /add/atlas             list the clusters in an Atlas project
    POST /add/atlas/pick        add the chosen ones, and start their first capture
    POST /add/directory         add a directory of FTDC
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


def add_page(error: str = "", env_keys: bool = False, uri: str = "", name: str = "") -> str:
    # Always asked for. Hiding the fields when a key sits in the environment made the page look
    # as if Atlas needed no key at all, and left no way to add a project that needs another one.
    required = "" if env_keys else "required"
    keys = f"""
        <label for="public_key">Public key</label>
        <input id="public_key" name="public_key" type="text" {required} autocomplete="off">
        <label for="private_key">Private key</label>
        <input id="private_key" name="private_key" type="password" {required}
               autocomplete="off">
        <p class="hint">An API key with Project Read Only on this project, and nothing more.
          {'Leave both empty to use the key in <code>.env</code>. ' if env_keys else ''}A key
          typed here is written to your config file, which only you can read.</p>"""
    return page("Add a cluster · mongo-health", f"""
    <p><a href="/index.html" class="back">← all clusters</a></p>
    <h1>Add a cluster</h1>
    {f'<div class="flash">{esc(error)}</div>' if error else ''}
    <h2>On Atlas</h2>
    <div class="card">
      <form method="post" action="/add/atlas">
        <label for="group_id">Project ID</label>
        <input id="group_id" name="group_id" type="text" required autocomplete="off"
               placeholder="24 hexadecimal characters, from Project Settings">
        {keys}
        <button type="submit">List its clusters</button>
      </form>
    </div>
    <h2>On your own servers</h2>
    <div class="card">
      <form method="post" action="/add/mongodb/test">
        <label for="m_id">Name</label>
        <input id="m_id" name="id" type="text" required placeholder="orders-prod"
               value="{esc(name)}">
        <label for="uri">Connection string</label>
        <input id="uri" name="uri" type="password" required autocomplete="off"
               placeholder="mongodb://mongo-health:…@db1,db2,db3/?replicaSet=rs0"
               value="{esc(uri)}">
        <p class="hint">Any member, or all of them, or a <code>mongodb+srv://</code> address:
          the rest are found on their own. It needs one user with the clusterMonitor role,
          created once on the primary — the set copies it to every member:</p>
        <pre class="snippet">{esc(CREATE_USER)}</pre>
        <button type="submit">Test the connection</button>
      </form>
    </div>
    <details class="card-fold">
      <summary>Or read FTDC files from a directory</summary>
    <div class="card">
      <form method="post" action="/add/directory">
        <label for="dir_id">Name</label>
        <input id="dir_id" name="id" type="text" required placeholder="orders-prod">
        <label for="path">Directory with the FTDC</label>
        <input id="path" name="path" type="text" required
               placeholder="/mnt/ftdc/orders-prod — one subdirectory per member">
        <p class="hint">A path this container can read: each member's
          <code>diagnostic.data</code>, mounted or copied there. Reading the files gives one
          sample a second and the history from before the tool was installed; a connection
          string gives one every ten seconds from now on.</p>
        <button type="submit">Add it</button>
      </form>
    </div>
    </details>""")


def tested_page(token: str, name: str, result: dict) -> str:
    rows = "".join(
        f"""<tr><td class="num">{esc(m['host'])}</td><td>{esc(m.get('version') or '—')}</td>
            <td style="color:var({'--ok' if m['ok'] else '--bad'})">
              {'reads diagnostics' if m['ok'] else esc(m['error'])}</td></tr>"""
        for m in result["members"])
    if result["ok"]:
        verdict = (f'<p class="capacity-line" data-state="spare">Found a {esc(result["kind"])} '
                   f'of {len(result["members"])} member(s), and every one answers.</p>')
        action = f"""
      <form method="post" action="/add/mongodb">
        <input type="hidden" name="token" value="{esc(token)}">
        <button type="submit">Add {esc(name)}</button>
      </form>
      <p class="hint">Samples start arriving in a minute; the first evaluation follows.</p>"""
    else:
        verdict = (f'<p class="capacity-line" data-state="tight">'
                   f'{esc(result["error"] or "Not every member can be read yet.")}</p>')
        action = ('<p class="hint">Fix what is marked above and test again. A member that says '
                  'it needs clusterMonitor has the user but not the role; one that does not '
                  'answer may not be reachable from here under the name it gives itself.</p>'
                  f'<pre class="snippet">{esc(CREATE_USER)}</pre>'
                  '<p><a href="/add">← back to the form</a></p>')
    table = (f'<div class="scroll"><table><thead><tr><th>Member</th><th>Version</th>'
             f'<th></th></tr></thead><tbody>{rows}</tbody></table></div>' if rows else "")
    return page("Test the connection · mongo-health", f"""
    <p><a href="/add" class="back">← back</a></p>
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
                "" if usable else "no replica set name, so it cannot be collected (M0/Flex)")
        rows.append(f"""
        <label class="pick">
          <input type="checkbox" name="cluster" value="{esc(c['name'])}"
                 {'checked' if usable and not taken else ''}
                 {'disabled' if taken or not usable else ''}>
          <b>{esc(c['name'])}</b> <span class="meta">{esc(c.get('tier') or '?')} ·
            MongoDB {esc(c.get('version') or '?')}{' · ' + esc(note) if note else ''}</span>
        </label>""")
    return page("Choose clusters · mongo-health", f"""
    <p><a href="/add" class="back">← back</a></p>
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
        if path == "/add":
            return self._html(add_page(env_keys=bool(os.environ.get("ATLAS_PUBLIC_KEY"))))
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
        if path == "/add/directory":
            return self._add_directory(one("id"), one("path"))
        if path == "/add/mongodb/test":
            return self._test_mongodb(one("id"), one("uri"))
        if path == "/add/mongodb":
            return self._add_mongodb(one("token"))
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
            return self._html(add_page("A project ID is 24 hexadecimal characters.", env_keys),
                              400)
        if not (public_key and private_key):
            return self._html(add_page("An API key is needed: both halves of it.", env_keys),
                              400)
        try:
            found = onboard.discover(group_id, public_key, private_key)
        except Exception as e:
            return self._html(add_page(f"Atlas did not answer as expected: {e}", env_keys), 502)
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
        if pending is None or time.time() - at > PENDING_TTL:
            return self._redirect("/add")
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

    def _add_directory(self, cluster_id: str, path: str):
        env_keys = bool(os.environ.get("ATLAS_PUBLIC_KEY"))
        if not config.CLUSTER_ID.match(cluster_id):
            return self._html(add_page("A name is letters, digits, dots, dashes or underscores.",
                                       env_keys), 400)
        root = Path(path)
        if not root.is_dir() or not any(root.rglob("metrics.*")):
            return self._html(add_page(f"No FTDC files under {path} — it has to be a directory "
                                       f"this container can read.", env_keys), 400)
        try:
            self.app.add_entry({"id": cluster_id, "source": {"type": "directory",
                                                             "path": str(root)}})
        except (ValueError, config.ConfigError) as e:
            return self._html(add_page(str(e), env_keys), 400)
        self.app.rebuild()
        self.app.start_capture(cluster_id)
        return self._redirect(f"/{cluster_id}/index.html")


    def _test_mongodb(self, cluster_id: str, uri: str):
        env_keys = bool(os.environ.get("ATLAS_PUBLIC_KEY"))
        if not config.CLUSTER_ID.match(cluster_id):
            return self._html(add_page("A name is letters, digits, dots, dashes or underscores.",
                                       env_keys, uri, cluster_id), 400)
        if not uri.startswith(("mongodb://", "mongodb+srv://")):
            return self._html(add_page("A connection string starts with mongodb:// or "
                                       "mongodb+srv://.", env_keys, uri, cluster_id), 400)
        import poller  # noqa: PLC0415 -- pymongo is only needed once somebody connects

        result = poller.check(uri)
        token = ""
        if result["ok"]:
            token = secrets.token_urlsafe(16)
            PENDING[token] = (time.time(), {"id": cluster_id, "uri": uri})
        return self._html(tested_page(token, cluster_id, result))

    def _add_mongodb(self, token: str):
        at, pending = PENDING.pop(token, (0, None))
        if pending is None or time.time() - at > PENDING_TTL or "uri" not in pending:
            return self._redirect("/add")
        try:
            self.app.add_entry({"id": pending["id"],
                                "source": {"type": "mongodb", "uri": pending["uri"]}})
        except (ValueError, config.ConfigError) as e:
            return self._html(add_page(str(e), bool(os.environ.get("ATLAS_PUBLIC_KEY"))), 400)
        self.app.rebuild()
        # The poller finds the new cluster within a minute and writes its first samples a
        # minute after that; the capture that turns them into a first evaluation waits for them.
        self.app.start_capture(pending["id"], delay=150)
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
