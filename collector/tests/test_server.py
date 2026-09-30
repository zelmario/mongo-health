"""The server: the site as it was, and the few forms that write -- including the ones it refuses."""
from __future__ import annotations

import base64
import json
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import onboard  # noqa: E402
import server  # noqa: E402
from tests.test_report import MS, HOUR, NOW, cluster, finding  # noqa: E402


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


OPEN = urllib.request.build_opener(NoRedirect)


@pytest.fixture
def running(tmp_path, monkeypatch):
    """A server over one cluster with one open incident, on a free port."""
    monkeypatch.delenv("ATLAS_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("ATLAS_PRIVATE_KEY", raising=False)
    data, site = tmp_path / "data", tmp_path / "site"
    cluster(data, [finding("a", at=MS - 3 * HOUR)])
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"clusters": [{"id": "prod", "source": {"type": "directory",
                                                                       "path": "/x"}}]}))
    started = []
    app = server.App(cfg, data, site, None, clock=lambda: NOW,
                     start_capture=lambda cid, delay=0: started.append(cid))
    app.rebuild()
    httpd = server.serve(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_port}"
    yield {"base": base, "app": app, "cfg": cfg, "data": data, "started": started,
           "tmp": tmp_path}
    httpd.shutdown()


def post(running, path, fields, origin=True, auth=None):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if origin:
        headers["Origin"] = running["base"]
        headers["Referer"] = running["base"] + "/prod/index.html"
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
    req = urllib.request.Request(running["base"] + path, method="POST", headers=headers,
                                 data=urllib.parse.urlencode(fields, doseq=True).encode())
    try:
        with OPEN.open(req) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def get(running, path, auth=None):
    req = urllib.request.Request(running["base"] + path)
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    try:
        with OPEN.open(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# ------------------------------------------------------------------------ the site

def test_the_site_is_served_as_it_was(running):
    status, body = get(running, "/")
    assert status == 200 and "Is my cluster healthy?" in body
    assert get(running, "/prod/index.html")[0] == 200


def test_nothing_outside_the_site_is_served(running):
    """The config beside the site holds API keys."""
    assert get(running, "/../config.json")[0] == 404
    assert get(running, "/%2e%2e/config.json")[0] == 404


# ------------------------------------------------------------------- marked as fixed

def test_fixing_an_incident_writes_the_note_and_rebuilds(running):
    status, headers, _ = post(running, "/prod/resolve", {"ids": "a", "note": "added an index"})
    assert status == 303 and headers["Location"] == "/prod/index.html"
    saved = json.loads((running["data"] / "prod" / "resolved.json").read_text())
    assert saved["a"]["note"] == "added an index"
    page = get(running, "/prod/index.html")[1]
    assert "Healthy" in page, "the page it sends you back to already shows it"


def test_putting_it_back(running):
    post(running, "/prod/resolve", {"ids": "a"})
    post(running, "/prod/reopen", {"ids": "a"})
    assert "At risk" in get(running, "/prod/index.html")[1]


def test_a_form_from_another_site_is_refused(running):
    """A page elsewhere must not be able to make the browser close incidents here."""
    status, _, _ = post(running, "/prod/resolve", {"ids": "a"}, origin=False)
    assert status == 403
    assert not (running["data"] / "prod" / "resolved.json").exists()


def test_ids_that_are_not_finding_ids_are_ignored(running):
    status, _, _ = post(running, "/prod/resolve", {"ids": "../../etc"})
    assert status == 400


# --------------------------------------------------------------------- adding clusters

def test_adding_starts_with_two_doors(running):
    status, body = get(running, "/add")
    assert status == 200 and 'href="/add/atlas"' in body and 'href="/add/onprem"' in body
    assert "Project ID" not in body, "each has its own page"
    assert "Project ID" in get(running, "/add/atlas")[1]
    onprem = get(running, "/add/onprem")[1]
    assert "Connection string" in onprem and "Drop FTDC files here" in onprem


def ftdc_archive(tmp: Path, members=("db1:27017", "db2:27017"), kind="tar") -> Path:
    """An archive the way somebody would make one: one directory per member, named anyhow."""
    import tarfile
    import zipfile
    from datetime import datetime, timedelta, timezone
    import bson
    import ftdcwrite
    t0 = datetime(2026, 8, 1, tzinfo=timezone.utc)
    root = tmp / "made"
    for n, name in enumerate(members):
        clock = iter(t0 + timedelta(seconds=10 * i) for i in range(1000))
        w = ftdcwrite.Writer(root / f"whatever{n}" / "diagnostic.data",
                             lambda: {"hostInfo": {"system": {"hostname": name.split(":")[0]}}},
                             clock=lambda: next(clock))
        for i in range(5):
            w.add(bson.encode({"start": t0 + timedelta(seconds=10 * i),
                               "replSetGetStatus": {"members": [
                                   {"name": m, "self": m == name, "health": 1.0}
                                   for m in members]}}))
        w.flush()
    if kind == "zip":
        out = tmp / "ftdc.zip"
        with zipfile.ZipFile(out, "w") as z:
            for f in root.rglob("*"):
                z.write(f, f.relative_to(root))
        return out
    out = tmp / "ftdc.tar.gz"
    with tarfile.open(out, "w:gz") as t:
        t.add(root, arcname="backup")
    return out


def upload(running, path: Path, origin=True):
    headers = {"X-Filename": path.name, "Content-Type": "application/octet-stream"}
    if origin:
        headers["Origin"] = running["base"]
    req = urllib.request.Request(running["base"] + "/add/onprem/upload", method="POST",
                                 headers=headers, data=path.read_bytes())
    try:
        with OPEN.open(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body)
        except ValueError:  # a refusal answers in HTML, not JSON
            return e.code, {}


@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_an_uploaded_archive_is_sorted_into_members(running, kind):
    """Named by what the files say about themselves, not by the folders in the archive."""
    status, body = upload(running, ftdc_archive(running["tmp"], kind=kind))
    assert status == 200
    assert [m["member"] for m in body["members"]] == ["db1:27017", "db2:27017"]
    assert body["members"][0]["from"] == "01 Aug 2026"


def test_uploaded_files_alone_add_a_cluster(running):
    token = upload(running, ftdc_archive(running["tmp"]))[1]["token"]
    status, headers, _ = post(running, "/add/onprem", {"id": "orders", "upload": token})
    assert status == 303 and headers["Location"] == "/orders/index.html"
    added = json.loads(running["cfg"].read_text())["clusters"][-1]
    assert added == {"id": "orders", "source": {"type": "onprem"}}
    incoming = running["data"] / "orders" / "incoming"
    assert sorted(p.name for p in incoming.iterdir()) == ["db1_27017", "db2_27017"]
    assert running["started"] == ["orders"]


def test_something_that_is_not_ftdc_is_explained(running):
    junk = running["tmp"] / "notes.txt"
    junk.write_text("not a capture")
    status, body = upload(running, junk)
    assert status == 400 and "neither an archive nor an FTDC file" in body["error"]


def test_an_upload_from_another_site_is_refused(running):
    status, _ = upload(running, ftdc_archive(running["tmp"]), origin=False)
    assert status == 403


def test_neither_a_connection_nor_files_is_explained(running):
    status, _, body = post(running, "/add/onprem", {"id": "orders", "uri": ""})
    assert status == 400 and "connection string, some FTDC files, or both" in body


def test_a_token_that_is_not_ours_is_ignored(running):
    status, _, body = post(running, "/add/onprem", {"id": "orders", "upload": "../../etc"})
    assert status == 400


def test_a_name_already_taken_is_refused(running):
    token = upload(running, ftdc_archive(running["tmp"]))[1]["token"]
    status, _, body = post(running, "/add/onprem", {"id": "prod", "upload": token})
    assert status == 400 and "already a cluster" in body


FOUND = [{"name": "Cluster1", "replica_set": "atlas-abc-shard-0", "tier": "M10",
          "version": "8.0", "state": "IDLE", "autoscaling": False},
         {"name": "sandbox", "replica_set": None, "tier": "M0", "version": "8.0",
          "state": "IDLE", "autoscaling": False}]


def test_adding_from_atlas_lists_then_adds_the_chosen(running, monkeypatch):
    monkeypatch.setattr(onboard, "discover", lambda *a: FOUND)
    status, _, body = post(running, "/add/atlas", {"group_id": "a" * 24,
                                                   "public_key": "pub", "private_key": "priv"})
    assert status == 200 and "Cluster1" in body and "cannot be collected" in body
    token = body.split('name="token" value="')[1].split('"')[0]
    status, headers, _ = post(running, "/add/atlas/pick", {"token": token,
                                                           "cluster": ["Cluster1"]})
    assert status == 303 and headers["Location"] == "/Cluster1/index.html"
    added = json.loads(running["cfg"].read_text())["clusters"][-1]
    assert added["id"] == "Cluster1"
    assert added["source"]["private_key"] == "priv", "a key typed in the form is kept"
    assert running["started"] == ["Cluster1"]


def test_keys_from_the_environment_stay_out_of_the_config(running, monkeypatch):
    monkeypatch.setenv("ATLAS_PUBLIC_KEY", "envpub")
    monkeypatch.setenv("ATLAS_PRIVATE_KEY", "envpriv")
    monkeypatch.setattr(onboard, "discover", lambda *a: FOUND)
    page = get(running, "/add/atlas")[1]
    assert "Private key" in page and "Leave both empty" in page, "always asked, empty allowed"
    body = post(running, "/add/atlas", {"group_id": "a" * 24})[2]
    token = body.split('name="token" value="')[1].split('"')[0]
    post(running, "/add/atlas/pick", {"token": token, "cluster": ["Cluster1"]})
    assert "private_key" not in json.loads(running["cfg"].read_text())["clusters"][-1]["source"]


def test_a_token_is_good_once(running, monkeypatch):
    monkeypatch.setattr(onboard, "discover", lambda *a: FOUND)
    body = post(running, "/add/atlas", {"group_id": "a" * 24, "public_key": "p",
                                        "private_key": "k"})[2]
    token = body.split('name="token" value="')[1].split('"')[0]
    post(running, "/add/atlas/pick", {"token": token, "cluster": ["Cluster1"]})
    status, headers, _ = post(running, "/add/atlas/pick", {"token": token,
                                                           "cluster": ["Cluster1"]})
    assert headers["Location"] == "/add/atlas"


def test_a_bad_project_id_is_explained(running):
    status, _, body = post(running, "/add/atlas", {"group_id": "nope", "public_key": "p",
                                                   "private_key": "k"})
    assert status == 400 and "24 hexadecimal" in body


# --------------------------------------------------------------------------- password

def test_a_password_guards_everything(running):
    running["app"].password = "s3cret"
    assert get(running, "/")[0] == 401
    assert get(running, "/", auth="any:wrong")[0] == 401
    assert get(running, "/", auth="any:s3cret")[0] == 200
    assert post(running, "/prod/resolve", {"ids": "a"})[0] == 401


def test_a_key_typed_for_another_project_is_used_and_kept(running, monkeypatch):
    """With a key in the environment for one project, a second project needs its own."""
    monkeypatch.setenv("ATLAS_PUBLIC_KEY", "envpub")
    monkeypatch.setenv("ATLAS_PRIVATE_KEY", "envpriv")
    seen = []
    monkeypatch.setattr(onboard, "discover", lambda g, pub, priv: seen.append(pub) or FOUND)
    body = post(running, "/add/atlas", {"group_id": "b" * 24, "public_key": "other",
                                        "private_key": "otherpriv"})[2]
    token = body.split('name="token" value="')[1].split('"')[0]
    post(running, "/add/atlas/pick", {"token": token, "cluster": ["Cluster1"]})
    assert seen == ["other"]
    source = json.loads(running["cfg"].read_text())["clusters"][-1]["source"]
    assert source["public_key"] == "other"


# ------------------------------------------------------------------ connection string

def test_a_connection_string_is_tested_before_it_is_added(running, monkeypatch):
    import poller
    monkeypatch.setattr(poller, "check", lambda uri: {
        "ok": True, "kind": "replica set", "error": None,
        "members": [{"host": "db1:27017", "ok": True, "version": "8.0.3", "error": None}]})
    uri = "mongodb://mongo-health:pw@db1/?replicaSet=rs0"
    status, _, body = post(running, "/add/onprem", {"id": "orders", "uri": uri})
    assert status == 200 and "db1:27017" in body and "every one answers" in body
    assert "pw@" not in body, "the password does not come back to the page"
    token = body.split('name="token" value="')[1].split('"')[0]
    status, headers, _ = post(running, "/add/onprem/confirm", {"token": token})
    assert headers["Location"] == "/orders/index.html"
    added = json.loads(running["cfg"].read_text())["clusters"][-1]
    assert added == {"id": "orders", "source": {"type": "onprem", "uri": uri}}
    assert running["started"] == ["orders"]


def test_a_connection_and_files_together(running, monkeypatch):
    """The files bring the past, the connection keeps it going: both end up on one cluster."""
    import poller
    monkeypatch.setattr(poller, "check", lambda uri: {
        "ok": True, "kind": "replica set", "error": None,
        "members": [{"host": "db1:27017", "ok": True, "version": "8.0.3", "error": None}]})
    token = upload(running, ftdc_archive(running["tmp"]))[1]["token"]
    body = post(running, "/add/onprem", {"id": "orders", "uri": "mongodb://u:p@db1/",
                                         "upload": token})[2]
    assert "Plus the history from the files" in body
    confirm = body.split('name="token" value="')[1].split('"')[0]
    post(running, "/add/onprem/confirm", {"token": confirm})
    incoming = running["data"] / "orders" / "incoming"
    assert sorted(p.name for p in incoming.iterdir()) == ["db1_27017", "db2_27017"]


def test_a_member_the_user_cannot_read_is_explained_and_not_added(running, monkeypatch):
    import poller
    monkeypatch.setattr(poller, "check", lambda uri: {
        "ok": False, "kind": "replica set", "error": None,
        "members": [{"host": "db2:27017", "ok": False, "version": "8.0.3",
                     "error": "the user cannot read diagnostics here — it needs the "
                              "clusterMonitor role"}]})
    status, _, body = post(running, "/add/onprem", {"id": "orders", "uri": "mongodb://u:p@db2/"})
    assert "clusterMonitor" in body and "createUser" in body
    assert 'action="/add/onprem/confirm"' not in body
