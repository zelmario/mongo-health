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
    assert added == {"id": "orders", "retention_days": 90, "source": {"type": "onprem"}}
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
    assert added == {"id": "orders", "retention_days": 90,
                     "source": {"type": "onprem", "uri": uri, "interval": 10}}
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


# ------------------------------------------------------------------------- removing

@pytest.fixture
def lock(running, monkeypatch):
    path = running["tmp"] / ".run.lock"
    monkeypatch.setenv("LOCK", str(path))
    return path


def test_the_cluster_page_links_to_removing_it(running):
    assert 'href="../remove/prod"' in get(running, "/prod/index.html")[1]


def test_removing_asks_first_and_says_what_is_held(running):
    status, body = get(running, "/remove/prod")
    assert status == 200 and "Remove prod?" in body
    assert "cannot be undone" in body


def test_removing_keeps_the_data_unless_asked(running, lock):
    status, headers, _ = post(running, "/remove/prod", {"confirm": "prod"})
    assert status == 303 and headers["Location"] == "/index.html"
    assert json.loads(running["cfg"].read_text())["clusters"] == []
    assert (running["data"] / "prod").is_dir(), "the only copy of its FTDC stays"
    assert get(running, "/prod/index.html")[0] == 404, "its page goes with it"


def test_removing_with_its_data_deletes_the_data(running, lock):
    post(running, "/remove/prod", {"confirm": "prod", "delete_data": "1"})
    assert not (running["data"] / "prod").exists()


def test_a_post_that_skipped_the_confirmation_removes_nothing(running, lock):
    status, headers, _ = post(running, "/remove/prod", {"delete_data": "1"})
    assert status == 303 and headers["Location"] == "/remove/prod"
    assert len(json.loads(running["cfg"].read_text())["clusters"]) == 1
    assert (running["data"] / "prod").is_dir()


def test_removing_a_cluster_that_is_not_there(running, lock):
    assert get(running, "/remove/nope")[0] == 404
    assert post(running, "/remove/nope", {"confirm": "nope"})[0] == 404


def test_deleting_data_waits_for_no_round(running, lock):
    """A round holding the lock may be reading the files: nothing is removed."""
    import fcntl
    with open(lock, "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        status, _, body = post(running, "/remove/prod", {"confirm": "prod", "delete_data": "1"})
    assert status == 409 and "Nothing was removed" in body
    assert len(json.loads(running["cfg"].read_text())["clusters"]) == 1
    assert (running["data"] / "prod").is_dir()


def test_a_removal_from_another_site_is_refused(running, lock):
    assert post(running, "/remove/prod", {"confirm": "prod"}, origin=False)[0] == 403
    assert len(json.loads(running["cfg"].read_text())["clusters"]) == 1


# ------------------------------------------------------------------------ progress

def test_progress_while_analyzing_and_after(running):
    base = running["data"] / "prod"
    assert json.loads(get(running, "/progress/prod")[1]) == {"analyzing": False}
    (base / "analyzing.json").write_text(json.dumps({"started": NOW.isoformat(), "files": 81}))
    assert json.loads(get(running, "/progress/prod")[1]) == {"analyzing": True}, \
        "started, nothing decoded yet"
    (base / "analyzing.progress.json").write_text(
        json.dumps({"done": 38, "total": 81, "node": "db1_27017", "stage": "decoding"}))
    p = json.loads(get(running, "/progress/prod")[1])
    assert p["analyzing"] and p["done"] == 38 and p["total"] == 81


def test_a_killed_analysis_does_not_report_progress_for_ever(running):
    (running["data"] / "prod" / "analyzing.json").write_text(
        json.dumps({"started": "2020-01-01T00:00:00+00:00"}))
    assert json.loads(get(running, "/progress/prod")[1]) == {"analyzing": False}


# --------------------------------------------------------------- over SFTP and from a folder

def test_the_ways_in_ask_for_nothing_on_the_hosts(running):
    body = get(running, "/add")[1]
    assert 'href="/add/folder"' in body and 'href="/add/onprem"' in body
    assert "/add/ssh" not in body
    assert get(running, "/add/ssh")[0] == 404


def test_every_way_in_asks_how_long_to_keep_the_files(running):
    for path in ("/add/onprem", "/add/folder"):
        body = get(running, path)[1]
        assert 'name="retention_days"' in body and '<option value="90" selected>' in body


def test_a_folder_with_one_subfolder_per_member(running):
    import tarfile
    archive = ftdc_archive(running["tmp"])
    with tarfile.open(archive) as t:
        t.extractall(running["tmp"] / "x")
    root = running["tmp"] / "x" / "backup"
    for d in root.iterdir():            # whatever0/diagnostic.data -> whatever0/
        for f in (d / "diagnostic.data").iterdir():
            f.rename(d / f.name)
    status, _, body = post(running, "/add/folder", {"id": "orders", "path": str(root)})
    assert status == 200 and "Found 2 members" in body
    assert "db1:27017" in body and "db2:27017" in body
    import re
    token = re.search(r'name="token" value="([^"]+)"', body).group(1)
    assert post(running, "/add/folder/confirm", {"token": token})[0] == 303
    added = json.loads(running["cfg"].read_text())["clusters"][-1]
    assert added == {"id": "orders", "retention_days": 90,
                     "source": {"type": "directory", "path": str(root)}}


def test_one_members_diagnostic_data_is_named_after_the_member(running):
    import tarfile
    with tarfile.open(ftdc_archive(running["tmp"], members=("db7:27017",))) as t:
        t.extractall(running["tmp"] / "y")
    diag = running["tmp"] / "y" / "backup" / "whatever0" / "diagnostic.data"
    body = post(running, "/add/folder", {"id": "solo", "path": str(diag)})[2]
    import re
    token = re.search(r'name="token" value="([^"]+)"', body).group(1)
    post(running, "/add/folder/confirm", {"token": token})
    added = json.loads(running["cfg"].read_text())["clusters"][-1]
    assert added["source"]["node"] == "db7_27017"


def test_a_folder_that_is_not_there_says_how_to_mount_it(running):
    status, _, body = post(running, "/add/folder", {"id": "o", "path": "/nowhere/at/all"})
    assert status == 400 and "docker-compose.override.yml" in body


def test_removing_an_sftp_cluster_deletes_its_key(running, lock):
    keys = running["cfg"].parent / "keys"
    keys.mkdir()
    (keys / "prod_ed25519").write_text("private")
    (keys / "prod.known_hosts").write_text("db1 ssh-ed25519 AAAA")
    elsewhere = running["tmp"] / "mine_ed25519"
    elsewhere.write_text("somebody else's")
    running["cfg"].write_text(json.dumps({"clusters": [{"id": "prod", "source": {
        "type": "ssh", "hosts": ["db1"], "path": "/diagnostic.data",
        "identity": str(keys / "prod_ed25519"), "known_hosts": str(keys / "prod.known_hosts")}},
        {"id": "other", "source": {"type": "ssh", "hosts": ["db2"], "path": "/d",
                                   "identity": str(elsewhere), "known_hosts": str(elsewhere)}}]}))
    post(running, "/remove/prod", {"confirm": "prod"})
    assert not (keys / "prod_ed25519").exists() and not (keys / "prod.known_hosts").exists()
    post(running, "/remove/other", {"confirm": "other"})
    assert elsewhere.exists(), "a key the page did not make is not the page's to delete"


def test_the_retention_chosen_is_the_one_kept(running):
    token = upload(running, ftdc_archive(running["tmp"]))[1]["token"]
    post(running, "/add/onprem", {"id": "orders", "upload": token, "retention_days": "30"})
    assert json.loads(running["cfg"].read_text())["clusters"][-1]["retention_days"] == 30


def test_a_retention_not_offered_falls_back_to_the_default(running):
    token = upload(running, ftdc_archive(running["tmp"]))[1]["token"]
    post(running, "/add/onprem", {"id": "orders", "upload": token, "retention_days": "99999"})
    assert json.loads(running["cfg"].read_text())["clusters"][-1]["retention_days"] == 90


def test_the_interval_is_priced_with_the_clusters_own_sample(running, monkeypatch):
    import poller
    monkeypatch.setattr(poller, "check", lambda uri: {
        "ok": True, "kind": "replica set", "error": None, "members": [
            {"host": f"db{i}:27017", "ok": True, "version": "8.0.4", "error": None,
             "sample_bytes": 226_000, "compressed_bytes": 33_600} for i in (1, 2, 3)]})
    body = post(running, "/add/onprem", {"id": "orders", "uri": "mongodb://u:p@db1/",
                                         "retention_days": "60"})[2]
    assert 'value="10"\n                 checked' in body or 'value="10"' in body
    assert "0.29 GB a day per member" in body and "2.90 GB a day per member" in body
    assert "for all 3" in body
    import re
    token = re.search(r'name="token" value="([^"]+)"', body).group(1)
    post(running, "/add/onprem/confirm", {"token": token, "interval": "1"})
    added = json.loads(running["cfg"].read_text())["clusters"][-1]
    assert added["source"]["interval"] == 1 and added["retention_days"] == 60


def test_an_interval_not_offered_is_the_default(running, monkeypatch):
    import poller
    monkeypatch.setattr(poller, "check", lambda uri: {
        "ok": True, "kind": "replica set", "error": None,
        "members": [{"host": "db1:27017", "ok": True, "version": "8.0", "error": None}]})
    body = post(running, "/add/onprem", {"id": "orders", "uri": "mongodb://u:p@db1/"})[2]
    import re
    token = re.search(r'name="token" value="([^"]+)"', body).group(1)
    post(running, "/add/onprem/confirm", {"token": token, "interval": "0"})
    assert json.loads(running["cfg"].read_text())["clusters"][-1]["source"]["interval"] == 10


def test_atlas_clusters_keep_the_retention_chosen(running, monkeypatch):
    monkeypatch.setattr(onboard, "discover", lambda g, pub, priv: [
        {"name": "orders-prod", "replica_set": "atlas-abc-shard-0", "tier": "M10",
         "version": "8.0"}])
    body = post(running, "/add/atlas", {"group_id": "a" * 24, "public_key": "p",
                                        "private_key": "k"})[2]
    assert 'name="retention_days"' in body
    import re
    token = re.search(r'name="token" value="([^"]+)"', body).group(1)
    post(running, "/add/atlas/pick", {"token": token, "cluster": "orders-prod",
                                      "retention_days": "180"})
    assert json.loads(running["cfg"].read_text())["clusters"][-1]["retention_days"] == 180


# ------------------------------------------------------------------------ retention

def hold(running, *names, node="db1_27017"):
    d = running["data"] / "prod" / "ftdc" / node
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        (d / n).write_bytes(b"x" * 1024 * 1024)


def retention(running):
    return json.loads(running["cfg"].read_text())["clusters"][0].get("retention_days")


def test_the_cluster_page_says_how_long_and_links_to_change_it(running):
    page = get(running, "/prod/index.html")[1]
    assert "Raw FTDC kept for 1 year." in page and 'href="../settings/prod"' in page
    body = get(running, "/settings/prod")[1]
    assert '<option value="365" selected>' in body


def test_keeping_longer_is_saved_straight_away(running):
    running["cfg"].write_text(json.dumps({"clusters": [{"id": "prod", "retention_days": 30,
        "source": {"type": "directory", "path": "/x"}}]}))
    status, headers, _ = post(running, "/settings/prod", {"retention_days": "180"})
    assert status == 303 and headers["Location"] == "/prod/index.html"
    assert retention(running) == 180
    assert "Raw FTDC kept for 6 months." in get(running, "/prod/index.html")[1]


def test_keeping_less_says_what_goes_and_waits_for_a_yes(running):
    # NOW is 20 Aug 2026: one file from May and one from June are past a month, the newest
    # of the node is spared whatever its age, exactly as prune.py does.
    hold(running, "metrics.2026-05-01T00-00-00Z-00000", "metrics.2026-06-01T00-00-00Z-00000",
         "metrics.2026-08-19T00-00-00Z-00000", "metrics.interim")
    status, _, body = post(running, "/settings/prod", {"retention_days": "30"})
    assert status == 200 and "2 files, 2 MB" in body and "01 May 2026 to 01 Jun 2026" in body
    assert "cannot be undone" in body
    assert retention(running) is None, "nothing changes before the yes"
    post(running, "/settings/prod", {"retention_days": "30", "confirm": "prod"})
    assert retention(running) == 30


def test_keeping_less_with_nothing_that_old_needs_no_yes(running):
    hold(running, "metrics.2026-08-19T00-00-00Z-00000")
    assert post(running, "/settings/prod", {"retention_days": "30"})[0] == 303
    assert retention(running) == 30


def test_a_retention_set_by_hand_survives_saving_the_page(running):
    running["cfg"].write_text(json.dumps({"clusters": [{"id": "prod", "retention_days": 120,
        "source": {"type": "directory", "path": "/x"}}]}))
    body = get(running, "/settings/prod")[1]
    assert '<option value="120" selected>120 days, as set in the config</option>' in body
    post(running, "/settings/prod", {"retention_days": "120"})
    assert retention(running) == 120


def test_atlas_clusters_are_told_atlas_cannot_give_the_files_back(running):
    running["cfg"].write_text(json.dumps({"clusters": [{"id": "prod", "source": {
        "type": "atlas", "group_id": "g", "replica_set": "rs"}}]}))
    hold(running, "metrics.2026-05-01T00-00-00Z-00000", "metrics.2026-08-19T00-00-00Z-00000")
    body = post(running, "/settings/prod", {"retention_days": "30"})[2]
    assert "Atlas no longer holds files that old" in body


def test_settings_for_a_cluster_that_is_not_there(running):
    assert get(running, "/settings/nope")[0] == 404
    assert post(running, "/settings/nope", {"retention_days": "30"})[0] == 404
