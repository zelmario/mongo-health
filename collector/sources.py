"""Where FTDC files come from.

The format is the same wherever they arrive from: a `diagnostic.data` off a mongod on EC2
decodes exactly like one from Atlas. Only the transport differs, so the transport is the only
thing abstracted here -- the rest of the pipeline always receives the same thing: new
`metrics.*` files for a (customer_id, cluster_id).

Atlas, a directory on this machine, and SFTP to each member are the ways files are pulled;
the poller and the upload form put theirs in a directory the collector then reads.
"""
from __future__ import annotations

import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Protocol

import requests
from requests.auth import HTTPDigestAuth


def node_from_path(path: Path, fallback: str) -> str:
    """Work out which member a file belongs to, from its path.

    Two layouts are in circulation and both are worth supporting:

        <hostname>/27017/diagnostic.data/metrics.*   <- Atlas bundles
        /var/lib/mongodb/diagnostic.data/metrics.*   <- a standalone mongod

    The directory containing `diagnostic.data` is the node, unless it is a number: then it is
    the port and the real name sits one level further up.
    """
    parts = path.parts
    if "diagnostic.data" not in parts:
        return fallback
    i = parts.index("diagnostic.data")
    if i == 0:
        return fallback
    candidate = parts[i - 1]
    if candidate.isdigit() and i >= 2:
        return parts[i - 2]
    return candidate


@dataclass(frozen=True)
class FTDCFile:
    """An FTDC file ready to be stored.

    `node` identifies the member within the cluster -- it is used as a directory name, so it
    has to be stable across runs. `name` is the original file name
    (`metrics.<timestamp>-NNNNN` or `metrics.interim`), which is what allows deduplication
    without decoding anything.
    """

    node: str
    name: str
    path: Path

    @property
    def is_interim(self) -> bool:
        # The interim file is the only mutable one: mongod keeps appending chunks to it, so
        # it has to be re-fetched and re-processed on every run.
        return self.name == "metrics.interim"


class Source(Protocol):
    """The contract any origin of FTDC satisfies."""

    def describe(self) -> str: ...

    def fetch(self, since: datetime | None) -> Iterator[FTDCFile]:
        """Bring the available files into a temporary directory and yield them.

        `since` is a hint to bound volume, not a strict filter: the caller must deduplicate
        regardless. On Atlas, for instance, the date filter applies to the file *name* rather
        than its contents, so asking for more than needed is the only safe way not to lose
        data.
        """
        ...


# --------------------------------------------------------------------------- Atlas

class AtlasSource:
    """Atlas, through the `logCollectionJobs` endpoint of the v1.0 Admin API.

    Needs an API key with the Project Read Only role -- the lowest that exists. That is
    enough for FTDC; it is not enough for mongod logs, which require more.

    The endpoint only exists in the v1.0 API, which was never migrated to v2 -- verified
    against the published spec rather than assumed. The usual answer, polling
    `getDiagnosticData`, is a database command and needs a database user, so it is not a
    drop-in replacement: it costs the promise in `docs/api-key.md` that we never ask for one.
    """

    BASE = "https://cloud.mongodb.com/api/atlas/v1.0"

    # The endpoint this whole product depends on lives ONLY in v1.0. Verified against the
    # published v2 spec: 335 routes, and "logCollection" appears in none of them -- the only
    # log route there downloads mongod, mongos and audit text logs, not FTDC. So the day Atlas
    # retires v1.0, collection stops for every Atlas customer at once.
    #
    # The fallback everyone assumes -- polling `getDiagnosticData` -- is a database command,
    # not an API call. It needs a connection to the cluster and a database user, which is
    # exactly what `docs/api-key.md` promises a customer we never ask for. That is not the same
    # product with a different transport; it is a different conversation about access.
    #
    # None of which we can fix in advance. What we can do is not be surprised: RFC 8594 says a
    # server announces this in headers, so every reply from that endpoint is read for them. It
    # costs nothing on the normal path and turns "we found out when it broke" into "we found
    # out the day they said so".
    SUNSET_HEADERS = ("deprecation", "sunset")

    # How long to wait for Atlas to assemble the bundle. Two numbers, because the two requests
    # are not the same size: a routine run asks for the open file only, and a first capture asks
    # for everything Atlas still holds -- three to ten days across every member. Measured on a
    # real M10 with load on it, the first one crossed five minutes and returned 366 MB, and a
    # single timeout there throws away a job the cluster already paid to build.
    #
    # Waiting longer costs nothing. The job runs on Atlas whether we are watching or not, so
    # the only thing a short deadline saves is the process sitting idle -- and the only thing
    # it buys is discarding finished work.
    JOB_TIMEOUT = 600
    BOOTSTRAP_TIMEOUT = 1800

    def __init__(self, group_id: str, replica_set: str, public_key: str, private_key: str,
                 job_timeout: int | None = None, bootstrap_timeout: int | None = None,
                 pending_job: str | None = None, job_estimate: float | None = None,
                 on_progress=None) -> None:
        self.group_id = group_id
        self.replica_set = replica_set
        self.auth = HTTPDigestAuth(public_key, private_key)
        self.job_timeout = self.JOB_TIMEOUT if job_timeout is None else job_timeout
        self.bootstrap_timeout = (self.BOOTSTRAP_TIMEOUT if bootstrap_timeout is None
                                  else bootstrap_timeout)
        # A job we asked Atlas for and did not manage to wait out. Read from the stored state
        # and written back to it, so the next run collects the bundle instead of ordering a
        # second one: Atlas keeps a finished job downloadable for thirty days, and building it
        # again is the expensive half of the whole operation.
        self.pending_job = pending_job
        # How long this cluster's last job took to build, if we have ever seen one finish. The
        # API reports a status and never a percentage, so this is the only ground there is for
        # saying how far along the wait is -- and it is an estimate, which is why everything
        # derived from it is marked as one.
        self.job_estimate = job_estimate
        self.job_seconds: float | None = None
        self.on_progress = on_progress or (lambda *a, **kw: None)
        # How many files the bundle turned out to hold. The caller stores them one by one and
        # cannot know the total until the tarball is open, which is here.
        self.expected: int | None = None

    def describe(self) -> str:
        return f"atlas:{self.group_id}/{self.replica_set}"

    def fetch(self, since: datetime | None) -> Iterator[FTDCFile]:
        # A first capture (`since is None`) is the big one and gets the long deadline.
        timeout = self.job_timeout if since is not None else self.bootstrap_timeout

        if self.pending_job:
            try:
                # Not measured: this job was ordered by an earlier run and may well be finished
                # already, so the time spent here is our wait and not the build. Recording it
                # would tell the next run a first capture takes two seconds.
                self._wait(self.pending_job, timeout, measure=False)
                job_id = self.pending_job
            except (RuntimeError, requests.HTTPError):
                # The job failed, expired, or was deleted from the project. Nothing to salvage,
                # and refusing to move on would leave the cluster wedged on a dead id for as
                # long as it kept coming back -- which is worse than the wait we were avoiding.
                self.pending_job = None
                job_id = self._create_job(since)
                self.pending_job = job_id
                self._wait(job_id, timeout)
        else:
            self.on_progress("order")
            job_id = self._create_job(since)
            # Recorded before the wait, not after: the point is to survive a wait that does not
            # finish, and the id only exists here.
            self.pending_job = job_id
            self._wait(job_id, timeout)

        tmp = Path(tempfile.mkdtemp(prefix="ftdc-"))
        tarball = tmp / "bundle.tar.gz"
        self._download(job_id, tarball)
        # Collected. Anything after this point is local work on a file we already hold, and a
        # failure there must not send the next run back to Atlas for the same bundle.
        self.pending_job = None

        target = tmp / "extracted"
        with tarfile.open(tarball) as t:
            extract(t, target)

        paths = [p for p in sorted(target.rglob("metrics.*")) if p.is_file()]
        self.expected = len(paths)
        for path in paths:
            node = node_from_path(path, fallback=path.parent.name)
            yield FTDCFile(node=node, name=path.name, path=path)

    def _create_job(self, since: datetime | None) -> str:
        body = {
            "resourceType": "REPLICASET",
            "resourceName": self.replica_set,
            "redacted": True,
            "sizeRequestedPerFileBytes": 500_000_000,
            "logTypes": ["FTDC"],
        }
        if since is not None:
            # The filter matches the timestamp in the file NAME, not the data inside it, so
            # `since` must be the creation time of the oldest file that might still be open --
            # never a wall-clock offset. The caller computes that; a small margin here only
            # absorbs clock skew between us and Atlas.
            #
            # Both dates must be in the past or Atlas rejects the job.
            until = datetime.now(timezone.utc) - timedelta(minutes=1)
            margin = since - timedelta(minutes=5)
            body["logCollectionFromDate"] = margin.strftime("%Y-%m-%dT%H:%M:%SZ")
            body["logCollectionToDate"] = until.strftime("%Y-%m-%dT%H:%M:%SZ")

        r = requests.post(
            f"{self.BASE}/groups/{self.group_id}/logCollectionJobs",
            auth=self.auth, json=body, timeout=60,
        )
        self._check_sunset(r)
        r.raise_for_status()
        return r.json()["id"]

    def _check_sunset(self, response) -> None:
        """Say something loud if Atlas has started announcing the end of this API.

        To stderr rather than raised: an announcement is not a failure, and turning the first
        deprecation header into a broken capture would do the damage early instead of avoiding
        it. `run.sh` sends stderr to the log and the journal, which is where somebody looking at
        a cluster would see it.
        """
        announced = {h: response.headers[h] for h in self.SUNSET_HEADERS
                     if h in response.headers}
        if not announced:
            return
        detail = ", ".join(f"{h}: {v}" for h, v in announced.items())
        link = response.headers.get("link", "")
        print(f"ATLAS API RETIREMENT ANNOUNCED for {self.BASE} — {detail}"
              + (f" · {link}" if link else "")
              + " · FTDC has no equivalent in v2: this needs a decision, not a patch.",
              file=sys.stderr)

    def _wait(self, job_id: str, timeout: int | None = None, measure: bool = True) -> None:
        timeout = self.job_timeout if timeout is None else timeout
        started = time.monotonic()
        deadline = started + timeout
        while time.monotonic() < deadline:
            r = requests.get(
                f"{self.BASE}/groups/{self.group_id}/logCollectionJobs/{job_id}",
                auth=self.auth, timeout=60,
            )
            r.raise_for_status()
            status = r.json().get("status")
            elapsed = time.monotonic() - started
            if status == "SUCCESS":
                if measure:
                    self.job_seconds = elapsed
                self.on_progress("build", done=1, total=1,
                                 note=f"{int(elapsed)}", certain=bool(self.job_estimate))
                return
            if status == "FAILURE":
                raise RuntimeError(f"job {job_id} failed")
            # The API answers with a status and never a percentage, so the only honest fraction
            # is elapsed against how long this same cluster took last time -- and it is capped
            # short of the end, because a bar that reaches 100% and keeps waiting is a lie the
            # customer can catch. With no previous run there is no fraction at all: the phase
            # reports itself as uncertain and the page shows a wait, not a number.
            fraction = min(elapsed / self.job_estimate, 0.95) if self.job_estimate else 0
            self.on_progress("build", done=fraction, total=1 if self.job_estimate else 0,
                             note=f"{int(elapsed)}", certain=False)
            time.sleep(8)
        # Not an error to hide: the job keeps building on Atlas and its id has been recorded,
        # so the next run picks it up where this one left off.
        raise TimeoutError(f"job {job_id} is still building after {timeout}s — "
                           f"the next run will collect it")

    # A download cut halfway is retried from the start rather than resumed: the bundle is a
    # stream with no byte ranges we can rely on, and measured on a real first capture, fetching
    # it again took 90 seconds -- against 25 minutes for Atlas to build a new one at the next
    # run. Seen once in a container, on the first capture: "Response ended prematurely".
    DOWNLOAD_ATTEMPTS = 3
    DOWNLOAD_BACKOFF = 10  # seconds, doubled after each failure

    def _download(self, job_id: str, target: Path) -> None:
        for attempt in range(1, self.DOWNLOAD_ATTEMPTS + 1):
            try:
                self._download_once(job_id, target)
                return
            except (requests.exceptions.ChunkedEncodingError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                if attempt == self.DOWNLOAD_ATTEMPTS:
                    raise
                wait = self.DOWNLOAD_BACKOFF * 2 ** (attempt - 1)
                print(f"  download interrupted ({type(e).__name__}); retrying in {wait}s")
                time.sleep(wait)

    def _download_once(self, job_id: str, target: Path) -> None:
        r = requests.get(
            f"{self.BASE}/groups/{self.group_id}/logCollectionJobs/{job_id}/download",
            auth=self.auth, timeout=600, stream=True,
        )
        r.raise_for_status()
        # The one number in the whole capture that is a fact rather than an estimate: bytes
        # arrived out of bytes promised. Absent if Atlas streams without a length, and then the
        # phase reports what has arrived and no total.
        total = int(r.headers.get("Content-Length") or 0)
        got = 0
        self.on_progress("download", done=0, total=total)
        with target.open("wb") as fh:
            for block in r.iter_content(chunk_size=1 << 20):
                fh.write(block)
                got += len(block)
                self.on_progress("download", done=got, total=total)


def extract(tar: tarfile.TarFile, target: Path) -> None:
    """Unpack a bundle without letting a member write outside `target`.

    The `data` filter does exactly that, but it only exists from Python 3.11.4 and 3.10.12 (and
    3.12 on): Debian 12 ships 3.11.2, and on it every Atlas capture failed at this line. Without
    the filter, the same guarantee by hand: regular files and directories only -- no links, no
    devices -- and nothing whose resolved path leaves the target.
    """
    if hasattr(tarfile, "data_filter"):
        tar.extractall(target, filter="data")
        return
    root = Path(target).resolve()
    safe = []
    for member in tar.getmembers():
        if not (member.isfile() or member.isdir()):
            continue
        dest = (root / member.name).resolve()
        if dest != root and root not in dest.parents:
            raise ValueError(f"refusing to extract {member.name!r}: it points outside {root}")
        safe.append(member)
    tar.extractall(target, members=safe)


# ------------------------------------------------------------------- self-managed

class DirectorySource:
    """A `diagnostic.data` reachable on the filesystem.

    Covers the simplest self-managed case: a mounted directory, a shared volume, or whatever
    an agent on the customer side dropped there. For a replica set, one subdirectory per node
    is expected; for a single mongod, the `diagnostic.data` directly.
    """

    def __init__(self, root: Path, single_node: str | None = None) -> None:
        self.root = Path(root)
        self.single_node = single_node

    def describe(self) -> str:
        return f"dir:{self.root}"

    def fetch(self, since: datetime | None) -> Iterator[FTDCFile]:
        for path in sorted(self.root.rglob("metrics.*")):
            if not path.is_file():
                continue
            node = self.single_node or node_from_path(path, fallback=self._node_dir(path))
            yield FTDCFile(node=node, name=path.name, path=path)

    def _node_dir(self, path: Path) -> str:
        """The node a file belongs to when no `diagnostic.data` names it.

        One subdirectory per node is the layout this source asks for, and nothing says those
        subdirectories are called `diagnostic.data`: `rs0-a/metrics.*` is just as natural. Taking
        the root's name for every file merged a three-node set into one node, and the three
        `metrics.interim` files overwrote each other. The same number-means-port rule as
        `node_from_path` applies, so `host/27017/metrics.*` is `host`.
        """
        parts = path.relative_to(self.root).parts[:-1]
        if not parts:
            return self.root.name
        if parts[-1].isdigit() and len(parts) >= 2:
            return parts[-2]
        return parts[-1]


class SSHSource:
    """Each member's `diagnostic.data`, read over SFTP as a user that can do nothing else.

    The same files mongod writes every second, so the same resolution as Atlas, and the same
    shape of run: once a round, only what is new. The add page creates the user, the key and
    the read grant, and learns each host's key while somebody is looking at it.

    Only files from `since` on are downloaded, plus `metrics.interim`. `since` is the oldest
    file that may still be growing (State.oldest_open_file), the same anchor Atlas's date
    filter uses; the first run, with none, takes the whole directory. The first version copied
    every file on every run -- up to 200 MB a member an hour, of which almost all was held.

    One member failing does not stop the others: they are read, and the failure is raised at
    the end, so the run reports it and the members that answered are still captured.
    """

    def __init__(self, hosts: list[str], remote_path: str, user: str, identity: str,
                 known_hosts: str) -> None:
        self.hosts = hosts
        self.remote_path = remote_path.rstrip("/")
        self.user = user
        self.identity = Path(identity)
        self.known_hosts = Path(known_hosts)

    def describe(self) -> str:
        return f"ssh:{self.user}@{','.join(self.hosts)}:{self.remote_path}"

    def fetch(self, since: datetime | None) -> Iterator[FTDCFile]:
        import sftp
        from state import timestamp_of

        failures = []
        tmp = Path(tempfile.mkdtemp(prefix="ftdc-ssh-"))
        for entry in self.hosts:
            host, port = sftp.split_host(entry)
            try:
                session = sftp.connect(host, port, self.user, self.identity, self.known_hosts)
            except Exception as e:  # noqa: BLE001
                failures.append(f"{entry}: {sftp.explain(e, self.user, self.remote_path)}")
                continue
            try:
                for a in sftp.metrics_in(session, self.remote_path):
                    stamp = timestamp_of(a.filename)
                    if since is not None and stamp is not None and stamp < since:
                        continue
                    local = tmp / sftp.member_name(entry) / a.filename
                    local.parent.mkdir(parents=True, exist_ok=True)
                    sftp.download(session, f"{self.remote_path}/{a.filename}", local)
                    yield FTDCFile(node=sftp.member_name(entry), name=a.filename, path=local)
            except Exception as e:  # noqa: BLE001
                failures.append(f"{entry}: {sftp.explain(e, self.user, self.remote_path)}")
            finally:
                session.close()
        if failures:
            raise RuntimeError("; ".join(failures))


def build(spec: dict, pending_job: str | None = None, job_estimate: float | None = None,
          on_progress=None) -> Source:
    """Assemble the source from its description in the config.

    The rest of the system does not know which kind of source it is: it only uses it.

    `pending_job` and `job_estimate` are what the last run left behind. They mean something only
    on Atlas, which is why they arrive here as optional arguments rather than as methods every
    source has to implement in order to answer "not applicable".
    """
    kind = spec.get("type", "atlas")
    if kind == "atlas":
        return AtlasSource(
            group_id=spec["group_id"],
            replica_set=spec["replica_set"],
            public_key=spec["public_key"],
            private_key=spec["private_key"],
            pending_job=pending_job,
            job_estimate=job_estimate,
            on_progress=on_progress,
        )
    if kind == "directory":
        return DirectorySource(Path(spec["path"]), spec.get("node"))
    if kind == "ssh":
        return SSHSource(spec.get("hosts") or [spec["host"]], spec["path"],
                         spec.get("user") or "mongo-health-ftdc", spec["identity"],
                         spec["known_hosts"])
    raise ValueError(f"unknown source type: {kind}")
