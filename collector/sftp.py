"""Reading a member's `diagnostic.data` over SFTP: the key, the connection, and the test.

The collector logs in as a user that can do nothing but read that one directory -- the
instructions on the add page create it -- so everything here is read-only by construction:
it lists, it downloads, and it never runs a command on the host.

Host keys are learnt once, when the cluster is added and somebody is looking at the
fingerprints, and enforced after that. A key that changes later fails the capture loudly
rather than being accepted, because that is exactly what a man in the middle looks like.
"""
from __future__ import annotations

import io
import socket
from dataclasses import dataclass
from pathlib import Path

DEFAULT_USER = "mongo-health-ftdc"
DEFAULT_PATH = "/var/lib/mongo/diagnostic.data"
TIMEOUT = 15


def split_host(entry: str) -> tuple[str, int]:
    """`db1`, `db1:2222` or `[fe80::1]:2222` -> (host, port). SSH's port, not mongod's."""
    entry = entry.strip()
    if entry.startswith("["):
        host, _, rest = entry[1:].partition("]")
        return host, int(rest.lstrip(":") or 22)
    if entry.count(":") == 1:
        host, port = entry.split(":")
        return host, int(port)
    return entry, 22


def member_name(entry: str) -> str:
    """The directory a member's files are kept under: its host, without the SSH port."""
    import re

    return re.sub(r"[^A-Za-z0-9._-]", "_", split_host(entry)[0])


def generate_key(private: Path, comment: str) -> str:
    """A new ed25519 key at `private`, readable by its owner only. Returns the public line."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                            serialization.NoEncryption())
    tmp = private.with_name(f".{private.name}.tmp")
    tmp.touch(mode=0o600)
    tmp.write_bytes(pem)
    tmp.replace(private)
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                           serialization.PublicFormat.OpenSSH).decode()
    return f"{public} {comment}"


def public_line(private: Path, comment: str) -> str:
    import paramiko

    key = paramiko.Ed25519Key.from_private_key_file(str(private))
    return f"{key.get_name()} {key.get_base64()} {comment}"


def fingerprint(key) -> str:
    """As `ssh-keygen -lf` prints it, so it can be compared on the host by eye."""
    import base64
    import hashlib

    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    return f"{key.get_name()} SHA256:{digest}"


@dataclass
class Session:
    client: object
    sftp: object
    host_key: object

    def close(self) -> None:
        try:
            self.sftp.close()
        finally:
            self.client.close()


def connect(host: str, port: int, user: str, private: Path, known_hosts: Path,
            learn: bool = False) -> Session:
    """An SFTP session. `learn` accepts a host key not seen before (adding a cluster);
    otherwise only the keys in `known_hosts` are accepted (every capture after that)."""
    import paramiko

    client = paramiko.SSHClient()
    if known_hosts.exists():
        client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy() if learn
                                       else paramiko.RejectPolicy())
    client.connect(host, port=port, username=user,
                   pkey=paramiko.Ed25519Key.from_private_key_file(str(private)),
                   timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT,
                   allow_agent=False, look_for_keys=False)
    if learn:
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        client.save_host_keys(str(known_hosts))
    sftp = client.open_sftp()
    sftp.get_channel().settimeout(120)
    return Session(client, sftp, client.get_transport().get_remote_server_key())


def metrics_in(session: Session, path: str) -> list:
    """The `metrics.*` entries of the remote directory, with their sizes."""
    return sorted((a for a in session.sftp.listdir_attr(path) if a.filename.startswith("metrics.")),
                  key=lambda a: a.filename)


def explain(error: Exception, user: str, path: str) -> str:
    """What went wrong, in the terms of the step on the add page that fixes it."""
    import paramiko

    if isinstance(error, paramiko.AuthenticationException):
        return (f"the key was refused for {user}: the public key is not in its "
                f"authorized_keys, or the file's permissions are too open (step 1)")
    if isinstance(error, paramiko.BadHostKeyException):
        return ("the host key is not the one seen when this cluster was added -- the host was "
                "reinstalled, or something is in between")
    if isinstance(error, paramiko.SSHException) and "not found in known_hosts" in str(error):
        return "the host key was never confirmed for this cluster"
    if isinstance(error, PermissionError) or getattr(error, "errno", None) == 13:
        return (f"{user} logged in but cannot read {path}: the ACL in step 2 is missing on "
                f"the directory or on its parent")
    if isinstance(error, FileNotFoundError) or getattr(error, "errno", None) == 2:
        return f"{path} does not exist on this host: check storage.dbPath in mongod.conf"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "no answer on the SSH port: a firewall, or sshd is not listening there"
    if isinstance(error, (ConnectionRefusedError, OSError)) and not isinstance(error, EOFError):
        return f"cannot reach the SSH port: {error}"
    if isinstance(error, EOFError) or "subsystem" in str(error).lower():
        return "logged in, but SFTP is not available: check the Match block in step 3"
    return f"{type(error).__name__}: {error}"


def probe(host: str, port: int, user: str, path: str, private: Path, known_hosts: Path,
          describe) -> dict:
    """Everything the add page needs to say about one member, without storing anything.

    `describe` is ftdcfiles.describe, passed in to keep this module free of the decoder: it
    reads the member's own name and how far back its files go.
    """
    out = {"host": host, "port": port, "ok": False}
    try:
        session = connect(host, port, user, private, known_hosts, learn=True)
    except Exception as e:  # noqa: BLE001 -- every failure is reported, none is fatal
        out["error"] = explain(e, user, path)
        return out
    try:
        out["fingerprint"] = fingerprint(session.host_key)
        files = metrics_in(session, path)
        if not files:
            out["error"] = f"{path} is readable but holds no metrics files: is this the dbPath?"
            return out
        out["files"] = len(files)
        out["mb"] = round(sum(a.st_size for a in files) / 1024 ** 2, 1)
        # The oldest file says how far back the history goes, the interim file who this member
        # is and that its data is current. Two small downloads, never the whole directory.
        import tempfile

        from state import timestamp_of

        with tempfile.TemporaryDirectory() as tmp:
            spans = []
            # Newest first: its replSetGetStatus names the member as the set knows it now.
            for a in dict.fromkeys([files[-1].filename, files[0].filename]):
                local = Path(tmp) / a
                session.sftp.get(f"{path}/{a}", str(local))
                spans.append(describe(local))
        out["member"] = next((s["member"] for s in spans if s.get("member")), None)
        # A file mongod rotated straight after starting holds metadata and no samples; its
        # name still says when it began.
        starts = [s["from"] for s in spans if s.get("from")] + [timestamp_of(files[0].filename)]
        out["from"] = min((t for t in starts if t), default=None)
        out["to"] = max((s["to"] for s in spans if s.get("to")), default=None)
        out["ok"] = True
    except Exception as e:  # noqa: BLE001
        out["error"] = explain(e, user, path)
    finally:
        session.close()
    return out


def download(session: Session, remote: str, local: Path) -> None:
    buf = io.BytesIO()
    session.sftp.getfo(remote, buf)
    local.write_bytes(buf.getvalue())
