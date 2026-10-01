"""How the cluster is configured, against what MongoDB recommends for production.

The rules watch what happens; these judge what is set. They read only the metadata mongod
writes at the top of every FTDC file -- version, ulimits, transparent huge pages, the cache
size, authorization, the bind address, the filesystem under the data -- so they need no
connection and run on the first capture like everything else.

A configuration is not an event: it is true all the time, until somebody changes it. So these
are recommendations, shown on the cluster page and in the first evaluation, never mailed as
incidents. Every check stays silent when its input is absent: an older server that does not
report THP has no THP recommendation, not a guess at one.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date

# End of support, as published at mongodb.com/legal/support-policy/lifecycles (checked
# 1 Oct 2026). 8.1 is from the Atlas auto-upgrade schedule; the page lists it nowhere else.
# Dated, so a stale table is visible: a year past `TABLE_CHECKED` the text says when it was
# last checked, rather than state a date that may have moved -- 7.0's already did once.
END_OF_LIFE = {
    "4.0": date(2022, 4, 30),
    "4.2": date(2023, 4, 30),
    "4.4": date(2024, 2, 29),
    "5.0": date(2024, 10, 31),
    "6.0": date(2025, 7, 31),
    "7.0": date(2027, 8, 31),
    "8.0": date(2029, 10, 31),
    "8.1": date(2025, 9, 30),
    "8.2": date(2026, 7, 31),
    "8.3": date(2029, 10, 31),
    "9.0": date(2031, 10, 31),
}
TABLE_CHECKED = date(2026, 10, 1)
EOL_SOON_DAYS = 180

# mongod's own startup warning (startup_warnings_mongod.cpp, 8.0): open files only. Processes
# are not checked there any more, and an invented threshold would flag 63,167 against 64,000.
MIN_OPEN_FILES = 64_000

# WiredTiger's own default is half of (RAM - 1 GB), floored at 256 MB. The rest of memory is
# not idle: the filesystem cache, connections and every aggregation need it.
CACHE_SHARE_LIMIT = 0.60

LOCAL_ADDRESSES = {"127.0.0.1", "::1", "localhost"}


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    why: str
    how: str = ""               # when it speaks, for the catalog
    severity: str = "warning"


CHECKS = {c.id: c for c in [
    Check("version-end-of-life", "MongoDB version past or near end of support",
          "A version past its end of life gets no security fixes and no bug fixes, and the "
          "next upgrade has to cross every release in between.",
          how='Past the end-of-life date MongoDB publishes for that major version (warning), or within 180 days of it (info).', severity="warning"),
    Check("members-share-a-host", "Members of the replica set run on the same host",
          "Members on one machine fail together. The point of three members is surviving the "
          "loss of one host; with a majority on one, losing it takes the primary away.",
          how='Two or more members report the same host name, port aside.', severity="warning"),
    Check("unequal-members", "Members with different memory or CPU",
          "Any member can become primary. A smaller one holds a smaller cache and fewer "
          "cores, so a routine failover makes the whole cluster slower.",
          how='A member has less than three quarters of the memory or cores of the largest one.', severity="warning"),
    Check("mixed-versions", "Members running different MongoDB versions",
          "Normal in the middle of a rolling upgrade and nowhere else: a member left behind "
          "behaves differently when it becomes primary.",
          how='Members report different versions: a warning across major versions, info within one.', severity="warning"),
    Check("transparent-huge-pages", "Transparent huge pages set the wrong way for the allocator",
          "The right setting depends on the memory allocator mongod was built with. 8.0's "
          "tcmalloc-google uses per-CPU caches over huge pages and wants THP always; the older "
          "tcmalloc fragments under THP and wants it off. The advice reversed with 8.0, so "
          "many hosts carry the old one. These are the same checks mongod makes at startup and "
          "writes to a log almost nobody reads.",
          how="tcmalloc-google with THP not 'always' (warning), or defrag not 'defer+madvise' or max_ptes_none above 0 (info); any other allocator with THP 'always'. Silent where the server does not report THP.", severity="warning"),
    Check("glibc-rseq", "glibc rseq left on under tcmalloc-google",
          "tcmalloc-google needs restartable sequences for itself; with glibc holding them, "
          "its per-CPU caches are off. mongod's own startup warning calls it critical.",
          how='tcmalloc-google, glibc with rseq support, and rseq not disabled for mongod.', severity="warning"),
    Check("ulimits-low", "Open-file limit below MongoDB's minimum",
          "Every connection and every data and index file takes a file descriptor. At the "
          "limit mongod refuses connections, and can abort mid-write.",
          how="The soft limit on open files is below 64,000 — mongod's own startup check.", severity="warning"),
    Check("overcommit-strict", "Strict memory overcommit",
          "With vm.overcommit_memory=2 the kernel refuses allocations mongod would have "
          "survived; mongod's startup warning asks for 1 (or the default, 0).",
          how='vm.overcommit_memory is 2.', severity="info"),
    Check("cache-too-large", "WiredTiger cache too large for the host's memory",
          "The cache is not all the memory mongod uses, and the filesystem cache under it is "
          "what keeps reads off the disk. Several mongods on one host each take half of "
          "memory by default.",
          how="The WiredTiger caches of the mongods on one host — set, or WiredTiger's default — add up to more than 60% of its memory.", severity="warning"),
    Check("open-without-auth", "Reachable from the network without authorization",
          "Anyone who can reach the port can read, change or drop every database.",
          how='bindIp includes an address other than localhost, and neither authorization nor a keyFile/x509 between members is on.', severity="warning"),
    Check("open-without-tls", "Reachable from the network without TLS",
          "Credentials and data cross the network in clear text.",
          how='bindIp includes an address other than localhost and net.tls.mode is not set.', severity="info"),
    Check("filesystem-not-xfs", "Data on ext4 rather than XFS",
          "MongoDB recommends XFS for WiredTiger: on ext4, checkpoints under write load are a "
          "known cause of stalls.",
          how='The mount holding the dbPath is ext4. Silent where the mount cannot be resolved.', severity="info"),
    Check("write-concern-w1", "Default write concern lowered to w:1",
          "Since 5.0 the default is majority. With w:1 a write acknowledged by the primary "
          "is lost if the primary fails before a secondary copies it.",
          how='The cluster-wide default write concern was set to w:1 with setDefaultRWConcern.', severity="info"),
]}


@dataclass
class Recommendation:
    id: str
    severity: str               # "warning" or "info"
    title: str
    what: str                   # what is set, in this cluster's numbers
    fix: str
    members: list[str] = field(default_factory=list)

    @property
    def why(self) -> str:
        return CHECKS[self.id].why


def _major(version: str | None) -> str | None:
    m = re.match(r"(\d+)\.(\d+)", version or "")
    return f"{m.group(1)}.{m.group(2)}" if m else None


def _host(name: str) -> str:
    """The machine, without the port mongod appends when it is not 27017."""
    return re.sub(r":\d+$", "", name)


def _short(name: str) -> str:
    return name.split(".")[0]


def _bracketed(value: str | None) -> str | None:
    """`[always] madvise never` as the kernel prints it, or `always` as mongod parses it."""
    if not value:
        return None
    m = re.search(r"\[(\w[\w+]*)\]", value)
    return m.group(1) if m else value.strip()


def _cache_gb(cfg: dict) -> float | None:
    if cfg.get("cacheSizeGB"):
        return float(cfg["cacheSizeGB"])
    if cfg.get("memMB"):
        return max(0.5 * (cfg["memMB"] / 1024 - 1), 0.25)
    return None


def _exposed(cfg: dict) -> bool | None:
    if cfg.get("bindIpAll"):
        return True
    if not cfg.get("bindIp"):
        return None
    return any(a.strip() not in LOCAL_ADDRESSES for a in cfg["bindIp"].split(","))


def evaluate(nodes: list[dict], today: date) -> list[Recommendation]:
    """Recommendations for one cluster, from the `config` of each node in summary.json."""
    members = [(n.get("hostname") or n["node"], n["config"]) for n in nodes if n.get("config")]
    if not members:
        return []
    out: list[Recommendation] = []

    # --- version -----------------------------------------------------------------------
    by_version: dict[str, list[str]] = defaultdict(list)
    for name, cfg in members:
        if cfg.get("version"):
            by_version[cfg["version"]].append(name)
    stale = ((today - TABLE_CHECKED).days > 365
             and f" (support dates as published on {TABLE_CHECKED:%d %b %Y})" or "")
    for version, names in sorted(by_version.items()):
        eol = END_OF_LIFE.get(_major(version) or "")
        if eol is None:
            continue
        left = (eol - today).days
        if left < 0:
            out.append(Recommendation(
                "version-end-of-life", "warning", f"MongoDB {version} is past its end of life",
                f"Support for {_major(version)} ended on {eol:%d %b %Y}{stale}.",
                "Plan the upgrade one major version at a time, with the feature compatibility "
                "version set at each step.", names))
        elif left <= EOL_SOON_DAYS:
            out.append(Recommendation(
                "version-end-of-life", "info",
                f"MongoDB {version} reaches its end of life in {left} days",
                f"Support for {_major(version)} ends on {eol:%d %b %Y}{stale}.",
                "Schedule the upgrade now, while it can be done on a quiet day.", names))
    majors = {_major(v) for v in by_version}
    if len(by_version) > 1:
        listing = "; ".join(f"{v} on {', '.join(_short(n) for n in ns)}"
                            for v, ns in sorted(by_version.items()))
        out.append(Recommendation(
            "mixed-versions", "warning" if len(majors) > 1 else "info",
            "Members run different MongoDB versions", f"{listing}.",
            "Finish the rolling upgrade: every member on the same version.",
            [n for ns in by_version.values() for n in ns]))

    # --- topology ----------------------------------------------------------------------
    by_host: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for name, cfg in members:
        by_host[_host(cfg.get("hostname") or name)].append((name, cfg))
    if len(members) > 1:
        for host, here in by_host.items():
            if len(here) < 2:
                continue
            out.append(Recommendation(
                "members-share-a-host", "warning",
                f"{len(here)} of {len(members)} members run on the same host",
                (f"Every member reports the host {host}." if len(here) == len(members)
                 else f"These {len(here)} report the host {host}."),
                "Put each member on its own machine, and in production in its own failure "
                "domain (rack, zone).", [n for n, _ in here]))

    for key, unit, label in (("memMB", "GB", "memory"), ("cores", "cores", "CPU")):
        sized = [(n, c[key]) for n, c in members if c.get(key)]
        if len(sized) < 2:
            continue
        low, high = min(v for _, v in sized), max(v for _, v in sized)
        if low < 0.75 * high:
            def shown(v):
                return f"{v / 1024:.1f} GB" if key == "memMB" else f"{v:g} cores"
            small = [n for n, v in sized if v == low]
            out.append(Recommendation(
                "unequal-members", "warning", f"Members have different {label}",
                f"{', '.join(_short(n) for n in small)} has {shown(low)}; the largest member "
                f"has {shown(high)}.",
                "Size every member the same, so whichever is elected primary can carry the "
                "load.", small))

    # --- the host ----------------------------------------------------------------------
    for name, cfg in members:
        thp = _bracketed(cfg.get("thpEnabled"))
        defrag = _bracketed(cfg.get("thpDefrag"))
        allocator = cfg.get("allocator") or ""
        google = allocator == "tcmalloc-google"
        if thp and allocator:
            if google:
                wrong = [f"enabled is '{thp}'"] if thp != "always" else []
                if defrag and defrag != "defer+madvise":
                    wrong.append(f"defrag is '{defrag}'")
                if (cfg.get("thpMaxPtesNone") or 0) > 0:
                    wrong.append(f"khugepaged/max_ptes_none is {cfg['thpMaxPtesNone']:g}")
                if wrong:
                    out.append(Recommendation(
                        "transparent-huge-pages", "warning" if thp != "always" else "info",
                        "Transparent huge pages are not set the way tcmalloc-google wants",
                        f"Built with tcmalloc-google, and {', '.join(wrong)}.",
                        "Set /sys/kernel/mm/transparent_hugepage/enabled to always, defrag to "
                        "defer+madvise and khugepaged/max_ptes_none to 0, persistently.",
                        [name]))
            elif thp == "always":
                out.append(Recommendation(
                    "transparent-huge-pages", "warning",
                    "Transparent huge pages are on, under an allocator that wants them off",
                    f"Built with {allocator}, and THP enabled is 'always'"
                    + (f", defrag '{defrag}'" if defrag else "") + ".",
                    "Set /sys/kernel/mm/transparent_hugepage/enabled and defrag to never, "
                    "persistently. On 8.0 with tcmalloc-google the advice is the opposite.",
                    [name]))
        if google and cfg.get("rseqPresent") and cfg.get("rseqDisabled") is False:
            out.append(Recommendation(
                "glibc-rseq", "warning", "glibc holds rseq, so tcmalloc-google runs without it",
                "glibc was built with rseq support and it is not disabled for mongod.",
                "Start mongod with GLIBC_TUNABLES=glibc.pthread.rseq=0 in its environment.",
                [name]))
        if cfg.get("overcommit") == 2:
            out.append(Recommendation(
                "overcommit-strict", "info", "vm.overcommit_memory is 2",
                "The kernel is set to strict overcommit.",
                "Set vm.overcommit_memory to 1 in sysctl.", [name]))

        fd = cfg.get("fdSoft")
        if isinstance(fd, (int, float)) and 0 <= fd < MIN_OPEN_FILES:
            out.append(Recommendation(
                "ulimits-low", "warning", "Open-file limit below MongoDB's minimum",
                f"mongod may open {int(fd):,} files.",
                f"Raise the soft and hard nofile limit for mongod to at least "
                f"{MIN_OPEN_FILES:,} (LimitNOFILE in the systemd unit).", [name]))

        if cfg.get("dataFs") == "ext4":
            out.append(Recommendation(
                "filesystem-not-xfs", "info", "The data is on ext4",
                f"{cfg.get('dbPath')} is on {cfg.get('dataMountPoint')}, formatted ext4.",
                "Use XFS for the data volume when it is next rebuilt or replaced.", [name]))

        exposed = _exposed(cfg)
        if exposed:
            if cfg.get("auth") != "enabled" and not cfg.get("internalAuth"):
                out.append(Recommendation(
                    "open-without-auth", "warning",
                    "Listening on the network with authorization off",
                    f"bindIp {'all addresses' if cfg.get('bindIpAll') else cfg['bindIp']}, and "
                    "security.authorization is not enabled.",
                    "Create an admin user, then set security.authorization: enabled (and a "
                    "keyFile between members).", [name]))
            if cfg.get("tlsMode") in (None, "disabled"):
                out.append(Recommendation(
                    "open-without-tls", "info", "Listening on the network without TLS",
                    f"bindIp {'all addresses' if cfg.get('bindIpAll') else cfg['bindIp']}, and "
                    "net.tls.mode is not set.",
                    "Enable TLS (net.tls.mode: requireTLS once every client supports it).",
                    [name]))

    for host, here in by_host.items():
        mem = max((c.get("memMB") or 0) for _, c in here)
        caches = [_cache_gb(c) for _, c in here]
        if not mem or None in caches:
            continue
        total = sum(caches)
        if total * 1024 > CACHE_SHARE_LIMIT * mem:
            several = len(here) > 1
            out.append(Recommendation(
                "cache-too-large", "warning",
                "WiredTiger cache too large for the host's memory",
                (f"{len(here)} mongods on {_short(host)} hold {total:.1f} GB of cache between "
                 if several else f"{_short(here[0][0])} holds {total:.1f} GB of cache on ")
                + f"{mem / 1024:.1f} GB of memory ({total * 1024 / mem:.0%}).",
                "Set storage.wiredTiger.engineConfig.cacheSizeGB so the caches on a host add "
                "up to at most half its memory.", [n for n, _ in here]))

    # --- the cluster's defaults ----------------------------------------------------------
    for name, cfg in members:
        if str(cfg.get("writeConcernW")) == "1" and cfg.get("writeConcernSource") == "global":
            out.append(Recommendation(
                "write-concern-w1", "info", "The default write concern is w:1",
                "setDefaultRWConcern lowered the cluster-wide default from majority to 1.",
                "Restore majority as the default, and ask for w:1 only on writes that can "
                "afford to be lost.", [name]))
            break

    return _merge(out)


def _merge(recs: list[Recommendation]) -> list[Recommendation]:
    """One line per finding, not per member: three members with the same ulimit are one
    recommendation naming three members."""
    merged: dict[tuple[str, str, str], Recommendation] = {}
    for r in recs:
        key = (r.id, r.title, r.what)
        if key in merged:
            merged[key].members += [m for m in r.members if m not in merged[key].members]
        else:
            merged[key] = r
    order = {"warning": 0, "info": 1}
    return sorted(merged.values(), key=lambda r: (order[r.severity], r.id))
