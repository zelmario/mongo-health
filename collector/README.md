# Collector

> **This is operator documentation. Customers never see it and never install anything.**
>
> The whole design is that the customer hands over one read-only API key and receives reports.
> No agent, no software, no cron on their side, nothing running near their cluster. What
> follows is how *we* run the service — see `docs/api-key.md` for what the customer actually
> does, which takes about two minutes.

Pulls FTDC off MongoDB clusters on a schedule, runs pathology rules over it, and emails what
it finds. Everything it stores is plain files on disk.

It exists because Atlas keeps FTDC for a few days and then deletes it. Measured on an idle
M10: 19 MB per node per day against a 400 MB ceiling, so roughly three weeks idle and two to
five days under production traffic. After that the data is gone and no API call brings it
back — including for the incident you are about to be asked to explain.

Five commands, run in order by `run.sh`:

| | |
|---|---|
| `capture.py` | fetch new FTDC, deduplicate, store |
| `analyze.py` | run the rules, record findings and the metric baseline |
| `status.py`  | rebuild the status page |
| `notify.py`  | email what fired |
| `prune.py`   | drop raw FTDC past its retention |

Plus `watchdog.py`, which runs **separately** — see below.

## Tests

```bash
python3 -m pytest
```

162 tests, one file per module. They cover the parts where a mistake is silent rather than
loud: what counts as a new file
(four separate capture bugs live in those thirty lines of `state.py`), what `prune.py` must
never delete, how findings collapse into incidents, and both edges of the anomaly detector.

The bias throughout is towards asserting what must *not* happen. A collector that reports too
little looks identical to a healthy cluster, and that is the failure this project keeps
rediscovering.

## Requirements

- Python 3.10+ with `requests`, `pymongo` and `matplotlib`
- Node, plus a checkout of [Big Hole](https://github.com/zelmario/big-hole) — the decoder,
  the alias table and the rules live there so they exist in exactly one place
- An Atlas API key with **Project Read Only**, the lowest role there is

## Install

```bash
pip install requests matplotlib
cp config.example.json config.json     # then fill it in
chmod 600 config.json                  # it holds credentials

# the analysis engine runs inside Big Hole: analyze.py copies runner/analyze.ts into its
# tools/ on every run, so runner/ is the only copy to edit.
# The advisor's own Big Hole sits at ../big-hole and is found automatically.
# Set BIGHOLE only for a deployment that puts it somewhere else:
#   export BIGHOLE=/srv/big-hole
```

`analyze.py` fails with an explicit message if that file is missing, so a bad `BIGHOLE` shows
up immediately rather than as an empty result.

## Configure

```json
{
  "customers": [
    {
      "id": "acme",
      "notify": ["ops@acme.com"],
      "clusters": [
        {
          "id": "orders-prod",
          "source": {
            "type": "atlas",
            "group_id": "YOUR_ATLAS_PROJECT_ID",
            "replica_set": "atlas-abc123-shard-0",
            "public_key": "…",
            "private_key": "…"
          }
        }
      ]
    }
  ],
  "smtp": { "host": "smtp.example.com", "port": 587, "from": "collector@example.com",
            "user": "…", "password": "…" }
}
```

Finding the two Atlas identifiers:

- `group_id` — `GET /api/atlas/v1.0/groups` lists the projects the key can reach. Use that
  rather than the id in the console URL; a key from a different organisation returns 401 and
  the message does not say which project it expected.
- `replica_set` — **not** the `replicaSetName` field, which comes back empty. Take it from
  the `replicaSet=` parameter of `connectionStrings.standard` on
  `GET /groups/{id}/clusters/{name}`. Do not derive it from hostnames: those read
  `…shard-00-00` while the set is `…shard-0`.

### Clusters that are not on Atlas

Nothing below the source cares where the files came from. A `diagnostic.data` from a mongod on
somebody's own hardware decodes, is judged by the same rules and produces the same reports and
emails as one pulled from the Atlas API — verified end to end against a local mongod 8.0 and
against a three-member set.

```json
{ "type": "directory", "path": "/mnt/captures/rs-prod" }
{ "type": "onprem", "uri": "mongodb://mongo-health:…@db1,db2,db3/?replicaSet=rs0", "interval": 10 }
{ "type": "ssh", "hosts": ["db1.internal", "db2.internal", "db3.internal"],
  "path": "/diagnostic.data", "user": "mongo-health-ftdc",
  "identity": "/etc/bighole/keys/rs-prod_ed25519",
  "known_hosts": "/etc/bighole/keys/rs-prod.known_hosts" }
```

The add page offers the first two, which need nothing changed on a database host. `interval` is
the poller's seconds between samples, 10 unless set; the page prices each choice with the
cluster's own sample size. `ssh` is configured by hand, for an operator who already runs those
hosts; see below.

**Layout for a replica set.** One directory per member, named after the host. Both of these are
recognised, which covers the two ways people hand a capture over:

```
given/db1.internal/27017/diagnostic.data/metrics.*      <- as mongod lays it out
given/db1.internal/metrics.*                            <- flattened
```

For a single mongod, point `path` at the `diagnostic.data` itself and set `"node"` to name it.

**The node name in reports comes from the capture, not from the config.** FTDC carries the
host's own name in its metadata and that is what findings are labelled with, so a cluster
configured as `mongo-prod-1` can report findings against `dbhost:27026`. That is deliberate —
the report should name the machine an operator can log into.

### Two ways to reach a self-hosted cluster

Both are supported because they suit different customers, and the difference is who opens what.

**We pull, over restricted SFTP.** Not offered on the add page: it needs root changes on every
member, which is more than most teams will make on a database host. For an operator who
already runs the hosts, it gives the files mongod writes, a sample a second, with no database
user at all. The source reads each member once a round and downloads only what may have
changed since the last one: the oldest file still growing, and `metrics.interim`.

mongod runs with `umask 077`, so `diagnostic.data` is `drwx------` and its group cannot read it.
An ACL is the way in, and its default entry is what makes the files mongod creates later
readable too. A chroot that holds only `diagnostic.data` keeps the user away from every other
world-readable file, `mongod.conf` included. Tested as written on PSMDB 8.0 on Rocky Linux 8,
run twice to check it is safe to repeat; SELinux enforcing and Debian/Ubuntu (dbPath
`/var/lib/mongodb`, service `ssh`) are untested. As root on each member:

```bash
DIAG=/var/lib/mongo/diagnostic.data          # storage.dbPath + /diagnostic.data
PUBKEY='ssh-ed25519 AAAA… mongo-health:rs-prod'
U=mongo-health-ftdc

id -u $U >/dev/null 2>&1 || useradd --system --create-home --shell /sbin/nologin $U
install -d -m 700 -o $U -g $U /home/$U/.ssh
grep -qxF "$PUBKEY" /home/$U/.ssh/authorized_keys 2>/dev/null ||
  echo "$PUBKEY" >> /home/$U/.ssh/authorized_keys
chown $U: /home/$U/.ssh/authorized_keys; chmod 600 /home/$U/.ssh/authorized_keys

setfacl -m u:$U:x "$(dirname "$DIAG")"
setfacl -m u:$U:rx "$DIAG"
setfacl -d -m u:$U:r "$DIAG"
setfacl -m u:$U:r "$DIAG"/metrics.*

mountpoint -q /srv/$U/diagnostic.data || install -d -m 755 -o root -g root /srv/$U/diagnostic.data
grep -q " /srv/$U/diagnostic.data " /etc/fstab ||
  echo "$DIAG /srv/$U/diagnostic.data none bind,ro 0 0" >> /etc/fstab
mountpoint -q /srv/$U/diagnostic.data || mount /srv/$U/diagnostic.data

grep -qx "Match User $U" /etc/ssh/sshd_config || cat >> /etc/ssh/sshd_config <<SSHD

Match User $U
    ChrootDirectory /srv/$U
    ForceCommand internal-sftp -R
    PasswordAuthentication no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
SSHD
sshd -t && systemctl reload sshd
```

The `Match` block goes at the end of the file because it applies to everything after it. What
the user can do afterwards, checked on the test set: list and read `/diagnostic.data`; nothing
else. Writing, a shell, port forwarding and reading `mongod.conf` are all refused.

On the collector's side, the key and the host keys. Host keys are enforced: a host that
presents a key not in `known_hosts` stops being read, and the run says so.

```bash
ssh-keygen -t ed25519 -N '' -C mongo-health:rs-prod -f config/keys/rs-prod_ed25519
ssh-keyscan -t ed25519 db1.internal db2.internal db3.internal > config/keys/rs-prod.known_hosts
ssh-keygen -lf config/keys/rs-prod.known_hosts   # compare with each host's own
```

Measured on the three-member test set: the first run brought down 7.5 MB in 0.7 s, and each
run after it only the open file and `metrics.interim`.

**They push, over HTTPS.** The customer opens nothing at all and we hold no credentials to
their machines — which stops being a small thing once there are fifty customers. Issue a token
for the cluster, put `tools/push-ftdc.sh` on each member, and add a line of cron:

```
*/10 * * * * BIGHOLE_TOKEN=... /usr/local/bin/push-ftdc.sh >>/var/log/bighole.log 2>&1
```

The script reads the diagnostic directory, sends what is new, remembers what it sent, and
re-sends `metrics.interim` every time because that is the file still being written. It needs
no write access anywhere except its own state file and never touches mongod.

What you give up is control of the schedule. A cron that dies is a cluster that goes quiet, and
quiet looks identical to healthy — which is what `watchdog.py` is for, and it matters more for
these clusters than for any other kind.

**What the SSH key needs.** Read access to the diagnostic directory and nothing else. There is
no database user, no `clusterMonitor`, and nothing to install on the customer's side. Note that
this is a bigger thing to ask for than the Atlas path, where a read-only API key never grants
access to a machine — which is the argument for the push direction.

## Run

```bash
./run.sh                    # nothing irreversible: no email sent, nothing deleted
./run.sh --send             # also deliver the email
./run.sh --send --prune     # also delete raw FTDC past its retention
./run.sh --customer acme    # just one
```

As a cron entry:

```cron
5  * * * *  cd /srv/collector && ./run.sh --send --prune
35 * * * *  cd /srv/collector && python3 watchdog.py --send
```

Two entries, and the second one matters more than it looks — see "Knowing it is still
running" below.

Hourly, because the report is only as fresh as the last run. It is cheaper than it sounds: the
collection job is filtered by the timestamp in the FTDC file *name*, so the file still being
written arrives whole however narrow the window — measured against a real cluster, a one-hour
request and a six-hour request returned the same bundle byte for byte. A run therefore costs
the size of the open file rather than the length of the gap, which on a three-node replica set
averages some 15 MB, and the duplicates are deduplicated on arrival so nothing extra is stored.

A full first capture is about 26 MB and 40 s for a three-node cluster.

**The two irreversible things are both opt-in.** Without `--send` the message is written to
`outbox/` and nothing is marked as notified; without `--prune` nothing is deleted. An email
cannot be recalled and a deleted capture cannot be re-fetched once Atlas has dropped it, so in
both cases the safe behaviour is the default and the irreversible one has to be asked for.

## Retention

`retention_days` sets how long raw FTDC is kept — per cluster, per customer, or globally, most
specific first. The add page asks for it, from one month to a year with three months selected,
because the answer is disk and only the person adding the cluster knows how much there is. A
cluster written into `config.json` without it gets 365.

Only raw FTDC is pruned. `baseline.jsonl`, `findings.jsonl` and `usage.jsonl` are never
touched: measured on a real three-node cluster the raw data runs ~20.5 GB a year against ~55 MB
of baseline, so the derived data is roughly 1/420th of the cost and cannot be recomputed once
the raw is gone. Compression was considered and rejected — FTDC chunks are already
zlib-compressed, so gzip buys 1%.

Two files are never pruned regardless of age: `metrics.interim`, and the newest numbered file
of each node, because mongod may still be appending to it. Its *name* can be days old while its
contents are current.

## Knowing it is still running

A monitoring service that dies quietly is worse than none: the customer believes their cluster
is watched, and the silence reads as "nothing is wrong" rather than "nobody is looking".

The status page cannot report this, because **the collector is what generates it**. If cron
stops firing, the page is never rebuilt and freezes displaying the last healthy run — actively
asserting that everything is fine. So there are two independent guards, covering different
failures.

**`watchdog.py` — the collector is broken.** Reads only the state files and the clock. It
imports nothing from the analysis path, takes no lock, and needs neither Node nor Big Hole, so
it still works when everything else is broken. Run it from its own cron entry, offset from the
main one, and it emails when a cluster has not captured in 14 hours (two missed runs). It exits
non-zero whenever it had something to report, so cron's own mail is a second net under it.

The further it runs from the collector, the more it can see: pointed at the same storage from
another machine, it also catches that machine being down.

**`HEARTBEAT_URL` — the machine is gone.** No watchdog running on a box can report that the box
is switched off. Set `HEARTBEAT_URL` and `run.sh` pings it on success and appends `/fail` when
a run fails, which is the shape healthchecks.io, Cronitor and similar services expect. They
alert when the pings stop, which is the only signal that survives the host dying.

```bash
HEARTBEAT_URL=https://hc-ping.com/your-uuid ./run.sh --send --prune
```

Neither is required to collect. Both are required to trust that collection is happening.

## What it writes

```
data/{customer_id}/{cluster_id}/
    ftdc/{node}/metrics.*     the captured FTDC, as Atlas served it (pruned past retention)
    state.json                what has been downloaded, analysed and notified
    findings.jsonl            what the rules fired on
    baseline.jsonl            per-metric percentiles, one row per metric per run
    usage.jsonl               one line per run: files, bytes, seconds
status.html                   the status page
outbox/                       messages written but not sent
logs/run-YYYY-MM.log          one file per month
```

`baseline.jsonl` is the one that cannot be rebuilt later. Once Atlas drops the raw data,
those percentiles are all that is left to say "that is unusual **for this cluster**", so it
starts accumulating from the very first capture rather than when someone thinks to enable it.

## Before capturing anything: turn off autoscaling

If the tier changes mid-capture, every metric changes scale in the middle of the window and
the baseline is contaminated from its first row — and that row cannot be recomputed. Turn off
compute autoscaling, scale-down and disk autoscaling on any cluster this watches.

A `Project Read Only` key cannot do this, which is correct: it is the same permission a
customer would grant. It has to be done from the Atlas UI.

## When something looks wrong

**A rule that never fires looks exactly like a cluster with no problems.** That failure mode
has bitten this project repeatedly, so the status page prints how many rules could not resolve
their metric on the build being watched. If that number is not zero, there is coverage you
believe you have and do not — usually a metric renamed in a MongoDB release, which the alias
table in Big Hole is what fixes.

**A finding you do not believe: check the capture before the rule.** Findings are computed
over whatever was captured, so an incomplete capture produces correct findings about incorrect
data. A node reported as "stopped reporting" for hours, on a cluster that was demonstrably up,
means files are missing rather than that the rule is wrong. Compare sample counts and time
ranges per node in `summary.json`; a healthy 1 Hz capture has as many samples as seconds.

**`capture.py` warns when a source returns no files at all.** That is different from returning
nothing new, and it means a wrong path, revoked credentials or a renamed cluster.

**Two runs never overlap.** `run.sh` takes a lock and a second run gives up its slot rather
than queueing, because overlapping runs would fight over `state.json` and could send the same
finding twice.

## Three things about FTDC files that are not obvious

All three were found running against a live Atlas cluster, and none is visible when testing
against bundles already on disk. They are why `state.py` looks the way it does.

1. **Numbered files are not immutable.** `metrics.<timestamp>-NNNNN` stops changing only
   *after* mongod rotates away from it. Until then it keeps growing, for hours, up to about
   10 MB. Observed: 284 KB stored under a name that Atlas was serving at 8,360 KB nine hours
   later.

2. **`metrics.interim` shrinks.** It buffers samples not yet flushed to the numbered file, so
   it gets smaller every time mongod flushes — 62 KB down to 46 KB, observed. Which is why
   the test for "worth fetching" is that the size *changed*, not that it grew.

3. **Atlas filters by the timestamp in the file name, not by the data inside it.** The file
   holding the last ten minutes of metrics can be named from this morning, so a date filter
   anchored to `now - 6h` excludes exactly the file the new data is in. `capture.py` anchors
   it to the oldest file that could still be open, across all nodes.

## Design notes

- `customer_id` and `cluster_id` are in every path from day one, though there is one of each
  today. Adding the second customer should be a line of config, not a data migration.
- `state.json` is shaped like a table — flat rows, ids, timestamps — so that becoming a
  database later does not mean reinterpreting nested structures.
- Sources sit behind a Protocol. `DirectorySource` and `SSHSource` are sketched rather than
  finished, because knowing non-Atlas clusters were coming shaped the interface, and that was
  worth deciding early even though it was not worth building early.
- Metrics are named with the **oldest** path that exists and the alias table maps them
  forward, so one name resolves from MongoDB 4.0 through 8.0 and a cluster's history survives
  the customer upgrading.
- Findings get a stable id from rule + node + start of the worst episode, deliberately
  excluding duration: an episode that keeps growing between runs is still the same episode,
  and a second email about it is the noise that gets a service muted.
