# What the checks cover, and what they do not

An audit of the common ways a MongoDB deployment gets into trouble, against what mongo-health
detects today. For every gap it records whether the data to close it is in FTDC — verified on
two real captures, not assumed — and what that data looked like:

- **Cluster1**: Atlas M10, MongoDB 8.0, three members, 20 days.
- **rs-local**: a self-managed 7.0 replica set, three members on one host, 9.7 days, under a
  load generator that injected incidents on purpose.

The measurements come from `big-hole/tools/measure-gaps.ts` (30 Sep 2026). The rules that exist
are in [rules.md](rules.md).

## Covered today

| Trouble | Check |
|---|---|
| Execution tickets saturated or exhausted | `read-/write-tickets-saturated`, `-exhausted` |
| Operations queueing | `read-/write-queue-building` |
| Cache under pressure, eviction falling behind | `cache-dirty-high`, `cache-full`, `eviction-by-app-threads`, `eviction-aggressive` |
| Host running out of memory, paging | `memory-low`, `page-faults-sustained` |
| Slow checkpoints, slow disk | `checkpoint-slow`, `disk-read-/write-latency-high` |
| Members down or lagging, elections | `member-unhealthy`, `replication-lag`, `election-held` |
| Replication pushing back on the primary | `flow-control-engaged`, `oplog-backlog`, `oplog-churn` |
| Bad queries: scans, poor targeting, sorts on disk | `collection-scans-sustained`, `query-targeting-poor`, `sorts-spilling-*` |
| Contention, leaked cursors, TTL storms | `write-conflicts`, `cursors-leaking`, `ttl-storm` |
| Connections near the limit, reconnect storms | `connections-high`, `connection-storm` |
| Slow commands, and telling a slow server from a slow network | `command-latency-high`, `slow-wire-not-server` |
| Old snapshots pinning history | `history-store-pinned` |
| A member stopped or stalling | `ftdc-long-outage`, `ftdc-micro-stalls` |
| Failures that should never happen | alarm counters (checkpoint, index build, salvage, initial sync) |
| Resizes and membership changes | `setting-changed` |
| One member unlike the others | `peer-outlier` |
| Unusual for this cluster | `baseline-excursion` |
| Cache, connections, memory or tickets running out | `capacity-runway` |
| Paying for more than the workload uses | `oversized-cluster` |

## Gaps where the data is there

Ordered by how often each one takes a cluster down, weighed against how much the data supports
a rule today.

### 1. The disk filling up — no check at all

The most common way a mongod stops, and nothing watches it. `capacity-runway` forecasts the
cache, connections, memory and tickets, but not the disk.

- **Data:** `systemMetrics.mounts.<path>.available` and `.capacity` for every mount, and the
  `dbPath` in the metadata (`getCmdLineOpts.parsed.storage.dbPath`), so the mount holding the
  data can be picked as the longest mount path that prefixes it.
- **Measured:** root disk 60% free on Cluster1, 70% on rs-local, both steady.
- **Proposal:** add the dbPath mount to the runway's limits ("at this rate the disk is full in N
  days"), plus a plain threshold rule for a disk already under 10% free.

### 2. The oplog window shrinking under write load — no check

How long a member can be away and still catch up. When the window is shorter than an outage,
the member needs a full initial sync — hours, on a large set — and nothing says so beforehand.

- **Data:** `local.oplog.rs.stats.storageStats.maxSize`, and the bytes going into the oplog from
  `…wiredTiger.cursor.insert key and value bytes`. Window = size ÷ rate.
- **Measured:** Cluster1 ~1,000 h at its usual rate, 19 h at its busiest. rs-local, under the
  load generator, fell to **minutes**: p50 0.7 h, minimum 0.
- **Proposal:** the window averaged over an hour, under 24 h sustained for an hour → warning,
  and under the longest outage seen on this cluster → critical. The instantaneous rate swings
  too much to judge on.

### 3. Swapping — not named

`memory-low` and `page-faults-sustained` circle it without saying it. A mongod swapping is slow
in a way nothing else explains, and the fix (memory, or a smaller cache) is specific.

- **Data:** `systemMetrics.vmstat.pswpin`/`pswpout`, `SwapTotal_kb`/`SwapFree_kb`.
- **Measured:** rs-local used up to 4 GB of swap, with 916 pages/s swapped in at p99 during
  load. Cluster1 holds 16–40 MB in swap and swaps in only in rare bursts.
- **Proposal:** swap-ins above ~100 pages/s sustained for a minute → warning. Calibrate against
  the rs-local load windows (fires) and Cluster1 (stays silent).

### 4. CPU steal — burstable instances out of credits

On Atlas M10/M20 and any burstable cloud instance, steal is the host taking the CPU back. It
looks like the database got slow for no reason.

- **Data:** `systemMetrics.cpu.steal_ms`, `iowait_ms`.
- **Measured:** **unusable as a plain rate on Atlas**: it peaks at 437% of the host, which is
  impossible. It is the known Atlas artefact — CPU counters there advance every 300 s — that the
  engine already corrects for elsewhere (`cadenceAwareRate`). rs-local shows 0 steal.
- **Proposal:** a steal rule only through the cadence-aware rate, and only after checking it
  against a burstable instance that ran out of credits.

### 5. TCP retransmissions — a direct witness for network trouble

`slow-wire-not-server` infers a slow network from what stays still. Retransmissions are the
network saying so itself.

- **Data:** `systemMetrics.netstat.Tcp:RetransSegs` and `Tcp:OutSegs`.
- **Measured:** rs-local reached 767 retransmits/s inside the injected network fault; Cluster1
  stays at 0–1/s with rare bursts to 20.
- **Proposal:** add retransmissions as a second condition on `slow-wire-not-server` rather than a
  rule of its own: it sharpens the one finding that blames the network.

### 6. Error bursts — user asserts

User asserts count errors returned to clients: duplicate keys, failed authentication, bad
queries.

- **Data:** `serverStatus.asserts.user`.
- **Measured:** Cluster1 sits at about 9/s at p99, steadily (its own background traffic);
  rs-local spiked to 11,257/s.
- **Proposal:** against the cluster's own history (a baseline excursion), never a fixed number —
  the steady level differs by two orders of magnitude between the two.

### Lower priority — the data is quirky or the trouble is rare

- **Majority commit lag** (`appliedOpTime` − `lastCommittedOpTime`): only meaningful on the
  primary, and the series carries zeros and garbage on secondaries (values in the billions of
  seconds). `replication-lag` already covers the common case.
- **tcmalloc fragmentation** (`pageheap_free_bytes` against `current_allocated_bytes`): the
  ratio goes negative and past 2,000% on rs-local, so the two series are not aligned the way the
  arithmetic assumes. Needs work before it can be trusted.
- **Aborted transactions**: zero on Cluster1, a few bursts on rs-local. Worth a check once a
  cluster that uses transactions heavily is available to calibrate against.

## Configuration, not metrics — the recommendations step

Everything here is in the FTDC metadata, so it needs no connection: a version past end of
support, file and process ulimits below what MongoDB recommends, the cache set larger than
memory allows, the default write concern, transparent huge pages. Planned as recommendations
rather than findings: they are true all the time, not events.

## Not in FTDC at all

Which queries are slow and what they look like, which indexes are unused, how big each
collection is and how fast it grows, and what the log says. A connection string could fetch
some of it (`$indexStats`, `collStats`); the log stays out by decision — see the notes on why
showing the mongod log is not part of the product.
