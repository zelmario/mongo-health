/**
 * The pathology rules, as data.
 *
 * Kept free of logic on purpose: this is the file a support engineer edits, and it should be
 * editable by someone who knows MongoDB rather than this codebase. `detect.ts` holds every
 * behaviour; a rule is a metric, a comparison, a threshold and a duration.
 *
 * Three constraints on adding one:
 *
 * 1. **Name the metric the way a dashboard template does.** Rules resolve through the same
 *    `expandMetric`, so aliases and role prefixes apply and a rule written against one release
 *    fires on another where the metric was renamed. Never write a version-specific path.
 * 2. **Justify the threshold.** Every number below is either a documented WiredTiger trigger or
 *    a value observed on a real capture. A guessed threshold produces findings nobody trusts,
 *    and one untrusted finding discredits the whole list.
 * 3. **Make `sustainMs` long enough to mean something.** Almost all of these metrics touch
 *    their threshold briefly on a perfectly healthy server. What distinguishes a pathology is
 *    that it persists.
 * 4. **Set `toleranceMs` to how long this condition typically recovers for.** These conditions
 *    flap -- that is their nature, because the server is actively fighting them. Without a
 *    tolerance, `sustainMs` means "unbroken", and a capture that spent 377 s above the dirty
 *    trigger with a 36% peak produced no finding at all, because no single stretch reached 60 s.
 *    `sustainMs` still counts only time actually in breach, so this widens what can be seen
 *    without widening what can be claimed.
 */

import type { Rule } from './detect.js';

export const RULES: readonly Rule[] = [
  /* ------------------------------------------------- execution ticket pressure ---- */
  // MongoDB 8.0 sizes the execution pools adaptively: when it sees pressure it *grows* the
  // pool, so the pathology no longer looks like a pool pinned at zero for half a minute. It
  // looks like a pool that is almost entirely checked out, with `available` flickering
  // through zero for a second at a time.
  //
  // Measured on a saturated M10 (2 vCPU, 8.0.29) under a deliberate collection-scan storm:
  // `available` hit zero on 132 samples but the longest unbroken run was 3 seconds, so a
  // rule requiring 30 s of continuous exhaustion saw nothing. Over the same window the mean
  // ratio of checked-out tickets to pool size sat at 46-77%, against under 20% at rest --
  // which separates load from idle cleanly, and is what these rules test instead.
  //
  // Written against the 7.x paths so the alias table maps them forward to
  // `queues.execution.*` on 8.0; both releases resolve.
  {
    id: 'read-tickets-saturated',
    title: 'Read ticket pool saturated',
    severity: 'critical',
    metric:
      'pct(serverStatus.wiredTiger.concurrentTransactions.read.out, serverStatus.wiredTiger.concurrentTransactions.read.totalTickets)',
    op: '>=',
    threshold: 50,
    sustainMs: 60_000,
    // The ratio dips whenever the adaptive sizer grows the pool; those dips are part of the
    // episode, not the end of it.
    toleranceMs: 15_000,
    // Saturated means something waited. Four scans holding four of an eight-ticket pool, with
    // nothing queued at any moment, was called critical: it is load, not saturation. Required
    // somewhere in the episode, not at every moment -- see `Rule.during`.
    during: { metric: 'serverStatus.globalLock.currentQueue.readers', op: '>=', threshold: 1 },
    unit: 'percent',
    what: 'Most of the read ticket pool was checked out, so reads were queueing for a slot.',
    check: 'Read latency and the global lock read queue over the same window, then what was consuming the tickets — a collection scan, a missing index, or storage that stopped keeping up.',
  },
  {
    id: 'write-tickets-saturated',
    title: 'Write ticket pool saturated',
    severity: 'critical',
    metric:
      'pct(serverStatus.wiredTiger.concurrentTransactions.write.out, serverStatus.wiredTiger.concurrentTransactions.write.totalTickets)',
    op: '>=',
    threshold: 50,
    sustainMs: 60_000,
    toleranceMs: 15_000,
    // Saturated means something waited. Four scans holding four of an eight-ticket pool, with
    // nothing queued at any moment, was called critical: it is load, not saturation. Required
    // somewhere in the episode, not at every moment -- see `Rule.during`.
    during: { metric: 'serverStatus.globalLock.currentQueue.writers', op: '>=', threshold: 1 },
    unit: 'percent',
    what: 'Most of the write ticket pool was checked out, so writes were queueing for a slot.',
    check: 'Write latency, the global lock write queue, and cache dirty over the same window — a full pool is usually downstream of eviction falling behind.',
  },

  /* ------------------------------------------------------- execution tickets ---- */
  // The single most useful signal in a saturation investigation. Available tickets at zero
  // means every further operation queues, and the server is no longer keeping up with what is
  // being asked of it -- everything else (latency, queue depth, connection count) is downstream
  // of this. The 8.0 rename to `queues.execution` is handled by the alias table.
  {
    id: 'read-tickets-exhausted',
    title: 'Read tickets exhausted',
    severity: 'critical',
    metric: 'serverStatus.wiredTiger.concurrentTransactions.read.available',
    op: '<=',
    threshold: 0,
    // Brief exhaustion is normal under load; a pool that stays empty is not.
    sustainMs: 30_000,
    // No tolerance, unlike the cache rules. MongoDB 8.0 sizes this pool adaptively -- it shrinks
    // to single digits on an idle server -- so `available` touches zero routinely, and on a
    // healthy 8.0 node it did so on 91 scattered samples with a pool of 6. Bridging those into an
    // episode reported a critical saturation on a server that was fine. The pathology this rule
    // exists for is a pool pinned at zero, which needs no bridging to be seen.
    toleranceMs: 0,
    unit: 'count',
    what: 'No read ticket was available, so every incoming read waited for one.',
    check: 'Read latency and the global lock read queue over the same window, then what was consuming the tickets — a collection scan, a missing index, or storage that stopped keeping up.',
  },
  {
    id: 'write-tickets-exhausted',
    title: 'Write tickets exhausted',
    severity: 'critical',
    metric: 'serverStatus.wiredTiger.concurrentTransactions.write.available',
    op: '<=',
    threshold: 0,
    sustainMs: 30_000,
    toleranceMs: 0, // see read-tickets-exhausted
    unit: 'count',
    what: 'No write ticket was available, so every incoming write waited for one.',
    check: 'Dirty cache and checkpoint activity over the same window — write tickets usually empty because eviction is behind, not because the writes themselves are slow.',
  },

  /* ---------------------------------------------------------- WiredTiger cache ---- */
  // WiredTiger targets 5% dirty and starts evicting application threads at 20%. Past that
  // trigger the server is making user operations do eviction work, which is felt as latency
  // with no corresponding change in workload.
  {
    id: 'cache-dirty-high',
    title: 'Cache dirty above the eviction trigger',
    severity: 'warning',
    metric:
      'pct(serverStatus.wiredTiger.cache.tracked dirty bytes in the cache, serverStatus.wiredTiger.cache.maximum bytes configured)',
    op: '>=',
    threshold: 20,
    sustainMs: 60_000,
    // Eviction pulls dirty back under the trigger within seconds and it climbs straight back;
    // measured at 30 s of unbroken breach on a capture spending 6+ minutes over the line.
    toleranceMs: 30_000,
    unit: 'percent',
    what: 'Dirty cache stayed at or above the 20% mark where WiredTiger makes application threads evict.',
    check: 'Checkpoint duration and disk write throughput — this is eviction failing to keep up with the write rate, and the storage is the usual reason.',
  },
  // The cache is meant to sit near full; that is what it is for. What matters is being pinned
  // at the ceiling, because it means eviction has no headroom left.
  {
    id: 'cache-full',
    title: 'Cache pinned at capacity',
    severity: 'warning',
    metric:
      'pct(serverStatus.wiredTiger.cache.bytes currently in the cache, serverStatus.wiredTiger.cache.maximum bytes configured)',
    op: '>=',
    threshold: 95,
    sustainMs: 300_000,
    toleranceMs: 30_000,
    unit: 'percent',
    what: 'The cache stayed within 5% of its configured maximum, leaving eviction no headroom.',
    check: 'Pages evicted and bytes read into cache — a working set larger than the cache shows up here first, and as page faults next.',
  },

  /* ----------------------------------------------------------------- queueing ---- */
  // The global lock queue is the symptom the user actually feels. It is downstream of the
  // ticket pool, so it is `warning` rather than `critical`: worth surfacing, but the tickets
  // above are the finding.
  {
    id: 'read-queue-building',
    title: 'Read queue building',
    severity: 'warning',
    metric: 'serverStatus.globalLock.currentQueue.readers',
    op: '>=',
    threshold: 10,
    sustainMs: 60_000,
    toleranceMs: 15_000,
    unit: 'count',
    what: 'Reads were waiting on the global lock queue rather than executing.',
    check: 'Read tickets over the same window — a sustained read queue is almost always the ticket pool emptying.',
  },
  {
    id: 'write-queue-building',
    title: 'Write queue building',
    severity: 'warning',
    metric: 'serverStatus.globalLock.currentQueue.writers',
    op: '>=',
    threshold: 10,
    sustainMs: 60_000,
    toleranceMs: 15_000,
    unit: 'count',
    what: 'Writes were waiting on the global lock queue rather than executing.',
    check: 'Write tickets and dirty cache over the same window.',
  },

  /* -------------------------------------------------------------- replication ---- */
  // Flow control throttles writes on the primary when secondaries fall behind the configured
  // majority-commit window. Any sustained time in it means replication, not the primary, is
  // setting the write rate. The metric is microseconds accumulated per second; scaling by 1e-4
  // turns that into a percentage of wall clock, matching the dashboard's own panel.
  {
    id: 'flow-control-engaged',
    title: 'Flow control throttling writes',
    severity: 'warning',
    metric: 'scale(rate(serverStatus.flowControl.isLaggedTimeMicros), 0.0001)',
    op: '>=',
    threshold: 10,
    sustainMs: 60_000,
    toleranceMs: 15_000,
    unit: 'percent',
    what: 'The primary was throttling its own writes because a secondary was behind the majority-commit point.',
    check: 'Replication lag across the nodes, and whether the lagging secondary was itself ticket- or cache-bound.',
  },

  /* ------------------------------------------------------------------ storage ---- */
  // Page faults on a database server mean the working set is not resident. A handful is
  // routine; a sustained rate is the machine paging its way through the workload.
  {
    id: 'page-faults-sustained',
    title: 'Sustained page faults',
    severity: 'warning',
    metric: 'rate(serverStatus.extra_info.page_faults)',
    op: '>=',
    threshold: 100,
    sustainMs: 300_000,
    toleranceMs: 30_000,
    unit: 'per-sec',
    what: 'The server was faulting pages from disk continuously, so its working set did not fit in memory.',
    check: 'Resident memory against the cache size, and whether another process on the host is taking the memory.',
  },

  /* ------------------------------------------------ measured on real captures ---- */
  // Everything below was calibrated with tools/calibrar.ts against captures where the
  // verdict was already known, rather than estimated. Where a threshold could not be
  // measured, its comment says so.

  {
    id: 'checkpoint-slow',
    // The metric holds the last checkpoint's duration until the next one, so elapsed time over
    // it is meaningless -- see `echoesAnEvent`. Reported as "620 of 865 checkpoints" instead.
    echoesAnEvent: true,
    title: 'WiredTiger checkpoints running long',
    severity: 'warning',
    // Written against the 7.x path so the alias table maps it forward: 8.0 moved this to
    // `wiredTiger.checkpoint.most recent time (msecs)`, and before the alias existed this
    // metric resolved to nothing at all on any modern cluster.
    metric:
      'serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)',
    op: '>=',
    threshold: 1_000,
    // A checkpoint that takes seconds stalls writes behind it, and it is one of the few
    // explanations for the "everything froze for a moment" that users report and no
    // throughput panel accounts for.
    //
    // Measured across the three nodes of the demo capture, samples at or above each cut:
    //
    //           >=500ms   >=1s    >=5s   >=10s
    //   node-00       0      0       0      0     (healthy throughout)
    //   node-02     121      0       0      0     (brief saturation)
    //   node-01    1046    828     627    164     (the node that actually suffered)
    //
    // 1 s is where the healthy node and the sick one stop overlapping: node-00 never reaches
    // it and node-01 sits above it for 8.9% of the capture. 500 ms would also catch node-02's
    // brief episode, but that one is already reported by the ticket rules, and a second
    // finding for the same incident is noise.
    sustainMs: 120_000,
    // `most recent time` holds its value until the next checkpoint, so a 60 s sustain would
    // fire on a single slow checkpoint. Two minutes means at least two consecutive slow ones.
    // The tolerance spans the gap between checkpoints, which would otherwise end the episode
    // every time a fast one lands in the middle of a bad stretch.
    toleranceMs: 60_000,
    unit: 'ms',
    what: 'Checkpoints are taking over a second, which stalls writes waiting behind them.',
    check:
      'Look at cache dirty bytes and disk write throughput in the same window: a checkpoint ' +
      'gets slow either because there is too much dirty data to flush or because the volume ' +
      'cannot absorb it.',
  },

  {
    id: 'oplog-backlog',
    title: 'Replication buffer backing up',
    severity: 'warning',
    // 8.0 splits the pipeline in two and the alias maps this to `buffer.write.sizeBytes`,
    // which occupies the same position: the first place incoming oplog piles up. On 8.0 a
    // backlog can additionally sit in `buffer.apply`, so this rule under-reports there rather
    // than over-reports — the failure direction to prefer.
    metric: 'serverStatus.metrics.repl.buffer.sizeBytes',
    op: '>=',
    threshold: 100_000_000,
    // The secondary is receiving oplog faster than it applies it. Measured on the demo
    // capture: the two healthy nodes never put a single sample above 1 MB, while the node
    // that fell behind during the incident spent 28 samples above 100 MB and peaked at
    // 193 MB. There is no overlap at all between the two populations, so the exact cut
    // inside that range hardly matters; 100 MB is a round number well clear of both ends.
    sustainMs: 60_000,
    toleranceMs: 15_000,
    unit: 'bytes',
    what: 'A secondary is receiving oplog faster than it can apply it.',
    check:
      'Check whether the secondary is ticket-starved or IO-bound. A backlog that keeps ' +
      'growing ends with the node falling off the oplog window and needing a full resync.',
  },

  {
    id: 'memory-low',
    title: 'Host running out of memory',
    severity: 'critical',
    metric:
      'pct(systemMetrics.memory.MemAvailable_kb, systemMetrics.memory.MemTotal_kb)',
    op: '<=',
    threshold: 20,
    // `MemAvailable` is the kernel's own estimate of what a new allocation could obtain
    // *including* reclaimable page cache, so it is already the right question to ask of a
    // database host -- unlike `MemFree`, which looks alarming on every healthy server.
    //
    // Calibrated against two captures of the same tier (M10, ~1.85 GB):
    //
    //                        <=20%      <=25%      <=30%     samples / longest run
    //   idle cluster            0/0        0/0        0/0    never approaches any cut
    //   incident, node-00    138/36s    404/51s   4780/2152s
    //   incident, node-01    184/60s   1734/530s  4367/1841s
    //   incident, node-02     87/27s    942/284s  3245/2828s
    //
    // 30% is where a merely busy cluster lives -- the incident capture sat at a median of
    // 30-34% throughout -- so a rule there would fire on load rather than on trouble. 20% is
    // clear of the idle cluster by a factor of two and still catches all three incident nodes.
    //
    // 10% was tempting as "obviously bad" and is the wrong choice: the longest unbroken run
    // below it was 11 seconds. By the time a host stays under 10% for a minute the OOM killer
    // has usually already acted, and a rule that only fires after the fact reports history.
    sustainMs: 120_000,
    toleranceMs: 30_000,
    unit: 'percent',
    what: 'Available memory on the host is low enough that allocations are at risk.',
    check:
      'Look at the WiredTiger cache size against the instance tier, and at whether another ' +
      'process shares the host. Sustained pressure here ends in the OOM killer stopping mongod, ' +
      'which reads as an unexplained restart.',
  },

  {
    id: 'connections-high',
    title: 'Connection pool near its limit',
    severity: 'warning',
    // `connections.available` is what is LEFT, not the size of the pool, so the total is
    // `current + available`. Dividing by `available` alone reads 100% at half full -- which is
    // exactly what happened: a run whose real peak was 2,503 of ~5,000 connections reported
    // 100.24% and fired a rule that says "using most of the connections it is allowed to
    // accept". Half is not most, and a finding that says so is worse than no finding.
    metric:
      'pct(serverStatus.connections.current, sum(serverStatus.connections.current, serverStatus.connections.available))',
    op: '>=',
    // 85 rather than 80, now that the number means what it says. Running out of connections
    // takes an application down outright rather than slowing it, so the warning still wants
    // room ahead of the wall.
    threshold: 85,
    // Still the least-measured threshold here: no capture has yet shown a pool genuinely close
    // to full. A soak run reached 50% and nothing has gone past it, so 85 remains the
    // conventional headroom figure rather than an observed one.
    sustainMs: 300_000,
    toleranceMs: 60_000,
    unit: 'percent',
    what: 'The server is using most of the connections it is allowed to accept.',
    check:
      'Compare against driver pool settings across all clients. Reaching the limit refuses ' +
      'new connections rather than slowing existing ones, so the failure is abrupt.',
  },

  /* --------------------------------------------------- query efficiency ---- */
  // Measured on the same M10 during a deliberate collection-scan storm, comparing the 24
  // minutes of the incident against the 15 hours either side of it:
  //
  //             at rest (55k samples)      during the incident
  //   ratio     p50 1.25, max 2.00         p95 483, 169 s above 100
  //   collscans p95 0, 2 s above 10/s      p95 48/s, 169 s above 10/s
  //
  // Both secondaries stayed at rest throughout on the ratio (max 17 and 8), which is what
  // makes the separation trustworthy: it is not "the cluster was busy", it is "this member
  // was reading badly".
  {
    id: 'query-targeting-poor',
    title: 'Queries scanning far more than they return',
    severity: 'warning',
    metric:
      'ratio(rate(serverStatus.metrics.queryExecutor.scannedObjects), rate(serverStatus.metrics.document.returned))',
    op: '>=',
    // 100 documents read per document returned. At rest this cluster never exceeded 2, so the
    // cut sits fifty times above observed normal and still caught 169 seconds of the incident.
    // It is also the figure the wider MongoDB world recognises for query targeting, which
    // matters for a finding whose whole value is that the reader acts on it.
    threshold: 100,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'count',
    what: 'The server read far more documents than it returned, which is what a query with no usable index looks like from the outside.',
    check:
      'Turn on the profiler for the slow operations in this window, or check the shape of the ' +
      'heaviest queries against the indexes that exist. This is usually one missing index, and ' +
      'it is usually also the reason the cache, the tickets and the disk look busy.',
  },

  {
    id: 'collection-scans-sustained',
    title: 'Full collection scans running steadily',
    severity: 'warning',
    metric: 'rate(serverStatus.metrics.queryExecutor.collectionScans.total)',
    op: '>=',
    // 10/s, not 5. At rest this cluster spent 1,118 seconds above 5/s across its three
    // members — internal collections scan constantly and a cut there would fire everywhere,
    // forever. Above 10/s it spent 2 seconds in fifteen hours, against 169 seconds during
    // the incident.
    threshold: 10,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'per-sec',
    what: 'Whole collections were being read end to end, repeatedly.',
    check:
      'Which collection, and whether the query behind it could use an index. A burst confined ' +
      'to one time of day is usually a batch job rather than a capacity problem, and the two ' +
      'have completely different fixes.',
  },

  /* ------------------------------------------------- eviction pressure ---- */
  // A cache at 95% is not a problem by itself; a cache that makes the application's own
  // threads stop and evict pages IS one, because that wait is paid by the query the user is
  // waiting for. This is the difference between "the cache is full" — which is what a cache
  // is for — and "the cache is not keeping up".
  //
  // The cleanest separation of anything measured here: across 55,000 samples at rest on all
  // three members this metric was *exactly zero*. During the incident the loaded member spent
  // 30 s above zero and peaked at 1,199% — twelve threads' worth of time, spent evicting
  // instead of answering.
  {
    id: 'eviction-by-app-threads',
    title: 'Queries are being made to evict cache pages themselves',
    // Warning, not critical, and the measurement is why. The peak is alarming -- 1,199%, twelve
    // threads' worth of time spent evicting instead of answering -- but it totalled 41 seconds
    // across a 24-minute incident. What was critical in that window was the ticket pool, held
    // saturated for 1,325 seconds; this is one of the reasons for it, reported as a lead rather
    // than as the emergency.
    severity: 'warning',
    // Named with the OLDEST path, as every rule here is: `thread-yield` from 4.0 through 7.0,
    // and the alias table maps it forward to `cache` on 8.0. Written the other way round it
    // resolved to nothing on a real 7.0 cluster and never fired.
    metric:
      'scale(rate(serverStatus.wiredTiger.thread-yield.application thread time evicting (usecs)), 0.0001)',
    op: '>=',
    // 0.1% of one thread — one millisecond per second. A cut that low is only defensible
    // because the floor is not "low" but exactly zero: across 55,000 samples on three members
    // at rest this metric never left it. Anything measurable here is already outside normal.
    //
    // The cut was 1% first, which gave 30 seconds of evidence against a 30-second sustain —
    // true, but with no margin at all. At 0.1% the same episode gives 43 seconds, and both
    // secondaries replicating the same load stay at 5 s and 4 s, well clear.
    threshold: 0.1,
    sustainMs: 30_000,
    // Two minutes, measured rather than guessed. Those 43 seconds arrived as 28 separate
    // stretches of one to four seconds spread over nine minutes; at 60 s the gaps still closed
    // the episode often enough that no group reached the 30 s sustain. Widening it does not
    // widen the claim -- `sustainMs` counts only time actually in breach, never the bridged
    // span. And there is no risk of joining two unrelated incidents, because at rest this
    // metric is not low, it is exactly zero: there is nothing to bridge.
    toleranceMs: 120_000,
    unit: 'percent',
    what: 'WiredTiger could not free cache space fast enough, so the threads serving queries had to stop and evict pages themselves.',
    check:
      'This is cache pressure arriving as latency. Look at what filled the cache in this ' +
      'window — usually a scan reading data nobody needed — before concluding the cache is ' +
      'too small for the workload.',
  },

  {
    id: 'eviction-aggressive',
    title: 'WiredTiger eviction in aggressive mode',
    severity: 'warning',
    metric: 'serverStatus.wiredTiger.cache.eviction currently operating in aggressive mode',
    op: '>=',
    threshold: 1,
    // The engine's own declaration that it is struggling, so there is nothing to calibrate
    // except how long to require.
    //
    // **This one has not been seen to fire.** Zero on every member at rest, and 16 seconds on
    // the loaded member during the incident — short of the 30 s below. It is kept because it
    // measures something the neighbouring rule does not: `eviction-by-app-threads` measures
    // what the application PAID, this measures what the engine DECIDED, and a server can enter
    // aggressive mode while no query is waiting on it. The first capture that sustains it for
    // half a minute should be used to confirm the cut.
    sustainMs: 30_000,
    unit: 'count',
    what: 'The storage engine switched itself into aggressive eviction, which it does when normal eviction is not keeping up.',
    check:
      'Read alongside cache usage and dirty cache over the same window. On its own this says ' +
      'the engine noticed; the other two say how bad it got.',
  },

  /* ------------------------------------------------------ storage ---- */
  // Latency per operation, not utilisation. `io_time_ms` — iostat's %util — does NOT mean
  // saturation on a device that services requests in parallel, and the capture proves it
  // rather than merely warning about it: at rest these members spent 45 s above 80% util,
  // against 8 s during the incident. Utilisation was HIGHER when nothing was wrong.
  //
  // Time per operation does not have that problem. It is also the one number here that means
  // the same thing on every cluster, which is why the threshold is a hardware fact rather
  // than a percentile of this capture: Atlas presents EBS volumes as `nvme*`, and EBS answers
  // in well under a millisecond until it runs out of the IOPS the tier is paying for.
  //
  // Verified not to fire falsely: across 55,000 samples at rest the longest stretch above
  // 10 ms was a few seconds, nowhere near the sustain below.
  {
    id: 'disk-read-latency-high',
    title: 'Storage slow to answer reads',
    severity: 'warning',
    metric:
      'div(rate(systemMetrics.disks.*.read_time_ms), rate(systemMetrics.disks.*.reads))',
    op: '>=',
    threshold: 10,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'ms',
    what: 'Each read from disk took ten milliseconds or more, sustained — an order of magnitude above what this class of storage answers in.',
    check:
      'On Atlas this is usually the tier IOPS limit rather than a sick disk: check whether the ' +
      'volume is being throttled. Then check what is reading from disk at all, because a ' +
      'working set that fits in cache should not be.',
  },

  {
    id: 'disk-write-latency-high',
    title: 'Storage slow to accept writes',
    severity: 'warning',
    metric:
      'div(rate(systemMetrics.disks.*.write_time_ms), rate(systemMetrics.disks.*.writes))',
    op: '>=',
    threshold: 10,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'ms',
    what: 'Each write to disk took ten milliseconds or more, sustained.',
    check:
      'Checkpoints and the journal both wait on this, so a slow volume shows up as long ' +
      'checkpoints and stalled writes before anyone thinks to look at storage.',
  },

  /* ------------------------------------------------------- disk space ---- */
  // The most common way a mongod stops, and until these nothing watched it: when the volume
  // holding the data fills, writes fail and the process shuts down.
  //
  // `{dataMount}` is not a metric path. It stands for the mount holding this member's dbPath --
  // the longest `systemMetrics.mounts.<path>` that is a prefix of
  // `getCmdLineOpts.parsed.storage.dbPath` in the FTDC metadata -- and the collector's runner
  // substitutes it per member before detection. A glob over every mount would be wrong:
  // /dev/shm, /run and the read-only mounts of WSL or a container sit at or near 0% free by
  // design, and would fire on every healthy host.
  //
  // Measured on the two clusters the coverage audit used: 60% free on Atlas, 70% on the
  // self-managed set, both steady. A disk does not flap, so the duration only has to rule out a
  // momentary reading; the forecast that something is filling belongs to capacity-runway, which
  // tracks this same mount.
  //
  // Ten percent is the conventional alarm for a database volume: on a large disk it is still
  // gigabytes, enough for compaction and a few days of growth, and it is where the alert is
  // still a plan rather than an emergency. Five percent is the emergency.
  {
    id: 'disk-space-low',
    title: 'The data disk is running out of space',
    severity: 'warning',
    metric: 'pct({dataMount}.available, {dataMount}.capacity)',
    op: '<=',
    threshold: 10,
    sustainMs: 300_000,
    toleranceMs: 60_000,
    unit: 'percent',
    what: 'Less than a tenth of the disk holding the data is free.',
    check:
      'What is growing: a collection, the oplog, the journal, or log files left on the data ' +
      'volume. Make room or grow the volume before it fills — when it does, writes fail and ' +
      'mongod shuts down.',
  },
  {
    id: 'disk-space-critical',
    title: 'The data disk is almost full',
    severity: 'critical',
    metric: 'pct({dataMount}.available, {dataMount}.capacity)',
    op: '<=',
    threshold: 5,
    sustainMs: 120_000,
    toleranceMs: 60_000,
    unit: 'percent',
    what: 'Less than one twentieth of the disk holding the data is free.',
    check:
      'This is the emergency: grow the volume or free space now. Compaction itself needs room ' +
      'to run, so it is not a way out from here.',
  },

  /* --------------------------------------------------- replica set health ---- */
  // Nothing to calibrate: `health` is the heartbeat verdict, 1 or 0, and 0 means this member
  // has not answered. Never observed at 0 in our captures — three members, 55,000 samples,
  // always 1 — so this rule has not been seen to fire. It is written anyway because the cost
  // of missing it is a customer discovering after the fact that they had been running without
  // a replica for a day.
  //
  // The wildcard expands to one finding per member, and the sustain keeps out the brief zeroes
  // a member reports while restarting or during a network blip.
  {
    id: 'member-unhealthy',
    title: 'Replica set member not answering',
    severity: 'critical',
    metric: 'replSetGetStatus.members.*.health',
    op: '<=',
    threshold: 0,
    sustainMs: 60_000,
    unit: 'count',
    what: 'A member of the replica set stopped answering heartbeats.',
    check:
      'Whether that member is down, unreachable, or merely slow. Losing one of three still ' +
      'serves writes; losing two stops them, so this is worth acting on before it compounds.',
  },

  /* ------------------------------------------------------ replication lag ---- */
  // Members compared against EACH OTHER, never against the clock.
  //
  // The obvious form -- `diff(localTime, members.*.lastAppliedWallTime)` -- is what Big Hole's
  // own panel draws, and it is fine to look at and useless to alert on: those stamps only
  // advance when there are writes, so an idle cluster drifts away from the clock together.
  // Measured on the real capture: a median of 6,011 ms of "lag" at rest, and LESS during the
  // incident, when there were writes. An alert on that fires hardest when nothing is
  // happening.
  //
  // `spread()` has none of that. With no writes every member is equally stale and the spread
  // is zero, which is the truth -- median 0 ms at rest on the same capture.
  {
    id: 'replication-lag',
    title: 'A member is falling behind the others',
    severity: 'critical',
    metric: 'spread(replSetGetStatus.members.*.optimeDate)',
    op: '>=',
    // 30 s, and the floor underneath it is not arbitrary: an idle replica set writes a
    // periodic no-op every 10 seconds, so between two of them the members legitimately sit up
    // to 10 s apart. Measured at rest on a healthy set: 8,508 s spent above 10 s, and not one
    // sample above 30 s. Anything under about fifteen would fire on every quiet cluster.
    threshold: 30_000,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'ms',
    // NOT been seen to fire: three members in one region, and nothing in the capture ever came
    // close. Written because a secondary that stops applying is invisible until the day it is
    // needed, and because the shape of it is now measurable without the artefact above.
    what: 'One member of the set is applying oplog entries well behind the others, so it holds a copy of the data that is out of date.',
    check:
      'Which member, and whether it is short of CPU, memory or disk — a secondary that cannot ' +
      'keep up is usually starved rather than broken. Until it catches up it cannot be relied ' +
      'on for reads, and it does not count towards a majority write.',
  },

  /* ------------------------------------------------- contention on documents ---- */
  // The strongest signal in an eight-hour soak run with a known timeline, and one that leaves
  // no trace on CPU, disk or memory: a dashboard of resources looks perfectly healthy while
  // this is happening, which is exactly why it gets reported as "the database is slow".
  //
  // Two writers updating the same document make one of them lose and retry. The work happens,
  // the latency doubles, and nothing is saturated. It is a data-modelling problem -- a counter
  // everybody increments, a queue everybody claims from -- not a capacity one, so no amount of
  // hardware fixes it.
  //
  // Measured on the run: at rest this metric is 0 at both the median and the p95; inside the
  // injected window the median was 48.9/s and it peaked at 139/s.
  {
    id: 'write-conflicts',
    title: 'Writes are colliding on the same documents',
    severity: 'warning',
    metric: 'rate(serverStatus.metrics.operation.writeConflicts)',
    op: '>=',
    // Ten a second. The floor is not "low" but zero, so this is already far outside normal --
    // and well clear of the handful a busy cluster produces incidentally.
    threshold: 10,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'per-sec',
    what: 'Write operations were repeatedly colliding on the same documents, so the server made them wait and retry.',
    check:
      'Which documents: a hot counter, a queue everybody polls, a lock row. The fix is in the ' +
      'data model — spread the writes across more documents — and not in the hardware. Look ' +
      'at write latency over the same window to see what it cost.',
  },

  /* ---------------------------------------------- pathologies with no resource cost ---- */
  // These leave nothing on CPU, disk or memory. That is what makes them worth having: a
  // resource dashboard looks healthy while they happen, so they arrive as "the database is
  // slow" with nothing to point at. Calibrated against an eight-hour soak run with a known
  // timeline of injected incidents, comparing each window against the time outside EVERY
  // window rather than against the rest of the run.
  {
    id: 'cursors-leaking',
    title: 'Cursors are piling up',
    severity: 'warning',
    metric: 'serverStatus.metrics.cursor.open.total',
    op: '>=',
    // At rest this cluster sat at a median of 6 open cursors and a p95 of 154. Inside the
    // injected leak the median was 1,145 and it reached 2,569. Five hundred is far above
    // anything normal here and still low enough to catch a leak before it exhausts anything.
    threshold: 500,
    // Longer than most: a batch job legitimately opens many cursors for a while. What
    // distinguishes a leak is that they do not close.
    sustainMs: 120_000,
    toleranceMs: 60_000,
    unit: 'count',
    what: 'The number of open cursors stayed high, which is what a client that opens cursors and never closes them looks like from the server.',
    check:
      'Usually a driver used without exhausting or closing its cursors, or a connection pool ' +
      'that reconnects and abandons them. Each one holds a snapshot, so they also stop old ' +
      'versions of documents from being freed.',
  },

  {
    id: 'ttl-storm',
    title: 'TTL deletions running hot',
    severity: 'warning',
    metric: 'rate(serverStatus.metrics.ttl.deletedDocuments)',
    op: '>=',
    // The TTL monitor deletes constantly on a cluster that uses it -- at rest here the median
    // was 0 with a p95 of 1,400/s. Inside the storm the median was 4,935/s. Four thousand
    // separates the two without firing on ordinary expiry.
    threshold: 4000,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'per-sec',
    what: 'The TTL monitor was deleting documents far faster than usual, which competes with the application for the same write capacity.',
    check:
      'Whether a bulk load just landed with expiry dates in the past, or a TTL index was ' +
      'created over existing data. The deletions are real writes: they fill the oplog and the ' +
      'cache like any other.',
  },

  {
    id: 'command-latency-high',
    title: 'Commands are taking milliseconds each',
    severity: 'warning',
    // The AVERAGE microseconds one command cost, which exists nowhere in FTDC: the two counters
    // are cumulative totals, and the ratio of their rates is the only way to ask "how long is a
    // command taking right now" rather than "how long has one taken since the server started".
    //
    // `commands` deliberately, not `reads` or `writes`. Those two have their own rules through
    // the queues and the tickets; this bucket holds everything else -- aggregate, count,
    // distinct, the admin traffic -- and it is the one that goes up when the server is spending
    // its time PLANNING rather than executing. That is a failure with no other symptom: no
    // resource is saturated, nothing is queued, the cache is fine, and the application is slow.
    metric:
      'div(rate(serverStatus.opLatencies.commands.latency), rate(serverStatus.opLatencies.commands.ops))',
    op: '>=',
    // ...and reads have to be slow too, or this is not the server's fault.
    //
    // The commands bucket counts awaitable and handshake traffic, so anything that slows the
    // WIRE inflates it while the server is untouched. Measured on the same replica set, the
    // same rule, two injected pathologies:
    //
    //   plan cache churn (the server IS slow)    us/command 10,576   us/read  72,855
    //   netem on loopback (the network is slow)  us/command 22,502   us/read     850
    //
    // Two orders of magnitude between them, on the metric this rule was not reading. Before
    // this guard the rule fired through the whole netem window -- 14:26:24 to 14:32:21, peak
    // 99ms per command -- under the title "Commands are taking milliseconds each", which sends
    // somebody to look at a database that was working perfectly.
    //
    // 5ms, the same line as the rule itself: the question is not whether reads are as bad as
    // commands, it is whether the server is slow at all. Under real churn reads were fourteen
    // times this; under netem they were a fifth of it.
    alongside: {
      metric:
        'div(rate(serverStatus.opLatencies.reads.latency), rate(serverStatus.opLatencies.reads.ops))',
      op: '>=',
      threshold: 5000,
    },
    // Five milliseconds per command. Measured on every node of two real Atlas clusters -- nine
    // days, 2.45 million samples -- plus the injected pathology:
    //
    //   healthy, all six Atlas nodes    median 85-94us, p99 179-217us
    //   longest stretch above 5,000     73s, 24s, 16s, 8s, 5s, 3s  (one figure per node)
    //   under injected plan-cache churn median 6,289us, 200 of 332 samples above
    //
    // The first calibration read ONE node per cluster, saw 3s and 5s, and concluded the line
    // was never approached. It was: the worst node crossed it for 73 seconds. Checking a single
    // member of a replica set is how a threshold gets set against the quietest thing in the
    // room -- the members do different work, and the one under the read load is not the one to
    // ask.
    //
    // The threshold survived the correction on its own merits. Across those nine days it
    // produces exactly ONE finding, 32 seconds long on a cluster whose median command costs
    // 91us -- a three-hundred-fold excursion, which is an event and not noise. What it does not
    // survive is a lower line: at 2ms the same data would report several a day.
    //
    // That one finding was then read metric by metric, because an AVERAGE has an obvious way to
    // lie: on a cluster running two commands a second, one slow command carries the mean and
    // the rule would report an idle server as a sick one. It was not that. Through the window
    // the node served a median of 86 commands a second -- 15 at the quietest -- each costing
    // 5.3ms, while the cache sat at 4.7% dirty and NO OTHER RULE FIRED within two hours either
    // side. Busy, slow, and nothing saturated: the exact shape this rule exists to name, and one
    // nothing else in the set can see.
    threshold: 5000,
    // Thirty seconds, the same floor every non-burst rule here uses. Fifteen was the first
    // choice, on the argument that a planner storm is short -- but the measurement did not
    // support needing it: at thirty the rule still catches the injected churn, because the
    // pathology is dense rather than brief. Keeping the shorter window would have bought
    // nothing and spent the margin that keeps the two Atlas clusters quiet.
    sustainMs: 30_000,
    // Small, and chosen against the false-positive data rather than the true-positive data: the
    // isolated seconds on the two Atlas clusters were scattered minutes apart, and a generous
    // tolerance is exactly what would stitch them into an incident that never occurred.
    toleranceMs: 5_000,
    unit: 'us',
    what: 'Each command was taking milliseconds on average, which is where the time goes when the server is planning queries rather than running them.',
    check:
      'Query shapes. A plan cache that never hits -- filters assembled dynamically by an ORM, ' +
      'or an API that accepts arbitrary filters -- makes every query pay the full multiplanner, ' +
      'which runs several candidate plans before choosing one. It shows up as CPU with no ' +
      'saturated resource behind it. Look at whether the same shapes repeat, not just whether ' +
      'the same collections do.',
  },

  {
    id: 'slow-wire-not-server',
    title: 'The server is answering fast; the time is going somewhere else',
    severity: 'warning',
    // The mirror image of `command-latency-high`, on the same two metrics and with the opposite
    // conjunction. Commands slow AND reads slow is a slow server. Commands slow AND reads FINE
    // is not: the commands bucket counts awaitable and handshake traffic, so it absorbs the
    // wait whenever something between the clients and the server is slow, while the work the
    // server actually does stays exactly as fast as it was.
    //
    // Measured on a replica set with netem on loopback -- 120ms delay, 40ms jitter, 0.5% loss:
    //
    //   us per command  200  ->  22,502     (and 13,515, 14,327, 10,958 through the window)
    //   us per read     840  ->     850     (unchanged)
    //   requests/s    2,000  ->     280     (the clients spend their time waiting)
    //   cache 87% -> 81%, read tickets free 5 -> 5, read queue 0, connections 90 -> 90
    //
    // Everything the server owns stayed still. That is the whole finding, and it is one no
    // dashboard of database metrics will ever show, because every number on it is normal.
    //
    // This is deliberately NOT called "the network". FTDC cannot see a network: what it can
    // say is that the server was not slow at the work it did, which is a fact, and that the
    // time went somewhere it cannot see, which is also a fact. Naming the cause would be
    // guessing, and this rule exists because guessing the cause is what sent people to the
    // database in the first place.
    metric:
      'div(rate(serverStatus.opLatencies.commands.latency), rate(serverStatus.opLatencies.commands.ops))',
    op: '>=',
    threshold: 5000,
    // The same 5ms line as its sibling, and the same on both sides on purpose: the pair of
    // rules partitions one situation rather than overlapping on it. Above the line for
    // commands, below it for reads -- the server is not slow at its own work by exactly the
    // definition the other rule uses to say that it is.
    alongside: {
      metric:
        'div(rate(serverStatus.opLatencies.reads.latency), rate(serverStatus.opLatencies.reads.ops))',
      op: '<=',
      threshold: 5000,
    },
    // Longer than its sibling's thirty seconds. A slow server is worth reporting quickly; this
    // one is a claim about where the time is NOT going, and a brief handshake storm -- a
    // deployment reconnecting every client at once -- produces the same shape for a few
    // seconds without meaning anything.
    //
    // Sixty was tried and dropped: on the same capture it changed nothing at all. The second,
    // shorter netem injection (2m46s, and only about a minute of it above the line) stays
    // unreported at either figure, so the lower threshold bought no detection and would only
    // have widened the door. Not shipping it is the measurement's answer, not caution.
    sustainMs: 120_000,
    toleranceMs: 15_000,
    unit: 'us',
    what:
      'Commands were taking milliseconds each while the reads and writes the server actually ' +
      'ran stayed fast, and nothing inside the server was saturated. Time spent like that is ' +
      'not time the database is spending.',
    check:
      'The path between the clients and this server, before the database. Latency or packet ' +
      'loss on the link, a proxy or load balancer in front of it, TLS renegotiating on every ' +
      'connection, DNS resolution on each connect. The giveaway is that the application sees ' +
      'slow queries and every server-side number looks healthy -- which is exactly what this ' +
      'is reporting. Compare a client-side timing against the same operation run from a shell ' +
      'on the server itself.',
  },

  {
    id: 'packets-retransmitted',
    title: 'The network is losing packets',
    severity: 'warning',
    // The one network fact FTDC does carry: the kernel's count of TCP segments it had to send
    // again. `slow-wire-not-server` infers a slow path from what stays still and deliberately
    // names no cause; this one can, because a retransmission is the network saying so itself.
    // It is a rule of its own rather than a condition on that one: a proxy, TLS or DNS make the
    // wire slow without losing a packet, and requiring retransmissions would blind it to them.
    //
    // Measured on rs-local, netem on loopback (0.4-0.6% loss plus delay): the three injected
    // windows -- 41 s on 9 Aug, 6 min and 2m46s on 14 Aug -- all at 5/s or more, and at 0.5%
    // of segments or more, for 40 s, 356 s and 167 s. The 2m46s one is the injection the
    // slow-wire rule cannot report at all.
    //
    // The rate alone is not enough. Retry storms on the same set reached 133/s for five
    // minutes, but out of thousands of segments a second -- under 0.5% -- because a listen
    // queue overflowing under a reconnect stampede retransmits SYNs, not data; the
    // connection-storm rule already reports those. And a busy host sends tens of thousands of
    // segments a second, where 5/s is nothing. Hence the share alongside. Cluster1 never held
    // 5/s for more than 3 s in 20 days.
    metric: 'rate(systemMetrics.netstat.Tcp:RetransSegs)',
    op: '>=',
    threshold: 5,
    alongside: {
      metric:
        'pct(rate(systemMetrics.netstat.Tcp:RetransSegs), rate(systemMetrics.netstat.Tcp:OutSegs))',
      op: '>=',
      // Half a percent, not one: a moment where the companion fails cuts the episode outright
      // -- tolerance does not bridge it -- and at 1% the first two minutes of the 6-minute
      // injection came out in pieces too short to count. The retry storms stay under 0.5%.
      threshold: 0.5,
    },
    // Thirty seconds, so the shortest injection (41 s) is read; tolerance for the gaps loss
    // leaves between bursts.
    sustainMs: 30_000,
    toleranceMs: 30_000,
    unit: 'per-sec',
    what: 'At least one in two hundred TCP segments this host sent had to be sent again: packets were being lost or badly delayed on the network.',
    check:
      'The network between this host and its clients or the other members: a saturated link, a ' +
      'failing NIC or cable, a congested switch port, packet loss at a firewall or across ' +
      'regions. If every member shows it at once, look at what they share. Queries will look ' +
      'slow from the application while the server itself is fast -- see slow-wire-not-server.',
  },

  {
    id: 'oplog-churn',
    title: 'Oplog growing far faster than the workload explains',
    severity: 'warning',
    // A RATIO, not a level. High oplog bytes with high traffic is a busy cluster; high oplog
    // bytes with ordinary traffic means each operation is writing far more than it should --
    // an unindexed multi-update, a document rewritten whole on every change.
    metric:
      'div(rate(serverStatus.wiredTiger.log.log bytes written), sum(rate(serverStatus.opcounters.update), rate(serverStatus.opcounters.insert), rate(serverStatus.opcounters.delete)))',
    op: '>=',
    // Bytes of journal per write operation. At rest the median was 517 and the p95 1,790;
    // inside the injected churn the median was 5,484. Four thousand sits between them with
    // room on both sides.
    threshold: 4000,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'bytes',
    what: 'Each write was putting far more into the oplog than a write of its kind should, so the oplog is being consumed much faster than the operation count suggests.',
    check:
      'The real cost is the recovery window: an oplog that fills in an hour instead of a day ' +
      'means a secondary that falls behind for an hour needs a full resync. Look for updates ' +
      'that rewrite whole documents, or multi-updates touching more than intended.',
  },

  {
    id: 'oplog-window-short',
    title: 'The oplog holds less than a day of writes',
    severity: 'warning',
    // The window a member actually has: how far back the last `maxSize` bytes written to the
    // oplog reach. Not size over the current rate, which on a real Atlas cluster swung from
    // 1,000 hours to 19 inside a day. Measured: Cluster1 never went under 4,479 h; rs-local,
    // with a 512 MB oplog and a load generator writing 2.5 MB/s, spent 36.7 h under a day.
    //
    // A day because it is the outage people plan for -- a member down overnight, a host
    // rebuilt, a maintenance window -- and an hour of it sustained because the window only
    // recovers at the speed of the clock: once the writes stop it grows back by one hour per
    // hour, so a short dip after a burst is the same oplog, not a new problem.
    metric:
      'window(local.oplog.rs.stats.storageStats.wiredTiger.cursor.insert key and value bytes, local.oplog.rs.stats.storageStats.maxSize)',
    op: '<=',
    threshold: 86_400,
    sustainMs: 3_600_000,
    toleranceMs: 300_000,
    unit: 'seconds',
    what: 'The oplog holds less than a day of writes: a member away for longer than that cannot catch up and needs a full initial sync.',
    check:
      'The oplog is too small for the write load. Grow it with replSetResizeOplog on every ' +
      'member -- online, no restart -- or set oplogMinRetentionHours so it keeps a minimum ' +
      'time rather than a size. If the load itself is the surprise, look at what is writing: ' +
      'oplog-churn reports writes that put far more into the oplog than their count suggests.',
  },
  {
    id: 'oplog-window-critical',
    title: 'The oplog holds less than an hour of writes',
    severity: 'critical',
    // Under an hour a restart, a slow initial sync of another member or a network blip is
    // enough to push a secondary off the end. rs-local spent 19 h there, 8.2 h unbroken.
    metric:
      'window(local.oplog.rs.stats.storageStats.wiredTiger.cursor.insert key and value bytes, local.oplog.rs.stats.storageStats.maxSize)',
    op: '<=',
    threshold: 3_600,
    sustainMs: 900_000,
    toleranceMs: 120_000,
    unit: 'seconds',
    what: 'The oplog holds less than an hour of writes: a secondary that stops for longer than that falls off the end and needs a full initial sync.',
    check:
      'Grow the oplog now with replSetResizeOplog, on every member. Until then avoid anything ' +
      'that takes a member out -- restarts, rolling upgrades, rebuilding a host -- because it ' +
      'will not come back on its own.',
  },

  {
    id: 'swapping',
    title: 'The host is swapping mongod back in from disk',
    severity: 'warning',
    // Swap-ins, not swap used: a few megabytes parked in swap and never touched cost nothing
    // (Cluster1 holds 16-40 MB there for weeks), while pages coming back in mean a query is
    // waiting on the disk for memory it already had. Pages of 4 KB, so 100/s is 400 KB/s.
    //
    // Measured: rs-local, three mongods on one host with 4 GB in swap, spent 165 minutes at or
    // above 100/s under load -- in flaps of seconds, the longest unbroken one 151 s, hence the
    // tolerance. Cluster1 reached it in two to six bursts of one or two seconds in 20 days per
    // member, which no amount of bridging adds up to a minute.
    metric: 'rate(systemMetrics.vmstat.pswpin)',
    op: '>=',
    threshold: 100,
    sustainMs: 60_000,
    toleranceMs: 30_000,
    unit: 'per-sec',
    what: 'The operating system was reading memory pages back from swap, so mongod was waiting on the disk for memory it already had.',
    check:
      'The host does not have the memory its processes want. Look at what else runs there, and ' +
      'at the WiredTiger cache against total memory -- several mongods on one host each take ' +
      'half of it by default. Give it more memory or a smaller cacheSizeGB, and set ' +
      'vm.swappiness to 1 so the kernel keeps mongod in memory over file cache.',
  },

  {
    id: 'connection-storm',
    title: 'Clients are reconnecting in a storm',
    severity: 'warning',
    // The rate of NEW connections, which is a different failure from a pool that is merely
    // large. A steady 2,000 connections is a well-behaved application with a big pool; 200 new
    // ones a second is a client reconnecting in a loop, and each handshake costs the server
    // real work before any query runs.
    metric: 'rate(serverStatus.connections.totalCreated)',
    op: '>=',
    // At rest this cluster created 0 new connections a second at both the median and the p95.
    // Across three injected storms the p95 ran 36-58/s with peaks to 252/s. Ten is well clear
    // of the reconnect that follows an ordinary deploy.
    threshold: 10,
    // Short, because a storm is short and self-inflicted: the pool exhausts, clients back off,
    // it starts again. Waiting a minute would miss the ones that matter.
    sustainMs: 30_000,
    toleranceMs: 30_000,
    unit: 'per-sec',
    what: 'New connections were being opened far faster than a healthy client does, which is what a reconnect loop or an exhausted client-side pool looks like.',
    check:
      'Driver pool settings and timeouts on the application side. A storm is usually a client ' +
      'giving up and retrying rather than the server refusing anything, and it costs the ' +
      'server handshake work that competes with real queries.',
  },

  /* ------------------------------------------------------ pinned content ---- */
  // Cache pressure and pinned content look almost identical and have opposite remedies, which
  // is why this is a rule of its own rather than a note on `cache-full`.
  //
  //   cache pressure   the working set does not fit. More RAM fixes it.
  //   pinned content   an old snapshot -- a forgotten query, a transaction left open -- stops
  //                    old versions being freed. More RAM fixes NOTHING; the query has to go.
  //
  // What separates them is the history store. Under ordinary pressure it does not grow: the
  // cache is simply full of current data. When something holds a snapshot open, WiredTiger has
  // to keep every version written since, and they accumulate there.
  //
  // Expressed against the cache size rather than in bytes, because what matters is how much of
  // the cache is being spent on versions nobody asked for.
  {
    id: 'history-store-pinned',
    title: 'Old document versions are filling the cache',
    severity: 'warning',
    metric:
      'pct(serverStatus.wiredTiger.cache.bytes belonging to the history store table in the cache, serverStatus.wiredTiger.cache.maximum bytes configured)',
    op: '>=',
    // Measured on a soak run: at rest the history store held a median of 1% of the cache with
    // a p95 of 9%; inside the injected incident the median was 8% and it reached 47%. Twenty
    // is above anything the run produced without something holding a snapshot.
    threshold: 20,
    sustainMs: 120_000,
    toleranceMs: 60_000,
    unit: 'percent',
    what: 'A growing share of the cache was holding old versions of documents rather than current data, which happens when something keeps an old snapshot alive.',
    check:
      'Look for a long-running query, an open transaction, or a cursor nobody closed — the ' +
      'oldest one is usually the culprit. Adding memory does not help here: the versions are ' +
      'kept because a reader still needs them, and they will be freed the moment it finishes.',
  },

  {
    id: 'sorts-spilling-to-disk',
    title: 'Sorts are spilling to disk',
    severity: 'warning',
    metric: 'rate(serverStatus.metrics.query.sort.spillToDisk)',
    op: '>=',
    // One a second. The threshold is semantic rather than statistical: MongoDB allows a sort
    // 100 MB of memory, and a sort that exceeds it writes to disk. A single one is an
    // occasional heavy query; a steady stream means queries are routinely ordering more than
    // fits, which is an index that does not exist.
    //
    // Confirmed against a capture with a known timeline: outside every load window this metric
    // spent 8 seconds above 1/s in seven and a half hours -- median and p95 both zero. Inside
    // the window the median was 1,032/s, peaking at 5,975/s while writing 227 MB a second.
    threshold: 1,
    // Half a minute, which is short for this file. It can be, because the floor is zero: what
    // is being asked is not "is this high" but "is this happening at all, consistently".
    sustainMs: 30_000,
    toleranceMs: 30_000,
    unit: 'per-sec',
    what: 'Sort operations ran out of the memory they are allowed and had to write to disk to finish, which is far slower and competes with everything else for the same storage.',
    check:
      'A sort spills when there is no index that already provides the order asked for, so the ' +
      'server has to read everything and sort it. Find the queries with a sort stage in the ' +
      'profiler and check whether an index covering the sort would let them stream instead.',
  },

  {
    id: 'sorts-spilling-burst',
    title: 'A burst of sorts spilled to disk at once',
    // Same severity as the sustained rule above rather than higher. A burst this violent tends
    // to take something else down with it -- in the capture below the node stopped reporting
    // FTDC entirely -- but that consequence has its own critical rule, and raising this one
    // would report the same episode as critical twice.
    severity: 'warning',
    metric: 'rate(serverStatus.metrics.query.sort.spillToDisk)',
    op: '>=',
    // A hundred a second: a hundred sorts, each of which exceeded the 100 MB a sort is allowed,
    // finishing in the same second. That is not the "occasional heavy query" the sustained rule
    // above deliberately tolerates, whatever it does for the next thirty seconds.
    //
    // The pair exists because the sustained rule asks "is this happening consistently" and
    // answers no to something that matters. Measured against a capture with a known timeline,
    // an injected sort spill peaked at 4,701/s and was over in 8 seconds -- three times the
    // peak of an index build that did trip the sustained rule, and invisible to it.
    threshold: 100,
    // Five seconds, and the margin is not close. Across three healthy stretches of that same
    // run -- 7,983 samples per node, two hours of real load between the injected windows --
    // this metric was flat zero on all three members: not "low", zero, with no run above 1/s
    // lasting a single second. The floor being zero is what lets the window be this short.
    sustainMs: 5_000,
    // No bridging, like the exhausted-ticket rules: what is being claimed is a real contiguous
    // burst, and stitching scattered spikes into one would invent it.
    toleranceMs: 0,
    unit: 'per-sec',
    what: 'A large number of sort operations exceeded the memory they are allowed at the same moment and all wrote to disk at once, competing with each other and with everything else for the same storage.',
    check:
      'Look for what ran at that exact moment rather than for a standing problem: a report, a ' +
      'migration, or a scheduled job that sorts a whole collection. The fix is the same as for ' +
      'a steady spill — an index providing the order asked for — but the query to find is the ' +
      'one that ran once, so the profiler window has to cover those seconds.',
  },
];
