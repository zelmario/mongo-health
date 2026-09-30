/**
 * Cross-version metric aliases.
 *
 * MongoDB renames and relocates metrics between releases. A dashboard pinned to one
 * release's names silently resolves nothing on another -- the panel is simply empty, with no
 * error to follow. Aliases let one logical metric name resolve to whichever path the capture
 * in front of you actually has.
 *
 * Entries are keyed by the name the dashboard templates use, with alternatives tried in
 * order. Every entry should be justified by an observed capture, not by reading release
 * notes: run `npm run catalogs` to diff real captures across the version matrix produced by
 * tools/fixtures/versions.sh.
 *
 * The current table was derived from FTDC captured off a live mongod of every release from
 * 4.0.28 through 8.0.4 -- 4.0, 4.2, 4.4, 5.0, 6.0, 7.0, 8.0 -- each running the same mixed
 * write/read/collscan load so that a metric missing from one catalogue means it was renamed,
 * not that it was idle. Catalogue size grows from 1530 keys on 4.0 to 4965 on 8.0.
 *
 * Two things this table deliberately does NOT cover:
 *
 *   - Metrics that simply did not exist yet. `serverStatus.flowControl` arrives in 4.2 and
 *     `serverStatus.queues.ingress` in 8.0; there is no older path to alias them to, so a
 *     rule that needs them is inapplicable to earlier releases rather than broken on them.
 *   - Sections that are enumerations rather than fixed shapes -- `metrics.commands.*` gains
 *     and loses entries every release. Aliasing those would be chasing the command list.
 */

export const METRIC_ALIASES: Readonly<Record<string, readonly string[]>> = {
  // Concurrency tickets moved out of the WiredTiger section in 8.0, when the execution
  // control queues became engine-independent. This is the single most important panel in a
  // saturation investigation, so losing it silently is the worst case. Verified identical
  // from 4.0 through 7.0, renamed only in 8.0.
  'serverStatus.wiredTiger.concurrentTransactions.read.available': [
    'serverStatus.queues.execution.read.available',
  ],
  'serverStatus.wiredTiger.concurrentTransactions.write.available': [
    'serverStatus.queues.execution.write.available',
  ],
  'serverStatus.wiredTiger.concurrentTransactions.read.out': [
    'serverStatus.queues.execution.read.out',
  ],
  'serverStatus.wiredTiger.concurrentTransactions.write.out': [
    'serverStatus.queues.execution.write.out',
  ],
  'serverStatus.wiredTiger.concurrentTransactions.read.totalTickets': [
    'serverStatus.queues.execution.read.totalTickets',
  ],
  'serverStatus.wiredTiger.concurrentTransactions.write.totalTickets': [
    'serverStatus.queues.execution.write.totalTickets',
  ],

  // The adaptive sizer's own counters, which are how you tell "the pool grew to meet demand"
  // from "the pool is pinned and everything is queued". Same 8.0 relocation as above.
  'serverStatus.wiredTiger.concurrentTransactions.monitor.timesDecreased': [
    'serverStatus.queues.execution.monitor.timesDecreased',
  ],
  'serverStatus.wiredTiger.concurrentTransactions.monitor.timesIncreased': [
    'serverStatus.queues.execution.monitor.timesIncreased',
  ],
  'serverStatus.wiredTiger.concurrentTransactions.monitor.totalAmountDecreased': [
    'serverStatus.queues.execution.monitor.totalAmountDecreased',
  ],
  'serverStatus.wiredTiger.concurrentTransactions.monitor.totalAmountIncreased': [
    'serverStatus.queues.execution.monitor.totalAmountIncreased',
  ],

  // The oplog's collStats moved under a `storageStats` sub-document in 7.0. Observed across
  // the whole matrix: 4.0, 4.2, 4.4, 5.0 and 6.0 report the flat form (255 keys on 6.0), 7.0
  // and 8.0 the nested one (302 keys on 7.0). The Big-hole dashboard was written against the
  // flat form, so that is the template name and the nested one is the alternative. Without
  // these, "Storage Size" and "avg Obj Size" -- the panels that answer "how much oplog window
  // is left" -- silently vanish on one side or the other of the 7.0 boundary.
  'local.oplog.rs.stats.storageSize': ['local.oplog.rs.stats.storageStats.storageSize'],
  'local.oplog.rs.stats.freeStorageSize': [
    'local.oplog.rs.stats.storageStats.freeStorageSize',
  ],
  'local.oplog.rs.stats.avgObjSize': ['local.oplog.rs.stats.storageStats.avgObjSize'],
  'local.oplog.rs.stats.size': ['local.oplog.rs.stats.storageStats.size'],
  'local.oplog.rs.stats.count': ['local.oplog.rs.stats.storageStats.count'],
  'local.oplog.rs.stats.maxSize': ['local.oplog.rs.stats.storageStats.maxSize'],

  // Checkpoint timings left the WiredTiger `transaction` section for their own `checkpoint`
  // section in 8.0, dropping the redundant "transaction checkpoint" prefix from every leaf.
  // These matter: a checkpoint that suddenly takes tens of seconds is a classic cause of the
  // stalls that show up as flat-lined throughput, and it is invisible if the path resolves
  // to nothing.
  'serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)': [
    'serverStatus.wiredTiger.checkpoint.most recent time (msecs)',
  ],
  'serverStatus.wiredTiger.transaction.transaction checkpoint max time (msecs)': [
    'serverStatus.wiredTiger.checkpoint.max time (msecs)',
  ],
  'serverStatus.wiredTiger.transaction.transaction checkpoint min time (msecs)': [
    'serverStatus.wiredTiger.checkpoint.min time (msecs)',
  ],
  'serverStatus.wiredTiger.transaction.transaction checkpoint total time (msecs)': [
    'serverStatus.wiredTiger.checkpoint.total time (msecs)',
  ],
  'serverStatus.wiredTiger.transaction.transaction checkpoint generation': [
    'serverStatus.wiredTiger.checkpoint.generation',
  ],
  // Note there is no alias for the plain `transaction checkpoints` counter: 8.0 does not
  // report a single total, only per-cause counters (`started by api`, `started by
  // compaction`, ...). `generation` above is the counter that increments once per
  // checkpoint on both sides, so it is the one to build a rule on.

  // Index build progress was renamed in 7.0 -- `activeIndexBuilds` to `indexBuilds` -- with
  // the seven phase counters unchanged underneath. A build that sits in one phase is the
  // explanation for a lot of otherwise unexplained load.
  'serverStatus.activeIndexBuilds.phases.scanCollection': [
    'serverStatus.indexBuilds.phases.scanCollection',
  ],
  'serverStatus.activeIndexBuilds.phases.drainSideWritesTable': [
    'serverStatus.indexBuilds.phases.drainSideWritesTable',
  ],
  'serverStatus.activeIndexBuilds.phases.drainSideWritesTablePreCommit': [
    'serverStatus.indexBuilds.phases.drainSideWritesTablePreCommit',
  ],
  'serverStatus.activeIndexBuilds.phases.drainSideWritesTableOnCommit': [
    'serverStatus.indexBuilds.phases.drainSideWritesTableOnCommit',
  ],
  'serverStatus.activeIndexBuilds.phases.waitForCommitQuorum': [
    'serverStatus.indexBuilds.phases.waitForCommitQuorum',
  ],
  'serverStatus.activeIndexBuilds.phases.commit': ['serverStatus.indexBuilds.phases.commit'],

  // 8.0 split the replication pipeline in two -- the fetcher now fills a *write* buffer, the
  // oplog writer drains it into an *apply* buffer -- so the single pre-8.0 buffer has two
  // successors. `write` is the alias because it occupies the same position in the chain: the
  // first place incoming oplog piles up when the node cannot keep up. Note this is a
  // positional equivalence, not an identity; on 8.0 a backlog can also sit in `apply`, so a
  // rule that wants "total unapplied oplog" has to add both rather than rely on this alias.
  'serverStatus.metrics.repl.buffer.sizeBytes': [
    'serverStatus.metrics.repl.buffer.write.sizeBytes',
  ],
  'serverStatus.metrics.repl.buffer.maxSizeBytes': [
    'serverStatus.metrics.repl.buffer.write.maxSizeBytes',
  ],
  'serverStatus.metrics.repl.buffer.count': ['serverStatus.metrics.repl.buffer.write.count'],

  // 5.0 moved the read-concern counters under a `nonTransactionOps` sub-document, alongside
  // a new `transactionOps` sibling.
  'serverStatus.opReadConcernCounters.available': [
    'serverStatus.readConcernCounters.nonTransactionOps.available',
  ],
  'serverStatus.opReadConcernCounters.linearizable': [
    'serverStatus.readConcernCounters.nonTransactionOps.linearizable',
  ],
  'serverStatus.opReadConcernCounters.local': [
    'serverStatus.readConcernCounters.nonTransactionOps.local',
  ],
  'serverStatus.opReadConcernCounters.majority': [
    'serverStatus.readConcernCounters.nonTransactionOps.majority',
  ],
  // `snapshot` has no alias on purpose: 5.0 split it into `snapshot.withClusterTime` and
  // `snapshot.withoutClusterTime`, so the old single counter has two successors and any
  // mapping would silently under-report. A rule that wants it must add both.
  'serverStatus.opReadConcernCounters.none': [
    'serverStatus.readConcernCounters.nonTransactionOps.none',
  ],

  // The fixed-size service executor became the inline one in 8.0. Same four counters; it is
  // how you see connection threads piling up.
  'serverStatus.network.serviceExecutors.fixed.threadsRunning': [
    'serverStatus.network.serviceExecutors.inline.threadsRunning',
  ],
  'serverStatus.network.serviceExecutors.fixed.clientsInTotal': [
    'serverStatus.network.serviceExecutors.inline.clientsInTotal',
  ],
  'serverStatus.network.serviceExecutors.fixed.clientsRunning': [
    'serverStatus.network.serviceExecutors.inline.clientsRunning',
  ],
  'serverStatus.network.serviceExecutors.fixed.clientsWaitingForData': [
    'serverStatus.network.serviceExecutors.inline.clientsWaitingForData',
  ],
  // Eviction done by the application's own threads moved from `thread-yield` to `cache` in
  // 8.0. The metric is the same one and it exists in every release from 4.0 -- verified
  // against a live mongod of each -- but a rule written with the 8.0 path resolves to nothing
  // on 7.0 and simply never fires, which is exactly the silent failure this table exists for.
  //
  // Found by running the advisor against a real 7.0.39 replica set: `eviction-by-app-threads`
  // reported as unresolved, and it was the only rule that did.
  'serverStatus.wiredTiger.thread-yield.application thread time evicting (usecs)': [
    'serverStatus.wiredTiger.cache.application thread time evicting (usecs)',
  ],
};

/**
 * Candidate expressions for a template metric, most-preferred first.
 *
 * Substitutes aliases one path at a time. Expressions reference at most a handful of paths
 * and each has at most a couple of alternatives, so the product stays tiny -- but it is
 * capped anyway so a future table cannot turn this into a combinatorial surprise.
 */
export function aliasCandidates(expression: string, paths: readonly string[]): string[] {
  let candidates = [expression];

  for (const path of paths) {
    const alternatives = METRIC_ALIASES[path];
    if (alternatives === undefined || alternatives.length === 0) continue;

    const next: string[] = [];
    for (const candidate of candidates) {
      next.push(candidate);
      for (const alternative of alternatives) {
        next.push(candidate.split(path).join(alternative));
      }
    }
    candidates = next;
    if (candidates.length > 64) break;
  }

  return [...new Set(candidates)];
}
