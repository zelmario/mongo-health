/**
 * Findings that are events rather than conditions.
 *
 * The rule engine asks whether something HELD -- above a threshold, for long enough. These
 * three ask whether something HAPPENED, which no sustain can express: a gap in the capture, an
 * election, a counter that only moves when something has gone wrong. All of them are one or two
 * samples wide and would be invisible to any rule honest enough to require persistence.
 *
 * Extracted from the collector's runner so they can be tested. They read only what is passed
 * in, which is the whole reason this file exists: as module-level code reaching for a global
 * they had no test at all, and they are the part of the pipeline most likely to be wrong in a
 * way nobody notices -- an election that is not reported is silence, and silence is what a
 * healthy cluster looks like.
 */
import type { Finding } from './detect.js';

/** What these detectors need from a node. A structural subset of the runner's own summary. */
export interface NodeEvents {
  node: string;
  hostname?: string;
  gaps: Array<{ fromMs: number; toMs: number; seconds: number; missingSamples: number }>;
  elections: Array<{ atMs: number; term: number }>;
  alarms: Array<{ path: string; atMs: number; by: number }>;
  /** Settings that stepped. Optional: a summary written before this existed simply has none. */
  changes?: Array<{ path: string; atMs: number; from: number; to: number }>;
  /** Per-metric percentiles for the analysed window, used to compare members against peers. */
  percentiles?: Array<{ metric: string; p50: number; p95: number; max: number }>;
  fromMs?: number;
  toMs?: number;
}

/**
 * Counters that only move when something has gone wrong.
 *
 * The other half of the rule set asks "is this number too high". These ask nothing: they sit at
 * zero on a healthy server for its entire life, and a single increment is the finding. There is
 * no threshold to calibrate and none to argue about, which is what makes them worth having --
 * they are the only checks here that cannot be miscalibrated.
 *
 * Choosing them is the whole job, and most candidates fail it. FTDC carries 379 paths whose name
 * contains "failed" or "killed", and nearly all are ordinary: `commands.find.failed` increments
 * every time a client sends a malformed query, and alerting on it would mean alerting on
 * somebody's typo. What survives is the short list where an increment has no benign reading.
 *
 * Verified against the real capture: all of these held at zero across 56,000 samples on three
 * members. `repl.initialSync.failedAttempts` is the interesting case -- it sat at 1 for the
 * whole capture, from an attempt that failed before the capture began. Reporting the LEVEL
 * would have announced an old event on every run forever; reporting only increments says
 * nothing, which is right, and would still catch the next one.
 */
export const ALARM_COUNTERS: Array<{
  path: string;
  title: string;
  severity: 'critical' | 'warning';
  what: string;
  check: string;
}> = [
  {
    path: 'serverStatus.wiredTiger.checkpoint.total failed number of checkpoints',
    title: 'A checkpoint failed',
    severity: 'critical',
    what: 'WiredTiger could not complete a checkpoint. Until one succeeds, nothing since the last successful checkpoint is durable on this node.',
    check: 'The mongod log around this time, and free space on the data volume. A node that cannot checkpoint will also take longer and longer to start.',
  },
  {
    path: 'serverStatus.indexBuilds.failedDueToDataCorruption',
    title: 'An index build hit corrupt data',
    severity: 'critical',
    what: 'An index build stopped because it found data it could not read.',
    check: 'Run validate on the collection. This does not resolve itself and the affected node should not be trusted to serve reads until it is understood.',
  },
  {
    path: 'serverStatus.indexBuilds.killedDueToInsufficientDiskSpace',
    title: 'An index build ran out of disk',
    severity: 'critical',
    what: 'An index build was killed because the volume filled up.',
    check: 'Free space on the data volume, and whether the build was retried. An index that never finished building is an index the planner cannot use.',
  },
  {
    path: 'serverStatus.wiredTiger.session.table salvage failed calls',
    title: 'A salvage attempt failed',
    severity: 'critical',
    what: 'WiredTiger tried to salvage a table and could not. Salvage only runs when a table is already damaged.',
    check: 'The log for what preceded it. This is a restore-from-backup conversation, not a tuning one.',
  },
  {
    path: 'serverStatus.metrics.repl.initialSync.failedAttempts',
    title: 'An initial sync attempt failed',
    severity: 'warning',
    what: 'A member tried to rebuild itself from another and the attempt failed.',
    check: 'Whether a later attempt succeeded. Repeated failures leave the member out of the set for as long as they continue, and each attempt costs a full copy of the data.',
  },
  {
    path: 'serverStatus.wiredTiger.chunk-cache.number of times a read from storage failed',
    title: 'A read from storage failed',
    severity: 'warning',
    what: 'The storage layer returned an error to a read.',
    check: 'The volume, and the host log for I/O errors. Transient on cloud storage, but a rising count is a failing disk.',
  },
];

/**
 * Settings that are supposed to hold still, so that a step in one means somebody moved it.
 *
 * This is the finding class that only retention can produce, and it is the answer to the
 * question a DBA actually asks in an incident: *what changed?* Nobody else can answer it,
 * because answering it needs the before — and the before is what Atlas deletes.
 *
 * Chosen the same way the alarm counters were, and the choosing is again the whole job: a path
 * belongs here only if moving it is a decision somebody made. Measured across 272,703 samples
 * of a real M10, every one of these was exactly constant — identical minimum and maximum — so
 * a step is signal and not drift. The ticket pool is the counter-example and stays out: 8.0
 * resizes it continuously on its own, and it would report a change every few minutes.
 */
export const WATCHED_SETTINGS: Array<{
  path: string;
  title: string;
  unit: 'bytes' | 'count';
  /**
   * How much it has to move to count. Byte quantities take a fraction of the old value; counts
   * take a whole unit, because half a core and half a member do not exist.
   *
   * Not decoration. Without it the first run against a real host reported "memory went from
   * 15 GB to 15 GB" — a true step of 4,096 bytes on 15.4 GB, which is 0.000025% and is the
   * kernel's own accounting moving, not a resize. A finding whose text says nothing changed is
   * worse than no finding: it teaches the reader that this section is noise.
   *
   * Five per cent is four orders of magnitude above that drift and far below any real change:
   * Atlas tiers roughly double, and nobody resizes a cache by a twentieth.
   */
  minChange: { relative: number } | { absolute: number };
  what: (from: string, to: string) => string;
}> = [
  {
    path: 'systemMetrics.memory.MemTotal_kb',
    minChange: { relative: 0.05 },
    title: 'The host was resized',
    unit: 'bytes',
    what: (a, b) => `Memory on this host went from ${a} to ${b}. On Atlas that is a tier change; ` +
      'elsewhere it is a resize of the machine or the container.',
  },
  {
    path: 'systemMetrics.cpu.num_logical_cores',
    minChange: { absolute: 1 },
    title: 'The core count changed',
    unit: 'count',
    what: (a, b) => `The host went from ${a} to ${b} logical cores.`,
  },
  {
    path: 'serverStatus.wiredTiger.cache.maximum bytes configured',
    minChange: { relative: 0.05 },
    title: 'The cache was resized',
    unit: 'bytes',
    what: (a, b) => `The WiredTiger cache went from ${a} to ${b}. Everything the server keeps ` +
      'in memory is bounded by this, so a cut here changes how much of the working set fits.',
  },
  {
    path: 'local.oplog.rs.stats.storageStats.maxSize',
    minChange: { relative: 0.05 },
    title: 'The oplog was resized',
    unit: 'bytes',
    what: (a, b) => `The oplog cap went from ${a} to ${b}. This is how far behind a secondary ` +
      'may fall, and how far back a point-in-time restore can reach, so shrinking it shortens ' +
      'both.',
  },
  {
    path: 'replSetGetStatus.votingMembersCount',
    minChange: { absolute: 1 },
    title: 'The replica set membership changed',
    unit: 'count',
    what: (a, b) => `Voting members went from ${a} to ${b}, which changes what a majority is ` +
      'and therefore how many failures the set survives.',
  },
];

/**
 * Metrics where the members of a replica set should look alike, so that one which does not is
 * the finding.
 *
 * Every other check here compares a number against a threshold or against the cluster's own
 * past. This one compares the members against each other, and that is a different kind of
 * evidence: three machines running the same software on the same data under the same load are
 * their own control group, so there is no threshold to calibrate and none to argue about.
 *
 * The product has been giving this advice in prose for months — several rules end with "compare
 * against the other nodes of the same replica set; if only one is affected, look at its volume".
 * It was asking the reader to do what it had the data to do itself.
 *
 * Choosing the metrics is the whole job, and most fail. Measured across the stored baselines of
 * two real clusters, members differ enormously in anything driven by clients, because clients
 * talk to the primary: `queryExecutor.scanned` ran to **6,726x** between healthy members and
 * `document.returned` to 748x. Comparing those would report a healthy primary as broken on
 * every run. What survives is what the machine does rather than what the clients ask of it,
 * where the same measurement put healthy members within 1.03x-1.24x of each other.
 *
 * Each entry carries a floor in its own unit, because a ratio near zero is arithmetic rather
 * than evidence: one node checkpointing in 3 ms against peers at 1 ms is 3x and means nothing.
 */
export const PEER_METRICS: Array<{
  path: string;
  title: string;
  /** Which end is the sick one: the member above its peers, or the one below. */
  worse: 'high' | 'low';
  /** Below this the difference is not worth a sentence, whatever the ratio says. */
  floor: number;
  /**
   * Divide by this member's own value of another metric before comparing, when the raw number
   * only means something against a capacity that members may not share.
   *
   * Found by testing rather than by thinking: given one member a 1 GB cache and its peers
   * 256 MB, dirty bytes came out 76 MB against 20 MB — 3.5x, and a finding. As a share of each
   * member's own cache they were 7.4%, 7.6% and 8.4%: identical, and nothing to report. The
   * absolute comparison was measuring the configuration, not the behaviour.
   */
  relativeTo?: string;
  what: (ratio: string, value: string, peers: string) => string;
  check: string;
}> = [
  {
    path: 'serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)',
    title: 'One member checkpoints far slower than the others',
    worse: 'high',
    // A second. Below it the whole set is healthy and the ratio is noise.
    floor: 1000,
    what: (r, v, p) => `Checkpoints on this member take ${v}, ${r} what the other members of ` +
      `the same set take (${p}). They hold the same data and take the same writes, so the ` +
      'difference is the machine underneath rather than the workload.',
    check:
      'Its storage, before anything in MongoDB. The same replica set on the same instance ' +
      'type doing the same work should checkpoint alike; when one does not, it is usually a ' +
      'volume that is throttled, degraded, or a different type from its peers.',
  },
  {
    path: 'serverStatus.wiredTiger.cache.tracked dirty bytes in the cache',
    relativeTo: 'serverStatus.wiredTiger.cache.maximum bytes configured',
    title: 'One member is holding far more dirty cache than the others',
    worse: 'high',
    // A twentieth of its own cache. Below that eviction is keeping up whatever the ratio says,
    // and the figure is a share now rather than a size, so it means the same thing on a 256 MB
    // cache and on a 32 GB one.
    floor: 0.05,
    what: (r, v, p) => `This member is holding ${v} of its cache dirty, ${r} its peers (${p}). ` +
      'Dirty pages are writes that have not reached disk, so one member falling behind the ' +
      'others points at that member rather than at the workload.',
    check:
      'Whether its checkpoints are also slower, which would make this the symptom and the ' +
      'storage the cause. If they are not, look at what else runs on that host.',
  },
];

/**
 * Findings that come from the absence of data rather than its value.
 *
 * The rule engine tests thresholds over series; a gap is the series not being there. They are
 * different things, which is why this is not a rule: `detect()` deliberately breaks an episode
 * on a NaN, because a gap is not evidence that the condition continued across it -- and that
 * is right. But the gap itself is a signal, and if nobody picks it up it is lost.
 *
 * Two shapes are distinguished, because they have different causes:
 *
 *   - **Long outage** (>= 60 s): the node stopped reporting. A restart, a failover, or the
 *     whole host frozen. Usually explainable and sometimes expected.
 *   - **Repeated micro-stalls**: the node freezes for a few seconds, over and over. No panel
 *     shows this, because each break is too short to see, and it is exactly what a user
 *     describes as "it gets slow every so often".
 *
 * The threshold of 10 comes from the demo capture: across three nodes of one replica set, two
 * had 0 and 1 micro-stalls and the one that was suffering had around 60. There is no grey
 * band to split. It now counts within one incident rather than across the whole capture, which
 * is what "it gets slow every so often" always meant: ten stalls in a quarter of an hour is a
 * node in trouble, ten spread over five days is a node with a long life.
 */
/**
 * Split a node's gaps into separate incidents.
 *
 * Without this the detector reported one finding per node for the whole retained history, and
 * that made it blind in a way nobody would guess from reading it: a node that stopped
 * reporting today produced no new finding, because the same node had stopped reporting harder
 * four days earlier and the aggregate was already known. Measured on a five-day capture with
 * an injected 77-second freeze — the freeze is in the data, the outage was never reported, and
 * the longer the cluster had been watched the more certain that outcome became.
 *
 * A quarter of an hour of normal reporting between two gaps makes them two incidents. The
 * number is not new: it is the same window the report already uses to decide that two findings
 * belong to the same moment, and two detectors disagreeing about what "at the same time" means
 * would show up as an incident that splits or merges depending on which screen you read.
 */
const SAME_INCIDENT_MS = 15 * 60_000;

function byIncident<T extends { fromMs: number; toMs: number }>(gaps: T[]): T[][] {
  const out: T[][] = [];
  let current: T[] = [];
  for (const g of gaps) {
    if (current.length && g.fromMs - current[current.length - 1]!.toMs > SAME_INCIDENT_MS) {
      out.push(current);
      current = [];
    }
    current.push(g);
  }
  if (current.length) out.push(current);
  return out;
}

export function gapFindings(nodeSummaries: NodeEvents[]): Finding[] {
  const LONG_OUTAGE_MS = 60_000;
  const MIN_MICRO = 10;
  const out: Finding[] = [];

  for (const node of nodeSummaries) {
    const label = node.hostname ?? node.node;

    const base = {
      captureId: label,
      captureLabel: label,
      metric: '(FTDC sampling cadence)',
      unit: 'seconds' as Finding['unit'],
    };

    for (const incident of byIncident(node.gaps)) {
      const long = incident.filter((g) => g.seconds * 1000 >= LONG_OUTAGE_MS);
      const micro = incident.filter((g) => g.seconds * 1000 < LONG_OUTAGE_MS);

      if (long.length > 0) {
        const worst = long.reduce((a, b) => (b.seconds > a.seconds ? b : a));
        const total = long.reduce((s, g) => s + g.seconds, 0);
        out.push({
          ...base,
          ruleId: 'ftdc-long-outage',
          title: 'Node stopped reporting',
          severity: total >= 300 ? 'critical' : 'warning',
          episodes: long.length,
          firstMs: long[0]!.fromMs,
          lastMs: long[long.length - 1]!.toMs,
          worstFromMs: worst.fromMs,
          worstToMs: worst.toMs,
          totalMs: total * 1000,
          peak: worst.seconds,
          what:
            `The node stopped writing metrics ${long.length} time(s), ` +
            `${total} seconds in total and up to ${worst.seconds}s in a row.`,
          check:
            'Cross-check the mongod log for that window: a restart or an election explains it. ' +
            'If there is nothing, the host froze and the hypervisor or the volume is where to look.',
        });
      }

      if (micro.length >= MIN_MICRO) {
        const worst = micro.reduce((a, b) => (b.seconds > a.seconds ? b : a));
        const total = micro.reduce((s, g) => s + g.seconds, 0);
        out.push({
          ...base,
          ruleId: 'ftdc-micro-stalls',
          title: 'Repeated short stalls',
          severity: 'warning',
          episodes: micro.length,
          firstMs: micro[0]!.fromMs,
          lastMs: micro[micro.length - 1]!.toMs,
          worstFromMs: worst.fromMs,
          worstToMs: worst.toMs,
          totalMs: total * 1000,
          peak: worst.seconds,
          what:
            `${micro.length} short breaks in the sampling cadence, ${total} blind seconds in ` +
            'total. mongod stalled long enough that it could not write even its own metrics.',
          check:
            'Usually goes with long checkpoints or a saturated disk. Compare against the other ' +
            'nodes of the same replica set: if only one is affected, look at its volume.',
        });
      }
    }
  }
  return out;
}

/**
 * Elections, as findings.
 *
 * Separate from the rules for the same reason the gaps are: the rule engine asks whether a
 * condition HELD, and an election does not hold -- it happens. The whole event is one or two
 * samples wide, so any rule honest enough to require a sustain would be blind to it.
 *
 * What makes it worth reporting is that nobody sees it otherwise. A failover is a few seconds
 * with no primary and therefore no writes; the application logs a handful of errors and
 * recovers, and by the time anyone asks, the only surviving record is this counter. Being able
 * to answer "yes, at 04:12 on Tuesday, and it took eight seconds" is precisely the kind of
 * thing a customer cannot get from anywhere else once Atlas has dropped the raw data.
 *
 * Reported once per cluster rather than once per node: every member observes the same election
 * and three copies of one event is noise. The node reporting it is whichever saw it first.
 */
export function electionFindings(nodeSummaries: NodeEvents[]): Finding[] {
  // Members learn of a new term within a heartbeat of each other. Anything inside this window
  // is one election seen from several angles, not several elections.
  const SAME_EVENT_MS = 30_000;

  const seen: Array<{ atMs: number; term: number; label: string }> = [];
  for (const node of nodeSummaries) {
    const label = node.hostname ?? node.node;
    for (const e of node.elections) seen.push({ ...e, label });
  }
  if (seen.length === 0) return [];
  seen.sort((a, b) => a.atMs - b.atMs);

  const merged: Array<{ atMs: number; term: number; label: string }> = [];
  for (const e of seen) {
    const last = merged[merged.length - 1];
    if (last !== undefined && e.term === last.term && e.atMs - last.atMs <= SAME_EVENT_MS) continue;
    merged.push(e);
  }

  const first = merged[0]!;
  const last = merged[merged.length - 1]!;
  const plural = merged.length === 1 ? '' : 's';
  return [
    {
      captureId: first.label,
      captureLabel: first.label,
      ruleId: 'election-held',
      title: merged.length === 1 ? 'The replica set elected a new primary'
        : `The replica set elected a new primary ${merged.length} times`,
      // Informational on purpose. One election is normal -- a maintenance restart causes one,
      // and Atlas restarts members to patch them. What deserves attention is several in a
      // short window, and a reader can see that from the count without being alarmed by one.
      severity: merged.length > 2 ? 'warning' : 'info',
      metric: 'replSetGetStatus.term',
      unit: 'count',
      episodes: merged.length,
      firstMs: first.atMs,
      lastMs: last.atMs,
      worstFromMs: last.atMs,
      worstToMs: last.atMs,
      totalMs: 0,
      peak: last.term,
      what:
        `The set held ${merged.length} election${plural}, the last of them reaching term ` +
        `${last.term}. Writes stop for the duration of an election, so each one is a short ` +
        'window in which the application could not write.',
      check:
        'Look for a restart or a network interruption on the member that stepped down. One ' +
        'election around a maintenance window is expected; several without one means members ' +
        'are losing sight of each other, and that will keep happening.',
    },
  ];
}

/**
 * The alarm counters, as findings.
 *
 * Alongside the elections rather than among the rules, for the same reason: an increment is an
 * instant. The rule engine can only ask whether something held, and these do not hold -- they
 * happen once and the counter stays where it landed.
 *
 * Per node, not merged across the set. A failed checkpoint on one member says something about
 * that member's disk; the same count on all three says something about the deployment, and a
 * reader can tell those apart only if each is reported where it happened.
 */
export function alarmFindings(nodeSummaries: NodeEvents[]): Finding[] {
  const out: Finding[] = [];

  for (const node of nodeSummaries) {
    const label = node.hostname ?? node.node;
    for (const counter of ALARM_COUNTERS) {
      const hits = node.alarms.filter((a) => a.path === counter.path);
      if (hits.length === 0) continue;

      const total = hits.reduce((sum, h) => sum + h.by, 0);
      const first = hits[0]!;
      const last = hits[hits.length - 1]!;
      out.push({
        captureId: label,
        captureLabel: label,
        ruleId: `alarm:${counter.path}`,
        title: counter.title,
        severity: counter.severity,
        metric: counter.path,
        unit: 'count',
        episodes: hits.length,
        firstMs: first.atMs,
        lastMs: last.atMs,
        worstFromMs: last.atMs,
        worstToMs: last.atMs,
        // Zero: nothing here lasted, it happened. Reporting a duration would invent one.
        totalMs: 0,
        peak: total,
        what:
          `${counter.what} It happened ${total === 1 ? 'once' : `${total} times`} in this ` +
          'window.',
        check: counter.check,
      });
    }
  }

  return out;
}

/**
 * Settings that moved, as findings.
 *
 * Informational on purpose, and that is the design rather than a hedge. A resize is not a
 * fault: somebody chose it, often for a good reason, and alerting on choices is how a product
 * teaches people to ignore it. What earns its place is being *there*, in the same report as the
 * incident, so that "the cache was halved on the 14th" sits next to "eviction has been
 * stalling since the 14th" and the reader draws the line themselves.
 *
 * One finding per change rather than one per setting: two resizes a month apart are two
 * different decisions with two different consequences, and merging them would hide whichever
 * one matters.
 */
export function changeFindings(nodeSummaries: NodeEvents[]): Finding[] {
  const out: Finding[] = [];
  const byPath = new Map(WATCHED_SETTINGS.map((s) => [s.path, s]));

  for (const node of nodeSummaries) {
    const label = node.hostname ?? node.node;
    for (const change of node.changes ?? []) {
      const setting = byPath.get(change.path);
      if (setting === undefined) continue;
      const shown = (v: number) =>
        setting.unit === 'bytes' ? formatBytes(v) : String(Math.round(v));
      // Belt and braces over the numeric floor above: whatever the values, refuse to publish a
      // sentence that reads "from 15 GB to 15 GB". Rounding for humans can always collapse two
      // numbers that differ, and the reader sees the sentence, not the float.
      if (shown(change.from) === shown(change.to)) continue;
      out.push({
        captureId: label,
        captureLabel: label,
        ruleId: 'setting-changed',
        title: setting.title,
        severity: 'info',
        metric: change.path,
        unit: setting.unit === 'bytes' ? 'bytes' : 'count',
        episodes: 1,
        firstMs: change.atMs,
        lastMs: change.atMs,
        worstFromMs: change.atMs,
        worstToMs: change.atMs,
        totalMs: 0,
        peak: change.to,
        what: setting.what(shown(change.from), shown(change.to)),
        check:
          'Line this up with when the behaviour changed. If they are the same day, the change ' +
          'is the explanation and the fix is to put it back or to size for it; if they are not, ' +
          'this is one thing you can now rule out.',
      });
    }
  }
  return out;
}

/** Round numbers a reader recognises: an 8 GB cache should not print as 8589934592. */
function formatBytes(v: number): string {
  const units = [['GB', 1024 ** 3], ['MB', 1024 ** 2], ['kB', 1024]] as const;
  for (const [name, size] of units) {
    if (v >= size) {
      const n = v / size;
      return `${n >= 10 ? Math.round(n) : Math.round(n * 10) / 10} ${name}`;
    }
  }
  return `${Math.round(v)} bytes`;
}

/**
 * Members that do not look like their peers.
 *
 * Needs three: with two there is no majority to be unlike, and calling one of a pair the odd one
 * is a coin toss. The comparison is against the median of the others rather than their mean, so
 * a single sick member cannot drag the thing it is being judged against.
 */
export function peerFindings(nodeSummaries: NodeEvents[]): Finding[] {
  // Three times. Measured across the stored baselines of two real clusters: on the metrics
  // below, healthy members sat within 1.03x-1.24x of each other, and the widest gap anywhere in
  // the comparable set was 1.93x. Three is comfortably past anything a healthy set produced and
  // well short of the ratios a struggling member reaches.
  const RATIO = 3;
  const out: Finding[] = [];
  if (nodeSummaries.length < 3) return out;

  for (const setting of PEER_METRICS) {
    const readings: Array<{ node: NodeEvents; value: number }> = [];
    for (const node of nodeSummaries) {
      const find = (path: string) => (node.percentiles ?? []).find(
        (p) => p.metric.split(' (via')[0] === path);
      const row = find(setting.path);
      if (row === undefined || !Number.isFinite(row.p50)) continue;

      let value = row.p50;
      if (setting.relativeTo !== undefined) {
        const against = find(setting.relativeTo);
        // No capacity to divide by means no comparable number. Falling back to the raw value
        // would compare members' configuration and call it behaviour.
        if (against === undefined || !(against.p50 > 0)) continue;
        value = row.p50 / against.p50;
      }
      readings.push({ node, value });
    }
    if (readings.length < 3) continue;

    readings.sort((a, b) => a.value - b.value);
    const odd = setting.worse === 'high' ? readings[readings.length - 1]! : readings[0]!;
    const peers = readings.filter((r) => r !== odd);
    const peerMedian = peers[Math.floor(peers.length / 2)]!.value;

    if (odd.value < setting.floor) continue;
    if (peerMedian <= 0) continue;
    const ratio = setting.worse === 'high' ? odd.value / peerMedian : peerMedian / odd.value;
    if (ratio < RATIO) continue;

    const label = odd.node.hostname ?? odd.node.node;
    const shown = (v: number) => formatValue(setting.path, v,
                                             setting.relativeTo !== undefined);
    out.push({
      captureId: label,
      captureLabel: label,
      ruleId: 'peer-outlier',
      title: setting.title,
      // A warning, never critical. What this reports is a difference, and the member may be
      // perfectly able to serve its share -- what it has stopped being is interchangeable with
      // the others, which is a thing to look at rather than to be woken for.
      severity: 'warning',
      metric: setting.path,
      unit: 'count',
      episodes: 1,
      firstMs: odd.node.fromMs ?? 0,
      lastMs: odd.node.toMs ?? 0,
      worstFromMs: odd.node.fromMs ?? 0,
      worstToMs: odd.node.toMs ?? 0,
      totalMs: 0,
      peak: Math.round(ratio * 100) / 100,
      what: setting.what(`${ratio.toFixed(1)}x`, shown(odd.value), shown(peerMedian)),
      check: setting.check,
    });
  }
  return out;
}

/** Milliseconds as a duration, bytes as bytes, and anything else as itself. */
function formatValue(path: string, v: number, relative = false): string {
  if (relative) return `${(v * 100).toFixed(1)}%`;
  if (path.includes('(msecs)')) {
    return v >= 1000 ? `${(v / 1000).toFixed(1)} s` : `${Math.round(v)} ms`;
  }
  if (path.includes('bytes')) return formatBytes(v);
  return String(Math.round(v));
}
