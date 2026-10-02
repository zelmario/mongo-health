/**
 * The collector's analysis engine: decode one captured cluster and emit JSON.
 *
 * It leans on Big Hole on purpose. The decoder, the alias table and the rules live in one
 * place; if the collector had its own, every new rule would have to be written twice and the
 * two copies would drift apart. It goes further than reusing the decoder: captures are built
 * with the same CaptureWriter/CaptureReader the app uses, so what the cron detects here is
 * exactly what someone opening the capture by hand would see.
 *
 * Belongs in Big Hole's `tools/`, invoked from `analyze.py`:
 *
 *   npx vite-node tools/analyze.ts -- <cluster-dir> [--since ISO] [--daily DIR]
 *
 * `<cluster-dir>` is `data/{cluster}/ftdc`, with one subdirectory per node.
 *
 * `--daily` is what keeps a run's cost flat as the history grows: see `src/data/daily.ts`.
 * With it, a run decodes only the last two days and reads the whole-history percentiles from
 * per-day summaries. Without it, everything held is decoded, which is what the calibration
 * tools want and what every run did before.
 * Everything on stdout is a single JSON document; messages for humans go to stderr.
 *
 * It emits three things, each mattering for its own reason:
 *
 *   findings     what the rules caught -- this is what gets sent to the customer
 *   percentiles  the per-metric baseline, which must be recorded from the FIRST capture
 *                because it cannot be reconstructed: once Atlas drops the raw data, this is
 *                all that is left to say "that is unusual for this cluster"
 *   gaps         breaks in the sampling cadence, which mean mongod stalled
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync,
         unlinkSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { decodeFTDC, readMetadata } from '../src/ftdc/index.js';
import { NodeFileStore } from '../src/data/nodeFileStore.js';
import { CaptureWriter } from '../src/data/writer.js';
import { CaptureReader } from '../src/data/reader.js';
import { detectRolePrefixes, expandMetric } from '../src/dashboard/layout.js';
import { detect, type DetectCapture, type Finding } from '../src/insights/detect.js';
import { RULES } from '../src/insights/rules.js';
import { ALARM_COUNTERS, WATCHED_SETTINGS, alarmFindings, changeFindings,
         electionFindings, gapFindings, peerFindings, restartFindings, versionFindings }
  from '../src/insights/events.js';
import type { SeriesQuery } from '../src/data/reader.js';
import { parseExpr, unitOf, unitOfPath } from '../src/data/expr.js';
import { cadenceAwareRate } from '../src/data/cadence.js';
import { DAILY_FORMAT, DAY_MS, Histogram, dayChart, dayName, dayStart, mergeCharts,
         type DayChart, type DaySummary, type Quantiles } from '../src/data/daily.js';

/* ------------------------------------------------------------------- arguments ---- */

const argv = process.argv.slice(2);
const root = argv.find((a) => !a.startsWith('--'));
if (root === undefined) {
  console.error('usage: vite-node tools/analyze.ts -- <cluster-dir> [--since ISO] [--until ISO]');
  process.exit(1);
}
const sinceMs = argv.includes('--since') ? Date.parse(argv[argv.indexOf('--since') + 1]!) : 0;
// Upper bound for the judged window. Only calibration passes it: production always wants
// "everything since the last run". Without it a window is open-ended, which makes it
// impossible to grade a stretch of the past without dragging in everything that came after.
const untilMs = argv.includes('--until') ? Date.parse(argv[argv.indexOf('--until') + 1]!) : 0;
// Never with `--until`: a calibration pass judges a stretch of the past, and writing summaries
// of it would overwrite days a production run had summarised with more data.
const dailyDir = argv.includes('--daily') && untilMs === 0
  ? argv[argv.indexOf('--daily') + 1]! : undefined;
// Where to write how far the decode has got, for the page's progress bar. Separate from stdout,
// which is the result and nothing else.
const progressPath = argv.includes('--progress')
  ? argv[argv.indexOf('--progress') + 1]! : undefined;

/* --------------------------------------------------------------------- metrics ---- */

/**
 * The series a baseline is kept for.
 *
 * Not all of them: storing percentiles for all 5,700 on every run would be expensive and the
 * vast majority never move. These are the ones the rules use or that describe node health,
 * and they are what "that is unusual for this cluster" gets measured against.
 *
 * Each is named with the oldest path that exists: the alias table maps them forward, so one
 * entry resolves from 4.0 to 8.0 and a cluster's history survives the customer upgrading.
 *
 * **Counters are wrapped in rate() and gauges are not**, and getting this wrong quietly ruins
 * the baseline. `opcounters.query` only ever increases, so its percentiles climb forever and
 * every window looks higher than the last -- an anomaly detector fed that would report growth
 * on every run of every cluster, permanently. What is comparable across time is the *rate*.
 * A gauge like `connections.current` is already a level and rate() would turn it into noise.
 */
const GAUGES = [
  'serverStatus.wiredTiger.concurrentTransactions.read.out',
  'serverStatus.wiredTiger.concurrentTransactions.read.totalTickets',
  'serverStatus.wiredTiger.concurrentTransactions.write.out',
  'serverStatus.wiredTiger.concurrentTransactions.write.totalTickets',
  'serverStatus.wiredTiger.cache.bytes currently in the cache',
  'serverStatus.wiredTiger.cache.tracked dirty bytes in the cache',
  'serverStatus.wiredTiger.cache.maximum bytes configured',
  'serverStatus.globalLock.currentQueue.readers',
  'serverStatus.globalLock.currentQueue.writers',
  'serverStatus.connections.current',
  'serverStatus.connections.available',
  // A checkpoint going from milliseconds to tens of seconds explains a good share of the
  // stalls a customer experiences as "it all went down for a while". 8.0 moved this.
  //
  // `most recent time` only -- NOT `max time`, which is a high-water mark that never comes
  // back down. Its percentiles can only ever rise, so comparing it against its own past
  // reports growth forever, exactly like a raw counter would.
  'serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)',
  // The replication buffer: if it grows, the secondary is receiving more than it applies.
  'serverStatus.metrics.repl.buffer.sizeBytes',
  'systemMetrics.memory.MemAvailable_kb',
  // Capacity, not load. These barely move, and percentiles of a constant are wasteful -- but
  // they are what turns a level into a fraction. Without the total, "3.2 GB free" says nothing
  // about whether the host is oversized, and that judgement has to survive in the baseline
  // long after the raw FTDC is gone.
  'systemMetrics.memory.MemTotal_kb',
  'systemMetrics.cpu.num_logical_cores',
];

const COUNTERS = [
  'serverStatus.opcounters.query',
  'serverStatus.opcounters.insert',
  'serverStatus.opcounters.update',
  'serverStatus.opcounters.delete',
  'serverStatus.opcounters.command',
  'serverStatus.metrics.document.returned',
  'serverStatus.metrics.queryExecutor.scanned',
  'serverStatus.metrics.queryExecutor.scannedObjects',
  'serverStatus.flowControl.isLaggedTimeMicros',
  'systemMetrics.cpu.user_ms',
  // Kernel time counts as used just as much as user time: a server busy in the network stack
  // is a busy server. Sizing advice that ignored it would recommend shrinking a host that is
  // already at its limit.
  'systemMetrics.cpu.system_ms',
  'systemMetrics.cpu.iowait_ms',
];

/**
 * Baselined metrics that are neither a gauge nor a counter, but a ratio of two rates.
 *
 * Average command latency exists nowhere in FTDC: both halves are cumulative totals, and only
 * their rates divided say how long a command is taking *now*. It is baselined rather than only
 * ruled on because the absolute number does not carry the finding. Measured on this cluster
 * with the pathology run alone against an otherwise idle server:
 *
 *   at rest        median 54us, p95 123us, p99 180us
 *   during a DDL   median 545us, p95 4,951us      -- 10x and 40x its own normal
 *
 * Half a millisecond a command is unremarkable anywhere; on THIS cluster it is ten times
 * normal, and no absolute threshold can say that. It is also the shape a blocking DDL has --
 * short total pauses that a rule wanting sixty sustained seconds will never admit happened.
 *
 * The rate-correction below deliberately skips these: it matches `rate(x)` at the top level,
 * and for a ratio of two rates sampled on the same clock the cadence factor cancels out, so
 * correcting one half and not the other is the only way to get it wrong.
 */
const DERIVED: Array<{ name: string; expr: string }> = [
  {
    name: 'us per command',
    expr: 'div(rate(serverStatus.opLatencies.commands.latency), rate(serverStatus.opLatencies.commands.ops))',
  },
];

/** Canonical name -> the expression to evaluate for it. */
const TRACKED: Array<{ name: string; expr: string }> = [
  ...GAUGES.map((m) => ({ name: m, expr: m })),
  ...COUNTERS.map((m) => ({ name: `rate(${m})`, expr: `rate(${m})` })),
  ...DERIVED,
  // The disk holding the data, under one name on every member whatever it is mounted as, so
  // the baseline and capacity-runway can follow it. See dataMount().
  { name: 'disk.data.available', expr: '{dataMount}.available' },
  { name: 'disk.data.capacity', expr: '{dataMount}.capacity' },
];

/**
 * The mount holding this member's data, as the `systemMetrics.mounts.<path>` prefix of its
 * metrics: the longest mount path that is a prefix of the dbPath in the FTDC metadata.
 *
 * Every mount is reported, and most are not the data's: /dev/shm, /run, the read-only mounts of
 * WSL or a container. Some of those sit at 0% free by design, so watching all of them would
 * raise a disk alarm on every healthy host. Without a dbPath in the metadata it falls back to
 * MongoDB's default, /data/db -- which on most hosts resolves to the root mount.
 */
/**
 * The part of a member's configuration the recommendations judge, read from the metadata
 * mongod writes at the top of every FTDC file. Nothing here needs a connection.
 *
 * Every field is optional: older servers do not report THP, an operating system without
 * /proc/mounts reports no filesystem, and a check whose input is absent must stay silent
 * rather than guess.
 */
interface NodeConfig {
  version?: string;
  hostname?: string;
  replSet?: string;
  memMB?: number;
  cores?: number;
  cacheSizeGB?: number;
  fdSoft?: number;
  allocator?: string;
  thpEnabled?: string;
  thpDefrag?: string;
  thpMaxPtesNone?: number;
  overcommit?: number;
  rseqPresent?: boolean;
  rseqDisabled?: boolean;
  auth?: string;
  /** A keyFile or x509 between members turns authorization on by itself. */
  internalAuth?: boolean;
  bindIp?: string;
  bindIpAll?: boolean;
  tlsMode?: string;
  writeConcernW?: string | number;
  writeConcernSource?: string;
  dbPath?: string;
  dataFs?: string;
  dataMountPoint?: string;
}

function configOf(doc: any): NodeConfig {
  const parsed = doc?.getCmdLineOpts?.parsed ?? {};
  const sys = doc?.hostInfo?.system ?? {};
  const extra = doc?.hostInfo?.extra ?? {};
  const dbPath: string = parsed.storage?.dbPath ?? '/data/db';
  // The filesystem under the data, by the same longest-prefix rule `dataMount` uses for the
  // metrics. On WSL the root mount is not listed at all, and then there is no answer.
  let mount: { mountPoint: string; type: string } | undefined;
  for (const m of (extra.mountInfo ?? []) as Array<{ mountPoint?: string; type: string }>) {
    // Atlas lists entries with no mount point at all; one of them used to throw here and
    // take the whole configuration with it.
    const p = m.mountPoint;
    if (typeof p !== 'string') continue;
    const covers = p === '/' || dbPath === p || dbPath.startsWith(p.endsWith('/') ? p : `${p}/`);
    if (covers && (mount === undefined || p.length > mount.mountPoint.length)) {
      mount = { mountPoint: p, type: m.type };
    }
  }
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
  const out: NodeConfig = {
    version: doc?.buildInfo?.version,
    hostname: sys.hostname,
    replSet: parsed.replication?.replSetName ?? parsed.replication?.replSet,
    memMB: num(sys.memLimitMB) ?? num(sys.memSizeMB),
    cores: num(sys.numCoresAvailableToProcess) ?? num(sys.numCores),
    cacheSizeGB: num(parsed.storage?.wiredTiger?.engineConfig?.cacheSizeGB),
    fdSoft: num(doc?.ulimits?.fileDescriptors?.soft),
    allocator: doc?.buildInfo?.allocator,
    thpEnabled: extra.thp_enabled,
    thpDefrag: extra.thp_defrag,
    // The kernel's files hold text; mongod passes them on as strings.
    thpMaxPtesNone: extra.thp_max_ptes_none !== undefined ? Number(extra.thp_max_ptes_none) : undefined,
    overcommit: extra.overcommit_memory !== undefined ? Number(extra.overcommit_memory) : undefined,
    rseqPresent: typeof extra.glibc_rseq_present === 'boolean' ? extra.glibc_rseq_present : undefined,
    rseqDisabled: typeof extra.glibc_pthread_rseq_disabled === 'boolean'
      ? extra.glibc_pthread_rseq_disabled : undefined,
    auth: parsed.security?.authorization,
    internalAuth: parsed.security?.keyFile || parsed.security?.clusterAuthMode === 'x509'
      ? true : undefined,
    bindIp: parsed.net?.bindIp,
    bindIpAll: parsed.net?.bindIpAll === true ? true : undefined,
    tlsMode: parsed.net?.tls?.mode ?? parsed.net?.ssl?.mode,
    writeConcernW: doc?.getDefaultRWConcern?.defaultWriteConcern?.w,
    writeConcernSource: doc?.getDefaultRWConcern?.defaultWriteConcernSource,
    dbPath,
    dataFs: mount?.type,
    dataMountPoint: mount?.mountPoint,
  };
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined)) as NodeConfig;
}

function dataMount(paths: ReadonlySet<string>, dbPath: string | undefined): string | undefined {
  const target = dbPath ?? '/data/db';
  let best: string | undefined;
  for (const p of paths) {
    const m = /^(.*systemMetrics\.mounts\.)(.+)\.available$/.exec(p);
    if (!m) continue;
    const mountPath = m[2]!;
    const prefix = mountPath.endsWith('/') ? mountPath : `${mountPath}/`;
    if (target !== mountPath && !target.startsWith(prefix)) continue;
    if (best === undefined || mountPath.length > best.length) best = mountPath;
  }
  return best === undefined ? undefined : `systemMetrics.mounts.${best}`;
}

/** An expression with `{dataMount}` replaced by this member's data mount, or one that resolves
 * to nothing when the member has none. */
function withDataMount(expr: string, mount: string | undefined): string {
  if (!expr.includes('{dataMount}')) return expr;
  return mount === undefined ? '' : expr.split('{dataMount}').join(mount);
}

/** Per capture, the data mount found for it. */
const dataMounts = new Map<string, string | undefined>();

/**
 * The subset drawn as charts in the profile report.
 *
 * Percentiles tell you what a cluster is like; a chart tells you what it *did*, and that is
 * what makes a reader believe there is real data behind the numbers. Kept small on purpose --
 * every series here is carried in the output JSON and then embedded in an HTML report, so
 * this is the difference between a report that opens instantly and one that does not.
 */
const CHARTED = [
  'rate(serverStatus.opcounters.query)',
  'rate(serverStatus.opcounters.insert)',
  'rate(serverStatus.opcounters.update)',
  'serverStatus.wiredTiger.concurrentTransactions.read.out',
  'serverStatus.wiredTiger.cache.bytes currently in the cache',
  'serverStatus.connections.current',
  'serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)',
  // Two series for one row: the profile's "documents read per document returned" is a ratio,
  // and a ratio has to be divided out second by second to be drawn. Without both stored, that
  // row was the only one in the table with an empty space where every other row had a shape --
  // which reads as a chart that failed, not as a row that never had one.
  'rate(serverStatus.metrics.queryExecutor.scannedObjects)',
  'rate(serverStatus.metrics.document.returned)',
];

/** Points per charted series. Enough shape for a report-sized figure, small enough to embed. */
const CHART_WIDTH = 300;

/**
 * Legend names for chart entries that are expressions rather than metric paths.
 *
 * The legend takes the last dotted component of a path, which reads well for
 * "totalTickets" and produces "ops))" for `div(rate(a.latency), rate(a.ops))`.
 */
const DISPLAY_LABELS: Record<string, string> = {
  'div(rate(serverStatus.opLatencies.commands.latency), rate(serverStatus.opLatencies.commands.ops))':
    'per command',
  'div(rate(serverStatus.opLatencies.reads.latency), rate(serverStatus.opLatencies.reads.ops))':
    'per read',
};

/**
 * Rules where the GAP between the two lines is the finding, so the companion is kept however
 * flat it looks beside the subject.
 *
 * The general guard drops a context line more than twenty times smaller than the subject,
 * because a line pinned to the axis is not context. For this pair it is the opposite: commands
 * at 99,000us over reads at 2,200us is a ratio of forty-five, and that ratio IS the claim --
 * the server was fast at its own work while something else was slow. A chart that drops the
 * flat line leaves the reader looking at one climbing curve, which is the picture the wrong
 * conclusion is drawn from.
 */
const CONTRAST_RULES: ReadonlySet<string> = new Set([
  'command-latency-high', 'slow-wire-not-server',
]);

/**
 * Points per baseline-excursion series, and the context around the judged window.
 *
 * Narrower than CHART_WIDTH because there is one of these per tracked metric per node, and
 * only a handful ever become findings -- the rest are decoded, carried through stdout and
 * thrown away. The padding is what makes an excursion legible at all: a window that is
 * entirely above the old ceiling looks like a flat line until you can see what came before it.
 */
const WINDOW_CHART_WIDTH = 160;

/**
 * How far back detection reads, beyond the window being judged.
 *
 * A day. Long enough that an episode running across the last run is read whole, short enough
 * that the cost of a run does not grow with how long somebody has been a customer.
 */
const ANALYSIS_WINDOW_MS = 24 * 3_600_000;
const WINDOW_CHART_PAD_MS = 5 * 60_000;



/**
 * What a finding's chart should SHOW, which is not always what the rule tests.
 *
 * The ticket rules are the clear case. They test `out / totalTickets` because that is the only
 * shape that detects saturation on MongoDB 8.0, where the pool resizes and `available` rarely
 * reaches zero. But Big Hole's own dashboard plots **tickets available**, counting down from
 * 128 towards nothing, and that is the picture every MongoDB DBA already has in their head.
 *
 * Charting the ratio meant the same incident appeared upside-down in the report and in the
 * viewer -- one climbing towards trouble, the other falling towards it. The first person to
 * look at it read the recovery as the failure, which is exactly what you would expect.
 *
 * So: detect with whatever works, draw what the viewer draws. A missing entry means "chart the
 * metric the rule tested", which is right for every rule whose metric is already the natural
 * picture -- page faults and flow control are literally the dashboard's own expressions, and
 * checkpoint duration has no panel because a duration is its own picture.
 *
 * FIRST ENTRY IS THE SUBJECT, the rest are context, and that order matters: a context series
 * whose scale dwarfs the subject is dropped rather than drawn (see `comparable`), because a
 * line flattened against the axis by a companion twenty times its size shows nothing at all.
 * Every path here is the pre-8.0 canonical name; `expandMetric` aliases it forward, which is
 * how the same table works against `queues.execution` on 8.0 and `concurrentTransactions`
 * before it.
 */
const DISPLAY_METRICS: Record<string, string[]> = {
  // Tickets: the count down from the pool size, with the pool size behind it. On 8.0 that
  // ceiling moves, and seeing it move is half of understanding the incident.
  'read-tickets-saturated': [
    'serverStatus.wiredTiger.concurrentTransactions.read.available',
    'serverStatus.wiredTiger.concurrentTransactions.read.totalTickets',
  ],
  'write-tickets-saturated': [
    'serverStatus.wiredTiger.concurrentTransactions.write.available',
    'serverStatus.wiredTiger.concurrentTransactions.write.totalTickets',
  ],
  'read-tickets-exhausted': [
    'serverStatus.wiredTiger.concurrentTransactions.read.available',
    'serverStatus.wiredTiger.concurrentTransactions.read.totalTickets',
  ],
  'write-tickets-exhausted': [
    'serverStatus.wiredTiger.concurrentTransactions.write.available',
    'serverStatus.wiredTiger.concurrentTransactions.write.totalTickets',
  ],
  // Cache rules test a percentage of the configured maximum; the dashboard plots the bytes.
  // Dirty gets no ceiling: eviction triggers in the 5-20% band, so drawing the maximum
  // alongside it presses the line everybody came to see flat against the axis. Big Hole
  // splits these into two panels for the same reason -- "WiredTiger cache" carries the
  // maximum, "Dirty mb in the cache" stands alone.
  'cache-dirty-high': [
    'serverStatus.wiredTiger.cache.tracked dirty bytes in the cache',
  ],
  'cache-full': [
    'serverStatus.wiredTiger.cache.bytes currently in the cache',
    'serverStatus.wiredTiger.cache.maximum bytes configured',
  ],
  'memory-low': [
    'systemMetrics.memory.MemAvailable_kb',
    'systemMetrics.memory.MemTotal_kb',
  ],
  // `available` is the headroom, not the limit, and on Atlas it runs to six figures while
  // `current` sits in the tens -- the rule divides them, but drawing them together would
  // render the connection count as a flat line on zero. `active` is the useful companion:
  // same order of magnitude, and the gap between the two is idle connections.
  'connections-high': [
    'serverStatus.connections.current',
    'serverStatus.connections.active',
  ],
  // The two latency buckets, on both rules that read them -- because for this pair the second
  // line IS the finding. `command-latency-high` says the server is slow and `slow-wire-not-server`
  // says it is not, and the only thing separating them is where the reads line sits relative to
  // the commands one. Drawn alone, either chart shows the same climbing line and the reader has
  // no way to check the claim printed above it.
  'command-latency-high': [
    'div(rate(serverStatus.opLatencies.commands.latency), rate(serverStatus.opLatencies.commands.ops))',
    'div(rate(serverStatus.opLatencies.reads.latency), rate(serverStatus.opLatencies.reads.ops))',
  ],
  'slow-wire-not-server': [
    'div(rate(serverStatus.opLatencies.commands.latency), rate(serverStatus.opLatencies.commands.ops))',
    'div(rate(serverStatus.opLatencies.reads.latency), rate(serverStatus.opLatencies.reads.ops))',
  ],
  // Both queues on both rules. A read queue building while writes stay flat is a different
  // problem from both climbing together, and the reader cannot tell which without the pair.
  'read-queue-building': [
    'serverStatus.globalLock.currentQueue.readers',
    'serverStatus.globalLock.currentQueue.writers',
  ],
  'write-queue-building': [
    'serverStatus.globalLock.currentQueue.writers',
    'serverStatus.globalLock.currentQueue.readers',
  ],
};

/**
 * Whether a context series can share an axis with the subject.
 *
 * Twenty times is where a line stops being readable: the subject still moves, but every
 * movement is inside one pixel. Dropping the companion loses context; keeping it loses the
 * finding. This only ever removes context lines -- the subject is index 0 and never tested.
 */
const SCALE_RATIO_LIMIT = 20;

function comparable(subject: ChartSeries, other: ChartSeries): boolean {
  // NaN is how a gap in the capture is carried; it must not count as a peak of zero.
  const peak = (s: ChartSeries) =>
    s.v.reduce<number>((m, x) => (Number.isNaN(x) ? m : Math.max(m, Math.abs(x))), 0);
  const a = peak(subject);
  const b = peak(other);
  if (a === 0 || b === 0) return true; // nothing to flatten, or nothing to flatten it with
  return Math.max(a, b) / Math.min(a, b) <= SCALE_RATIO_LIMIT;
}



/* ------------------------------------------------------------------ percentiles ---- */

interface Summary {
  metric: string;
  n: number;
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}

function summarise(canonical: string, resolved: string, values: Float64Array): Summary | null {
  const clean = Array.from(values).filter((v) => Number.isFinite(v));
  if (clean.length === 0) return null;
  const sorted = clean.sort((a, b) => a - b);
  const at = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p))]!;
  return fromQuantiles(canonical, resolved, {
    n: sorted.length,
    min: sorted[0]!,
    max: sorted[sorted.length - 1]!,
    mean: clean.reduce((s, v) => s + v, 0) / clean.length,
    p50: at(0.5),
    p95: at(0.95),
    p99: at(0.99),
  });
}

/** The row shape, from quantiles computed exactly or merged from daily histograms alike. */
function fromQuantiles(canonical: string, resolved: string, q: Quantiles): Summary {
  const round = (v: number) => Math.round(v * 100) / 100;
  return {
    // Stored under the canonical name, but recording which path actually resolved: when the
    // customer upgrades, the series is still the same one and that has to be provable.
    metric: resolved === canonical ? canonical : `${canonical} (via ${resolved})`,
    n: q.n,
    min: round(q.min),
    p50: round(q.p50),
    p95: round(q.p95),
    p99: round(q.p99),
    max: round(q.max),
    mean: round(q.mean),
  };
}

/** When mongod opened an FTDC file, from its name: `metrics.2026-09-30T18-21-49Z-00000`. */
function fileOpenedMs(file: string): number | undefined {
  const m = /metrics\.(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})Z/.exec(file);
  if (!m) return undefined;
  const t = Date.parse(`${m[1]}T${m[2]}:${m[3]}:${m[4]}Z`);
  return Number.isFinite(t) ? t : undefined;
}

/* ----------------------------------------------------------------------- loading ---- */

interface NodeSummary {
  node: string;
  hostname?: string;
  version?: string;
  /** How this member is configured, from the newest metadata this run read. See `configOf`. */
  config?: NodeConfig;
  fromMs: number;
  toMs: number;
  samples: number;
  cadenceMs: number;
  gaps: Array<{ fromMs: number; toMs: number; seconds: number; missingSamples: number }>;
  /**
   * Gaps across everything held, when `--daily` is on and `gaps` only covers what this run
   * decoded. The status page counts these; the gap findings only need the recent ones.
   */
  gapsHeld?: { count: number; seconds: number };
  /**
   * Every point where the replica set's term advanced, which is every election it held.
   *
   * Not a rule, because an election is not a condition that persists -- it is an instant, and
   * the rule engine only knows how to ask "did this hold for long enough". The term counter is
   * the honest record of one: it only ever moves when the set elects, so a step in it is an
   * election that definitely happened, not an inference from something that correlates.
   */
  elections: Array<{ atMs: number; term: number }>;
  /** Settings that moved and stayed moved: a resize, a new cache size, a changed pool. */
  changes: Array<{ path: string; atMs: number; from: number; to: number }>;
  /** Every time mongod started again: `serverStatus.uptime` went down. */
  restarts: Array<{ fromMs: number; atMs: number }>;
  /** The MongoDB version changing between two files, from the metadata at the top of each. */
  versions: Array<{ atMs: number; from: string; to: string }>;
  /** Increments seen on the alarm counters, keyed by path. Empty on a healthy node. */
  alarms: Array<{ path: string; atMs: number; by: number }>;
  percentiles: Summary[];
  /** Same metrics, but only over what arrived since the last analysis. Empty on a first run. */
  recent: Summary[];
  /** Downsampled shapes for the profile report's charts, keyed by canonical name. */
  series: Record<string, { t: number[]; v: number[] }>;
  /**
   * The judged window for EVERY tracked metric, keyed by canonical name.
   *
   * The baseline excursions are found in Python, against history this process cannot see --
   * `baseline.jsonl` holds percentiles from runs whose raw FTDC Atlas deleted days ago. So the
   * side that knows an excursion happened is not the side that can read a series. Emitting the
   * shapes here lets the Python side chart what it found without decoding anything twice.
   *
   * Every tracked metric, not a filtered subset: the filter lives in the history, and guessing
   * it from this capture alone would drop exactly the excursion that has been sitting at its
   * new level since before the capture began.
   */
  windowSeries: Record<string, { t: number[]; v: number[]; unit: string }>;
  /** Real extent of that window, null when there was no `--since`. */
  recentFromMs: number | null;
  recentToMs: number | null;
}

const nodeSummaries: NodeSummary[] = [];




/**
 * The points behind a finding, for the chart that goes in the email.
 *
 * Extracted here rather than re-derived later because everything is already decoded and in
 * memory at this moment. The alternative -- handing the notifier a capture and having it
 * decode the whole thing again to draw one panel -- costs minutes per finding and adds a
 * second place where metric resolution can go wrong.
 *
 * The window is padded either side of the worst episode so the reader can see the shape
 * arrive and recede; a chart that starts already in breach shows nothing about what happened.
 * Downsampled to roughly `MAX_POINTS` because this is embedded per finding in a JSONL file
 * and an email chart cannot resolve more than that anyway.
 */
// How long a new value must hold before it counts as a change rather than a misread sample.
const SETTING_CONFIRM_SAMPLES = 10;

const CHART_POINTS = 240;

interface ChartSeries {
  label: string;
  v: number[];
  /**
   * The lowest and highest sample in each bucket, for the subject only. A bucket is ~45 s on
   * a three-hour chart, and its mean hides what a second-by-second condition did inside it: a
   * read-ticket pool emptied for 22 s at a time averaged to 23% checked out, and the chart
   * showed a pool that never got near empty during an episode the detector had right.
   */
  lo?: number[];
  hi?: number[];
  /**
   * The unit these values are in AFTER the reader's normalisation, not the one the path name
   * suggests. `systemMetrics.memory.MemTotal_kb` arrives in bytes because `PATH_SCALES` has
   * already multiplied it by 1024; a consumer that trusts the `_kb` suffix labels a 1.8 GiB
   * host as 1.8 TiB. Carrying the unit from the same table that did the scaling is the only
   * way to keep the two from drifting apart.
   */
  unit: string;
}

/**
 * The threshold in the units the chart is drawn in, when it can be worked out honestly.
 *
 * A rule like `memory-low` tests `pct(MemAvailable_kb, MemTotal_kb) <= 20` and is drawn as the
 * two raw series in gigabytes. There is no single height on that axis to draw 20% at -- but
 * there is a *line*: twenty per cent of whatever total the host reported at that moment. It is
 * the same condition, plotted in the reader's units.
 *
 * Without it the chart arrives with no threshold at all, and the report falls back to shading
 * the entire finding window: fifty minutes of pale red across a picture where the reader can
 * see perfectly well that memory dipped twice. That was the complaint that produced this.
 *
 * Only for the exact case where the drawn pair IS the tested pair. Anything cleverer -- the
 * ticket rules test `out` and draw `available` -- would be arithmetic the reader cannot check
 * against the legend, and a threshold line nobody can verify is worse than none.
 */
function derivedThreshold(
  rule: { metric: string; threshold?: number } | undefined,
  wanted: readonly string[],
  drawn: ChartSeries[],
): number[] | null {
  if (!rule || rule.threshold == null || drawn.length < 2) return null;
  const pct = /^pct\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)$/.exec(rule.metric);
  if (!pct) return null;
  const [, numerator, denominator] = pct;
  if (wanted[0] !== numerator || wanted[1] !== denominator) return null;

  const share = rule.threshold / 100;
  return drawn[1]!.v.map((total) =>
    Number.isFinite(total) ? Math.round(total * share * 100) / 100 : NaN);
}

/**
 * The ticket rules' line, in the chart's own terms.
 *
 * They test `pct(out, totalTickets) >= X` and draw `available` against `totalTickets`. Every
 * sample of the test set had out + available = totalTickets (1438 of 1439 over 24 minutes), so
 * the condition is exactly `available <= totalTickets * (1 - X/100)`: at X = 50, half the
 * pool. Unlike the general case above this is arithmetic the reader can check on the chart --
 * the line sits at half the height of the dashed `totalTickets` -- which is why it is drawn.
 */
const TICKET_RULES: ReadonlySet<string> = new Set([
  'read-tickets-saturated', 'write-tickets-saturated',
]);

function ticketThreshold(
  rule: { id: string; metric: string; threshold?: number } | undefined,
  drawn: ChartSeries[],
): { line: number[]; note: string } | null {
  if (!rule || !TICKET_RULES.has(rule.id) || rule.threshold == null || drawn.length < 2) return null;
  const left = 1 - rule.threshold / 100;
  const share = left === 0.5 ? 'half the pool' : `${Math.round(left * 100)}% of the pool`;
  return {
    line: drawn[1]!.v.map((total) =>
      Number.isFinite(total) ? Math.round(total * left * 100) / 100 : NaN),
    note: `${share} available, a problem below this line`,
  };
}

async function chartFor(
  finding: Finding,
  reader: CaptureReader,
  paths: ReadonlySet<string>,
): Promise<{
  t: number[];
  v: number[];
  series: ChartSeries[];
  threshold: number | null;
  thresholdSeries: number[] | null;
  thresholdNote?: string;
  fromMs: number;
  toMs: number;
} | null> {
  // Framed on the whole finding, not on its worst episode.
  //
  // A finding can hold several episodes -- one real capture had five spread over sixteen
  // minutes. Framing on the worst one showed four minutes of a sixteen-minute incident, so the
  // chart looked uniformly bad from edge to edge with no sign that anything else happened. The
  // reader cannot tell a recovered blip from a sustained problem when the recovery is off
  // screen.
  const span = finding.lastMs - finding.firstMs;
  const pad = Math.max(120_000, span * 0.25);
  const from = finding.firstMs - pad;
  const to = finding.lastMs + pad;

  const prefixes = detectRolePrefixes(paths);
  const wanted = DISPLAY_METRICS[finding.ruleId] ?? [finding.metric];

  try {
    const drawn: ChartSeries[] = [];
    let stamps: number[] = [];

    for (const metric of wanted) {
      const options = expandMetric(metric, paths, prefixes);
      if (options.length === 0) continue;
      const series = await reader.getSeries(options[0]!, { from, to, maxPoints: CHART_POINTS });

      if (stamps.length === 0) {
        stamps = Array.from(series.t).map((x) => Math.round(x));
      }
      drawn.push({
        // The last path component reads well enough as a legend entry: "available",
        // "totalTickets", "maximum bytes configured". Not for an expression, where it is
        // "maxSize)" -- the chart title names a lone series anyway.
        label: DISPLAY_LABELS[metric] ?? (metric.includes('(') ? '' : metric.split('.').pop()!),
        // The unit of the whole expression, not of its text read as one path: that put the
        // oplog window, in seconds, on an axis in bytes because the word "bytes" was in it.
        unit: unitOf(parseExpr(options[0]!)),
        // NaN survives on purpose: a gap in the capture must show as a break in the line,
        // not as a line drawn straight through it.
        v: Array.from(series.mean).map((x) =>
          Number.isFinite(x) ? Math.round(x * 100) / 100 : NaN),
        ...(drawn.length === 0 ? {
          lo: Array.from(series.min).map((x) => (Number.isFinite(x) ? Math.round(x * 100) / 100 : NaN)),
          hi: Array.from(series.max).map((x) => (Number.isFinite(x) ? Math.round(x * 100) / 100 : NaN)),
        } : {}),
      });
    }

    if (drawn.length === 0) return null;

    // Context lines that would flatten the subject are dropped rather than drawn. Better a
    // chart with one honest line than two where the one that matters is pinned to the axis.
    const subject = drawn[0]!;
    const keep = CONTRAST_RULES.has(finding.ruleId)
      ? drawn
      : [subject, ...drawn.slice(1).filter((s) => comparable(subject, s))];

    const rule = RULES.find((r) => r.id === finding.ruleId);
    const tickets = ticketThreshold(rule, keep);
    return {
      t: stamps,
      // `v` stays for anything still reading the single-series shape.
      v: subject.v,
      series: keep,
      // The threshold belongs to the tested metric, so it only means something on a chart of
      // that metric. Drawing it over a different series would be a line at an arbitrary height.
      threshold: DISPLAY_METRICS[finding.ruleId] ? null : (rule?.threshold ?? null),
      thresholdSeries: tickets?.line ?? derivedThreshold(rule, wanted, keep),
      ...(tickets ? { thresholdNote: tickets.note } : {}),
      fromMs: from,
      toMs: to,
    };
  } catch {
    // A chart is a nice-to-have; a finding without one is still worth sending.
    return null;
  }
}

function metricsFilesIn(dir: string): string[] {
  return readdirSync(dir)
    .filter((n) => n.startsWith('metrics.') && !n.includes(':'))
    .sort()
    .map((n) => join(dir, n))
    .filter((p) => statSync(p).isFile());
}

/** When a numbered FTDC file began, from its name. Null for `metrics.interim`. */
function fileStart(path: string): number | null {
  const m = /metrics\.(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})Z/.exec(path);
  return m ? Date.parse(`${m[1]}T${m[2]}:${m[3]}:${m[4]}Z`) : null;
}

/**
 * The files that can hold samples at or after `from`.
 *
 * A file runs from its name to the next file's name, so the one that began before `from` is
 * kept when the next one began after it. That also keeps the last file before a long outage,
 * which is what lets the outage be seen as a gap rather than as a node that started late.
 */
function filesFrom(files: string[], from: number): string[] {
  if (from <= 0) return files;
  return files.filter((_, i) => {
    const next = i + 1 < files.length ? fileStart(files[i + 1]!) : null;
    return next === null || next > from;
  });
}

/** [midnight, first index, end index) of each UTC day in a sorted time column. */
function dayRanges(t: Float64Array): Array<[number, number, number]> {
  const out: Array<[number, number, number]> = [];
  let i = 0;
  while (i < t.length) {
    const day = dayStart(t[i]!);
    let j = i;
    while (j < t.length && t[j]! < day + DAY_MS) j++;
    out.push([day, i, j]);
    i = j;
  }
  return out;
}

function readDays(dir: string): DaySummary[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((n) => /^\d{4}-\d{2}-\d{2}\.json$/.test(n))
    .sort()
    .map((n) => JSON.parse(readFileSync(join(dir, n), 'utf8')) as DaySummary);
}

/** Written aside and renamed, so a run killed mid-write leaves the old day, not half a new one. */
function writeJson(path: string, value: unknown): void {
  writeFileSync(`${path}.tmp`, JSON.stringify(value));
  renameSync(`${path}.tmp`, path);
}

const nodes = readdirSync(root)
  .filter((n) => statSync(join(root, n)).isDirectory())
  .sort();

/*
 * Daily summaries: whether they can be trusted, and so how far back this run has to decode.
 *
 * They are trusted only if written by this format with this list of tracked metrics. Adding a
 * metric to TRACKED leaves every stored day without it, and a baseline merged from those days
 * would quietly describe the last two only -- so a changed list rebuilds from the raw files,
 * which costs one run what every run used to cost.
 */
const dailyKey = { format: DAILY_FORMAT, tracked: TRACKED.map((t) => t.name) };
let dailyValid = false;
if (dailyDir !== undefined) {
  try {
    const stored = JSON.parse(readFileSync(join(dailyDir, 'format.json'), 'utf8'));
    dailyValid = JSON.stringify(stored) === JSON.stringify(dailyKey);
  } catch {
    // Missing or unreadable: rebuilt below.
  }
  if (!dailyValid) {
    rmSync(dailyDir, { recursive: true, force: true });
    console.error('daily summaries missing or stale: decoding everything held to rebuild them');
  }
}
// From midnight of the day before the detection window opens, so that every day this run
// rewrites is a whole day and not the tail of one.
const decodeFrom = dailyValid && sinceMs > 0 ? dayStart(sinceMs - ANALYSIS_WINDOW_MS) : 0;
const electionsFrom = decodeFrom > 0 ? sinceMs - ANALYSIS_WINDOW_MS : 0;

const tmpDir = await mkdtemp(join(tmpdir(), 'collector-'));
const store = new NodeFileStore(tmpDir);
const readers = new Map<string, CaptureReader>();
const captures: DetectCapture[] = [];

// Every file this run decodes, worked out first so the progress has a denominator. Never empty
// for a node with files: the newest file is always read, even when every sample in it is older
// than `decodeFrom`. That is a node that stopped, and it still has a history.
const plan = nodes.map((node) => {
  const held = metricsFilesIn(join(root, node));
  return { held, files: held.length === 0 ? [] : filesFrom(held, decodeFrom) };
});
const totalFiles = plan.reduce((n, p) => n + p.files.length, 0);
let doneFiles = 0;
function progress(node: string | null, stage: 'decoding' | 'summarising' | 'checks'): void {
  if (progressPath === undefined) return;
  try {
    writeJson(progressPath, { done: doneFiles, total: totalFiles, node, stage });
  } catch {
    // A progress bar that cannot be drawn is no reason to fail the analysis.
  }
}

try {
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i]!;
    const { held, files } = plan[i]!;
    if (held.length === 0) continue;
    progress(node, 'decoding');
    const nodeDaily = dailyDir !== undefined ? join(dailyDir, node) : undefined;
    // What every whole-history read below is limited to. Everything, without `--daily`.
    const scope = (decodeFrom > 0 ? { from: decodeFrom } : {}) as SeriesQuery;

    const captureId = `n${i}`;
    const writer = await CaptureWriter.create(store, { captureId, sourceFile: node });
    let hostname: string | undefined;
    let mongoVersion: string | undefined;
    let dbPath: string | undefined;
    let config: NodeConfig | undefined;
    // The version of each file in turn, to see an upgrade: Atlas moved Cluster1 from 8.0.32 to
    // 8.0.34 on 30 Sep 2026 and nothing said so, because only the first file's was kept.
    const versions: Array<{ atMs: number; from: string; to: string }> = [];
    let lastVersion: string | undefined =
      decodeFrom > 0 && nodeDaily !== undefined ? readDays(nodeDaily).at(-1)?.version : undefined;

    for (const file of files) {
      const bytes = new Uint8Array(readFileSync(file));
      // The configuration from the NEWEST file, unlike the name: after a resize the oldest
      // metadata describes a server that no longer exists.
      let meta: ReturnType<typeof readMetadata> | undefined;
      try {
        meta = readMetadata(bytes);
      } catch {
        /* no metadata in this file */
      }
      if (meta?.version) {
        const opened = fileOpenedMs(file);
        if (lastVersion !== undefined && meta.version !== lastVersion && opened !== undefined) {
          versions.push({ atMs: opened, from: lastVersion, to: meta.version });
        }
        lastVersion = meta.version;
        // The newest file's, unlike the hostname: the version a member runs now is the one the
        // end-of-life recommendation has to judge.
        mongoVersion = meta.version;
      }
      if (meta?.doc) {
        try {
          config = configOf(meta.doc);
        } catch (e) {
          // Said out loud: swallowed, it looked exactly like a server that reports nothing.
          console.error(`  note: ${node}: configuration unreadable: ${(e as Error).message}`);
        }
      }
      if (hostname === undefined) {
        try {
          const meta = readMetadata(bytes);
          hostname = meta?.hostname;
          mongoVersion ??= meta?.version;
          dbPath = (meta?.doc as any)?.getCmdLineOpts?.parsed?.storage?.dbPath ?? dbPath;
        } catch {
          /* a file without metadata is not a problem: it comes in the next one */
        }
      }
      try {
        for (const chunk of decodeFTDC(bytes)) await writer.addChunk(chunk);
      } catch (e) {
        // A half-written metrics.interim is normal: mongod was writing it when we copied it.
        // It must not sink the rest of the node.
        console.error(`  note: ${node}/${file.split('/').pop()}: ${(e as Error).message}`);
      }
      doneFiles++;
      progress(node, 'decoding');
    }
    progress(node, 'summarising');

    // The label every finding id is built from. If the files this run read carried no metadata,
    // the name has to come from the stored days: falling back to the directory name would
    // give the same node a new id, and every finding about it would be sent again.
    if (hostname === undefined && nodeDaily !== undefined) {
      const last = readDays(nodeDaily).at(-1);
      hostname = last?.hostname;
      mongoVersion ??= last?.version;
    }

    const manifest = await writer.finish({
      ...(hostname !== undefined ? { hostname } : {}),
      ...(mongoVersion !== undefined ? { mongoVersion } : {}),
    });
    const reader = await CaptureReader.open(store, captureId);
    readers.set(captureId, reader);

    const paths = new Set(reader.catalog.map((c) => c.path));
    captures.push({ id: captureId, label: hostname ?? node, paths });
    const mount = dataMount(paths, dbPath);
    dataMounts.set(captureId, mount);

    // Percentiles at full resolution: a baseline must not be taken from already-averaged
    // data, because a p99 over bucket means is not a p99 of anything.
    const prefixes = detectRolePrefixes(paths);
    const percentiles: Summary[] = [];
    const recent: Summary[] = [];
    const series: Record<string, { t: number[]; v: number[] }> = {};
    const windowSeries: Record<string, { t: number[]; v: number[]; unit: string }> = {};
    let recentFromMs = Infinity;
    let recentToMs = -Infinity;
    // With `--daily`: per UTC day, each metric's histogram and, for the charted ones, its shape.
    const dayMetrics = new Map<number, DaySummary['metrics']>();
    const dayCharts = new Map<number, Record<string, DayChart>>();
    for (const { name, expr } of TRACKED) {
      const options = expandMetric(withDataMount(expr, mount), paths, prefixes);
      if (options.length === 0) continue;
      const resolved = options[0]!;
      try {
        // Two summaries of the same series, and they answer different questions. The first
        // covers everything held for this cluster and is the baseline -- what normal looks
        // like here. The second covers only what arrived since the last analysis and is the
        // window under judgement. Comparing a window against a baseline that includes it
        // would dilute exactly the excursion worth catching.
        //
        // With `--daily` the first is not computed here: this run holds two days, and the
        // whole-history summary is merged from the stored days further down.
        const whole = await reader.getSeries(resolved, scope);

        // A counter sampled less often than the capture needs its rate computed against the
        // interval it really covers. Reading the underlying counter to find that out costs one
        // extra series per counter, and buys a baseline that is not silently 300x too high.
        //
        // With `--daily` this judges the two days decoded rather than everything held. NOT one
        // day at a time, which was tried: a day with a few minutes of data holds too few changes
        // to judge, falls back to the plain rate, and records the 300-second jumps as millions of
        // ms per second -- measured on the local set, a CPU maximum of 4.4M against 16k.
        let column = whole.mean;
        const counterPath = /^rate\((.*)\)$/.exec(resolved)?.[1];
        if (counterPath !== undefined) {
          try {
            const base = await reader.getSeries(counterPath, scope);
            const corrected = cadenceAwareRate(base.t, base.mean);
            if (corrected !== null) {
              column = corrected;
              console.error(`  note: ${node} ${name}: counter is undersampled, rate recomputed`);
            }
          } catch {
            // No underlying counter to check. Keep what the engine produced.
          }
        }
        if (nodeDaily !== undefined) {
          for (const [day, from, to] of dayRanges(whole.t)) {
            const hist = new Histogram();
            for (let k = from; k < to; k++) hist.add(column[k]!);
            if (hist.n > 0) {
              if (!dayMetrics.has(day)) dayMetrics.set(day, {});
              dayMetrics.get(day)![name] = { resolved, hist: hist.toJSON() };
            }
            if (CHARTED.includes(name)) {
              // The uncorrected series, as the chart without `--daily` draws it.
              const chart = dayChart(whole.t.subarray(from, to), whole.mean.subarray(from, to), day);
              if (!dayCharts.has(day)) dayCharts.set(day, {});
              dayCharts.get(day)![name] = chart;
            }
          }
        } else {
          const s = summarise(name, resolved, column);
          if (s) percentiles.push(s);
        }

        if (CHARTED.includes(name) && nodeDaily === undefined) {
          // Downsampled over the whole capture, which is the span the report describes.
          const reportShape = await reader.getSeries(resolved, { maxPoints: CHART_WIDTH } as SeriesQuery);
          series[name] = {
            t: Array.from(reportShape.t).map((x) => Math.round(x)),
            v: Array.from(reportShape.mean).map((x) =>
              Number.isFinite(x) ? Math.round(x * 100) / 100 : NaN),
          };
        }

        // The same window the excursion detector judges, drawn with room on the left. When
        // there is no `--since` the judged window is the whole capture, and so is this.
        const shapeQuery = (sinceMs > 0
          ? (untilMs > 0
              ? { from: sinceMs - WINDOW_CHART_PAD_MS, to: untilMs }
              : { from: sinceMs - WINDOW_CHART_PAD_MS })
          : {}) as SeriesQuery;
        const shape = await reader.getSeries(resolved,
          { ...shapeQuery, maxPoints: WINDOW_CHART_WIDTH } as SeriesQuery);
        windowSeries[name] = {
          t: Array.from(shape.t).map((x) => Math.round(x)),
          v: Array.from(shape.mean).map((x) =>
            Number.isFinite(x) ? Math.round(x * 100) / 100 : NaN),
          unit: unitOfPath(resolved),
        };

        if (sinceMs > 0) {
          const query = (untilMs > 0 ? { from: sinceMs, to: untilMs } : { from: sinceMs }) as SeriesQuery;
          const window = await reader.getSeries(resolved, query);
          const r = summarise(name, resolved, window.mean);
          if (r) {
            recent.push(r);
            // The window's real extent, so a finding about it can say when it happened. The
            // node's own from/to covers the whole capture and would misreport every excursion
            // as spanning the entire history.
            if (window.t.length > 0) {
              recentFromMs = Math.min(recentFromMs, window.t[0]!);
              recentToMs = Math.max(recentToMs, window.t[window.t.length - 1]!);
            }
          }
        }
      } catch (e) {
        console.error(`  note: ${node} ${name}: ${(e as Error).message}`);
      }
    }

    // The term counter, read once per node. Cheap -- one series -- and it is the only place
    // an election leaves a mark that survives into FTDC.
    const elections: Array<{ atMs: number; term: number }> = [];
    try {
      const termSeries = await reader.getSeries('replSetGetStatus.term', {} as SeriesQuery);
      let previous = NaN;
      for (let k = 0; k < termSeries.mean.length; k++) {
        const value = termSeries.mean[k]!;
        if (!Number.isFinite(value)) continue;
        // The first readable sample establishes the baseline: a capture that begins mid-life
        // has no way to tell whether that term was reached now or a month ago, and reporting
        // it as an election every time a capture starts would be an election on every run.
        // With `--daily`, only those in the detection window. The finding says "elected a new
        // primary N times" with no period attached, and before this N was every election in
        // everything held -- 35 on nine days of the local set, and it would only have grown.
        // Now it is the same window every rule judges, whichever run reads it.
        if (Number.isFinite(previous) && value > previous && termSeries.t[k]! >= electionsFrom) {
          elections.push({ atMs: Math.round(termSeries.t[k]!), term: value });
        }
        previous = value;
      }
    } catch {
      // Standalone mongod, or a release that does not report it. Neither is an error.
    }

    // Restarts: uptime only ever climbs while mongod runs, so a drop is a new process. A new
    // FTDC file is not evidence of one, since mongod also rotates files when they fill up.
    // Same window as the elections, for the same reason.
    const restarts: Array<{ fromMs: number; atMs: number }> = [];
    try {
      const up = await reader.getSeries('serverStatus.uptime', {} as SeriesQuery);
      let previous = NaN;
      let previousT = NaN;
      for (let k = 0; k < up.mean.length; k++) {
        const value = up.mean[k]!;
        if (!Number.isFinite(value)) continue;
        if (Number.isFinite(previous) && value < previous - 1 && up.t[k]! >= electionsFrom) {
          restarts.push({ fromMs: Math.round(previousT), atMs: Math.round(up.t[k]!) });
        }
        previous = value;
        previousT = up.t[k]!;
      }
    } catch {
      // A release that does not report it.
    }

    // The alarm counters. One series each, and they are almost always a flat zero -- which is
    // the point: the read is cheap and the answer is usually "nothing to say".
    const alarms: Array<{ path: string; atMs: number; by: number }> = [];
    for (const counter of ALARM_COUNTERS) {
      try {
        const series = await reader.getSeries(counter.path, {} as SeriesQuery);
        let previous = NaN;
        for (let k = 0; k < series.mean.length; k++) {
          const value = series.mean[k]!;
          if (!Number.isFinite(value)) continue;
          // Increments only, never the level: a counter already above zero when the capture
          // begins records something that happened before it, possibly years before, and
          // announcing that on every run would be a permanent false alarm.
          if (Number.isFinite(previous) && value > previous) {
            alarms.push({ path: counter.path, atMs: Math.round(series.t[k]!), by: value - previous });
          }
          previous = value;
        }
      } catch {
        // Not present in this release. Not an error: the list spans several.
      }
    }

    // Settings that are supposed to hold still. Read at full resolution on purpose: a step is
    // one sample wide, and a downsampled mean would turn "8 GB became 4 GB at 14:02" into a
    // slope that never equals either value.
    const changes: Array<{ path: string; atMs: number; from: number; to: number }> = [];
    for (const setting of WATCHED_SETTINGS) {
      try {
        const series = await reader.getSeries(setting.path, {} as SeriesQuery);
        let held = NaN;          // the last value that proved it was there to stay
        let candidate = NaN;     // a different value, not yet confirmed
        let runLength = 0;
        for (let k = 0; k < series.mean.length; k++) {
          const value = series.mean[k]!;
          if (!Number.isFinite(value)) continue;
          if (!Number.isFinite(held)) { held = value; continue; }
          if (value === held) { candidate = NaN; runLength = 0; continue; }
          // Below the setting's own floor this is drift, not a decision. Measured on a real
          // host: MemTotal steps by 4 kB on its own, which is the kernel's accounting and not
          // somebody resizing a machine.
          const moved = Math.abs(value - held);
          const enough = 'relative' in setting.minChange
            ? moved >= Math.abs(held) * setting.minChange.relative
            : moved >= setting.minChange.absolute;
          if (!enough) { candidate = NaN; runLength = 0; continue; }
          if (value === candidate) {
            runLength += 1;
            // Ten samples, which on a one-second cadence is ten seconds. Long enough that a
            // single misread sample cannot invent a resize, short enough that the timestamp is
            // still the moment it happened.
            if (runLength >= SETTING_CONFIRM_SAMPLES) {
              changes.push({ path: setting.path, atMs: Math.round(series.t[k]!),
                             from: held, to: value });
              held = value;
              candidate = NaN;
              runLength = 0;
            }
          } else {
            candidate = value;
            runLength = 1;
          }
        }
      } catch {
        // Not present in this release or this topology -- a standalone has no oplog cap, an
        // older build no core count. Silence is right: the list spans several.
      }
    }

    // The writer already computes gaps against the node's real cadence, so there is no
    // threshold to guess: this is a measured interruption, not a heuristic.
    const gaps = (manifest.gaps ?? []).map((g) => ({
      fromMs: g.fromMs,
      toMs: g.toMs,
      seconds: Math.round((g.toMs - g.fromMs) / 1000),
      missingSamples: g.missingSamples,
    }));

    // Extent of what is held. Without `--daily` that is what was decoded; with it, the stored days.
    let extent = { fromMs: manifest.startMs, toMs: manifest.endMs, samples: manifest.sampleCount };
    let gapsHeld: NodeSummary['gapsHeld'];

    if (nodeDaily !== undefined) {
      // Rewrite the days this run decoded. Each is whole: `decodeFrom` is a midnight.
      mkdirSync(nodeDaily, { recursive: true });
      const firstPath = reader.catalog[0]?.path;
      const clock = firstPath !== undefined ? (await reader.getSeries(firstPath, scope)).t : new Float64Array();
      for (const [day, from, to] of dayRanges(clock)) {
        const summary: DaySummary = {
          format: DAILY_FORMAT,
          day: dayName(day),
          ...(hostname !== undefined ? { hostname } : {}),
          ...(mongoVersion !== undefined ? { version: mongoVersion } : {}),
          fromMs: clock[from]!,
          toMs: clock[to - 1]!,
          samples: to - from,
          cadenceMs: manifest.cadenceMs,
          gaps: gaps.filter((g) => dayStart(g.toMs) === day),
          metrics: dayMetrics.get(day) ?? {},
          charts: dayCharts.get(day) ?? {},
        };
        writeJson(join(nodeDaily, `${summary.day}.json`), summary);
      }

      // Days whose raw FTDC has been pruned are dropped too, so "the whole history" keeps
      // meaning what it meant when it was decoded every run: everything still held.
      const starts = held.map(fileStart).filter((x): x is number => x !== null);
      const oldest = starts.length > 0 ? dayStart(Math.min(...starts)) : -Infinity;
      const days = readDays(nodeDaily).filter((d) => {
        if (Date.parse(`${d.day}T00:00:00Z`) >= oldest) return true;
        unlinkSync(join(nodeDaily, `${d.day}.json`));
        return false;
      });

      for (const { name } of TRACKED) {
        const merged = new Histogram();
        let resolved: string | undefined;
        for (const d of days) {
          const m = d.metrics[name];
          if (m === undefined) continue;
          merged.merge(m.hist);
          resolved = m.resolved;  // the newest day's: after an upgrade, the path in use now
        }
        const q = merged.quantiles();
        if (q !== null && resolved !== undefined) percentiles.push(fromQuantiles(name, resolved, q));
      }
      for (const name of CHARTED) {
        const shapes = days.map((d) => d.charts[name]).filter((c): c is DayChart => c !== undefined);
        if (shapes.length > 0) series[name] = mergeCharts(shapes, CHART_WIDTH);
      }
      if (days.length > 0) {
        extent = {
          fromMs: Math.min(...days.map((d) => d.fromMs)),
          toMs: Math.max(...days.map((d) => d.toMs)),
          samples: days.reduce((s, d) => s + d.samples, 0),
        };
      }
      const allGaps = days.flatMap((d) => d.gaps);
      gapsHeld = { count: allGaps.length, seconds: allGaps.reduce((s, g) => s + g.seconds, 0) };
    }

    nodeSummaries.push({
      node,
      hostname,
      version: mongoVersion,
      ...(config !== undefined ? { config } : {}),
      ...extent,
      cadenceMs: manifest.cadenceMs,
      changes,
      restarts,
      versions,
      gaps,
      ...(gapsHeld !== undefined ? { gapsHeld } : {}),
      elections,
      alarms,
      percentiles,
      recent,
      series,
      windowSeries,
      recentFromMs: Number.isFinite(recentFromMs) ? recentFromMs : null,
      recentToMs: recentToMs > 0 ? recentToMs : null,
    });
    console.error(
      `${(hostname ?? node).slice(0, 44).padEnd(46)} ${manifest.sampleCount.toLocaleString()} samples · ` +
        `${((manifest.endMs - manifest.startMs) / 3.6e6).toFixed(1)} h · ${mongoVersion ?? '?'}`,
    );
  }

  progress(null, 'checks');

  // Last, so a run that dies half way leaves no marker and the next one rebuilds.
  if (dailyDir !== undefined) {
    mkdirSync(dailyDir, { recursive: true });
    writeJson(join(dailyDir, 'format.json'), dailyKey);
  }

  const source = {
    async series(captureId: string, expressions: string[], query: SeriesQuery) {
      const reader = readers.get(captureId)!;
      const out = await Promise.all(expressions.map((e) => reader.getSeries(e, query)));
      return out.map((s) => ({ path: s.path, t: s.t, min: s.min, max: s.max, mean: s.mean, raw: s.raw }));
    },
  };

  // Full resolution, deliberately, and NOT the bucket width the app opens a capture at.
  //
  // Detection buckets are not a display choice. `detect` guards with the conservative edge of
  // each bucket -- the minimum, for a `>=` rule -- so a bucket only counts if the condition
  // held across all of it. That is right, and it means an intermittent condition disappears
  // as soon as buckets are wider than the condition flickers. Measured on the real capture,
  // one node, same rules:
  //
  //                          full     20,000 points
  //   query-targeting        163 s      2 s
  //   collection-scans       165 s      0 s
  //   eviction-by-app        41 s      12 s
  //   cache-dirty-high       13 s       2 s     <- an existing rule, already losing evidence
  //
  // A fixed point budget also makes the bucket width depend on how much history the cluster
  // has. The same incident is detected on a young cluster and missed on an old one, and the
  // longer somebody stays a customer the blinder this gets -- which inverts the one thing
  // the product sells. The cost is linear in the window analysed, which is the honest shape:
  // twice the data, twice the work, same sensitivity.
  // Detection runs over a MOVING WINDOW, not over everything held.
  //
  // Full resolution is not negotiable -- bucketing hides intermittent conditions, which is the
  // bug this replaced. But cost is linear in what gets read, and what gets held grows with
  // retention, which is the thing the product sells. Measured: 1.11 days of a three-node set
  // costs 12 s and 382 MB. At ninety days that is 17 minutes and 30 GB, per cluster, per run.
  //
  // Nothing older than the window can produce a new finding anyway: an episode that began
  // weeks ago was reported weeks ago, and the run filters out what it has already sent. So the
  // window only has to be wide enough that an episode straddling the last run is still seen
  // whole -- a day, against a cron that fires hourly, is twenty-four runs of slack.
  //
  // The baseline is unaffected: it accumulates per run from percentiles already computed, and
  // never re-reads history.
  const windowFrom = sinceMs > 0 ? sinceMs - ANALYSIS_WINDOW_MS : 0;
  const windowQuery = (windowFrom > 0 ? { from: windowFrom } : {}) as SeriesQuery;
  // Rules written against `{dataMount}` are resolved member by member, each against the mount
  // holding its own data; everything else runs across all members at once, as before.
  const perMember = RULES.filter((r) => r.metric.includes('{dataMount}'));
  const fromRules = [
    ...await detect(source, captures, RULES.filter((r) => !perMember.includes(r)), windowQuery),
    ...(await Promise.all(captures.map((c) => detect(source, [c], perMember.map((r) => ({
      ...r, metric: withDataMount(r.metric, dataMounts.get(c.id)),
    })), windowQuery)))).flat(),
  ];
  const findings = [...fromRules, ...gapFindings(nodeSummaries), ...electionFindings(nodeSummaries),
                    ...alarmFindings(nodeSummaries), ...changeFindings(nodeSummaries),
                    ...versionFindings(nodeSummaries), ...restartFindings(nodeSummaries),
                    ...peerFindings(nodeSummaries)];

  // A finding whose whole window predates the mark was already reported on an earlier run.
  // The filter lives here rather than in Python so that the output JSON is directly what
  // needs notifying.
  const fresh = findings.filter((f) => f.lastMs >= sinceMs);

  // Which rules could not even be evaluated. A rule that fails to resolve looks identical to
  // a rule that found nothing, and that is exactly the failure mode this project keeps
  // running into.
  const unresolved = RULES.filter((r) =>
    captures.every((c) => expandMetric(withDataMount(r.metric, dataMounts.get(c.id)), c.paths,
                                       detectRolePrefixes(c.paths)).length === 0),
  ).map((r) => ({ id: r.id, metric: r.metric }));

  // Charts only for what is actually going to be sent. The gap findings have no series
  // behind them -- their evidence is the absence of one -- so they get no chart.
  const charts = new Map<string, Awaited<ReturnType<typeof chartFor>>>();
  for (const f of fresh) {
    const capture = captures.find((c) => c.label === f.captureLabel);
    const reader = capture ? readers.get(capture.id) : undefined;
    if (reader === undefined || f.metric.startsWith('(')) continue;
    charts.set(`${f.ruleId}/${f.captureLabel}/${f.worstFromMs}`, await chartFor(f, reader, capture!.paths));
  }

  process.stdout.write(
    JSON.stringify(
      {
        nodes: nodeSummaries,
        findings: fresh.map((f) => ({
          chart: charts.get(`${f.ruleId}/${f.captureLabel}/${f.worstFromMs}`) ?? null,
          rule: f.ruleId,
          title: f.title,
          severity: f.severity,
          node: f.captureLabel,
          metric: f.metric,
          episodes: f.episodes,
          // Only present for rules whose metric echoes an event. Their absence is what tells
          // the report to fall back to elapsed time, so they must not be defaulted to zero.
          ...(f.occurrences !== undefined
            ? { occurrences: f.occurrences, observed: f.observed } : {}),
          fromMs: f.firstMs,
          toMs: f.lastMs,
          worstFromMs: f.worstFromMs,
          worstToMs: f.worstToMs,
          secondsInState: Math.round(f.totalMs / 1000),
          peak: f.peak,
          unit: f.unit,
          what: f.what,
          check: f.check,
        })),
        findingsSkippedAsOld: findings.length - fresh.length,
        rulesUnresolved: unresolved,
        rulesEvaluated: RULES.length,
      },
      null,
      2,
    ),
  );
} finally {
  for (const reader of readers.values()) await reader.close?.();
  await rm(tmpDir, { recursive: true, force: true });
}
