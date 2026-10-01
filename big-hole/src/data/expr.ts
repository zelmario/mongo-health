/**
 * Derived metrics.
 *
 * Most of FTDC is cumulative counters. `serverStatus.opcounters.query` only ever goes up, so
 * charting it raw produces a monotonic ramp that tells you nothing -- what an engineer
 * actually wants is queries per second. The same is true of network bytes, disk IO, page
 * faults, evictions and asserts. Several of the most useful signals are ratios that exist
 * nowhere in the raw data at all: cache dirty %, ticket utilisation, average operation
 * latency, disk utilisation.
 *
 * So expressions are not a power-user extra; without them the default dashboard is close to
 * useless. They are deliberately a tiny language rather than a general one -- small enough to
 * be safe, serialisable into a permalink, and readable in a panel legend.
 *
 *   serverStatus.mem.resident                          a raw metric
 *   rate(serverStatus.opcounters.query)                per-second delta of a counter
 *   pct(wt.cache.dirty, wt.cache.max)                  100 * a / b
 *   div(rate(latency), rate(ops))                      nested: average latency per op
 *   scale(rate(sys.cpu.user_ms), 0.1)                  ms/s -> % of one core
 *   sum(a, b, c)   diff(a, b)
 *   window(oplog insert bytes, oplog maxSize)         seconds back the last maxSize bytes reach
 *
 * Evaluation happens in the reader at FULL resolution, before downsampling. Computing a rate
 * from already-bucketed means would smear exactly the short spikes the envelope exists to
 * preserve.
 */

export type Unit =
  | 'count'
  | 'bytes'
  | 'bytes/s'
  | 'ms'
  | 'us'
  | 'seconds'
  | 'percent'
  | 'per-sec';

export type Expr =
  | { readonly fn: 'raw'; readonly path: string }
  | { readonly fn: 'rate'; readonly arg: Expr }
  | { readonly fn: 'pct'; readonly num: Expr; readonly den: Expr }
  | { readonly fn: 'div'; readonly num: Expr; readonly den: Expr }
  | { readonly fn: 'sum'; readonly args: Expr[] }
  /**
   * The distance between the highest and lowest of several series, sample by sample.
   *
   * Written for replication lag, where the question is not what any one member is doing but
   * how far apart the members are. Comparing each against the clock does not answer it:
   * `lastAppliedWallTime` only advances when there are writes, so on an idle cluster every
   * member drifts away from `localTime` together and the arithmetic reports hours of lag on a
   * set that is perfectly in sync. Measured on a real capture, six seconds of it at rest --
   * and LESS during the incident, when there were writes.
   *
   * Comparing the members against each other has none of that: with no writes they are all
   * equally stale, and the spread is zero, which is the truth.
   */
  | { readonly fn: 'spread'; readonly args: Expr[] }
  | { readonly fn: 'diff'; readonly a: Expr; readonly b: Expr }
  | { readonly fn: 'scale'; readonly arg: Expr; readonly k: number }
  /**
   * How far back in time the last `size` units of a cumulative counter reach, in seconds.
   *
   * Written for the oplog window: the counter is the bytes inserted into `local.oplog.rs`, the
   * size is the oplog's `maxSize`, and the answer is how long a member can be away and still
   * catch up. Size divided by the current rate answers a different question -- how long the
   * oplog would last if this second went on for ever -- and on a real capture it swung from
   * 1,000 hours to 19 within a day. The window a secondary actually has is the bytes it would
   * have to find, which is the history, not the present.
   */
  | { readonly fn: 'window'; readonly counter: Expr; readonly size: Expr };

export class ExprError extends Error {
  override readonly name = 'ExprError';
}

const FUNCTIONS = new Set(['rate', 'pct', 'div', 'diff', 'scale', 'sum', 'spread', 'window']);

/* ------------------------------------------------------------------ parse ---- */

/**
 * Split on top-level commas only, so nested calls survive.
 * `rate(a), div(b, c)` -> ['rate(a)', 'div(b, c)']
 */
function splitArgs(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    else if (ch === ',' && depth === 0) {
      out.push(text.slice(start, i));
      start = i + 1;
    }
  }
  out.push(text.slice(start));
  // Only leading whitespace is stripped -- see parseExpr on why the trailing kind matters.
  return out.map((s) => s.replace(/^\s+/, '')).filter((s) => s.length > 0);
}

export function parseExpr(text: string): Expr {
  // Leading whitespace is formatting; TRAILING whitespace can be part of the metric name.
  // WiredTiger emits paths that genuinely end in a space, e.g.
  // `serverStatus.wiredTiger.reconciliation.pages written including an aggregated newest
  // start durable timestamp ` -- 11 such paths in one real capture, and trimming them makes
  // the metric unresolvable. Leading whitespace was never observed on any path.
  const src = text.replace(/^\s+/, '');
  if (src.length === 0) throw new ExprError('empty expression');

  const open = src.indexOf('(');
  // No call syntax: a bare metric path. Paths contain dots, spaces and slashes and may carry
  // a duplicate-collision suffix (`path#1`), so anything non-empty is accepted here.
  if (open < 0 || !src.endsWith(')')) return { fn: 'raw', path: src };

  const fn = src.slice(0, open).trim();

  // Metric paths legitimately contain parentheses -- 80 of them in a real catalogue, e.g.
  // `systemMetrics.memory.Active(anon)_kb` and
  // `serverStatus.wiredTiger.transaction.transaction checkpoint prepare max time (msecs)`.
  // So a leading `something(` is only a call when `something` is a function we know; anything
  // else is part of the path. This also makes the nested case work, because the inner text is
  // re-parsed and falls through to the same check.
  if (!FUNCTIONS.has(fn)) return { fn: 'raw', path: src };

  const args = splitArgs(src.slice(open + 1, -1));

  const need = (n: number): void => {
    if (args.length !== n) {
      throw new ExprError(`${fn}() takes ${n} argument(s), got ${args.length}`);
    }
  };

  switch (fn) {
    case 'rate':
      need(1);
      return { fn: 'rate', arg: parseExpr(args[0]!) };
    case 'pct':
      need(2);
      return { fn: 'pct', num: parseExpr(args[0]!), den: parseExpr(args[1]!) };
    case 'div':
      need(2);
      return { fn: 'div', num: parseExpr(args[0]!), den: parseExpr(args[1]!) };
    case 'diff':
      need(2);
      return { fn: 'diff', a: parseExpr(args[0]!), b: parseExpr(args[1]!) };
    case 'scale': {
      need(2);
      const k = Number(args[1]);
      if (!Number.isFinite(k)) throw new ExprError(`scale() needs a number, got "${args[1]}"`);
      return { fn: 'scale', arg: parseExpr(args[0]!), k };
    }
    case 'sum':
      if (args.length < 2) throw new ExprError('sum() takes at least 2 arguments');
      return { fn: 'sum', args: args.map(parseExpr) };
    case 'spread':
      // One argument is valid here, unlike `sum`, because the template form carries a wildcard
      // that has not been expanded yet: `spread(members.*.optimeDate)` becomes
      // `spread(members.0…, members.1…, members.2…)` against a real capture. Requiring two at
      // parse time would reject the only form a rule is ever written in.
      //
      // The "at least two" rule still holds where it means something: `expandMetric` refuses to
      // produce a one-member spread, and `evaluate` returns NaN for any sample where fewer than
      // two members are readable.
      if (args.length < 1) throw new ExprError('spread() takes at least 1 argument');
      return { fn: 'spread', args: args.map(parseExpr) };
    case 'window':
      need(2);
      return { fn: 'window', counter: parseExpr(args[0]!), size: parseExpr(args[1]!) };
    default:
      throw new ExprError(`unknown function "${fn}"`);
  }
}

/** Every raw metric path an expression depends on. */
export function exprPaths(e: Expr): string[] {
  switch (e.fn) {
    case 'raw':
      return [e.path];
    case 'rate':
    case 'scale':
      return exprPaths(e.arg);
    case 'pct':
    case 'div':
      return [...exprPaths(e.num), ...exprPaths(e.den)];
    case 'diff':
      return [...exprPaths(e.a), ...exprPaths(e.b)];
    case 'window':
      return [...exprPaths(e.counter), ...exprPaths(e.size)];
    case 'sum':
    case 'spread':
      return e.args.flatMap(exprPaths);
  }
}

/* --------------------------------------------------------------- evaluate ---- */

/**
 * Per-second rate of a cumulative counter.
 *
 * Three cases have to be handled or the chart lies.
 *
 * A counter that goes *backwards* means the process restarted, so the delta is meaningless --
 * emit NaN (a visible break) rather than a huge negative spike that reads as a real event. A
 * zero time delta would divide by zero.
 *
 * And **a step across a gap in the capture is not a rate**. If the collector stopped for four
 * hours, the counter kept climbing the whole time and the first sample back carries all of it.
 * Dividing by the real elapsed time looks like it should be enough, and for a lone counter it
 * is -- but not for a ratio. Measured on a real capture of a laptop that was suspended:
 * `div(rate(disk write_time_ms), rate(disk writes))` came out at 15,230,403 ms per write, four
 * hours to complete one I/O, because the time counter advanced across the gap and the write
 * counter barely did. That went straight into a finding, and into the baseline behind it.
 *
 * The step across a gap tells us what happened in total but not when, so it is not evidence of
 * anything per second. NaN is the honest answer, and `detect` already treats NaN as a break
 * rather than as a quiet period.
 */
const GAP_FACTOR = 3;

/**
 * Some counters are 32 bits wide and wrap.
 *
 * `/proc/diskstats` is the one that bit us: on a real three-node capture,
 * `systemMetrics.disks.sdd.write_time_ms` ran NEGATIVE (-2,130,924,618, an unsigned value read
 * as signed) and then jumped to +2,164,050,247. The step is 4,294,973,664 -- 2^32 plus the
 * 6,368 ms that genuinely elapsed.
 *
 * Left alone it produced a finding claiming a single disk write took four hours, and put that
 * number into the cluster's baseline. Any server with enough uptime hits this; nobody notices
 * because nobody looks at the counter directly.
 *
 * The real increment is recoverable rather than merely detectable -- subtract the wrap -- so
 * that is what happens, and the sample survives instead of becoming a hole. Only a step just
 * above 2^32 qualifies: a genuine 4-billion increment in one second would have to be a 4 GB/s
 * device reporting in bytes, and that would land far above the window rather than inside it.
 */
const WRAP_32 = 2 ** 32;
const WRAP_SLACK = 2 ** 24; // ~16.7M, room for the real increment riding on top of the wrap

function unwrap(dv: number): number {
  return dv >= WRAP_32 && dv < WRAP_32 + WRAP_SLACK ? dv - WRAP_32 : dv;
}

function rateOf(t: Float64Array, v: Float64Array): Float64Array {
  const out = new Float64Array(v.length);
  out[0] = NaN; // no previous sample to difference against

  // The usual step for THIS series, taken from the middle of the sorted intervals so that the
  // gaps themselves cannot drag it upwards. Series are sampled on a fixed cadence, so anything
  // several times the median is an interruption rather than a slow sample.
  const steps: number[] = [];
  for (let i = 1; i < t.length; i++) steps.push(t[i]! - t[i - 1]!);
  steps.sort((a, b) => a - b);
  const typical = steps.length > 0 ? steps[Math.floor(steps.length / 2)]! : 0;
  const tooLong = typical > 0 ? typical * GAP_FACTOR : Infinity;

  for (let i = 1; i < v.length; i++) {
    const gap = t[i]! - t[i - 1]!;
    if (gap > tooLong) {
      out[i] = NaN;
      continue;
    }
    const dt = gap / 1000;
    const dv = unwrap(v[i]! - v[i - 1]!);
    out[i] = dt > 0 && dv >= 0 ? dv / dt : NaN;
  }
  return out;
}

function zip(
  a: Float64Array,
  b: Float64Array,
  f: (x: number, y: number) => number,
): Float64Array {
  const out = new Float64Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = f(a[i]!, b[i]!);
  return out;
}

/** Divide, treating a zero or absent denominator as "no value" rather than Infinity. */
function safeDiv(x: number, y: number): number {
  return y === 0 || Number.isNaN(y) || Number.isNaN(x) ? NaN : x / y;
}

export function evaluate(
  e: Expr,
  t: Float64Array,
  raw: ReadonlyMap<string, Float64Array>,
): Float64Array {
  switch (e.fn) {
    case 'raw': {
      const v = raw.get(e.path);
      if (v === undefined) throw new ExprError(`unknown metric: ${e.path}`);
      // Normalise to the base unit here rather than in the templates, so a metric picked
      // straight from the catalogue is as correct as one the dashboard shipped with.
      const factor = scaleOfPath(e.path);
      if (factor === 1) return v;
      const out = new Float64Array(v.length);
      for (let i = 0; i < v.length; i++) out[i] = v[i]! * factor;
      return out;
    }
    case 'rate':
      return rateOf(t, evaluate(e.arg, t, raw));
    case 'pct':
      return zip(evaluate(e.num, t, raw), evaluate(e.den, t, raw), (x, y) => safeDiv(x, y) * 100);
    case 'div':
      return zip(evaluate(e.num, t, raw), evaluate(e.den, t, raw), safeDiv);
    case 'diff':
      // A zero operand means the field was never reported -- a replica member that has not
      // checked in yet. Differencing against epoch yields ~56 years of "lag", which reads as
      // catastrophic rather than as missing.
      return zip(evaluate(e.a, t, raw), evaluate(e.b, t, raw), (x, y) =>
        x === 0 || y === 0 ? NaN : x - y,
      );
    case 'scale': {
      const v = evaluate(e.arg, t, raw);
      const out = new Float64Array(v.length);
      for (let i = 0; i < v.length; i++) out[i] = v[i]! * e.k;
      return out;
    }
    case 'sum': {
      const parts = e.args.map((a) => evaluate(a, t, raw));
      const out = new Float64Array(t.length);
      for (let i = 0; i < out.length; i++) {
        let acc = 0;
        let seen = false;
        for (const p of parts) {
          const x = p[i]!;
          if (!Number.isNaN(x)) {
            acc += x;
            seen = true;
          }
        }
        out[i] = seen ? acc : NaN;
      }
      return out;
    }
    case 'spread': {
      const parts = e.args.map((a) => evaluate(a, t, raw));
      const out = new Float64Array(t.length);
      for (let i = 0; i < out.length; i++) {
        let low = Infinity;
        let high = -Infinity;
        let seen = 0;
        for (const p of parts) {
          const x = p[i]!;
          // Zero is absence, not a value -- the same reading `diff` takes. A member that has
          // not reported an optime yet carries 0, and treating that as a timestamp puts it in
          // 1970: the spread comes out as the whole epoch, 1.8e12 ms, which then becomes the
          // maximum of the baseline for ever.
          if (Number.isNaN(x) || x === 0) continue;
          if (x < low) low = x;
          if (x > high) high = x;
          seen++;
        }
        // Fewer than two readable members is not a spread of zero, it is no measurement. A
        // member that stopped reporting would otherwise make the set look perfectly in sync
        // at the exact moment it stopped being so.
        out[i] = seen >= 2 ? high - low : NaN;
      }
      return out;
    }
    case 'window':
      return windowOf(t, evaluate(e.counter, t, raw), evaluate(e.size, t, raw));
  }
}

/**
 * The least history `window()` will judge from. Under an hour the bytes seen are one burst or
 * one lull, and extrapolating either to a size of gigabytes invents the answer.
 */
const WINDOW_MIN_LOOKBACK_MS = 3_600_000;

/**
 * For each sample, the seconds back to where the last `size` bytes of the counter begin.
 *
 * The counter is made monotonic first by summing only its positive steps: a restart sets it
 * back to zero, and the oplog did not empty because the process did. A step across a gap in
 * the capture is kept -- the bytes really went in, only when is unknown, and the timestamps on
 * either side are real.
 *
 * When the history reaches back past `size`, the answer is exact. When it does not -- the
 * window is longer than what is loaded -- it is the size over the average rate across all of
 * it, which is the best the data allows and is the same formula at the boundary, so the series
 * does not jump where one gives way to the other. Under an hour of history it is NaN.
 *
 * An oplog with `oplogMinRetentionHours` set grows past `maxSize` to honour it, and this reads
 * shorter than the truth there. It errs towards warning, which is the side a rule can afford.
 */
function windowOf(t: Float64Array, counter: Float64Array, size: Float64Array): Float64Array {
  const n = t.length;
  const out = new Float64Array(n).fill(NaN);
  const cum = new Float64Array(n);
  for (let i = 1; i < n; i++) {
    const a = counter[i - 1]!;
    const b = counter[i]!;
    const dv = Number.isNaN(a) || Number.isNaN(b) ? 0 : unwrap(b - a);
    cum[i] = cum[i - 1]! + (dv > 0 ? dv : 0);
  }
  let j = 0; // the oldest sample still inside the last `size` bytes
  for (let i = 0; i < n; i++) {
    const cap = size[i]!;
    if (!(cap > 0) || Number.isNaN(counter[i]!)) continue;
    // The newest j for which everything since still totals at least `size`.
    while (j + 1 <= i && cum[i]! - cum[j + 1]! >= cap) j++;
    if (j > i) j = i;
    const filled = cum[i]! - cum[j]!;
    const span = t[i]! - t[j]!;
    if (filled >= cap && span > 0) {
      // Interpolate inside the step that crosses the boundary, so the answer moves smoothly
      // rather than in whole sampling intervals.
      const over = filled - cap;
      const step = j + 1 <= i ? cum[j + 1]! - cum[j]! : 0;
      const back = step > 0 ? (over / step) * (t[j + 1]! - t[j]!) : 0;
      out[i] = (span - back) / 1000;
      continue;
    }
    const lookback = t[i]! - t[0]!;
    if (lookback < WINDOW_MIN_LOOKBACK_MS) continue;
    const total = cum[i]!;
    out[i] = total > 0 ? (cap * (lookback / 1000)) / total : NaN;
  }
  return out;
}

/* ------------------------------------------------------------------ units ---- */

/**
 * Metrics reported in a unit other than the base one, with the multiplier to normalise them.
 *
 * FTDC carries no unit metadata, so these are taken from mongod's own collectors rather than
 * guessed from the names:
 *
 * - `serverStatus.mem.{resident,virtual}` -- `ProcessInfo::getResidentSize()` and
 *   `getVirtualMemorySize()` are both documented "@return mbytes" (`util/processinfo.h`).
 *   A raw 956 would otherwise format as "956 B" instead of "956 MiB".
 * - `*_kb` -- `parseProcMemInfoFile` appends the `_kb` suffix only when /proc/meminfo itself
 *   reports the value in kB (`util/procparser.cpp`), so the suffix is a reliable marker.
 * - `*_sectors` -- `kDiskFields` names /proc/diskstats columns verbatim with no conversion
 *   (`util/procparser.cpp`). Linux always reports those in 512-byte sectors regardless of
 *   the device's physical block size, so they are bytes once scaled.
 *
 * CPU is deliberately absent: `convertTicksToMilliSeconds` already normalises USER_HZ to ms
 * before FTDC sees it, so `*_ms` needs no scaling -- only the /10 that turns ms/s into a
 * percentage of one core, which the templates do explicitly.
 */
export const PATH_SCALES: ReadonlyArray<readonly [RegExp, number, Unit]> = [
  [/(^|\.)mem\.(resident|virtual|mapped|mappedWithJournal)$/, 1024 * 1024, 'bytes'],
  [/_kb$/, 1024, 'bytes'],
  [/_sectors$/, 512, 'bytes'],
];

/** Multiplier needed to bring a path to its base unit, or 1. */
export function scaleOfPath(path: string): number {
  for (const [pattern, factor] of PATH_SCALES) if (pattern.test(path)) return factor;
  return 1;
}

/** Guess a unit from a metric path. FTDC has no unit metadata, so naming is all we have. */
export function unitOfPath(path: string): Unit {
  for (const [pattern, , unit] of PATH_SCALES) if (pattern.test(path)) return unit;

  const p = path.toLowerCase();
  if (/micros$/.test(p) || p.endsWith('_us')) return 'us';
  if (/millis$|_ms$|\bpingms$|\bms$/.test(p)) return 'ms';
  // Wall-clock stamps: `optimeDate`, `lastAppliedWallTime`, `localTime`. FTDC carries them as
  // epoch milliseconds, so as a level they are a millisecond count and as a difference they
  // are a duration in milliseconds. The second is what anybody actually plots -- the whole
  // point of reading them is `spread()` across members, or `diff()` against the clock.
  if (/walltime$|(^|\.)optimedate$|(^|\.)localtime$|(^|\.)date$/.test(p)) return 'ms';
  // WiredTiger spells the unit out in parentheses at the end of the name -- 84 metrics in a
  // real catalogue do this, e.g. `...checkpoint most recent time (msecs)` and `...time
  // evicting (usecs)`. Without these they all fall through to `count`, so every panel showing
  // one silently mislabels it and any rule over one has to lie about its own unit to match.
  if (/\(usecs?\)$/.test(p)) return 'us';
  if (/\(msecs?\)$/.test(p)) return 'ms';
  if (/\(secs?\)$/.test(p)) return 'seconds';
  if (/\buptime$|uptimeestimate$/.test(p)) return 'seconds';
  if (/\.latency$/.test(p)) return 'us'; // opLatencies are microseconds
  if (
    p.includes('bytes') ||
    /(^|\.)(storagesize|freestoragesize|avgobjsize|totalsize|totalindexsize|size)$/.test(p)
  ) {
    return 'bytes';
  }
  return 'count';
}

/**
 * Unit of an expression with any outer rate()/scale() peeled off.
 *
 * `rate(x_ms)` is milliseconds per second; its *base* is still milliseconds, which is what
 * the dimensional rules below need.
 */
function baseUnit(e: Expr): Unit {
  return e.fn === 'rate' || e.fn === 'scale' ? baseUnit(e.arg) : unitOf(e);
}

/** Whether an expression is a per-second quantity, however it is spelled. */
function perSecond(e: Expr): boolean {
  if (e.fn === 'rate') return true;
  if (e.fn === 'sum') return e.args.every(perSecond);
  if (e.fn === 'scale') return perSecond(e.arg);
  return false;
}

export function unitOf(e: Expr): Unit {
  switch (e.fn) {
    case 'raw':
      return unitOfPath(e.path);
    case 'pct':
      return 'percent';
    case 'rate': {
      const inner = unitOf(e.arg);
      return inner === 'bytes' ? 'bytes/s' : 'per-sec';
    }
    case 'div': {
      // A rate over a rate cancels the per-second and leaves the numerator's own unit:
      // ms/s over ops/s is milliseconds per operation. This is what makes the latency and
      // disk-service-time panels read in time rather than as a bare number.
      //
      // `sum(rate(a), rate(b))` is a rate too -- "all writes per second" is written that way
      // because opcounters are separate. Without this, bytes-of-oplog per write came out as a
      // bare count and the rule declaring it in bytes was rejected, correctly, by the test
      // that checks a rule's declared unit against the one its expression produces.
      if (perSecond(e.num) && perSecond(e.den)) return baseUnit(e.num);
      const n = unitOf(e.num);
      return n === 'per-sec' || n === 'bytes/s' ? 'count' : n;
    }
    case 'scale': {
      const inner = unitOf(e.arg);
      // Time accumulated per unit time is dimensionless -- 1000 ms/s is one core, or one
      // device, fully busy. Scaling to a fraction of that expresses it as a percentage, which
      // is how iostat's %util, CPU usage and flow-control lag are conventionally read. The
      // factor differs only by the base unit: 0.1 for ms/s, 1e-4 for µs/s.
      if (inner === 'per-sec') {
        const base = baseUnit(e.arg);
        if (base === 'ms' && e.k === 0.1) return 'percent';
        if (base === 'us' && e.k === 0.0001) return 'percent';
        // Scaled all the way to a plain ratio rather than a percentage. /proc/diskstats'
        // weighted queue time over elapsed time is the average number of requests in flight --
        // a count, and reading it as "18/s" invites it to be mistaken for an IOPS figure.
        if (base === 'ms' && e.k === 0.001) return 'count';
        if (base === 'us' && e.k === 0.000001) return 'count';
      }
      return inner;
    }
    case 'diff':
      return unitOf(e.a);
    case 'sum':
      return unitOf(e.args[0]!);
    case 'spread':
      // A difference between two values of the same unit keeps that unit. Wall-clock stamps
      // are epoch milliseconds, so the distance between two of them is milliseconds.
      return unitOf(e.args[0]!);
    case 'window':
      return 'seconds';
  }
}

/** Render an expression back to its canonical text form. */
export function exprToString(e: Expr): string {
  switch (e.fn) {
    case 'raw':
      return e.path;
    case 'rate':
      return `rate(${exprToString(e.arg)})`;
    case 'pct':
      return `pct(${exprToString(e.num)}, ${exprToString(e.den)})`;
    case 'div':
      return `div(${exprToString(e.num)}, ${exprToString(e.den)})`;
    case 'diff':
      return `diff(${exprToString(e.a)}, ${exprToString(e.b)})`;
    case 'scale':
      return `scale(${exprToString(e.arg)}, ${e.k})`;
    case 'sum':
      return `sum(${e.args.map(exprToString).join(', ')})`;
    case 'spread':
      return `spread(${e.args.map(exprToString).join(', ')})`;
    case 'window':
      return `window(${exprToString(e.counter)}, ${exprToString(e.size)})`;
  }
}
