/**
 * Per-day summaries of a node's tracked metrics, so a run never has to re-read the history.
 *
 * The collector's baseline is "percentiles over everything held for this cluster". Computing
 * that by decoding every FTDC file on every hourly run costs time linear in the retention --
 * measured on a three-node Atlas set, about 24 s per day of history, which crosses the
 * service's 45-minute timeout at around 110 days and a one-hour cadence at around 150. The
 * retention is the thing being sold, so the cost grew exactly where the product delivers.
 *
 * Percentiles do not add up, but histograms do. Each UTC day of each node keeps one histogram
 * per metric; the whole-history percentiles are the merge of the days held. A run decodes only
 * the last two days, rewrites those, and reads the rest from here.
 *
 * The histogram is exact where exactness is cheap and relative where it is not:
 *
 *   - integers up to a million keep their own bucket. Queue lengths, tickets in use,
 *     connections and core counts live there, and a median of 1 has to come back as 1, not as
 *     0.995 rounded the wrong way.
 *   - everything else goes into log buckets 1% wide, and each bucket carries the SUM of what
 *     fell in it, so what comes back is the mean of its members rather than its edge. The
 *     error is bounded by the bucket width and in practice far below it.
 *
 * min, max and mean are exact: they are carried alongside, not read off the buckets.
 *
 * This is a cache, not a record. Every day in it is a day whose raw FTDC is still held, so if
 * the directory is lost it is rebuilt from the raw files on the next run.
 */

const GAMMA = 1.01;
const LOG_GAMMA = Math.log(GAMMA);
const EXACT_LIMIT = 1_000_000;

/** A bucket: how many values fell in it and what they summed to. */
type Bucket = [count: number, sum: number];

export interface HistogramJSON {
  n: number;
  min: number;
  max: number;
  sum: number;
  /** Bucket key -> [count, sum]. See `keyOf` for what a key means. */
  h: Record<string, Bucket>;
}

export interface Quantiles {
  n: number;
  min: number;
  max: number;
  mean: number;
  p50: number;
  p95: number;
  p99: number;
}

/**
 * A bucket's key, as a number because this runs once per sample -- a hundred million times on
 * the first run of a cluster with months of history, where building strings measurably hurt.
 *
 *   |key| <= 1e6    the integer itself, exactly
 *   |key| ~  1e7    a log bucket: 1e7 + k, where k = ceil(log_gamma |v|), negated for v < 0
 *
 * k stays within +/-80,000 for every finite double, so the two ranges never meet.
 */
const LOG_OFFSET = 10_000_000;

function keyOf(v: number): number {
  if (Number.isInteger(v) && Math.abs(v) <= EXACT_LIMIT) return v;
  const k = LOG_OFFSET + Math.ceil(Math.log(Math.abs(v)) / LOG_GAMMA);
  return v > 0 ? k : -k;
}

export class Histogram {
  n = 0;
  min = Infinity;
  max = -Infinity;
  sum = 0;
  private readonly buckets = new Map<number, Bucket>();

  add(v: number): void {
    if (!Number.isFinite(v)) return;
    this.n += 1;
    this.sum += v;
    if (v < this.min) this.min = v;
    if (v > this.max) this.max = v;
    const key = keyOf(v);
    const b = this.buckets.get(key);
    if (b) {
      b[0] += 1;
      b[1] += v;
    } else {
      this.buckets.set(key, [1, v]);
    }
  }

  merge(other: Histogram | HistogramJSON): void {
    if (other.n === 0) return;
    this.n += other.n;
    this.sum += other.sum;
    this.min = Math.min(this.min, other.min);
    this.max = Math.max(this.max, other.max);
    const entries: Iterable<[number, Bucket]> = other instanceof Histogram
      ? other.buckets.entries()
      : Object.entries(other.h).map(([k, b]) => [Number(k), b] as [number, Bucket]);
    for (const [key, [count, sum]] of entries) {
      const b = this.buckets.get(key);
      if (b) {
        b[0] += count;
        b[1] += sum;
      } else {
        this.buckets.set(key, [count, sum]);  // a copy: the caller's array stays theirs
      }
    }
  }

  /**
   * The same ranks `summarise` takes from a sorted array: element floor((n - 1) * p).
   *
   * Buckets are ordered by the mean of their members. Exact buckets and log buckets never
   * overlap in a way that matters: an exact bucket holds one value, and a log bucket's members
   * all lie within 1% of each other.
   */
  quantiles(): Quantiles | null {
    if (this.n === 0) return null;
    const sorted = [...this.buckets.values()]
      .map(([count, sum]) => ({ count, value: sum / count }))
      .sort((a, b) => a.value - b.value);
    const at = (p: number): number => {
      const rank = Math.floor((this.n - 1) * p);
      let seen = 0;
      for (const b of sorted) {
        seen += b.count;
        if (rank < seen) return Math.min(this.max, Math.max(this.min, b.value));
      }
      return this.max;
    };
    return {
      n: this.n,
      min: this.min,
      max: this.max,
      mean: this.sum / this.n,
      p50: at(0.5),
      p95: at(0.95),
      p99: at(0.99),
    };
  }

  toJSON(): HistogramJSON {
    // Sums rounded to keep the files small; a sum is only ever divided back by its count.
    const h: Record<string, Bucket> = {};
    for (const [key, [count, sum]] of this.buckets) h[key] = [count, Number(sum.toPrecision(12))];
    return { n: this.n, min: this.min, max: this.max, sum: this.sum, h };
  }

  static fromJSON(json: HistogramJSON): Histogram {
    const out = new Histogram();
    out.merge(json);
    return out;
  }
}

/* ------------------------------------------------------------------------ days ---- */

export const DAY_MS = 86_400_000;

/** Midnight UTC of the day `ms` falls in. */
export function dayStart(ms: number): number {
  return Math.floor(ms / DAY_MS) * DAY_MS;
}

/** `YYYY-MM-DD` of the UTC day `ms` falls in. */
export function dayName(ms: number): string {
  return new Date(dayStart(ms)).toISOString().slice(0, 10);
}

/** Points per day kept for the profile chart: one every fifteen minutes. */
export const DAY_CHART_BUCKETS = 96;

export interface DayChart {
  t: number[];
  v: number[];
}

/**
 * Fifteen-minute means of one day of a series, for the profile report's chart.
 *
 * The report draws the whole history in a few hundred points, so a day never needs more than
 * this. Empty buckets are left out rather than carried as NaN: the merge re-buckets anyway.
 */
export function dayChart(t: ArrayLike<number>, v: ArrayLike<number>, from: number): DayChart {
  const width = DAY_MS / DAY_CHART_BUCKETS;
  const sumT = new Float64Array(DAY_CHART_BUCKETS);
  const sumV = new Float64Array(DAY_CHART_BUCKETS);
  const count = new Uint32Array(DAY_CHART_BUCKETS);
  for (let i = 0; i < t.length; i++) {
    const x = v[i]!;
    if (!Number.isFinite(x)) continue;
    const b = Math.floor((t[i]! - from) / width);
    if (b < 0 || b >= DAY_CHART_BUCKETS) continue;
    sumT[b] = sumT[b]! + t[i]!;
    sumV[b] = sumV[b]! + x;
    count[b] = count[b]! + 1;
  }
  const out: DayChart = { t: [], v: [] };
  for (let b = 0; b < DAY_CHART_BUCKETS; b++) {
    if (count[b] === 0) continue;
    out.t.push(Math.round(sumT[b]! / count[b]!));
    out.v.push(Math.round((sumV[b]! / count[b]!) * 100) / 100);
  }
  return out;
}

/**
 * Many days of chart points into `width` evenly spaced means, for the whole-history chart.
 *
 * Buckets that received nothing are carried as NaN, which is how the report already draws a
 * hole in a capture: a node that was down for a week must not be drawn as a straight line
 * across it.
 */
export function mergeCharts(days: DayChart[], width: number): DayChart {
  const t: number[] = [];
  const v: number[] = [];
  for (const d of days) {
    for (let i = 0; i < d.t.length; i++) {
      t.push(d.t[i]!);
      v.push(d.v[i]!);
    }
  }
  if (t.length === 0) return { t: [], v: [] };
  const first = Math.min(...t);
  const last = Math.max(...t);
  // No shortcut for "fewer points than the width": a sparse history is exactly the one with
  // days missing, and handing back the points as they are would draw a line across the hole.
  if (last === first) return { t, v };

  const step = (last - first) / width;
  const sumT = new Float64Array(width);
  const sumV = new Float64Array(width);
  const count = new Uint32Array(width);
  for (let i = 0; i < t.length; i++) {
    const b = Math.min(width - 1, Math.floor((t[i]! - first) / step));
    sumT[b] = sumT[b]! + t[i]!;
    sumV[b] = sumV[b]! + v[i]!;
    count[b] = count[b]! + 1;
  }
  const out: DayChart = { t: [], v: [] };
  for (let b = 0; b < width; b++) {
    if (count[b] === 0) {
      out.t.push(Math.round(first + (b + 0.5) * step));
      out.v.push(NaN);
    } else {
      out.t.push(Math.round(sumT[b]! / count[b]!));
      out.v.push(Math.round((sumV[b]! / count[b]!) * 100) / 100);
    }
  }
  return out;
}

/** One node, one UTC day. What gets written to `daily/<node>/<YYYY-MM-DD>.json`. */
export interface DaySummary {
  format: number;
  day: string;
  hostname?: string;
  version?: string;
  fromMs: number;
  toMs: number;
  samples: number;
  cadenceMs: number;
  /** Gaps that ENDED this day. A gap is only known once the next sample arrives. */
  gaps: Array<{ fromMs: number; toMs: number; seconds: number; missingSamples: number }>;
  /** Canonical name -> the path it resolved to and its histogram. */
  metrics: Record<string, { resolved: string; hist: HistogramJSON }>;
  /** Canonical name -> fifteen-minute means, for the charted subset only. */
  charts: Record<string, DayChart>;
}

export const DAILY_FORMAT = 1;
