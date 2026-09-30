import { describe, expect, it } from 'vitest';

import { DAY_MS, Histogram, dayChart, dayName, dayStart, mergeCharts } from '../src/data/daily';

/** What `tools/analyze.ts` computes from a sorted array -- the reference being replaced. */
function exact(values: number[]) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  const at = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p))]!;
  return {
    n: sorted.length,
    min: sorted[0]!,
    max: sorted[sorted.length - 1]!,
    mean: sorted.reduce((s, v) => s + v, 0) / sorted.length,
    p50: at(0.5),
    p95: at(0.95),
    p99: at(0.99),
  };
}

/** Deterministic, so a failure reproduces. */
function rng(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296;
    return s / 4294967296;
  };
}

function histOf(values: number[]) {
  const h = new Histogram();
  for (const v of values) h.add(v);
  return h;
}

describe('Histogram', () => {
  it('is exact on small integers, which is where gauges like queues live', () => {
    const r = rng(1);
    const values = Array.from({ length: 50_000 }, () => Math.floor(r() * r() * 12));
    expect(histOf(values).quantiles()).toEqual(exact(values));
  });

  it('a median of 1 comes back as 1', () => {
    const values = [0, 0, 1, 1, 1, 1, 2];
    expect(histOf(values).quantiles()!.p50).toBe(1);
  });

  it('stays within the bucket width on continuous values across many decades', () => {
    const r = rng(2);
    const values = Array.from({ length: 100_000 }, () => Math.exp(r() * 20) * (r() < 0.1 ? -1 : 1) + r());
    const got = histOf(values).quantiles()!;
    const want = exact(values);
    expect(got.n).toBe(want.n);
    expect(got.min).toBe(want.min);
    expect(got.max).toBe(want.max);
    expect(got.mean).toBeCloseTo(want.mean, 6);
    for (const p of ['p50', 'p95', 'p99'] as const) {
      expect(Math.abs(got[p] - want[p])).toBeLessThanOrEqual(Math.abs(want[p]) * 0.01);
    }
  });

  it('merging days gives what one histogram over all of them gives', () => {
    const r = rng(3);
    const days = Array.from({ length: 7 }, (_, d) =>
      Array.from({ length: 5_000 }, () => (d + 1) * 1e6 * r() + r()));
    const merged = new Histogram();
    for (const d of days) merged.merge(Histogram.fromJSON(JSON.parse(JSON.stringify(histOf(d).toJSON()))));
    const whole = histOf(days.flat());
    const a = merged.quantiles()!;
    const b = whole.quantiles()!;
    expect(a.n).toBe(b.n);
    expect(a.min).toBe(b.min);
    expect(a.max).toBe(b.max);
    for (const p of ['p50', 'p95', 'p99'] as const) expect(a[p]).toBeCloseTo(b[p], 3);
  });

  it('ignores what summarise ignores', () => {
    const h = histOf([NaN, Infinity, -Infinity, 5]);
    expect(h.quantiles()).toEqual(exact([5]));
    expect(new Histogram().quantiles()).toBeNull();
  });
});

describe('days', () => {
  it('names and bounds days in UTC', () => {
    const ms = Date.parse('2026-09-29T23:59:59.999Z');
    expect(dayName(ms)).toBe('2026-09-29');
    expect(dayStart(ms)).toBe(Date.parse('2026-09-29T00:00:00Z'));
    expect(dayName(ms + 1)).toBe('2026-09-30');
  });

  it('keeps one point per fifteen minutes and leaves empty stretches out', () => {
    const from = Date.parse('2026-09-29T00:00:00Z');
    const t = Array.from({ length: 3600 }, (_, i) => from + i * 1000);
    const v = t.map((_, i) => (i < 1800 ? 10 : 20));
    const c = dayChart(t, v, from);
    expect(c.v).toEqual([10, 10, 20, 20]);
  });

  it('draws a hole where days are missing rather than a line across it', () => {
    const d0 = Date.parse('2026-09-01T00:00:00Z');
    const day = (start: number) => dayChart(
      Array.from({ length: 86_400 / 60 }, (_, i) => start + i * 60_000),
      Array.from({ length: 86_400 / 60 }, () => 1), start);
    const out = mergeCharts([day(d0), day(d0 + 9 * DAY_MS)], 100);
    expect(out.t.length).toBe(100);
    expect(out.v.some((x) => Number.isNaN(x))).toBe(true);
    expect(out.v.filter((x) => !Number.isNaN(x)).every((x) => x === 1)).toBe(true);
  });

  it('marks the hole even when the history has fewer points than the chart is wide', () => {
    const d0 = Date.parse('2026-08-10T00:00:00Z');
    const sparse = { t: [d0, d0 + 60_000, d0 + 5 * DAY_MS, d0 + 5 * DAY_MS + 60_000], v: [1, 2, 3, 4] };
    const out = mergeCharts([sparse], 300);
    expect(out.t.length).toBe(300);
    expect(out.v.filter((x) => Number.isNaN(x)).length).toBeGreaterThan(290);
  });
});
