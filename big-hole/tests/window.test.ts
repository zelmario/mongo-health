/**
 * `window()` — how far back the last `size` bytes of a cumulative counter reach.
 *
 * Written for the oplog window. Size over the current rate swung from 1,000 hours to 19 in a
 * day on a real capture; the window a secondary actually has is what the history says.
 */
import { describe, expect, it } from 'vitest';

import { evaluate, exprToString, parseExpr, unitOf } from '../src/data/expr.js';

const C = 'local.oplog.rs.stats.storageStats.wiredTiger.cursor.insert key and value bytes';
const S = 'local.oplog.rs.stats.storageStats.maxSize';
const EXPR = parseExpr(`window(${C}, ${S})`);
const MIN = 60_000;

/** One sample a minute, the counter from `bytesPerMin`, a fixed oplog size. */
function run(bytesPerMin: (i: number) => number, minutes: number, size: number,
             reset?: number): number[] {
  const t = new Float64Array(minutes);
  const c = new Float64Array(minutes);
  let acc = 0;
  for (let i = 0; i < minutes; i++) {
    t[i] = i * MIN;
    if (i > 0) acc += bytesPerMin(i);
    if (i === reset) acc = 0;
    c[i] = acc;
  }
  const raw = new Map([[C, c], [S, new Float64Array(minutes).fill(size)]]);
  return Array.from(evaluate(EXPR, t, raw));
}

describe('window', () => {
  it('parses, prints back, and is measured in seconds', () => {
    expect(exprToString(EXPR)).toBe(`window(${C}, ${S})`);
    expect(unitOf(EXPR)).toBe('seconds');
  });

  it('is exact once the history covers the oplog', () => {
    // 1,000 bytes a minute into a 30,000-byte oplog: thirty minutes of window.
    const w = run(() => 1000, 180, 30_000);
    expect(w.at(-1)).toBeCloseTo(30 * 60, 6);
  });

  it('reads the past, not the present', () => {
    // Two hours quiet, then a burst that fills the whole oplog in ten minutes. Size over the
    // current rate would also say ten minutes; the point is that it says it from the history,
    // and that one hour after the burst stops the window is still bounded by it.
    const w = run((i) => (i >= 120 && i < 130 ? 10_000 : 10), 200, 100_000);
    expect(w[129]! / 60).toBeLessThan(11);
    expect(w[190]! / 60).toBeGreaterThan(60);
    expect(w[190]! / 60).toBeLessThan(80);
  });

  it('extrapolates over the whole history when the oplog reaches past it', () => {
    // Two hours at 1,000 bytes a minute against a million-byte oplog: 1,000 minutes.
    const w = run(() => 1000, 121, 1_000_000);
    expect(w.at(-1)! / 60).toBeCloseTo(1000, 0);
  });

  it('says nothing from under an hour of history', () => {
    const w = run(() => 1000, 50, 1_000_000);
    expect(w.every(Number.isNaN)).toBe(true);
  });

  it('does not count a restart as the oplog emptying', () => {
    // The counter falls to zero at minute 90; the bytes before it are still in the oplog. The
    // minute of the restart itself is unseen, so the window reads one minute long -- and not
    // ten, which is what counting from zero would say.
    const w = run(() => 1000, 180, 30_000, 90);
    expect(w[100]! / 60).toBeCloseTo(31, 0);
  });

  it('is NaN where the oplog size is unknown', () => {
    const t = Float64Array.from([0, MIN, 2 * MIN]);
    const raw = new Map([[C, Float64Array.from([0, 10, 20])], [S, new Float64Array(3)]]);
    expect(Array.from(evaluate(EXPR, t, raw)).every(Number.isNaN)).toBe(true);
  });
});
