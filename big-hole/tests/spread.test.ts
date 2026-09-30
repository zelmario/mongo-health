/**
 * `spread()` — the distance between the highest and lowest of several series.
 *
 * Written for replication lag, and the reason it exists is a measurement: comparing members
 * against the clock reported six seconds of lag on an idle set and less during a real
 * incident. Comparing them against each other reports zero when they are in sync, whether or
 * not anybody is writing.
 */
import { describe, expect, it } from 'vitest';

import { evaluate, parseExpr, unitOf } from '../src/data/expr.js';
import { expandMetric } from '../src/dashboard/layout.js';

const MEMBERS = ['replSetGetStatus.members.0.optimeDate',
                 'replSetGetStatus.members.1.optimeDate',
                 'replSetGetStatus.members.2.optimeDate'];
const TEMPLATE = 'spread(replSetGetStatus.members.*.optimeDate)';

function series(...values: number[][]): ReadonlyMap<string, Float64Array> {
  return new Map(values.map((v, i) => [MEMBERS[i]!, Float64Array.from(v)]));
}

const t = Float64Array.from([0, 1000, 2000]);

function run(raw: ReadonlyMap<string, Float64Array>): number[] {
  const resolved = `spread(${[...raw.keys()].join(', ')})`;
  return Array.from(evaluate(parseExpr(resolved), t, raw));
}

describe('spread', () => {
  it('is zero when the members agree, however stale they all are', () => {
    // The case the old approach got wrong: nobody is writing, so every member is equally
    // behind the clock — and perfectly in sync with each other.
    const old = 1_700_000_000_000;
    expect(run(series([old, old, old], [old, old, old], [old, old, old])))
      .toEqual([0, 0, 0]);
  });

  it('measures how far apart the furthest two are', () => {
    const now = 1_700_000_000_000;
    const out = run(series([now, now, now],
                           [now, now - 5000, now - 30_000],
                           [now, now - 1000, now - 2000]));
    expect(out).toEqual([0, 5000, 30_000]);
  });

  it('ignores a member that is not reporting yet', () => {
    // Zero is absence, not 1970. Counting it puts the spread at the whole epoch, and that
    // number then becomes the maximum of the cluster's baseline for ever.
    const now = 1_700_000_000_000;
    const out = run(series([now, now, now], [0, 0, 0], [now - 1000, now, now]));
    expect(out).toEqual([1000, 0, 0]);
  });

  it('refuses to answer when fewer than two members are readable', () => {
    // Not a spread of zero: no measurement. A set where two of three stopped reporting must
    // not look perfectly in sync at the moment it stopped being so.
    const now = 1_700_000_000_000;
    const out = run(series([now, now, now], [NaN, NaN, NaN], [NaN, 0, now - 4000]));
    expect(out[0]).toBeNaN();
    expect(out[1]).toBeNaN();
    expect(out[2]).toBe(4000);
  });

  it('expands a wildcard into arguments rather than into separate expressions', () => {
    // Every other function wants one result per member; this one is the comparison itself.
    expect(expandMetric(TEMPLATE, new Set(MEMBERS), [''])).toEqual([
      `spread(${MEMBERS.join(', ')})`,
    ]);
  });

  it('produces nothing for a set with one member', () => {
    expect(expandMetric(TEMPLATE, new Set([MEMBERS[0]!]), [''])).toEqual([]);
  });

  it('reports milliseconds, because the difference of two wall-clock stamps is a duration', () => {
    expect(unitOf(parseExpr(TEMPLATE))).toBe('ms');
  });
});

describe('rate across a gap in the capture', () => {
  it('refuses to turn a four-hour interruption into a rate', () => {
    // The measured case: a laptop suspended mid-capture. The counter kept climbing while
    // nothing was sampled, and the first sample back carried all of it.
    const t = Float64Array.from([0, 1000, 2000, 4 * 3600_000, 4 * 3600_000 + 1000]);
    const v = Float64Array.from([0, 10, 20, 900_000, 900_010]);

    const out = Array.from(evaluate(parseExpr('rate(x)'), t, new Map([['x', v]])));
    expect(out[1]).toBe(10);           // normal steps are untouched
    expect(out[2]).toBe(10);
    expect(out[3]).toBeNaN();          // the step across the gap is not a rate
    expect(out[4]).toBe(10);           // and the series resumes
  });

  it('keeps a ratio honest across the same gap', () => {
    // This is what actually produced the bad finding: the numerator advanced across the gap
    // and the denominator barely did, so the division read as four hours per operation.
    const t = Float64Array.from([0, 1000, 4 * 3600_000, 4 * 3600_000 + 1000]);
    const ms = Float64Array.from([0, 5, 14_000_000, 14_000_005]);
    const ops = Float64Array.from([0, 1, 2, 3]);

    const out = Array.from(evaluate(
      parseExpr('div(rate(ms), rate(ops))'), t, new Map([['ms', ms], ['ops', ops]])));
    expect(out[2]).toBeNaN();
    expect(out[3]).toBe(5);
  });

  it('leaves an evenly sampled series alone', () => {
    const t = Float64Array.from([0, 1000, 2000, 3000]);
    const v = Float64Array.from([0, 3, 6, 9]);
    const out = Array.from(evaluate(parseExpr('rate(v)'), t, new Map([['v', v]])));
    expect(out.slice(1)).toEqual([3, 3, 3]);
  });
});

describe('32-bit counters that wrap', () => {
  const W = 2 ** 32;

  it('recovers the real increment instead of reporting the wrap', () => {
    // The measured case, to the millisecond: /proc/diskstats write_time_ms on a real capture.
    const t = Float64Array.from([0, 1000, 2000, 3029]);
    const v = Float64Array.from([-2130924618, -2130923417, -2130922216, 2164050247 - 1201]);

    const out = Array.from(evaluate(parseExpr('rate(v)'), t, new Map([['v', v]])));
    expect(out[3]).toBeGreaterThan(0);
    expect(out[3]).toBeLessThan(100_000);   // milliseconds per second, not four hours
  });

  it('leaves a genuine large step alone', () => {
    // Far above the wrap window: this is real data movement, not a counter turning over.
    const t = Float64Array.from([0, 1000]);
    const v = Float64Array.from([0, W * 3]);
    const out = Array.from(evaluate(parseExpr('rate(v)'), t, new Map([['v', v]])));
    expect(out[1]).toBe(W * 3);
  });

  it('still treats a real restart as a break', () => {
    // A counter going backwards is a process restart, and the delta means nothing.
    const t = Float64Array.from([0, 1000]);
    const v = Float64Array.from([5000, 10]);
    expect(Array.from(evaluate(parseExpr('rate(v)'), t, new Map([['v', v]])))[1]).toBeNaN();
  });
});
