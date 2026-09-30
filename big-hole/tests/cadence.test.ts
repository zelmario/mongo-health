/**
 * Rates over counters that are not sampled as often as the capture.
 *
 * The case that produced this: on a real Atlas M10, `systemMetrics.cpu.user_ms` changes once
 * every 300 seconds. Divided by the one-second step it reads as 190 cores of work on a two-core
 * host, and every sizing judgement built on it is wrong by a factor of 300.
 *
 * The risk on the other side is worse than the bug, which is what most of these tests are
 * about: a counter that is genuinely quiet and then spikes must keep its spike. Spreading that
 * burst backwards would erase a real event, and a detector that erases events is not a
 * detector. So the correction only applies where undersampling can be demonstrated from the
 * shape of the whole series.
 */
import { describe, expect, it } from 'vitest';

import { cadenceAwareRate } from '../src/data/cadence.js';

/** Timestamps one second apart, as a capture at the usual cadence produces. */
function seconds(n: number): Float64Array {
  return Float64Array.from({ length: n }, (_, i) => 1_700_000_000_000 + i * 1000);
}

/** A counter that only moves every `stride` samples, by `step` each time. */
function undersampled(n: number, stride: number, step: number): Float64Array {
  return Float64Array.from({ length: n }, (_, i) => Math.floor(i / stride) * step);
}

describe('cadenceAwareRate', () => {
  it('spreads an increment over the interval it actually covers', () => {
    // The real shape: 383,680 ms of CPU appearing every 300 s on a 2-core host.
    // Ten stretches, because three changes are not a cadence: the function refuses to infer
    // one from too little, and that refusal is tested separately below.
    const t = seconds(3000);
    const raw = undersampled(3000, 300, 383_680);

    const rate = cadenceAwareRate(t, raw);
    expect(rate).not.toBeNull();

    const seen = Array.from(rate!).filter((x) => Number.isFinite(x));
    const peak = Math.max(...seen);
    expect(peak).toBeCloseTo(383_680 / 300, 0);
    expect(peak).toBeLessThan(2000); // under two cores, which is the whole point
  });

  it('reports the same rate across the flat stretch, not a spike at the end', () => {
    const rate = cadenceAwareRate(seconds(3000), undersampled(3000, 300, 3000))!;
    const window = Array.from(rate.slice(300, 600));
    expect(new Set(window).size).toBe(1);
    expect(window[0]).toBeCloseTo(10, 6);
  });

  it('leaves a counter that moves every sample alone', () => {
    // Nothing to correct: `rate()` is already right, and returning null says so.
    const t = seconds(100);
    const raw = Float64Array.from({ length: 100 }, (_, i) => i * 7);
    expect(cadenceAwareRate(t, raw)).toBeNull();
  });

  it('keeps a real burst after a quiet stretch', () => {
    // A counter idle for two minutes and then busy is NOT undersampled: the flat part is the
    // truth. Spreading the burst backwards would report a tenth of the load over ten times the
    // window, and the incident would vanish.
    const t = seconds(200);
    const raw = new Float64Array(200);
    for (let i = 0; i < 200; i++) raw[i] = i < 120 ? 0 : (i - 119) * 40;
    expect(cadenceAwareRate(t, raw)).toBeNull();
  });

  it('ignores floating-point noise in the low digits', () => {
    // Decoded values arrive as 154090.00000094384 rather than 154090. Without rounding, every
    // sample looks like a change and nothing is ever detected as undersampled.
    const t = seconds(3000);
    const raw = undersampled(3000, 300, 3000);
    for (let i = 0; i < raw.length; i++) raw[i]! += i * 1e-8;
    expect(cadenceAwareRate(t, raw)).not.toBeNull();
  });

  it('says nothing when there is too little to judge', () => {
    // Three changes cannot establish a stride, and guessing from them would be how a quiet
    // counter gets mistaken for an undersampled one.
    const t = seconds(20);
    const raw = Float64Array.from({ length: 20 }, (_, i) => Math.floor(i / 7) * 100);
    expect(cadenceAwareRate(t, raw)).toBeNull();
  });

  it('refuses an irregular stride', () => {
    // Changes at 1, 4, 5, 12, 13, 30... is activity, not a sampling interval. Only a stride
    // that repeats across most of the series is evidence of a cadence.
    const t = seconds(60);
    const raw = new Float64Array(60);
    let value = 0;
    for (const [i, at] of [1, 4, 5, 12, 13, 30, 44, 45].entries()) {
      value += 10 * (i + 1);
      for (let k = at; k < 60; k++) raw[k] = value;
    }
    expect(cadenceAwareRate(t, raw)).toBeNull();
  });

  it('survives gaps in the capture', () => {
    // NaN where the collector was not running. It must not become a huge negative rate or an
    // invented increment.
    const t = seconds(3000);
    const raw = undersampled(3000, 300, 3000);
    for (let i = 400; i < 430; i++) raw[i] = NaN;

    const rate = cadenceAwareRate(t, raw);
    if (rate !== null) {
      for (const x of rate) expect(Number.isNaN(x) || x >= 0).toBe(true);
    }
  });
});
