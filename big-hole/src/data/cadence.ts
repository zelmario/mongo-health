/**
 * A rate that survives a counter being sampled less often than the capture.
 *
 * `rate()` divides each step by the interval between samples, which is right when the counter
 * moves on every sample. It is badly wrong when it does not. On a real Atlas M10,
 * `systemMetrics.cpu.user_ms` only changes **every 300 seconds**: five minutes of repeated
 * readings, then a jump of 383,680 ms. Divided by one second that reads as 190 cores of work on
 * a two-core host; divided by the 300 seconds it actually covers it is 1.28 cores, which is
 * both plausible and true.
 *
 * The same capture samples memory, disks and everything under `serverStatus` every second, so
 * this is not "Atlas behaves differently" -- it is one metric family on one deployment, and
 * another Atlas capture in the same collection does not do it. Nothing here may key off the
 * provider: a self-hosted mongod can be configured any way its operator likes, and the customer
 * has to be able to bring one. So the cadence is measured, per metric, per capture.
 *
 * Only applied when a metric is *consistently* undersampled -- most of its changes separated by
 * the same stride. A counter that happens to be quiet for a while is a different thing: there
 * the flat stretch is the truth, and spreading a later burst back across it would erase a real
 * spike. That distinction is why this looks at the shape of the whole series rather than at
 * each gap on its own.
 */
export function cadenceAwareRate(t: Float64Array, raw: Float64Array): Float64Array | null {
  const CONSISTENT = 0.7;

  // Rounded: decoded values carry floating-point noise in their low digits, and without this
  // every sample looks like a change.
  const value = Array.from(raw).map((x) => (Number.isFinite(x) ? Math.round(x) : NaN));

  const changes: number[] = [];
  for (let i = 1; i < value.length; i++) {
    if (Number.isFinite(value[i]!) && Number.isFinite(value[i - 1]!) && value[i] !== value[i - 1]) {
      changes.push(i);
    }
  }
  if (changes.length < 4) return null;

  const strides = new Map<number, number>();
  for (let k = 1; k < changes.length; k++) {
    const stride = changes[k]! - changes[k - 1]!;
    strides.set(stride, (strides.get(stride) ?? 0) + 1);
  }
  let mode = 0;
  let seen = 0;
  for (const [stride, count] of strides) if (count > seen) { mode = stride; seen = count; }

  // Every sample carries a change: the ordinary case, and `rate()` is already right.
  if (mode <= 1 || seen / (changes.length - 1) < CONSISTENT) return null;

  // Spread each increment back over the interval it actually covers.
  const out = new Float64Array(value.length).fill(NaN);
  for (let k = 1; k < changes.length; k++) {
    const from = changes[k - 1]!;
    const to = changes[k]!;
    const seconds = (t[to]! - t[from]!) / 1000;
    if (!(seconds > 0)) continue;
    const perSecond = (value[to]! - value[from]!) / seconds;
    for (let i = from; i < to; i++) out[i] = perSecond;
  }
  return out;
}
