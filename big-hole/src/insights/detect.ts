/**
 * Pathology detection: the questions an engineer asks of every capture, asked automatically.
 *
 * A dashboard answers "what did this metric do". It does not answer "was anything wrong",
 * and on a 44-panel dashboard over 42 hours that second question is answered by scrolling and
 * squinting. Every support engineer opening an FTDC bundle runs the same handful of checks
 * first -- did the ticket pool empty, did the cache go dirty, did the queues build -- and
 * those checks are mechanical. This runs them.
 *
 * Three properties matter more than the rule list, which will always be incomplete:
 *
 * **Detection is conservative under downsampling.** A finding is read off the min/max envelope,
 * not full resolution, because reading 42 hours of full-resolution data for a dozen rules would
 * cost more than the dashboard does. That is only sound if the envelope cannot manufacture a
 * finding, so each test reads the column that makes it pessimistic: `<= threshold` reads the
 * bucket's MAX -- the whole bucket must have stayed at or below -- and `>=` reads its MIN.
 * Downsampling can then hide a short episode, never invent one. A tool that cries wolf on a
 * healthy capture gets switched off, and then it catches nothing at all.
 *
 * **Nothing is keyed to a version.** Rules name metrics the way dashboard templates do and
 * resolve through the same `expandMetric`, so aliases and role prefixes apply and a rule
 * written against 6.0 fires on 8.0 where the metric was renamed. A rule that cannot resolve
 * produces no finding rather than a wrong one.
 *
 * **Episodes aggregate, but only within an incident.** A saturating ticket pool flaps -- dozens
 * of separate crossings in a minute. Reporting each as its own finding buries the other rules,
 * so nearby episodes collapse into one finding carrying the count, the time spent in the state,
 * and the worst stretch to jump to.
 *
 * "Nearby" is the part that had to be learnt. Collapsing ALL of them produced a single finding
 * spanning 26 hours, which then overlapped every incident in the day: measured against a soak
 * run with a known timeline, the same handful of findings appeared to explain all 25 injected
 * incidents, including the ones nothing had detected. A finding that covers everything explains
 * nothing, and it also makes the report unreadable -- "checkpoints slow, yesterday, 10.6 h" is
 * not something anybody can act on.
 *
 * So episodes separated by more than `SEPARATE_INCIDENTS_MS` become separate findings. The
 * cluster had two bad afternoons, not one two-day outage.
 */

import { detectRolePrefixes, expandMetric } from '../dashboard/layout.js';
import type { Unit } from '../data/expr.js';
import type { SeriesQuery } from '../data/reader.js';
import type { SeriesPayload } from '../workers/protocol.js';

export type Severity = 'critical' | 'warning' | 'info';

/**
 * One pathology, as data.
 *
 * Deliberately declarative -- no predicates, no callbacks. Rules live in `rules.ts` and must
 * stay readable by someone who knows MongoDB and not this codebase, because that is who will
 * need to add the twentieth one.
 */
export interface Rule {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  /** Metric expression, written exactly as a dashboard template would write it. */
  readonly metric: string;
  readonly op: '<=' | '>=';
  readonly threshold: number;
  /** How long the condition must hold, in total, before it is worth reporting. */
  readonly sustainMs: number;
  /**
   * Recovery shorter than this does not end an episode.
   *
   * Real pathologies flap. WiredTiger's eviction pulls dirty cache back below its trigger within
   * seconds and lets it climb again; a ticket pool empties and refills. Measured on a capture
   * that spent 377 seconds above the 20% dirty trigger and peaked at 36%: the longest *unbroken*
   * stretch was 30 s, so a rule needing 60 s of unbroken breach reported nothing at all. Requiring
   * an unbroken run does not make a detector conservative, it makes it blind to the shape real
   * incidents have.
   *
   * The honesty is preserved elsewhere: `sustainMs` is compared against time actually spent in
   * breach, never against the bridged span, so tolerating a dip can extend an episode but can
   * never invent one. Omit for a condition that genuinely should be continuous.
   */
  readonly toleranceMs?: number;
  readonly unit: Unit;
  /**
   * The metric is the ECHO of an event, not a condition that lasts.
   *
   * `checkpoint most recent time (msecs)` is the case that revealed this: it holds the
   * duration of the last checkpoint until the next one finishes, so a single three-second
   * checkpoint leaves the metric at 3000 for the whole minute that follows. Counting time in
   * state over that measures how long the last checkpoint was slow, not how long checkpoints
   * were slow -- on a real capture it reported "10.6 hours" for what was actually 620 slow
   * checkpoints out of 865, the worst of them 35.7 seconds.
   *
   * Detection is unchanged: the condition is still real and still worth reporting. What
   * changes is the arithmetic that gets shown, because a duration here is a category error.
   * `occurrences` counts distinct values seen in breach -- one per event -- and `observed`
   * counts every event in the window, so the finding can say "620 of 865" instead of an
   * elapsed time that means nothing.
   */
  readonly echoesAnEvent?: boolean;
  /**
   * A second condition that must hold at the same moment, or nothing is reported.
   *
   * Added because one metric was not enough to tell two different mornings apart.
   * `command-latency-high` reads the average microseconds a command costs, and that number goes
   * up for two unrelated reasons: the server is slow, or the WIRE is slow -- the commands
   * bucket counts awaitable and handshake traffic, so a degraded network inflates it while the
   * server is perfectly healthy.
   *
   * Measured on the same replica set, one rule, two injected pathologies:
   *
   *   plan cache churn (the server IS slow)   us/command 10,576   us/read 72,855
   *   netem on loopback (the network is slow) us/command 22,502   us/read     850
   *
   * The reads bucket is the one that separates them, and it separates them by two orders of
   * magnitude. Without this the rule reported "commands are taking milliseconds each" through a
   * network fault -- pointing a reader at the database, which is the one thing the network
   * scenario exists to catch a monitor doing.
   *
   * A rule that asks for a second condition and cannot read it reports nothing: the claim it
   * makes is about both metrics, and half of it is not a weaker version of it.
   */
  readonly alongside?: {
    readonly metric: string;
    readonly op: '<=' | '>=';
    readonly threshold: number;
  };
  /**
   * A second condition that must have held at some moment of the episode, not at every one.
   *
   * For a consequence that comes in bursts. "The read ticket pool was saturated, so reads
   * queued" is only true if something queued; but the queue is spiky. On a real capture it was
   * non-zero in 3 to 11% of the seconds a saturated episode lasted, peaking at 17 to 40 --
   * required at every moment, as `alongside` does, every one of those episodes vanished. Held
   * anywhere inside the episode, it separates them from four scans holding half of an
   * eight-ticket pool with nothing waiting, which is load, not saturation.
   */
  readonly during?: {
    readonly metric: string;
    readonly op: '<=' | '>=';
    readonly threshold: number;
  };
  /** What it means, in one sentence. */
  readonly what: string;
  /** What to look at next. */
  readonly check: string;
}

export interface Finding {
  readonly ruleId: string;
  readonly title: string;
  readonly severity: Severity;
  readonly captureId: string;
  readonly captureLabel: string;
  /** The expression that actually resolved, which may be an alias of the rule's. */
  readonly metric: string;
  /** Separate stretches where the condition held. */
  readonly episodes: number;
  /** Span from the first episode's start to the last one's end. */
  readonly firstMs: number;
  readonly lastMs: number;
  /** The longest single episode -- the one worth jumping to. */
  readonly worstFromMs: number;
  readonly worstToMs: number;
  /** Time spent in the state, summed across episodes. */
  readonly totalMs: number;
  /** Most extreme value observed while the condition held. */
  readonly peak: number;
  /** For `echoesAnEvent` rules: how many events breached, and how many there were. */
  readonly occurrences?: number;
  readonly observed?: number;
  readonly unit: Unit;
  readonly what: string;
  readonly check: string;
}

/** What detection needs to know about a loaded capture. */
export interface DetectCapture {
  readonly id: string;
  readonly label: string;
  readonly paths: ReadonlySet<string>;
}

export interface DetectSource {
  series(captureId: string, expressions: string[], query: SeriesQuery): Promise<SeriesPayload[]>;
}

interface Episode {
  readonly fromMs: number;
  readonly toMs: number;
  readonly peak: number;
  /** Time actually spent in breach, which is less than `toMs - fromMs` when dips were bridged. */
  readonly inStateMs: number;
}

/**
 * Stretches where the condition held for at least `sustainMs` in total.
 *
 * `guard` is the conservative envelope column -- the one that must satisfy the test for the
 * whole bucket to count -- and `extreme` is the opposite one, used only to report how bad it
 * got. A NaN breaks the run outright: a gap in the capture is not evidence that the condition
 * continued across it, and treating it as such is how a detector reports a five-hour ticket
 * outage because the collector stopped for five hours.
 *
 * A recovery shorter than `toleranceMs` does not end the episode -- see `Rule.toleranceMs` for
 * why, and for the capture that made it necessary. Two properties keep that from becoming a
 * licence to invent findings:
 *
 *  - the qualifying test is on **time spent in breach**, not on the bridged span, so bridging a
 *    dip can join two halves of one episode but cannot manufacture duration that never happened;
 *  - an episode's reported window still starts and ends on samples that were in breach.
 *
 * Each in-breach sample contributes the interval up to the next sample, so a single sample
 * counts for one sample period rather than zero. On a 1 s clock that is the difference between
 * "377 seconds above the eviction trigger" and a detector that says nothing.
 */
export function episodesOf(
  t: Float64Array,
  guard: Float64Array,
  extreme: Float64Array,
  op: '<=' | '>=',
  threshold: number,
  sustainMs: number,
  toleranceMs = 0,
): Episode[] {
  const holds = (v: number): boolean => (op === '<=' ? v <= threshold : v >= threshold);
  const worse = (a: number, b: number): number =>
    op === '<=' ? Math.min(a, b) : Math.max(a, b);

  // The usual interval between samples AT EACH POINT, from the middle of the sorted gaps of its
  // block so that the holes themselves cannot drag it upwards. Computed rather than taken from
  // the first pair: a capture that begins right before an interruption would otherwise adopt
  // the interruption as its normal.
  //
  // Per block, not one for the whole series: a member polled at 1 s and then at 5 s took the
  // 1 s median over everything, every 5 s interval after the change read as a hole, and no
  // rule with a sustain could fire on that member until the 1 s files aged out.
  const steps = localSteps(t);
  const stepAt = (i: number): number => steps[Math.min(Math.max(i, 1), steps.length - 1)] ?? 1;

  // Past twice the local step, the samples either side are not consecutive: the collector
  // stopped, the host was suspended, the file rotated. What happened in between is UNKNOWN,
  // and an episode may not be carried across it.
  //
  // This is the difference between "the ticket pool was saturated for 35 minutes" and "for
  // 5.9 hours". Measured against a soak run with a known timeline, checkpoint findings were
  // reporting 638 minutes for a 3-minute incident -- 200x -- because a single sample before a
  // four-hour suspension claimed the whole suspension as time in state.

  const out: Episode[] = [];
  let start = -1; // first in-breach sample of the open episode
  let last = -1; // most recent in-breach sample
  let peak = NaN;
  let inStateMs = 0;

  const close = (): void => {
    if (start < 0) return;
    if (inStateMs >= sustainMs) {
      out.push({ fromMs: t[start]!, toMs: t[last]!, peak, inStateMs });
    }
    start = -1;
    last = -1;
    inStateMs = 0;
  };

  for (let i = 0; i <= t.length; i++) {
    // A jump in the clock is a hole even when both samples are readable: the collector was not
    // running in between, so there is no evidence about what the metric did.
    const jumped = i > 0 && i < t.length && t[i]! - t[i - 1]! > 2 * stepAt(i);
    const gapHere = i >= t.length || Number.isNaN(guard[i]!) || jumped;
    if (gapHere) {
      // A hole in the capture, or the end of it. Neither is evidence either way.
      close();
      // The sample after a jump is real and may open a new episode; it just cannot continue
      // the old one. Falling through re-reads it with the episode already closed.
      if (jumped && !Number.isNaN(guard[i]!)) {
        if (holds(guard[i]!)) {
          start = i;
          last = i;
          peak = Number.isNaN(extreme[i]!) ? guard[i]! : extreme[i]!;
          inStateMs = stepAt(i + 1);
        }
      }
      continue;
    }

    if (holds(guard[i]!)) {
      const value = Number.isNaN(extreme[i]!) ? guard[i]! : extreme[i]!;
      peak = start < 0 ? value : worse(peak, value);
      if (start < 0) start = i;
      // The interval this sample stands for, CAPPED at the usual step. Uncapped, the last
      // sample before an interruption claimed the whole interruption -- which is how three
      // minutes of slow checkpoints became ten hours.
      const step = stepAt(i + 1);
      const ahead = i + 1 < t.length ? t[i + 1]! - t[i]! : step;
      inStateMs += Math.min(ahead, step);
      last = i;
      continue;
    }

    // Out of breach. Keep the episode open while the recovery is shorter than the tolerance.
    if (start >= 0 && t[i]! - t[last]! > toleranceMs) close();
  }

  return out;
}

/** Intervals per block when finding the usual step; see `localSteps`. */
const STEP_BLOCK = 32;

/**
 * The usual sampling interval in force at each point of `t`: `out[i]` is the step for the
 * interval that ends at sample `i` (`out[0]` repeats `out[1]`).
 *
 * The lower median of the block of STEP_BLOCK intervals that holds it. A hole is one interval
 * in its block and cannot move the median; a change of polling interval moves it from the first whole
 * block after the change, so at most one block straddles the two clocks. Never below 1 ms.
 */
function localSteps(t: Float64Array): Float64Array {
  const out = new Float64Array(Math.max(t.length, 1)).fill(1);
  const n = t.length - 1; // intervals
  for (let from = 1; from <= n; from += STEP_BLOCK) {
    const to = Math.min(from + STEP_BLOCK, n + 1);
    // A short last block is measured over the last whole block's worth of intervals: two
    // intervals, one of them a hole, would otherwise make the hole the usual step.
    const block: number[] = [];
    for (let i = Math.max(1, to - STEP_BLOCK); i < to; i++) block.push(t[i]! - t[i - 1]!);
    block.sort((a, b) => a - b);
    out.fill(Math.max(1, block[Math.floor((block.length - 1) / 2)]!), from, to);
  }
  if (t.length > 1) out[0] = out[1]!;
  return out;
}

/**
 * How far apart two episodes have to be before they are different incidents.
 *
 * An hour: long enough that the flapping of a single bad stretch stays together, short enough
 * that yesterday's trouble and today's are told apart. A cluster with slow checkpoints every
 * afternoon should produce one finding per afternoon, not one that spans the week.
 */
const SEPARATE_INCIDENTS_MS = 3_600_000;

const RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

/**
 * Every rule, against every capture that can resolve it.
 *
 * One read per capture regardless of the rule count: the storage layer is explicit that reads
 * must be planned and issued together, and a dozen serialised round trips per node is exactly
 * the shape it warns about.
 */
export async function detect(
  source: DetectSource,
  captures: readonly DetectCapture[],
  rules: readonly Rule[],
  query: SeriesQuery,
): Promise<Finding[]> {
  const perCapture = await Promise.all(
    captures.map(async (capture): Promise<Finding[]> => {
      const prefixes = detectRolePrefixes(capture.paths);

      // A rule may expand to several series -- a glob over disks or mounts -- and two rules may
      // want the same expression. Ask for each distinct one once.
      const wanted: Array<{ rule: Rule; expression: string; alongside: string | undefined;
                            during: string | undefined }> = [];
      for (const rule of rules) {
        // The second condition resolves through the same expansion as the first, so it gets
        // aliases and role prefixes too. It is not globbed: one companion series, or none.
        const companion = rule.alongside
          ? expandMetric(rule.alongside.metric, capture.paths, prefixes)[0]
          : undefined;
        if (rule.alongside && companion === undefined) continue;
        // Same for the condition required somewhere inside the episode: unreadable, the claim
        // cannot be made, so the rule says nothing rather than half of it.
        const during = rule.during
          ? expandMetric(rule.during.metric, capture.paths, prefixes)[0]
          : undefined;
        if (rule.during && during === undefined) continue;
        for (const expression of expandMetric(rule.metric, capture.paths, prefixes)) {
          wanted.push({ rule, expression, alongside: companion, during });
        }
      }
      if (wanted.length === 0) return [];

      const expressions = [...new Set(wanted.flatMap(
        (w) => [w.expression, w.alongside, w.during].filter((x): x is string => x !== undefined)))];
      let payloads: SeriesPayload[];
      try {
        payloads = await source.series(capture.id, expressions, query);
      } catch {
        // A node that cannot be read is not a node with no pathologies, but reporting a read
        // failure as a finding would be worse than saying nothing. The dashboard already
        // surfaces per-capture read errors.
        return [];
      }

      const byExpression = new Map<string, SeriesPayload>();
      for (let i = 0; i < expressions.length; i++) {
        const payload = payloads[i];
        if (payload !== undefined) byExpression.set(expressions[i]!, payload);
      }

      const found: Finding[] = [];
      for (const { rule, expression, alongside, during } of wanted) {
        const series = byExpression.get(expression);
        if (series === undefined || series.t.length === 0) continue;

        // Conservative column first: `<=` must hold for the whole bucket, so read its maximum.
        let guard = rule.op === '<=' ? series.max : series.min;
        const extreme = rule.op === '<=' ? series.min : series.max;

        if (rule.alongside && alongside) {
          const other = byExpression.get(alongside);
          // Unreadable or bucketed differently: say nothing. The rule's claim covers both
          // metrics, and making it on one of them is not a more cautious version of it.
          if (other === undefined || other.t.length !== series.t.length) continue;
          const otherGuard = rule.alongside.op === '<=' ? other.max : other.min;
          // NaN where the companion does not hold: `episodesOf` already treats NaN as an
          // absence of data, so a moment the second condition rules out ends the episode
          // exactly as a gap in sampling would.
          const masked = new Float64Array(guard.length);
          for (let i = 0; i < guard.length; i++) {
            const companionValue = otherGuard[i]!;
            const holds = rule.alongside.op === '<='
              ? companionValue <= rule.alongside.threshold
              : companionValue >= rule.alongside.threshold;
            masked[i] = Number.isNaN(companionValue) || !holds ? Number.NaN : guard[i]!;
          }
          guard = masked;
        }
        let episodes = episodesOf(
          series.t,
          guard,
          extreme,
          rule.op,
          rule.threshold,
          rule.sustainMs,
          rule.toleranceMs ?? 0,
        );
        if (rule.during && during) {
          const other = byExpression.get(during);
          if (other === undefined || other.t.length !== series.t.length) continue;
          // The companion's most extreme value in the bucket: one queued read anywhere in it is
          // what the condition asks about.
          const reach = rule.during.op === '<=' ? other.min : other.max;
          const { op, threshold } = rule.during;
          // From the episode's first sample, found by bisection, not from the start of the
          // series: over a month held that was every sample once per episode, a few hundred
          // passes over two million samples for one rule on one node.
          const t = series.t;
          episodes = episodes.filter((e) => {
            let lo = 0;
            let hi = t.length;
            while (lo < hi) {
              const mid = (lo + hi) >>> 1;
              if (t[mid]! < e.fromMs) lo = mid + 1;
              else hi = mid;
            }
            for (let i = lo; i < t.length && t[i]! <= e.toMs; i++) {
              const v = reach[i]!;
              if (!Number.isNaN(v) && (op === '<=' ? v <= threshold : v >= threshold)) return true;
            }
            return false;
          });
        }
        if (episodes.length === 0) continue;

        // Split the run of episodes wherever there is a long quiet stretch: each group is one
        // incident, and gets its own finding.
        const grupos: Episode[][] = [[episodes[0]!]];
        for (let k = 1; k < episodes.length; k++) {
          const previo = episodes[k - 1]!;
          const actual = episodes[k]!;
          if (actual.fromMs - previo.toMs > SEPARATE_INCIDENTS_MS) grupos.push([actual]);
          else grupos[grupos.length - 1]!.push(actual);
        }

        // For a metric that echoes an event, count the events rather than the samples: each
        // distinct value the metric takes is one checkpoint, one flush, one of whatever it
        // reports on. The samples in between are the same event still being displayed.
        // Counted once per series, not once per group: the count is the same for every group,
        // and recounting it was another full pass over the history per incident.
        let occurrences: number | undefined;
        let observed: number | undefined;
        if (rule.echoesAnEvent === true) {
          occurrences = 0;
          observed = 0;
          let previous = NaN;
          for (let i = 0; i < extreme.length; i++) {
            const value = extreme[i]!;
            if (Number.isNaN(value)) continue;
            if (value === previous) continue;
            previous = value;
            observed++;
            const breaches = rule.op === '<=' ? value <= rule.threshold : value >= rule.threshold;
            if (breaches) occurrences++;
          }
        }

        for (const grupo of grupos) {
        let worst = grupo[0]!;
        let totalMs = 0;
        let peak = grupo[0]!.peak;
        for (const episode of grupo) {
          totalMs += episode.inStateMs;
          if (episode.inStateMs > worst.inStateMs) worst = episode;
          peak = rule.op === '<=' ? Math.min(peak, episode.peak) : Math.max(peak, episode.peak);
        }

        found.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          captureId: capture.id,
          captureLabel: capture.label,
          metric: expression,
          episodes: grupo.length,
          ...(occurrences !== undefined && observed !== undefined
            ? { occurrences, observed } : {}),
          firstMs: grupo[0]!.fromMs,
          lastMs: grupo[grupo.length - 1]!.toMs,
          worstFromMs: worst.fromMs,
          worstToMs: worst.toMs,
          totalMs,
          peak,
          unit: rule.unit,
          what: rule.what,
          check: rule.check,
        });
        }
      }
      return found;
    }),
  );

  // Worst first, then earliest: an investigation starts at the most severe thing that happened
  // and works outward in time from it.
  return perCapture
    .flat()
    .sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.firstMs - b.firstMs);
}
