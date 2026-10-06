/**
 * M6 pathology detection.
 *
 * The risk here is not missing a finding -- it is reporting one that is not there. A detector
 * that fires on a healthy capture gets switched off within a day, and then it catches nothing
 * at all. So most of this tests the ways a finding could be manufactured: by downsampling, by
 * a gap in the capture, or by a threshold touched briefly on a server that is fine.
 */

import { describe, expect, it } from 'vitest';

import { detect, episodesOf, type DetectCapture, type Rule } from '../src/insights/detect.js';
import { RULES } from '../src/insights/rules.js';
import { parseExpr, unitOf } from '../src/data/expr.js';
import type { SeriesPayload } from '../src/workers/protocol.js';

const f = (...xs: number[]): Float64Array => Float64Array.from(xs);

/** Seconds -> epoch ms, so the numbers in these tests read as a clock. */
const at = (...secs: number[]): Float64Array => Float64Array.from(secs.map((s) => s * 1000));

describe('finding episodes in a series', () => {
  it('reports a stretch that holds for long enough', () => {
    const t = at(0, 10, 20, 30, 40);
    const v = f(5, 0, 0, 0, 5);
    // Three samples at zero on a 10 s clock: 30 s in state, against a 10 s requirement.
    expect(episodesOf(t, v, v, '<=', 0, 10_000)).toEqual([
      { fromMs: 10_000, toMs: 30_000, peak: 0, inStateMs: 30_000 },
    ]);
  });

  it('ignores a stretch too short to mean anything', () => {
    const t = at(0, 10, 20, 30);
    const v = f(5, 0, 5, 5);
    // Every one of these metrics touches its threshold briefly on a healthy server.
    expect(episodesOf(t, v, v, '<=', 0, 30_000)).toEqual([]);
  });

  it('separates two episodes rather than spanning the recovery between them', () => {
    const t = at(0, 10, 20, 30, 40, 50, 60);
    const v = f(0, 0, 0, 9, 0, 0, 0);
    const episodes = episodesOf(t, v, v, '<=', 0, 10_000);
    expect(episodes).toHaveLength(2);
    expect(episodes[0]!.toMs).toBe(20_000);
    expect(episodes[1]!.fromMs).toBe(40_000);
  });

  /**
   * A gap is not evidence. The collector stopping for five hours must not be read as five hours
   * of whatever the metric was doing when it stopped -- that turns an FTDC outage into a
   * fabricated critical finding, on exactly the captures where the collector was struggling.
   */
  it('breaks a run at a gap instead of spanning it', () => {
    const t = at(0, 10, 20, 30, 40);
    const v = f(0, 0, NaN, 0, 0);
    const episodes = episodesOf(t, v, v, '<=', 0, 10_000);
    expect(episodes).toHaveLength(2);
    expect(episodes[0]).toEqual({ fromMs: 0, toMs: 10_000, peak: 0, inStateMs: 20_000 });
    expect(episodes[1]).toEqual({ fromMs: 30_000, toMs: 40_000, peak: 0, inStateMs: 20_000 });
  });

  it('reports the worst value reached, not the one that triggered it', () => {
    const t = at(0, 10, 20, 30);
    const guard = f(100, 100, 100, 10);
    const extreme = f(100, 340, 200, 10);
    const [episode] = episodesOf(t, guard, extreme, '>=', 50, 10_000);
    expect(episode!.peak).toBe(340);
  });
});

/**
 * Flapping is the shape real incidents have.
 *
 * WiredTiger fights its own dirty cache, so the metric crosses the trigger and is pulled back
 * within seconds. Measured on a capture that spent 377 s above the 20% trigger and peaked at
 * 36%: the longest unbroken stretch was 30 s, so a rule wanting 60 s of unbroken breach saw
 * nothing. Tolerating short recoveries is what makes that visible -- without letting a detector
 * claim time that was never in breach.
 */
describe('a condition that flaps', () => {
  // Over the line, back under for one sample, over again -- repeatedly, for a minute.
  const t = at(...Array.from({ length: 12 }, (_, i) => i * 10));
  const v = f(30, 30, 5, 30, 30, 5, 30, 30, 5, 30, 30, 5);

  it('is one episode when the recoveries are shorter than the tolerance', () => {
    const episodes = episodesOf(t, v, v, '>=', 20, 60_000, 20_000);
    expect(episodes).toHaveLength(1);
    expect(episodes[0]!.fromMs).toBe(0);
    expect(episodes[0]!.toMs).toBe(100_000);
  });

  it('counts only the time actually in breach, never the bridged dips', () => {
    const [episode] = episodesOf(t, v, v, '>=', 20, 60_000, 20_000);
    // Eight samples over the line on a 10 s clock -- not the 110 s the episode spans.
    expect(episode!.inStateMs).toBe(80_000);
  });

  it('still requires that in-breach time to reach sustainMs', () => {
    // The same shape, asked for two minutes in state. It only ever managed 80 s.
    expect(episodesOf(t, v, v, '>=', 20, 120_000, 20_000)).toEqual([]);
  });

  it('is several episodes without a tolerance, which is what made the flapping invisible', () => {
    // Each crossing is 20 s, so a 60 s requirement rejects all four.
    expect(episodesOf(t, v, v, '>=', 20, 60_000)).toEqual([]);
  });

  /** A gap is not a short recovery. No tolerance may bridge one. */
  it('never bridges a hole in the capture, however generous the tolerance', () => {
    const withGap = f(30, 30, 30, NaN, 30, 30, 30);
    const clock = at(0, 10, 20, 30, 40, 50, 60);
    const episodes = episodesOf(clock, withGap, withGap, '>=', 20, 20_000, 600_000);
    expect(episodes).toHaveLength(2);
  });
});

/**
 * The property the whole design rests on: findings are read off the min/max envelope rather
 * than full resolution, which is only sound if the envelope cannot invent one.
 */
describe('downsampling cannot manufacture a finding', () => {
  it('needs the whole bucket below the threshold, not just its minimum', () => {
    const t = at(0, 10, 20, 30);
    // Each bucket dipped to zero but also recovered inside the same bucket. Reading the min
    // would call this a sustained outage; reading the max -- the guard for `<=` -- does not.
    const min = f(0, 0, 0, 0);
    const max = f(8, 7, 9, 8);
    expect(episodesOf(t, max, min, '<=', 0, 10_000)).toEqual([]);
    // And the pessimistic reading does fire once the bucket genuinely never recovers.
    expect(episodesOf(t, f(0, 0, 0, 0), min, '<=', 0, 10_000)).toHaveLength(1);
  });

  it('needs the whole bucket above the threshold for a >= rule', () => {
    const t = at(0, 10, 20, 30);
    const min = f(1, 2, 1, 2);
    const max = f(99, 99, 99, 99);
    expect(episodesOf(t, min, max, '>=', 20, 10_000)).toEqual([]);
  });
});

/* --------------------------------------------------------------- end to end ---- */

/** A capture that reports whatever paths the test names, answering with canned series. */
function fakeSource(answers: Record<string, { t: Float64Array; min: Float64Array; max: Float64Array }>) {
  return {
    series(_captureId: string, expressions: string[]): Promise<SeriesPayload[]> {
      return Promise.resolve(
        expressions.map((expression) => {
          const a = answers[expression];
          const empty = new Float64Array(0);
          if (a === undefined) {
            return { path: expression, t: empty, min: empty, max: empty, mean: empty, raw: false };
          }
          return { path: expression, t: a.t, min: a.min, max: a.max, mean: a.min, raw: false };
        }),
      );
    },
  } as Parameters<typeof detect>[0];
}

const TICKETS = 'serverStatus.wiredTiger.concurrentTransactions.read.available';

describe('detecting across captures', () => {
  const capture = (id: string, label: string, paths: string[]): DetectCapture => ({
    id,
    label,
    paths: new Set(paths),
  });

  const ticketRule: Rule = {
    id: 'read-tickets-exhausted',
    title: 'Read tickets exhausted',
    severity: 'critical',
    metric: TICKETS,
    op: '<=',
    threshold: 0,
    sustainMs: 10_000,
    unit: 'count',
    what: '',
    check: '',
  };

  // ---------------------------------------------------------- a second condition

  const CMD = 'div(rate(serverStatus.opLatencies.commands.latency), rate(serverStatus.opLatencies.commands.ops))';
  const READ = 'div(rate(serverStatus.opLatencies.reads.latency), rate(serverStatus.opLatencies.reads.ops))';
  // The raw paths the two expressions are built from. A capture that does not carry them
  // resolves neither expression, and a test that expects silence would pass without ever
  // exercising the thing it is about.
  const LAT_PATHS = [
    'serverStatus.opLatencies.commands.latency', 'serverStatus.opLatencies.commands.ops',
    'serverStatus.opLatencies.reads.latency', 'serverStatus.opLatencies.reads.ops',
  ];

  const slowCommands: Rule = {
    id: 'command-latency-high',
    title: 'Commands are taking milliseconds each',
    severity: 'warning',
    metric: CMD,
    op: '>=',
    threshold: 5_000,
    sustainMs: 30_000,
    unit: 'us',
    what: '',
    check: '',
    alongside: { metric: READ, op: '>=', threshold: 5_000 },
  };

  it('stays quiet when only the commands bucket is slow', async () => {
    // The netem case, in miniature. A degraded network inflates the commands bucket -- it
    // counts awaitable and handshake traffic -- while the server itself is untouched. Measured
    // on a real replica set: 22,502us per command against 850us per read. Without the second
    // condition this reported "commands are taking milliseconds each" through a network fault.
    const t = at(0, 10, 20, 30, 40, 50, 60, 70);
    const source = fakeSource({
      [CMD]: { t, min: f(20_000, 20_000, 20_000, 20_000, 20_000, 20_000, 20_000, 20_000), max: f(20_000, 20_000, 20_000, 20_000, 20_000, 20_000, 20_000, 20_000) },
      [READ]: { t, min: f(850, 850, 850, 850, 850, 850, 850, 850), max: f(900, 900, 900, 900, 900, 900, 900, 900) },
    });

    const findings = await detect(source, [capture('c0', 'n', LAT_PATHS)], [slowCommands], {});

    expect(findings).toHaveLength(0);
  });

  it('reports when the whole server is slow, not just the wire', async () => {
    // Plan cache churn on the same set: 10,576us per command AND 72,855us per read.
    const t = at(0, 10, 20, 30, 40, 50, 60, 70);
    const source = fakeSource({
      [CMD]: { t, min: f(10_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000), max: f(10_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000, 10_000) },
      [READ]: { t, min: f(70_000, 70_000, 70_000, 70_000, 70_000, 70_000, 70_000, 70_000), max: f(70_000, 70_000, 70_000, 70_000, 70_000, 70_000, 70_000, 70_000) },
    });

    const findings = await detect(source, [capture('c0', 'n', LAT_PATHS)], [slowCommands], {});

    expect(findings).toHaveLength(1);
  });

  it('says nothing at all when the second condition cannot be read', async () => {
    // The claim is about both metrics. Making it on one of them is not a more cautious version
    // of it, it is a different and unsupported claim.
    const t = at(0, 10, 20, 30, 40, 50, 60, 70);
    const source = fakeSource({
      [CMD]: { t, min: f(20_000, 20_000, 20_000, 20_000, 20_000, 20_000, 20_000, 20_000), max: f(20_000, 20_000, 20_000, 20_000, 20_000, 20_000, 20_000, 20_000) },
    });

    const findings = await detect(source, [capture('c0', 'n', LAT_PATHS.slice(0, 2))], [slowCommands], {});

    expect(findings).toHaveLength(0);
  });

  // ------------------------------------------------- a condition somewhere in the episode

  const OUT = 'pct(serverStatus.queues.execution.read.out, serverStatus.queues.execution.read.totalTickets)';
  const QUEUE = 'serverStatus.globalLock.currentQueue.readers';
  const SAT_PATHS = ['serverStatus.queues.execution.read.out',
    'serverStatus.queues.execution.read.totalTickets', QUEUE];
  const saturated: Rule = {
    id: 'read-tickets-saturated', title: 'Read ticket pool saturated', severity: 'critical',
    metric: OUT, op: '>=', threshold: 50, sustainMs: 30_000, toleranceMs: 15_000,
    unit: 'percent', what: '', check: '',
    during: { metric: QUEUE, op: '>=', threshold: 1 },
  };
  const pool = (queue: number[]) => {
    const t = at(0, 10, 20, 30, 40, 50, 60, 70);
    const half = f(50, 50, 50, 50, 50, 50, 50, 50);
    return fakeSource({
      [OUT]: { t, min: half, max: half },
      [QUEUE]: { t, min: f(...queue.map(() => 0)), max: f(...queue) },
    });
  };

  it('calls half a pool in use with nothing waiting load, not saturation', async () => {
    // Four scans on an eight-ticket pool, measured: 4 of 8 out for five minutes, no reads
    // queued at any moment. That was reported as critical.
    const findings = await detect(pool([0, 0, 0, 0, 0, 0, 0, 0]), [capture('c0', 'n', SAT_PATHS)],
      [saturated], {});
    expect(findings).toHaveLength(0);
  });

  it('reports it when reads queued at any moment of the episode, however briefly', async () => {
    // The queue is spiky: on the real capture it was non-zero in 3 to 11% of the seconds.
    const findings = await detect(pool([0, 0, 0, 17, 0, 0, 0, 0]), [capture('c0', 'n', SAT_PATHS)],
      [saturated], {});
    expect(findings).toHaveLength(1);
  });

  it('keeps only the episodes that had a queue inside them, wherever they fall', async () => {
    // Three episodes 100 s apart. The queue is up between the first two, which is neither of
    // them, and inside the third. Each episode is looked up where it starts rather than by a
    // pass over the whole series, and that must not change which ones survive.
    const t = at(...Array.from({ length: 40 }, (_, i) => i * 10));
    const out = new Float64Array(40).fill(0);
    const queue = new Float64Array(40).fill(0);
    for (const start of [0, 10, 20]) for (let k = start; k < start + 5; k++) out[k] = 80;
    queue[7] = 3;   // between the first and second episode
    queue[23] = 3;  // inside the third
    const source = fakeSource({
      [OUT]: { t, min: out, max: out },
      [QUEUE]: { t, min: new Float64Array(40), max: queue },
    });
    const [finding, ...rest] = await detect(source, [capture('c0', 'n', SAT_PATHS)], [saturated], {});
    expect(rest).toHaveLength(0);
    expect(finding!.episodes).toBe(1);
    expect(finding!.firstMs).toBe(200_000);
    expect(finding!.lastMs).toBe(240_000);
  });

  const slowWire: Rule = {
    id: 'slow-wire-not-server',
    title: 'The server is answering fast; the time is going somewhere else',
    severity: 'warning',
    metric: CMD,
    op: '>=',
    threshold: 5_000,
    sustainMs: 30_000,
    unit: 'us',
    what: '',
    check: '',
    alongside: { metric: READ, op: '<=', threshold: 5_000 },
  };

  const both = [slowCommands, slowWire];
  const shape = (cmd: number, read: number) => {
    const t = at(0, 10, 20, 30, 40, 50, 60, 70);
    const eight = (x: number) => f(x, x, x, x, x, x, x, x);
    return fakeSource({
      [CMD]: { t, min: eight(cmd), max: eight(cmd) },
      [READ]: { t, min: eight(read), max: eight(read) },
    });
  };

  it('says the wire when only commands are slow, and the server when both are', async () => {
    // The two rules partition one situation rather than overlapping on it, which is the whole
    // reason they share a threshold. Exactly one of them speaks about any given moment.
    const capturado = [capture('c0', 'n', LAT_PATHS)];

    const wire = await detect(shape(22_500, 850), capturado, both, {});
    const server = await detect(shape(10_500, 72_800), capturado, both, {});

    expect(wire.map((x) => x.ruleId)).toEqual(['slow-wire-not-server']);
    expect(server.map((x) => x.ruleId)).toEqual(['command-latency-high']);
  });

  it('neither speaks when the server is simply quick', async () => {
    const findings = await detect(shape(200, 840), [capture('c0', 'n', LAT_PATHS)], both, {});
    expect(findings).toHaveLength(0);
  });

  it('aggregates flapping into one finding with the episode count', async () => {
    // A saturating pool crosses the line repeatedly. Twelve findings would bury every other
    // rule in the list; one finding that says "12 episodes" is the same information.
    const t = at(0, 10, 20, 30, 40, 50, 60, 70);
    const v = f(0, 0, 5, 0, 0, 5, 0, 0);
    const source = fakeSource({ [TICKETS]: { t, min: v, max: v } });

    const findings = await detect(source, [capture('c0', 'node1', [TICKETS])], [ticketRule], {});
    expect(findings).toHaveLength(1);
    expect(findings[0]!.episodes).toBe(3);
    // Six samples at zero on a 10 s clock. The old measure summed each run's span and reported
    // 30 s, which undercounted every episode by its last sample.
    expect(findings[0]!.totalMs).toBe(60_000);
    expect(findings[0]!.firstMs).toBe(0);
    expect(findings[0]!.lastMs).toBe(70_000);
    expect(findings[0]!.captureLabel).toBe('node1');
  });

  it('resolves through the alias table, so a rule written once fires on 8.0 too', async () => {
    // The rule names the pre-8.0 path; this capture only has the renamed one. Losing the
    // ticket detector on 8.0 would be the worst possible silent failure.
    const renamed = 'serverStatus.queues.execution.read.available';
    const t = at(0, 10, 20, 30);
    const v = f(0, 0, 0, 0);
    const source = fakeSource({ [renamed]: { t, min: v, max: v } });

    const findings = await detect(source, [capture('c0', 'n', [renamed])], [ticketRule], {});
    expect(findings).toHaveLength(1);
    expect(findings[0]!.metric).toBe(renamed);
  });

  it('resolves under a role prefix, as a sharded member reports it', async () => {
    const prefixed = `shard.${TICKETS}`;
    const t = at(0, 10, 20, 30);
    const v = f(0, 0, 0, 0);
    const source = fakeSource({ [prefixed]: { t, min: v, max: v } });

    const findings = await detect(
      source,
      [capture('c0', 'n', [prefixed, 'shard.serverStatus.localTime'])],
      [ticketRule],
      {},
    );
    expect(findings.map((x) => x.metric)).toEqual([prefixed]);
  });

  it('says nothing about a capture that cannot resolve the metric', async () => {
    const source = fakeSource({});
    const findings = await detect(
      source,
      [capture('c0', 'n', ['serverStatus.mem.resident'])],
      [ticketRule],
      {},
    );
    expect(findings).toEqual([]);
  });

  it('names the node, so a replica set says which member', async () => {
    const t = at(0, 10, 20, 30);
    const bad = f(0, 0, 0, 0);
    const good = f(60, 60, 60, 60);
    const source = {
      series: (id: string, expressions: string[]) =>
        Promise.resolve(
          expressions.map((expression) => {
            const v = id === 'c1' ? bad : good;
            return { path: expression, t, min: v, max: v, mean: v, raw: false };
          }),
        ),
    } as Parameters<typeof detect>[0];

    const findings = await detect(
      source,
      [capture('c0', 'primary', [TICKETS]), capture('c1', 'secondary', [TICKETS])],
      [ticketRule],
      {},
    );
    expect(findings.map((x) => x.captureLabel)).toEqual(['secondary']);
  });

  it('orders the worst thing first', async () => {
    const t = at(0, 10, 20, 30);
    const v = f(0, 0, 0, 0);
    const queue = 'serverStatus.globalLock.currentQueue.readers';
    const source = fakeSource({
      [TICKETS]: { t, min: v, max: v },
      [queue]: { t, min: f(99, 99, 99, 99), max: f(99, 99, 99, 99) },
    });
    const queueRule: Rule = {
      ...ticketRule,
      id: 'q',
      title: 'Read queue building',
      severity: 'warning',
      metric: queue,
      op: '>=',
      threshold: 10,
    };

    const findings = await detect(
      source,
      [capture('c0', 'n', [TICKETS, queue])],
      [queueRule, ticketRule],
      {},
    );
    expect(findings.map((x) => x.severity)).toEqual(['critical', 'warning']);
  });

  it('survives a capture whose reader throws rather than reporting a false all-clear', async () => {
    const source = {
      series: () => Promise.reject(new Error('columns.bin is truncated')),
    } as unknown as Parameters<typeof detect>[0];
    await expect(
      detect(source, [capture('c0', 'n', [TICKETS])], [ticketRule], {}),
    ).resolves.toEqual([]);
  });
});

/**
 * The rule file is edited by people who know MongoDB, not this codebase. These catch the
 * mistakes that produce a rule which silently never fires.
 */
describe('the shipped rule set', () => {
  it('has unique ids', () => {
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
  });

  it('parses every metric expression', () => {
    for (const rule of RULES) {
      expect(() => parseExpr(rule.metric), `${rule.id}: ${rule.metric}`).not.toThrow();
    }
  });

  it('declares the unit the expression actually produces', () => {
    // A mismatch here formats the evidence wrongly -- "20 bytes" for a percentage -- which
    // makes a correct finding look like a bug.
    for (const rule of RULES) {
      expect(unitOf(parseExpr(rule.metric)), `${rule.id}`).toBe(rule.unit);
    }
  });

  it('requires every rule to persist before it fires', () => {
    // Half a minute is the norm and the reason is noise: a metric that crosses a line for one
    // sample has not shown anybody anything. A handful of rules describe a burst rather than a
    // state, and for those the shorter window is the whole point -- but each one is named here,
    // so shortening a rule stays a decision somebody made rather than a mistyped zero.
    const BURSTS = new Set(['sorts-spilling-burst']);
    for (const rule of RULES) {
      const floor = BURSTS.has(rule.id) ? 5_000 : 30_000;
      expect(rule.sustainMs, `${rule.id} would fire on too few samples`).toBeGreaterThanOrEqual(
        floor,
      );
      if (BURSTS.has(rule.id)) {
        // A burst rule earns its short window by asking for a great deal more than the rule it
        // sits beside. Without this, "burst" becomes a way to smuggle in a hair trigger.
        const sibling = RULES.find((r) => r.metric === rule.metric && r.id !== rule.id);
        expect(sibling, `${rule.id} has no sustained rule to be the burst of`).toBeDefined();
        expect(rule.threshold, `${rule.id} must ask for much more than ${sibling!.id}`)
          .toBeGreaterThanOrEqual(sibling!.threshold * 10);
      }
    }
  });

  /**
   * The command-latency rule is the only one whose metric is a ratio of two rates, and the only
   * one built to catch a cluster that is slow with nothing saturated. Both properties are easy
   * to lose in an edit: change the expression and it silently stops resolving; lower the
   * threshold and it starts reporting every busy afternoon.
   */
  it('keeps the command-latency rule far above what healthy clusters showed', () => {
    const rule = RULES.find((r) => r.id === 'command-latency-high')!;
    expect(rule, 'the rule that catches a planner storm').toBeDefined();
    // Nine days of two Atlas clusters ran a p99 under 200us and never held 5 ms for more than
    // five seconds. Anything below a millisecond would fire on both of them constantly.
    expect(rule.threshold).toBeGreaterThanOrEqual(5000);
    // An average, not a total: `latency` alone is a cumulative counter that only ever grows, so
    // a rule written against it would fire on every cluster that has been up long enough.
    expect(rule.metric).toMatch(/^div\(rate\(.*latency\), rate\(.*ops\)\)$/);
    expect(rule.unit).toBe('us');
  });

  it('covers the two pathologies M6 exists to surface', () => {
    const ids = RULES.map((r) => r.id);
    expect(ids).toContain('read-tickets-exhausted');
    expect(ids).toContain('cache-dirty-high');
  });
});
