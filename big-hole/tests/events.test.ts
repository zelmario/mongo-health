/**
 * The findings that are events rather than conditions.
 *
 * These are the ones most likely to be wrong without anybody noticing. A rule that stops firing
 * shows up as a quiet cluster, which is what a healthy cluster also looks like — and these three
 * are exactly the checks whose silence is indistinguishable from good news. They ran against
 * real captures for days before they had a single test; this is that debt paid.
 */
import { describe, expect, it } from 'vitest';

import {
  ALARM_COUNTERS,
  alarmFindings,
  changeFindings,
  electionFindings,
  gapFindings,
  peerFindings,
  restartFindings,
  versionFindings,
  type NodeEvents,
} from '../src/insights/events.js';

const T0 = 1_786_000_000_000;

function node(over: Partial<NodeEvents> = {}): NodeEvents {
  return { node: 'n0', hostname: 'db1.internal', gaps: [], elections: [], alarms: [], ...over };
}

/* ------------------------------------------------------------------ elections ---- */

describe('electionFindings', () => {
  it('reports an election once for the set, not once per member', () => {
    // Every member sees the same election. Three findings for one event is noise, and it also
    // implies three events to anybody skimming.
    const at = T0 + 60_000;
    const found = electionFindings([
      node({ hostname: 'db1', elections: [{ atMs: at, term: 2 }] }),
      node({ hostname: 'db2', elections: [{ atMs: at + 2000, term: 2 }] }),
      node({ hostname: 'db3', elections: [{ atMs: at + 5000, term: 2 }] }),
    ]);
    expect(found).toHaveLength(1);
    expect(found[0]!.episodes).toBe(1);
  });

  it('counts elections that are genuinely separate', () => {
    const found = electionFindings([
      node({ elections: [{ atMs: T0, term: 2 }, { atMs: T0 + 6 * 3600_000, term: 3 }] }),
    ]);
    expect(found[0]!.episodes).toBe(2);
    expect(found[0]!.title).toContain('2 times');
  });

  it('stays informational for one election and warns about several', () => {
    // A maintenance restart causes one. Several in a short window is members losing sight of
    // each other, which is a different conversation.
    const una = electionFindings([node({ elections: [{ atMs: T0, term: 2 }] })]);
    expect(una[0]!.severity).toBe('info');

    const varias = electionFindings([node({
      elections: [2, 3, 4, 5].map((term, i) => ({ atMs: T0 + i * 3600_000, term })),
    })]);
    expect(varias[0]!.severity).toBe('warning');
  });

  it('says nothing when the set never elected', () => {
    expect(electionFindings([node(), node()])).toEqual([]);
  });

  it('reports no duration, because an election has none', () => {
    // It happens; it does not last. A duration here would be invented.
    const found = electionFindings([node({ elections: [{ atMs: T0, term: 2 }] })]);
    expect(found[0]!.totalMs).toBe(0);
  });
});

/* -------------------------------------------------------------------- alarms ---- */

describe('alarmFindings', () => {
  const checkpoint = ALARM_COUNTERS[0]!.path;

  it('reports a counter that moved', () => {
    const found = alarmFindings([node({ alarms: [{ path: checkpoint, atMs: T0, by: 1 }] })]);
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe('critical');
    expect(found[0]!.what).toContain('once');
  });

  it('keeps them per node, unlike elections', () => {
    // A failed checkpoint on one member is that member's disk; the same count on all three is
    // the deployment. A reader can only tell those apart if each is reported where it happened.
    const found = alarmFindings([
      node({ hostname: 'db1', alarms: [{ path: checkpoint, atMs: T0, by: 1 }] }),
      node({ hostname: 'db2', alarms: [{ path: checkpoint, atMs: T0, by: 1 }] }),
    ]);
    expect(found).toHaveLength(2);
    expect(found.map((f) => f.captureLabel).sort()).toEqual(['db1', 'db2']);
  });

  it('adds up repeated increments and says how many', () => {
    const found = alarmFindings([node({
      alarms: [
        { path: checkpoint, atMs: T0, by: 2 },
        { path: checkpoint, atMs: T0 + 60_000, by: 3 },
      ],
    })]);
    expect(found[0]!.episodes).toBe(2);
    expect(found[0]!.peak).toBe(5);
    expect(found[0]!.what).toContain('5 times');
  });

  it('is silent on a healthy node', () => {
    // The normal case, and the one that must stay cheap: these counters are flat zero for the
    // life of most servers.
    expect(alarmFindings([node(), node(), node()])).toEqual([]);
  });

  it('ignores a path that is not one of the alarm counters', () => {
    const found = alarmFindings([node({
      alarms: [{ path: 'serverStatus.metrics.commands.find.failed', atMs: T0, by: 900 }],
    })]);
    expect(found).toEqual([]);
  });

  it('describes every counter it watches', () => {
    // The list is the whole design: choosing these was the work, and one added without a
    // reason to act on it turns the feature into noise.
    for (const counter of ALARM_COUNTERS) {
      expect(counter.title.length).toBeGreaterThan(8);
      expect(counter.check.length).toBeGreaterThan(30);
      expect(['critical', 'warning']).toContain(counter.severity);
    }
  });
});

/* ---------------------------------------------------------------------- gaps ---- */

describe('gapFindings', () => {
  const hueco = (fromMs: number, seconds: number) => ({
    fromMs, toMs: fromMs + seconds * 1000, seconds, missingSamples: seconds,
  });

  it('reports a long outage with the total and the worst stretch', () => {
    // Measured against a real capture: 16,189 s, which matched the primary's own log exactly.
    const found = gapFindings([node({ gaps: [hueco(T0, 16_189)] })]);
    expect(found).toHaveLength(1);
    expect(found[0]!.ruleId).toBe('ftdc-long-outage');
    expect(found[0]!.peak).toBe(16_189);
  });

  it('calls a long outage critical only once it is long', () => {
    const corto = gapFindings([node({ gaps: [hueco(T0, 90)] })]);
    expect(corto[0]!.severity).toBe('warning');

    const largo = gapFindings([node({ gaps: [hueco(T0, 4000)] })]);
    expect(largo[0]!.severity).toBe('critical');
  });

  it('does not treat a handful of micro-stalls as an incident', () => {
    // Every capture has a few. Reporting them would bury everything else.
    expect(gapFindings([node({ gaps: [hueco(T0, 2), hueco(T0 + 10_000, 3)] })])).toEqual([]);
  });

  it('reports micro-stalls once there are enough of them to be a pattern', () => {
    const gaps = Array.from({ length: 20 }, (_, i) => hueco(T0 + i * 60_000, 3));
    const found = gapFindings([node({ gaps })]);
    expect(found.some((f) => f.ruleId === 'ftdc-micro-stalls')).toBe(true);
  });

  it('is silent on an uninterrupted capture', () => {
    expect(gapFindings([node(), node()])).toEqual([]);
  });

  it('reports today separately from four days ago', () => {
    // The bug this replaces: one finding per node for the whole retained history. A node that
    // stopped reporting today produced nothing new, because the same node had stopped reporting
    // harder days earlier and that aggregate was already known — so the longer a cluster had
    // been watched, the more certainly its next outage went unreported. Caught by an injected
    // 77-second freeze that the capture contained and the report never mentioned.
    const old = hueco(T0, 14_175);
    const today = hueco(T0 + 4 * 86_400_000, 77);

    const found = gapFindings([node({ gaps: [old, today] })]);
    expect(found).toHaveLength(2);
    expect(found.map((f) => f.peak).sort((a, b) => a! - b!)).toEqual([77, 14_175]);
    // Distinct worst-episode starts, because that is what the collector hashes into a finding
    // id: sharing one would make the second incident a duplicate of the first for ever.
    expect(new Set(found.map((f) => f.worstFromMs)).size).toBe(2);
  });

  it('keeps one incident together when the node flaps', () => {
    // The other half of the same decision. Three breaks two minutes apart are one bad quarter
    // of an hour, not three incidents, and reporting them separately would be its own noise.
    const gaps = [hueco(T0, 70), hueco(T0 + 120_000, 80), hueco(T0 + 240_000, 90)];
    const found = gapFindings([node({ gaps })]);
    expect(found).toHaveLength(1);
    expect(found[0]!.episodes).toBe(3);
  });

  it('counts micro-stalls within one incident, not across the capture', () => {
    // Ten stalls in a quarter of an hour is a node in trouble; ten spread over five days is a
    // node with a long life. Same count, opposite meanings.
    const spread = Array.from({ length: 12 }, (_, i) => hueco(T0 + i * 86_400_000, 3));
    expect(gapFindings([node({ gaps: spread })])).toEqual([]);
  });
});


/* ------------------------------------------------------------------ settings ---- */

describe('changeFindings', () => {
  const change = (path: string, atMs: number, from: number, to: number) =>
    ({ path, atMs, from, to });

  it('says what moved, from what, to what', () => {
    const found = changeFindings([node({
      changes: [change('serverStatus.wiredTiger.cache.maximum bytes configured',
                       T0, 8 * 1024 ** 3, 4 * 1024 ** 3)],
    })]);
    expect(found).toHaveLength(1);
    expect(found[0]!.ruleId).toBe('setting-changed');
    expect(found[0]!.what).toContain('8 GB');
    expect(found[0]!.what).toContain('4 GB');
  });

  it('is informational, never an alarm', () => {
    // A resize is a decision somebody made, often a good one. Alerting on choices is how a
    // product teaches people to ignore it; what earns the place is being in the same report as
    // the incident, so the reader draws the line themselves.
    const found = changeFindings([node({
      changes: [change('systemMetrics.memory.MemTotal_kb', T0, 8 * 1024 ** 3, 2 * 1024 ** 3)],
    })]);
    expect(found[0]!.severity).toBe('info');
  });

  it('reports two resizes as two findings', () => {
    // A month apart they are two different decisions with two different consequences, and
    // merging them would hide whichever one matters.
    const found = changeFindings([node({
      changes: [change('local.oplog.rs.stats.storageStats.maxSize', T0, 1e9, 2e9),
                change('local.oplog.rs.stats.storageStats.maxSize', T0 + 2.6e9, 2e9, 5e8)],
    })]);
    expect(found).toHaveLength(2);
    expect(new Set(found.map((f) => f.worstFromMs)).size).toBe(2);
  });

  it('ignores a path nobody chose to watch', () => {
    // The list is the design. Anything not on it arriving here is a bug upstream, and silently
    // rendering it would ship a finding with no title and no explanation.
    expect(changeFindings([node({ changes: [change('serverStatus.made.up', T0, 1, 2)] })]))
      .toEqual([]);
  });

  it('says nothing about a cluster nobody touched', () => {
    expect(changeFindings([node(), node()])).toEqual([]);
  });

  it('counts members without pretending they are bytes', () => {
    const found = changeFindings([node({
      changes: [change('replSetGetStatus.votingMembersCount', T0, 3, 5)],
    })]);
    expect(found[0]!.what).toContain('3');
    expect(found[0]!.what).toContain('5');
    expect(found[0]!.what).not.toContain('GB');
  });
});


/* ------------------------------------------------------------------ peers ---- */

describe('peerFindings', () => {
  const CHECKPOINT =
    'serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)';

  const member = (name: string, ms: number): NodeEvents => ({
    ...node({ hostname: name }),
    percentiles: [{ metric: CHECKPOINT, p50: ms, p95: ms, max: ms }],
    fromMs: T0,
    toMs: T0 + 3_600_000,
  });

  it('names the member that does not look like the others', () => {
    // The evidence no threshold can give: three machines running the same software on the same
    // data under the same load are their own control group.
    const found = peerFindings([member('db1', 1200), member('db2', 8000), member('db3', 1100)]);
    expect(found).toHaveLength(1);
    expect(found[0]!.ruleId).toBe('peer-outlier');
    expect(found[0]!.captureLabel).toBe('db2');
    expect(found[0]!.what).toContain('8.0 s');
  });

  it('says nothing when the members agree', () => {
    // Measured on two real clusters: healthy members sat within 1.03x-1.24x of each other, so
    // this is the case that runs on every cluster on every run and must stay silent.
    expect(peerFindings([member('db1', 1200), member('db2', 1300), member('db3', 1100)]))
      .toEqual([]);
  });

  it('ignores a difference that is large only because the numbers are small', () => {
    // 3 ms against 1 ms is 3x and is nothing at all. Without the floor this fires on every
    // healthy set in existence, which is how a detector teaches people to ignore it.
    expect(peerFindings([member('db1', 1), member('db2', 3), member('db3', 1)])).toEqual([]);
  });

  it('needs three members to call one of them odd', () => {
    // With two there is no majority to be unlike, and picking one is a coin toss.
    expect(peerFindings([member('db1', 1200), member('db2', 9000)])).toEqual([]);
  });

  it('is not dragged by the member it is judging', () => {
    // Compared against the median of the OTHERS. Against the mean of all three, one member at
    // fifty times its peers pulls up the very number it is measured against and hides itself.
    const found = peerFindings([member('db1', 1000), member('db2', 50_000), member('db3', 1000)]);
    expect(found).toHaveLength(1);
    expect(found[0]!.peak).toBe(50);
  });

  it('is a warning, not an alarm', () => {
    // It reports a difference. The member may still be serving its share perfectly well; what
    // it has stopped being is interchangeable with the others.
    const found = peerFindings([member('db1', 1200), member('db2', 8000), member('db3', 1100)]);
    expect(found[0]!.severity).toBe('warning');
  });

  it('says nothing when the metric is missing from the summaries', () => {
    // An older capture, or a release that does not report it. Silence, not a crash.
    expect(peerFindings([node(), node(), node()])).toEqual([]);
  });
});

describe('peerFindings, on a metric that needs a denominator', () => {
  const DIRTY = 'serverStatus.wiredTiger.cache.tracked dirty bytes in the cache';
  const CACHE = 'serverStatus.wiredTiger.cache.maximum bytes configured';
  const MB = 1024 * 1024;

  const member = (name: string, dirtyMb: number, cacheMb: number): NodeEvents => ({
    ...node({ hostname: name }),
    percentiles: [
      { metric: DIRTY, p50: dirtyMb * MB, p95: dirtyMb * MB, max: dirtyMb * MB },
      { metric: CACHE, p50: cacheMb * MB, p95: cacheMb * MB, max: cacheMb * MB },
    ],
    fromMs: T0,
    toMs: T0 + 3_600_000,
  });

  it('does not mistake a bigger cache for a sicker member', () => {
    // Measured, not imagined: one member was given a 1 GB cache and its peers 256 MB, and
    // dirty bytes came out 76 MB against 20 MB — 3.5x, and a finding. As a share of each
    // member's own cache: 7.4%, 7.6%, 8.4%. Identical, and nothing to report. The absolute
    // comparison was measuring the configuration and calling it behaviour.
    const found = peerFindings([
      member('db1', 20, 256), member('db2', 21, 256), member('db3', 76, 1024)]);
    expect(found).toEqual([]);
  });

  it('still catches a member that really is holding more', () => {
    // Same cache everywhere, one member four times as dirty as the others.
    const found = peerFindings([
      member('db1', 20, 256), member('db2', 21, 256), member('db3', 90, 256)]);
    expect(found).toHaveLength(1);
    expect(found[0]!.captureLabel).toBe('db3');
    expect(found[0]!.what).toContain('%');
  });

  it('says nothing when the cache size is missing', () => {
    // No capacity to divide by means no comparable number, and falling back to the raw bytes
    // is exactly the mistake above.
    const bare = (name: string, dirtyMb: number): NodeEvents => ({
      ...node({ hostname: name }),
      percentiles: [{ metric: DIRTY, p50: dirtyMb * MB, p95: 0, max: 0 }],
    });
    expect(peerFindings([bare('db1', 20), bare('db2', 21), bare('db3', 300)])).toEqual([]);
  });
});

/* ---------------------------------------------------------- restarts and versions ---- */

const MIN = 60_000;

describe('restartFindings', () => {
  // Cluster1 on 28 Sep 2026: three members, about 4.6 minutes each, ten minutes apart.
  const rolling = [
    node({ node: 'a', hostname: 'a', restarts: [{ fromMs: T0, atMs: T0 + 4.6 * MIN }] }),
    node({ node: 'b', hostname: 'b', restarts: [{ fromMs: T0 + 11 * MIN, atMs: T0 + 15.6 * MIN }] }),
    node({ node: 'c', hostname: 'c', restarts: [{ fromMs: T0 + 20 * MIN, atMs: T0 + 24.7 * MIN }] }),
  ];

  it('names members restarting one after another as one rolling restart', () => {
    const out = restartFindings(rolling);
    expect(out).toHaveLength(1);
    expect(out[0]!.ruleId).toBe('rolling-restart');
    expect(out[0]!.title).toBe('Rolling restart: 3 members, one at a time');
    expect(out[0]!.firstMs).toBe(T0);
    expect(out[0]!.lastMs).toBe(T0 + 24.7 * MIN);
    expect(out[0]!.what).toContain('4.6 to 4.7 minutes');
  });

  it('keeps a lone restart as a restart of that member', () => {
    const out = restartFindings([rolling[0]!]);
    expect(out.map((f) => f.ruleId)).toEqual(['member-restarted']);
  });

  it('does not chain restarts hours apart', () => {
    const later = node({ node: 'b', hostname: 'b',
                         restarts: [{ fromMs: T0 + 300 * MIN, atMs: T0 + 304 * MIN }] });
    expect(restartFindings([rolling[0]!, later]).map((f) => f.ruleId))
      .toEqual(['member-restarted', 'member-restarted']);
  });

  it('does not call the same member restarting twice a rolling restart', () => {
    const twice = node({ restarts: [{ fromMs: T0, atMs: T0 + MIN },
                                    { fromMs: T0 + 5 * MIN, atMs: T0 + 6 * MIN }] });
    expect(restartFindings([twice]).map((f) => f.ruleId))
      .toEqual(['member-restarted', 'member-restarted']);
  });
});

describe('versionFindings', () => {
  it('puts an upgrade on the timeline as a change', () => {
    const out = versionFindings([node({ versions: [{ atMs: T0, from: '8.0.32', to: '8.0.34' }] })]);
    expect(out).toHaveLength(1);
    expect(out[0]!.ruleId).toBe('setting-changed');
    expect(out[0]!.what).toBe('This member went from MongoDB 8.0.32 to 8.0.34.');
  });

  it('says nothing when the version held', () => {
    expect(versionFindings([node()])).toEqual([]);
  });
});

describe('restart durations', () => {
  it('says seconds for a restart of seconds, once when they are all the same', () => {
    const quick = ['a', 'b', 'c'].map((n, i) => node({
      node: n, hostname: n, restarts: [{ fromMs: T0 + i * 40_000, atMs: T0 + i * 40_000 + 7_000 }],
    }));
    expect(restartFindings(quick)[0]!.what).toContain('each without metrics for 7 seconds.');
  });
});
