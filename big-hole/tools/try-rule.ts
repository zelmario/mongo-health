/**
 * A candidate rule, through the real detector, at several thresholds, over a real capture.
 *
 *   npx vite-node tools/try-rule.ts <cluster ftdc dir with one subdirectory per node>
 *
 * measure-gaps.ts says what values a metric takes; this says what a rule built on it would
 * REPORT: how many episodes, how long in breach, when, on which node -- with the same sustain,
 * tolerance and full-resolution read the collector uses. A threshold is chosen from that table,
 * against a cluster known to be healthy and one known not to be, never from memory.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeFTDC, readMetadata } from '../src/ftdc/index.js';
import { NodeFileStore } from '../src/data/nodeFileStore.js';
import { CaptureWriter } from '../src/data/writer.js';
import { CaptureReader } from '../src/data/reader.js';
import { detect, type DetectCapture, type Rule } from '../src/insights/detect.js';
import type { SeriesQuery } from '../src/data/reader.js';

const CANDIDATES: Array<Omit<Rule, 'threshold' | 'id' | 'title'> & { id: string; thresholds: number[] }> = [];
// Counters that read zero on every real capture held, injected on the lab (2026-10-06). Each at
// the collector's usual 60 s sustain and at 20 s: some step only every few seconds (the cursor
// monitor sweeps every 4 s), and only the seconds in breach count towards the sustain.
for (const [id, metric, thresholds] of [
  ['maxtime-kills', 'rate(serverStatus.metrics.operation.killedDueToMaxTimeMSExpired)', [0.2, 1, 5, 10]],
  ['cursor-timeouts', 'rate(serverStatus.metrics.cursor.timedOut)', [0.2, 1, 5, 10]],
  ['aborted-transactions', 'rate(serverStatus.transactions.totalAborted)', [0.2, 1, 5, 20]],
  ['user-asserts', 'rate(serverStatus.asserts.user)', [5, 50, 200, 500]],
  ['rejected-connections', 'rate(serverStatus.connections.rejected)', [0.2, 1, 5, 10]],
] as const) {
  for (const sustainMs of [60_000, 20_000]) {
    CANDIDATES.push({
      id: `${id} (sustain ${sustainMs / 1000} s)`, severity: 'warning', metric, op: '>=',
      thresholds: [...thresholds], sustainMs, toleranceMs: 30_000, unit: 'per-sec',
      what: '', check: '',
    });
  }
}


const root = process.argv[2]!;
const nodes = readdirSync(root).filter((n) => statSync(join(root, n)).isDirectory()).sort();
const tmp = await mkdtemp(join(tmpdir(), 'try-'));
const store = new NodeFileStore(tmp);
const readers = new Map<string, CaptureReader>();
const captures: DetectCapture[] = [];
for (const [i, node] of nodes.entries()) {
  const dir = join(root, node);
  const files = readdirSync(dir).filter((n) => n.startsWith('metrics.')).sort();
  const w = await CaptureWriter.create(store, { captureId: `n${i}`, sourceFile: node });
  let host: string | undefined;
  for (const f of files) {
    const bytes = new Uint8Array(readFileSync(join(dir, f)));
    try { host ??= readMetadata(bytes)?.hostname; } catch { /* no metadata */ }
    try { for (const c of decodeFTDC(bytes)) await w.addChunk(c); } catch { /* truncated tail */ }
  }
  await w.finish({});
  const r = await CaptureReader.open(store, `n${i}`);
  readers.set(`n${i}`, r);
  captures.push({ id: `n${i}`, label: (host ?? node).split('.')[0]!, paths: new Set(r.catalog.map((c) => c.path)) });
}
const source = {
  async series(id: string, expressions: string[], query: SeriesQuery) {
    const r = readers.get(id)!;
    const out = await Promise.all(expressions.map((e) => r.getSeries(e, query)));
    return out.map((s) => ({ path: s.path, t: s.t, min: s.min, max: s.max, mean: s.mean, raw: s.raw }));
  },
};

const at = (ms: number) => new Date(ms).toISOString().slice(5, 16).replace('T', ' ');
for (const c of CANDIDATES) {
  console.log(`\n## ${c.id}  ${c.metric}`);
  for (const threshold of c.thresholds) {
    const rule = { ...c, title: c.id, threshold } as Rule;
    const found = await detect(source, captures, [rule], {} as SeriesQuery);
    const seconds = found.reduce((s, f) => s + f.totalMs / 1000, 0);
    console.log(`  >= ${String(threshold).padStart(6)}  ${String(found.length).padStart(3)} finding(s), ` +
                `${Math.round(seconds)} s in breach`);
    for (const f of found.slice(0, 8)) {
      console.log(`      ${f.captureLabel.padEnd(28)} ${at(f.firstMs)} -> ${at(f.lastMs)}  ` +
                  `${Math.round(f.totalMs / 1000)} s, ${f.episodes} episode(s), peak ${Math.round(f.peak * 10) / 10}`);
    }
    if (found.length > 8) console.log(`      … ${found.length - 8} more`);
  }
}
for (const r of readers.values()) await r.close();
await rm(tmp, { recursive: true, force: true });
