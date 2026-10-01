/**
 * The oplog window on a real capture, read the way a run reads it: each day judged with the
 * day before it as history, never the whole capture at once.
 *
 *   npx vite-node tools/measure-window.ts <cluster ftdc dir with one subdirectory per node>
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeFTDC } from '../src/ftdc/index.js';
import { NodeFileStore } from '../src/data/nodeFileStore.js';
import { CaptureWriter } from '../src/data/writer.js';
import { CaptureReader } from '../src/data/reader.js';

const EXPR =
  'window(local.oplog.rs.stats.storageStats.wiredTiger.cursor.insert key and value bytes, ' +
  'local.oplog.rs.stats.storageStats.maxSize)';
const DAY = 86_400_000;

/** Hours spent under `limit`, and the longest unbroken stretch under it. */
function under(t: Float64Array, v: Float64Array, limit: number): [number, number] {
  let total = 0, run = 0, longest = 0;
  for (let i = 1; i < v.length; i++) {
    const dt = t[i]! - t[i - 1]!;
    if (v[i]! < limit && dt < 60_000) {
      total += dt;
      run += dt;
      longest = Math.max(longest, run);
    } else run = 0;
  }
  return [total / 3.6e6, longest / 3.6e6];
}

const root = process.argv[2]!;
const nodes = readdirSync(root).filter((n) => statSync(join(root, n)).isDirectory()).sort();
const store = new NodeFileStore(await mkdtemp(join(tmpdir(), 'window-')));
for (const [i, node] of nodes.entries()) {
  const dir = join(root, node);
  const w = await CaptureWriter.create(store, { captureId: `n${i}`, sourceFile: node });
  for (const f of readdirSync(dir).filter((n) => n.startsWith('metrics.')).sort()) {
    try { for (const c of decodeFTDC(new Uint8Array(readFileSync(join(dir, f))))) await w.addChunk(c); }
    catch { /* truncated tail */ }
  }
  await w.finish({});
  const r = await CaptureReader.open(store, `n${i}`);
  const { startMs, endMs } = r.manifest;
  const ts: number[] = [], vs: number[] = [];
  for (let d = startMs; d < endMs; d += DAY) {
    let s;
    try { s = await r.getSeries(EXPR, { from: d - DAY, to: d + DAY }); }
    catch (e) { console.log(`## ${node}: ${(e as Error).message}`); break; }
    s.t.forEach((t, k) => { if (t >= d && t < d + DAY) { ts.push(t); vs.push(s.mean[k]!); } });
  }
  const t = Float64Array.from(ts), v = Float64Array.from(vs);
  const xs = vs.filter(Number.isFinite).sort((a, b) => a - b);
  if (!xs.length) { console.log(`## ${node}: no window`); continue; }
  const h = (x: number) => (x / 3600).toFixed(1);
  const q = (p: number) => xs[Math.floor(p * (xs.length - 1))]!;
  const [u24, l24] = under(t, v, 24 * 3600);
  const [u1, l1] = under(t, v, 3600);
  console.log(`## ${node}  window h: min ${h(xs[0]!)} p1 ${h(q(0.01))} p50 ${h(q(0.5))} max ${h(xs.at(-1)!)}` +
    `  | <24h ${u24.toFixed(1)}h (longest ${l24.toFixed(1)}h)  <1h ${u1.toFixed(1)}h (longest ${l1.toFixed(2)}h)`);
}
