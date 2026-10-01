/**
 * Measure, on a real capture, the metrics behind each candidate rule of the coverage audit:
 * what values they actually take, so a threshold is chosen against data rather than guessed.
 *
 *   npx vite-node tools/measure-gaps.ts <cluster ftdc dir with one subdirectory per node>
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeFTDC, readMetadata } from '../src/ftdc/index.js';
import { NodeFileStore } from '../src/data/nodeFileStore.js';
import { CaptureWriter } from '../src/data/writer.js';
import { CaptureReader } from '../src/data/reader.js';

const EXPRESSIONS: Record<string, string> = {
  'cpu steal % of host': 'pct(rate(systemMetrics.cpu.steal_ms), systemMetrics.cpu.num_logical_cores) / 1000 * 100',
  'cpu iowait % of host': 'pct(rate(systemMetrics.cpu.iowait_ms), systemMetrics.cpu.num_logical_cores) / 1000 * 100',
  'swap used MB': '(systemMetrics.memory.SwapTotal_kb - systemMetrics.memory.SwapFree_kb) / 1048576',
  'swap pages in /s': 'rate(systemMetrics.vmstat.pswpin)',
  'swap pages out /s': 'rate(systemMetrics.vmstat.pswpout)',
  'root disk free %': 'pct(systemMetrics.mounts./.available, systemMetrics.mounts./.capacity)',
  'oplog MB': 'local.oplog.rs.stats.storageStats.maxSize / 1048576',
  'oplog inserted KB/s': 'rate(local.oplog.rs.stats.storageStats.wiredTiger.cursor.insert key and value bytes) / 1024',
  'user asserts /s': 'rate(serverStatus.asserts.user)',
  'regular asserts /s': 'rate(serverStatus.asserts.regular)',
  'txn aborted /s': 'rate(serverStatus.transactions.totalAborted)',
  'txn committed /s': 'rate(serverStatus.transactions.totalCommitted)',
  'tcmalloc free/allocated %': 'pct(serverStatus.tcmalloc.tcmalloc.pageheap_free_bytes, serverStatus.tcmalloc.generic.current_allocated_bytes)',
  'majority lag s': '(replSetGetStatus.optimes.appliedOpTime.ts - replSetGetStatus.optimes.lastCommittedOpTime.ts) / 1000',
  'tcp retrans /s': 'rate(systemMetrics.netstat.Tcp:RetransSegs)',
  'tcp out segs /s': 'rate(systemMetrics.netstat.Tcp:OutSegs)',
};

function stats(v: Float64Array): string {
  const xs = Array.from(v).filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (!xs.length) return '(no data)';
  const q = (p: number) => xs[Math.min(xs.length - 1, Math.floor(p * xs.length))]!;
  const f = (x: number) => (Math.abs(x) >= 100 ? x.toFixed(0) : x.toFixed(2));
  return `min ${f(xs[0]!)}  p50 ${f(q(0.5))}  p99 ${f(q(0.99))}  max ${f(xs[xs.length - 1]!)}  (n=${xs.length})`;
}

const root = process.argv[2]!;
const nodes = readdirSync(root).filter((n) => statSync(join(root, n)).isDirectory()).sort();
const tmp = await mkdtemp(join(tmpdir(), 'gaps-'));
const store = new NodeFileStore(tmp);
for (const [i, node] of nodes.entries()) {
  const dir = join(root, node);
  const files = readdirSync(dir).filter((n) => n.startsWith('metrics.')).sort();
  const w = await CaptureWriter.create(store, { captureId: `n${i}`, sourceFile: node });
  let dbPath: string | undefined;
  for (const f of files) {
    const bytes = new Uint8Array(readFileSync(join(dir, f)));
    dbPath ??= (readMetadata(bytes)?.doc as any)?.getCmdLineOpts?.parsed?.storage?.dbPath;
    try { for (const c of decodeFTDC(bytes)) await w.addChunk(c); } catch { /* truncated tail */ }
  }
  await w.finish({});
  const r = await CaptureReader.open(store, `n${i}`);
  console.log(`\n## ${node}  (dbPath ${dbPath ?? '?'})`);
  // The expression language takes rate() and pct(), not free arithmetic, so composites are
  // computed here from their parts.
  const get = async (e: string) => {
    try { return (await r.getSeries(e, {} as any)).mean; } catch { return null; }
  };
  const combine = (a: Float64Array | null, b: Float64Array | null, f: (x: number, y: number) => number) =>
    a && b ? Float64Array.from(a, (x, i) => f(x, b[i]!)) : null;
  const cores = await get('systemMetrics.cpu.num_logical_cores');
  const derived: Record<string, Float64Array | null> = {
    'cpu steal % of host': combine(await get('rate(systemMetrics.cpu.steal_ms)'), cores, (x, c) => x / (c * 10)),
    'cpu iowait % of host': combine(await get('rate(systemMetrics.cpu.iowait_ms)'), cores, (x, c) => x / (c * 10)),
    'swap used MB': combine(await get('systemMetrics.memory.SwapTotal_kb'), await get('systemMetrics.memory.SwapFree_kb'), (t, f) => (t - f) / 1048576),
    'oplog MB': (await get('local.oplog.rs.stats.storageStats.maxSize'))?.map((x) => x / 1048576) ?? null,
    'oplog inserted KB/s': (await get('rate(local.oplog.rs.stats.storageStats.wiredTiger.cursor.insert key and value bytes)'))?.map((x) => x / 1024) ?? null,
    'majority lag s': combine(await get('replSetGetStatus.optimes.appliedOpTime.ts'), await get('replSetGetStatus.optimes.lastCommittedOpTime.ts'), (a, c) => (a - c) / 1000),
  };
  const oplog = derived['oplog MB'], ins = derived['oplog inserted KB/s'];
  derived['oplog window h (at that rate)'] = combine(oplog, ins, (mb, kbs) => (kbs > 0 ? (mb * 1024) / kbs / 3600 : NaN));
  for (const [name, expr] of Object.entries(EXPRESSIONS)) {
    const s = name in derived ? derived[name] : await get(expr);
    console.log(`  ${name.padEnd(30)} ${s ? stats(s) : '(not resolvable)'}`);
  }
  console.log(`  ${'oplog window h (at that rate)'.padEnd(30)} ${derived['oplog window h (at that rate)'] ? stats(derived['oplog window h (at that rate)']!) : '(not resolvable)'}`);
  await r.close();
}
await rm(tmp, { recursive: true, force: true });
