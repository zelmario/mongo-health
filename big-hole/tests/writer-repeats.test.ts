/**
 * A metrics.interim that repeats the tail of the previous file must not send the clock back.
 * Seen on a real 7.0 replica set: all 161 interim samples of each node were already written.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DecodedChunk } from '../src/ftdc/types.js';
import { NodeFileStore } from '../src/data/nodeFileStore.js';
import { CaptureWriter } from '../src/data/writer.js';
import { CaptureReader } from '../src/data/reader.js';

/** One sample per second from `t0`, with uptime and a counter that tracks the clock. */
function chunk(t0: number, n: number): DecodedChunk {
  const t = new Float64Array(n);
  const up = new Float64Array(n);
  const ops = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    t[i] = t0 + i * 1000;
    up[i] = t[i]! - 1_000_000; // started at a fixed instant: never goes back
    ops[i] = i;
  }
  return {
    keys: ['start', 'serverStatus.uptimeMillis', 'serverStatus.opcounters.query'],
    types: ['datetime', 'int64', 'int64'] as DecodedChunk['types'],
    columns: [t, up, ops],
    sampleCount: n,
    startMs: t0,
  };
}

let dir: string;
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'writer-repeats-'));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('CaptureWriter with repeated samples', () => {
  it('drops a chunk whose samples are all already written, and the tail of one that overlaps', async () => {
    const store = new NodeFileStore(dir);
    const w = await CaptureWriter.create(store, { captureId: 'c', sourceFile: 'x' });
    const T = 1_750_000_000_000;
    await w.addChunk(chunk(T, 300)); // the numbered file
    await w.addChunk(chunk(T + 139_000, 161)); // the interim: wholly inside it
    await w.addChunk(chunk(T + 250_000, 100)); // overlaps 50 samples, adds 50
    const m = await w.finish();

    expect(m.sampleCount).toBe(350);
    expect(m.endMs).toBe(T + 349_000);
    expect(m.restarts).toEqual([]);
    expect(m.gaps).toEqual([]);

    const r = await CaptureReader.open(store, 'c');
    const s = await r.getSeries('start');
    const t = Array.from(s.mean);
    for (let i = 1; i < t.length; i++) expect(t[i]!).toBeGreaterThan(t[i - 1]!);
    // A window read lands on the same samples however the search splits.
    const win = await r.getSeries('start', { from: T + 200_000, to: T + 299_000 });
    expect(win.mean.length).toBe(100);
    await r.close();
  });
});
