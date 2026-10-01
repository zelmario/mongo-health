/**
 * Which metrics a capture actually carries, for a list of patterns.
 *
 *   npx vite-node tools/has-metric.ts <ftdc dir> 'steal' 'Swap' 'oplog.*maxSize'
 *
 * Reads the first chunk of the newest file: enough to know the schema.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { decodeFTDC, readMetadata } from '../src/ftdc/index.js';

const [dir, ...patterns] = process.argv.slice(2);
const file = readdirSync(dir!).filter((n) => n.startsWith('metrics.2')).sort().at(-1)!;
const bytes = new Uint8Array(readFileSync(join(dir!, file)));
const meta = readMetadata(bytes);
const chunk = decodeFTDC(bytes, { maxChunks: 1 }).next().value!;
console.log(`# ${dir} · ${meta?.version} · ${chunk.keys.length} metrics`);
for (const p of patterns) {
  const re = new RegExp(p, 'i');
  const hits = chunk.keys.filter((k) => re.test(k));
  console.log(`\n## ${p} (${hits.length})`);
  for (const k of hits.slice(0, 12)) console.log(`  ${k}`);
  if (hits.length > 12) console.log(`  … ${hits.length - 12} more`);
}
