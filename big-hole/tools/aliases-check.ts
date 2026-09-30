/**
 * Check the alias table against real captures from the version matrix.
 *
 * An alias table is the kind of thing that rots quietly: a metric moves in a new release,
 * the panel goes blank, and nobody notices because a blank panel looks like an idle server.
 * This turns that into a failing check.
 *
 *   npx vite-node tools/aliases-check.ts -- sample-data/versions
 *
 * The directory holds one subdirectory per release, each with the `diagnostic.data` of a
 * mongod of that version -- produce it with tools/fixtures/versions.sh (Docker) or
 * tools/fixtures/versiones.py (downloads the official tarballs, no Docker required).
 *
 * Three outcomes per metric per version:
 *
 *   can / altN   resolved, via the canonical name or the Nth alternative
 *   n/a          the whole section is absent from that release -- the metric did not exist
 *                yet, which is information, not a bug
 *   ROTA         the section is there but no name in the table matches: the table is wrong
 *                or a rename was missed. This is the only failing case.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { decodeFTDC } from '../src/ftdc/index.js';
import { METRIC_ALIASES } from '../src/dashboard/aliases.js';

const raiz = process.argv.find((a, i) => i > 1 && !a.startsWith('--')) ?? 'sample-data/versions';

/**
 * Metrics that were *added* to a section that already existed.
 *
 * The parent-section test below cannot catch these: `local.oplog.rs.stats` is populated as
 * far back as 4.0, but `freeStorageSize` only appears in 4.4, so a 4.0 capture legitimately
 * lacks it. Rather than weaken the test for everything, the handful of known cases are
 * declared here with the release that introduced them. Anything not on this list that goes
 * missing while its section is present is a genuine failure.
 */
const DESDE: Readonly<Record<string, string>> = {
  'local.oplog.rs.stats.freeStorageSize': '4.4',
};

/** Compares "4.4" style releases numerically, so 10.0 would not sort before 4.4. */
function anterior(a: string, b: string): boolean {
  const [am, an] = a.split('.').map(Number) as [number, number];
  const [bm, bn] = b.split('.').map(Number) as [number, number];
  return am !== bm ? am < bm : an < bn;
}

/** Every metric name present in a release's capture. */
function catalogo(dir: string): Set<string> {
  const claves = new Set<string>();
  for (const archivo of readdirSync(dir)) {
    if (!archivo.startsWith('metrics.')) continue;
    try {
      for (const chunk of decodeFTDC(new Uint8Array(readFileSync(join(dir, archivo))))) {
        for (const k of chunk.keys) claves.add(k);
      }
    } catch (e) {
      console.error(`  aviso: ${dir}/${archivo}: ${(e as Error).message}`);
    }
  }
  return claves;
}

/**
 * Is the section this metric lives in present at all?
 *
 * Tests the metric's *immediate* parent, not some shorter prefix. The distinction matters:
 * `concurrentTransactions` exists as far back as 4.0, but the adaptive sizer's
 * `concurrentTransactions.monitor` only arrives in 7.0. Matching on the short prefix would
 * report every 4.0 capture as a broken table when the counters simply had not been invented.
 *
 * So: parent present but metric missing => the table is wrong. Parent absent => not
 * applicable to this release.
 */
function seccionPresente(path: string, claves: Set<string>): boolean {
  const padre = path.slice(0, path.lastIndexOf('.') + 1);
  if (padre === '') return false;
  for (const k of claves) if (k.startsWith(padre)) return true;
  return false;
}

const versiones = readdirSync(raiz)
  .filter((v) => statSync(join(raiz, v)).isDirectory())
  .sort();
if (versiones.length === 0) {
  console.error(`sin capturas en ${raiz} — corré tools/fixtures/versiones.py primero`);
  process.exit(2);
}

const catalogos = Object.fromEntries(versiones.map((v) => [v, catalogo(join(raiz, v))]));
for (const v of versiones) console.error(`${v}: ${catalogos[v]!.size} métricas`);
console.error('');

console.log('métrica'.padEnd(58) + versiones.map((v) => v.padStart(7)).join(''));
console.log('-'.repeat(58 + 7 * versiones.length));

const rotas: string[] = [];
for (const canonica of Object.keys(METRIC_ALIASES)) {
  const opciones = [canonica, ...METRIC_ALIASES[canonica]!];
  const fila = versiones.map((v) => {
    const claves = catalogos[v]!;
    const cual = opciones.findIndex((o) => claves.has(o));
    if (cual === 0) return '    can';
    if (cual > 0) return `   alt${cual}`;
    // Ninguna resolvió. No es un problema si la métrica todavía no existía en esta
    // release, ni si su sección entera está ausente.
    const nacimiento = DESDE[canonica];
    if (nacimiento !== undefined && anterior(v, nacimiento)) return '    n/a';
    if (opciones.some((o) => seccionPresente(o, claves))) {
      rotas.push(`${canonica} @ ${v}`);
      return '   ROTA';
    }
    return '    n/a';
  });
  const corto = canonica
    .replace('serverStatus.', 'sS.')
    .replace('local.oplog.rs.stats', 'oplog');
  console.log(corto.slice(0, 57).padEnd(58) + fila.join(''));
}

const total = Object.keys(METRIC_ALIASES).length;
console.log(`\n${total} métricas x ${versiones.length} versiones`);
if (rotas.length === 0) {
  console.log('todas resuelven donde su sección existe');
} else {
  console.log(`${rotas.length} sin resolver con la sección presente:`);
  for (const r of rotas) console.log(`   ${r}`);
  process.exit(1);
}
