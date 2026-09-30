/**
 * Medir métricas candidatas sobre capturas reales, antes de escribir una regla con ellas.
 *
 * Un umbral elegido de memoria es una regla que no dispara nunca o que dispara siempre, y
 * las dos fallas se ven igual desde afuera: silencio. Esto imprime la distribución de cada
 * candidata por ventanas, para poder elegir el corte mirando la separación entre "el cluster
 * estaba bien" y "el cluster estaba mal" en vez de suponerla.
 *
 *   npx vite-node tools/calibrar.ts -- <dir-con-un-subdir-por-nodo> [--ventana 60]
 *
 * Es el mismo papel que cumplió tools/tickets.ts cuando hubo que recalibrar las reglas de
 * tickets para 8.0; esta es la versión general.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { decodeFTDC, readMetadata } from '../src/ftdc/index.js';
import { NodeFileStore } from '../src/data/nodeFileStore.js';
import { CaptureWriter } from '../src/data/writer.js';
import { CaptureReader } from '../src/data/reader.js';
import { detectRolePrefixes, expandMetric } from '../src/dashboard/layout.js';

const argv = process.argv.slice(2);
const raiz = argv.find((a) => !a.startsWith('--'));
if (raiz === undefined) {
  console.error('uso: vite-node tools/calibrar.ts -- <dir-del-cluster> [--ventana 60]');
  process.exit(1);
}
const VENTANA_S = argv.includes('--ventana') ? Number(argv[argv.indexOf('--ventana') + 1]) : 60;

/**
 * Las candidatas, escritas como las escribiría una regla.
 *
 * Nombradas con la ruta más vieja que exista, para que la tabla de alias las resuelva en
 * todo el rango 4.0–8.0.
 */
const CANDIDATAS: Array<{ id: string; expr: string; nota: string }> = [
  {
    id: 'scan-ratio',
    expr: 'pct(rate(serverStatus.metrics.queryExecutor.scannedObjects), rate(serverStatus.metrics.document.returned))',
    nota: 'documentos escaneados por documento devuelto — falta de índice',
  },
  {
    id: 'conexiones',
    expr: 'pct(serverStatus.connections.current, serverStatus.connections.available)',
    nota: 'uso del pool de conexiones',
  },
  {
    id: 'checkpoint-ms',
    expr: 'serverStatus.wiredTiger.transaction.transaction checkpoint most recent time (msecs)',
    nota: 'duración del último checkpoint',
  },
  {
    id: 'repl-buffer',
    expr: 'serverStatus.metrics.repl.buffer.sizeBytes',
    nota: 'oplog recibido sin aplicar',
  },
  {
    id: 'mem-disponible-mb',
    expr: 'scale(systemMetrics.memory.MemAvailable_kb, 0.001)',
    nota: 'memoria libre del host',
  },
  {
    id: 'iowait',
    expr: 'rate(systemMetrics.cpu.iowait_ms)',
    nota: 'espera de disco',
  },
  {
    id: 'cache-dirty-pct',
    expr: 'pct(serverStatus.wiredTiger.cache.tracked dirty bytes in the cache, serverStatus.wiredTiger.cache.maximum bytes configured)',
    nota: 'referencia: ya existe regla al 20%',
  },
  {
    id: 'tickets-read-pct',
    expr: 'pct(serverStatus.wiredTiger.concurrentTransactions.read.out, serverStatus.wiredTiger.concurrentTransactions.read.totalTickets)',
    nota: 'referencia: ya existe regla al 50%',
  },
];

function percentil(ord: number[], p: number): number {
  if (ord.length === 0) return NaN;
  return ord[Math.min(ord.length - 1, Math.floor((ord.length - 1) * p))]!;
}

const dir = await mkdtemp(join(tmpdir(), 'calibrar-'));
const store = new NodeFileStore(dir);
const lectores: CaptureReader[] = [];

try {
  const nodos = readdirSync(raiz).filter((n) => statSync(join(raiz, n)).isDirectory()).sort();

  for (let i = 0; i < nodos.length; i++) {
    const nodo = nodos[i]!;
    const archivos = readdirSync(join(raiz, nodo))
      .filter((n) => n.startsWith('metrics.') && !n.includes(':'))
      .sort();
    if (archivos.length === 0) continue;

    const writer = await CaptureWriter.create(store, { captureId: `n${i}`, sourceFile: nodo });
    let hostname: string | undefined;
    for (const a of archivos) {
      const bytes = new Uint8Array(readFileSync(join(raiz, nodo, a)));
      if (hostname === undefined) {
        try { hostname = readMetadata(bytes)?.hostname; } catch { /* opcional */ }
      }
      try { for (const c of decodeFTDC(bytes)) await writer.addChunk(c); } catch { /* parcial */ }
    }
    await writer.finish(hostname !== undefined ? { hostname } : {});
    const reader = await CaptureReader.open(store, `n${i}`);
    lectores.push(reader);

    const paths = new Set(reader.catalog.map((c) => c.path));
    const prefijos = detectRolePrefixes(paths);

    console.log(`\n${'='.repeat(96)}`);
    console.log(hostname ?? nodo);
    console.log('='.repeat(96));
    console.log(
      'candidata'.padEnd(20) + ['p50', 'p90', 'p99', 'max'].map((s) => s.padStart(11)).join('') +
        '   ventanas de ' + VENTANA_S + 's sobre el umbral',
    );

    for (const cand of CANDIDATAS) {
      const opciones = expandMetric(cand.expr, paths, prefijos);
      if (opciones.length === 0) {
        console.log(`${cand.id.padEnd(20)}${'—  no resuelve en esta captura'.padStart(20)}`);
        continue;
      }
      let serie;
      try {
        serie = await reader.getSeries(opciones[0]!, {});
      } catch (e) {
        console.log(`${cand.id.padEnd(20)}   error: ${(e as Error).message.slice(0, 50)}`);
        continue;
      }

      const vals = Array.from(serie.mean).filter((v) => Number.isFinite(v));
      if (vals.length === 0) {
        console.log(`${cand.id.padEnd(20)}   sin valores finitos`);
        continue;
      }
      const ord = [...vals].sort((a, b) => a - b);
      const fmt = (v: number) => (v >= 1000 ? v.toExponential(2) : v.toFixed(2)).padStart(11);

      // Cuántas ventanas de VENTANA_S segundos pasarían un umbral candidato. Es lo que
      // decide si una regla va a disparar una vez por incidente o cien veces por hora.
      const porVentana: number[] = [];
      const ancho = VENTANA_S;
      for (let k = 0; k + ancho <= vals.length; k += ancho) {
        const trozo = vals.slice(k, k + ancho);
        porVentana.push(trozo.reduce((s, v) => s + v, 0) / trozo.length);
      }
      const cortes = [percentil(ord, 0.9), percentil(ord, 0.99)];
      const sobre = cortes
        .map((c) => `${porVentana.filter((m) => m >= c).length}/${porVentana.length}@${c.toFixed(1)}`)
        .join('  ');

      console.log(
        cand.id.padEnd(20) +
          fmt(percentil(ord, 0.5)) + fmt(percentil(ord, 0.9)) +
          fmt(percentil(ord, 0.99)) + fmt(ord[ord.length - 1]!) +
          '   ' + sobre,
      );
    }
  }
} finally {
  for (const r of lectores) await r.close?.();
  await rm(dir, { recursive: true, force: true });
}
