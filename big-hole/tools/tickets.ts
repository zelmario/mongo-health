/**
 * Extrae la serie de tickets de ejecución de una captura y describe qué tan cerca
 * estuvo del agotamiento, para decidir si un umbral de regla es el correcto.
 *
 *   npx vite-node tools/tickets.ts -- <diagnostic.data> [...]
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';

import { decodeFTDC } from '../src/ftdc/index.js';

const targets = process.argv.slice(2).filter((a) => !a.startsWith('-'));
if (targets.length === 0) {
  console.error('usage: vite-node tools/tickets.ts -- <diagnostic.data dir> [...]');
  process.exit(1);
}

const PATHS = [
  'serverStatus.queues.execution.write.available',
  'serverStatus.queues.execution.write.out',
  'serverStatus.queues.execution.write.totalTickets',
  'serverStatus.queues.execution.read.available',
  'serverStatus.queues.execution.read.out',
  'serverStatus.queues.execution.read.totalTickets',
];

function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return NaN;
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p))]!;
}

for (const target of targets) {
  const files = readdirSync(target)
    .filter((n) => n.startsWith('metrics.') && !n.endsWith('.jsonl'))
    .sort()
    .map((n) => join(target, n));

  const series = new Map<string, number[]>(PATHS.map((p) => [p, []]));
  let samples = 0;

  for (const file of files) {
    if (!statSync(file).isFile()) continue;
    for (const chunk of decodeFTDC(new Uint8Array(readFileSync(file)))) {
      for (const path of PATHS) {
        const i = chunk.keys.indexOf(path);
        if (i >= 0) {
          const col = chunk.columns[i]!;
          const dest = series.get(path)!;
          for (let k = 0; k < col.length; k++) dest.push(col[k]!);
        }
      }
      samples += chunk.sampleCount;
    }
  }

  console.log(`\n=== ${basename(target.replace(/\/27017.*/, ''))} — ${samples} samples ===`);
  for (const kind of ['write', 'read'] as const) {
    const avail = series.get(`serverStatus.queues.execution.${kind}.available`) ?? [];
    const out = series.get(`serverStatus.queues.execution.${kind}.out`) ?? [];
    const total = series.get(`serverStatus.queues.execution.${kind}.totalTickets`) ?? [];
    if (avail.length === 0) {
      console.log(`  ${kind}: sin datos`);
      continue;
    }
    const sorted = [...avail].sort((a, b) => a - b);
    const zeros = avail.filter((v) => v === 0).length;
    const leq1 = avail.filter((v) => v <= 1).length;
    // Racha más larga en cero, en muestras (≈ segundos)
    let run = 0;
    let longest = 0;
    for (const v of avail) {
      run = v === 0 ? run + 1 : 0;
      if (run > longest) longest = run;
    }
    const tmin = Math.min(...total);
    const tmax = Math.max(...total);
    console.log(
      `  ${kind}: available min=${sorted[0]} p01=${pct(sorted, 0.01)} p50=${pct(sorted, 0.5)} · ` +
        `en 0: ${zeros} muestras (racha máx ${longest}s) · <=1: ${leq1} · ` +
        `totalTickets ${tmin}..${tmax} · out máx=${Math.max(...out)}`,
    );
  }
}

/* ---- ¿qué señal discrimina carga de reposo? Ventanas de 60 s sobre el nodo dado ---- */
if (process.env.WINDOWS === '1') {
  const target = targets[targets.length - 1]!;
  const files = readdirSync(target).filter((n) => n.startsWith('metrics.')).sort().map((n) => join(target, n));
  const avail: number[] = [], out: number[] = [], total: number[] = [];
  for (const f of files) {
    if (!statSync(f).isFile()) continue;
    for (const c of decodeFTDC(new Uint8Array(readFileSync(f)))) {
      const push = (p: string, dst: number[]) => {
        const i = c.keys.indexOf(p); if (i < 0) return;
        const col = c.columns[i]!; for (let k = 0; k < col.length; k++) dst.push(col[k]!);
      };
      push('serverStatus.queues.execution.read.available', avail);
      push('serverStatus.queues.execution.read.out', out);
      push('serverStatus.queues.execution.read.totalTickets', total);
    }
  }
  console.log('\n=== ventanas de 60 s (nodo saturado) — solo las que muestran algo ===');
  console.log('ventana │ %muestras avail=0 │ ratio out/total medio │ pico out/total');
  for (let w = 0; w + 60 <= avail.length; w += 60) {
    const a = avail.slice(w, w + 60), o = out.slice(w, w + 60), t = total.slice(w, w + 60);
    const zeroPct = Math.round((a.filter((v) => v === 0).length / a.length) * 100);
    const ratios = o.map((v, i) => (t[i]! > 0 ? v / t[i]! : 0));
    const mean = Math.round((ratios.reduce((s, v) => s + v, 0) / ratios.length) * 100);
    const peak = Math.round(Math.max(...ratios) * 100);
    if (zeroPct > 0 || mean > 20) console.log(`  ${String(w / 60).padStart(3)} │ ${String(zeroPct).padStart(3)}% │ ${String(mean).padStart(3)}% │ ${String(peak).padStart(3)}%`);
  }
}
