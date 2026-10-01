/**
 * The rules as data, for the catalog the collector publishes (collector/catalog.py).
 *
 *   npx vite-node tools/rule-catalog.ts > rules.json
 *
 * Every field comes from RULES itself, and the reasoning from the comment written above each
 * rule in rules.ts -- which is where every threshold is justified. Generating the catalog from
 * here rather than writing it by hand is what keeps it from drifting from what actually runs.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { RULES } from '../src/insights/rules.js';
import { ALARM_COUNTERS, PEER_METRICS, WATCHED_SETTINGS } from '../src/insights/events.js';

const source = readFileSync(fileURLToPath(new URL('../src/insights/rules.ts', import.meta.url)), 'utf8');

/** The comment lines inside a rule's object and directly above it, as prose. */
function reasoning(id: string): string {
  const at = source.indexOf(`id: '${id}'`);
  if (at < 0) return '';
  const open = source.lastIndexOf('{', at);
  // Comment lines above the opening brace, back to the previous rule or section divider.
  const before = source.slice(0, open).split('\n');
  const above: string[] = [];
  for (let i = before.length - 1; i >= 0; i--) {
    const line = before[i]!.trim();
    if (line.startsWith('//')) above.unshift(line.replace(/^\/\/\s?/, ''));
    else if (line === '' && above.length === 0) continue;
    else break;
  }
  // Comment lines inside the object, up to its closing brace.
  const close = source.indexOf('\n  },', at);
  const inside = source.slice(at, close).split('\n')
    .map((l) => l.trim()).filter((l) => l.startsWith('//')).map((l) => l.replace(/^\/\/\s?/, ''));
  return [...above, ...inside].join('\n').replace(/\n(?!\n)/g, ' ').replace(/ {2,}/g, ' ').trim();
}

const rules = RULES.map((r) => ({
  id: r.id, title: r.title, severity: r.severity, metric: r.metric, op: r.op,
  threshold: r.threshold, unit: r.unit, sustainMs: r.sustainMs, toleranceMs: r.toleranceMs ?? 0,
  echoesAnEvent: r.echoesAnEvent ?? false, alongside: (r as any).alongside ?? null,
  during: (r as any).during ?? null,
  what: r.what, check: r.check, reasoning: reasoning(r.id),
}));

// The event detectors watch lists rather than thresholds; what is on each list is the part a
// reader needs.
const events = {
  alarms: ALARM_COUNTERS.map((c: any) => ({ path: c.path, title: c.title })),
  settings: WATCHED_SETTINGS.map((s: any) => ({ path: s.path, title: s.title })),
  peers: PEER_METRICS.map((m: any) => ({ path: m.path, title: m.title })),
};

console.log(JSON.stringify({ rules, events }, null, 1));
