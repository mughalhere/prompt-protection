// Re-samples bench/external/*.jsonl from the raw downloads produced by
// `make -C training fetch`. Seeded so the committed samples are reproducible.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const raw = join(here, '..', 'training', 'data', 'raw');
const out = join(here, 'external');

function rng(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}
function sample(arr, k, rand) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, k);
}
const read = (f) => readFileSync(join(raw, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const write = (f, rows) => writeFileSync(join(out, f), rows.map((r) => JSON.stringify(r)).join('\n') + '\n');

const notinject = read('notinject.jsonl').map((r) => ({ text: r.text, label: 0, source: 'leolee99/NotInject', split: r.split ?? '' }));
write('notinject.jsonl', notinject);

const wild = read('in_the_wild.jsonl');
const rand = rng(42);
const rows = [...sample(wild.filter((r) => r.label === 1), 300, rand), ...sample(wild.filter((r) => r.label === 0), 600, rand)].map((r) => ({
  text: r.text,
  label: r.label,
  source: 'TrustAIRLab/in-the-wild-jailbreak-prompts',
}));
write('in_the_wild.jsonl', rows);
console.log(`notinject ${notinject.length} rows, in_the_wild ${rows.length} rows`);
