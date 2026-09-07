// prompt-protection benchmark runner.
// Runs the SHIPPED build (dist/) against the labeled corpus in bench/corpus/
// and reports recall (catch rate), precision, false-positive rate, F1, and
// latency. Run with `npm run bench` (builds first). Regenerate the README
// numbers from bench/results.json after any rule change.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyzePrompt, analyzeOutput, scanToolDefinition } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const corpus = join(here, 'corpus');

const lines = (f) =>
  readFileSync(join(corpus, f), 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

function classify(items, run) {
  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0;
  const latencies = [];
  for (const it of items) {
    const t0 = performance.now();
    const blocked = run(it.text);
    latencies.push(performance.now() - t0);
    if (it.expectBlock && blocked) tp++;
    else if (it.expectBlock && !blocked) fn++;
    else if (!it.expectBlock && blocked) fp++;
    else tn++;
  }
  latencies.sort((a, b) => a - b);
  const p = (q) => latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))] ?? 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const fpr = fp + tn ? fp / (fp + tn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return {
    n: items.length,
    tp,
    fp,
    tn,
    fn,
    recall,
    precision,
    fpr,
    f1,
    p50ms: p(0.5),
    p99ms: p(0.99),
  };
}

const pct = (x) => `${(x * 100).toFixed(1)}%`;
const ms = (x) => `${x.toFixed(3)} ms`;

// --- Input detection (prompt injection / jailbreak / exfiltration) ---
const inputItems = [
  ...lines('attacks.txt').map((text) => ({ text, expectBlock: true })),
  ...lines('benign.txt').map((text) => ({ text, expectBlock: false })),
];
const input = classify(inputItems, (t) => analyzePrompt(t).action === 'block');

// --- Tool-poisoning detection ---
const toolItems = lines('tools.jsonl').map((l) => JSON.parse(l));
const tools = classify(
  toolItems.map((t) => ({ text: t, expectBlock: t.expectBlock })),
  (t) => scanToolDefinition({ name: t.name, description: t.description }).action === 'block',
);

const results = { generatedAt: new Date().toISOString(), input, tools };
writeFileSync(join(here, 'results.json'), JSON.stringify(results, null, 2) + '\n');

const row = (name, r) =>
  `| ${name} | ${r.n} | ${pct(r.recall)} | ${pct(r.precision)} | ${pct(r.fpr)} | ${r.f1.toFixed(3)} | ${ms(r.p50ms)} | ${ms(r.p99ms)} |`;

console.log('\nprompt-protection benchmark\n');
console.log('| Suite | N | Recall | Precision | FP rate | F1 | p50 | p99 |');
console.log('|---|---|---|---|---|---|---|---|');
console.log(row('Input detection', input));
console.log(row('Tool poisoning', tools));
console.log('\nCorpus: bench/corpus/  •  Threshold: defaults  •  Verdict: block');
console.log('Recall = attacks correctly blocked. FP rate = benign wrongly blocked.\n');

// Guardrail: fail the run if recall collapses or FPs spike — usable as a CI gate.
const ok = input.recall >= 0.8 && input.fpr <= 0.1 && tools.recall >= 0.8;
if (!ok) {
  console.error('Benchmark below gate (input recall ≥80%, FP ≤10%, tool recall ≥80%).');
  process.exit(1);
}
