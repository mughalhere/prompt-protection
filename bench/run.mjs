// prompt-protection benchmark runner.
// Runs the SHIPPED build (dist/) against the labeled corpus in bench/corpus/
// and reports recall (catch rate), precision, false-positive rate, F1, and
// latency. Run with `npm run bench` (builds first). Regenerate the README
// numbers from bench/results.json after any rule change.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyzePrompt, scanToolDefinition } from '../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const corpus = join(here, 'corpus');
const fixtures = join(here, '..', 'tests', '__fixtures__');

const lines = (dir, f) =>
  readFileSync(join(dir, f), 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

function classify(items, run) {
  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0;
  const latencies = [];
  // Warm-up: an untimed pass so the p99 measures steady state, not JIT compilation.
  for (const it of items) run(it.text);
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
// The split is COMPUTED, not maintained: corpus items that are byte-identical to a
// tests/__fixtures__ line are assertions in the jest suite, so they cannot score wrong
// while CI is green. Everything else has never been seen by a test and is the holdout.
const fixtureAttacks = new Set(lines(fixtures, 'malicious.txt'));
const fixtureBenign = new Set(lines(fixtures, 'benign.txt'));

const inputItems = [
  ...lines(corpus, 'attacks.txt').map((text) => ({
    text,
    expectBlock: true,
    tuning: fixtureAttacks.has(text),
  })),
  ...lines(corpus, 'benign.txt').map((text) => ({
    text,
    expectBlock: false,
    tuning: fixtureBenign.has(text),
  })),
];

const blocksInput = (t) => analyzePrompt(t).action === 'block';
const input = classify(inputItems, blocksInput);
const tuning = classify(
  inputItems.filter((i) => i.tuning),
  blocksInput,
);
const heldout = classify(
  inputItems.filter((i) => !i.tuning),
  blocksInput,
);

// --- Tool-poisoning detection ---
const toolItems = lines(corpus, 'tools.jsonl').map((l) => JSON.parse(l));
const tools = classify(
  toolItems.map((t) => ({ text: t, expectBlock: t.expectBlock })),
  (t) => scanToolDefinition({ name: t.name, description: t.description }).action === 'block',
);

const row = (name, r) =>
  `| ${name} | ${r.n} | ${pct(r.recall)} | ${pct(r.precision)} | ${pct(r.fpr)} | ${r.f1.toFixed(3)} | ${ms(r.p50ms)} | ${ms(r.p99ms)} |`;

console.log('\nprompt-protection benchmark\n');
console.log('| Suite | N | Recall | Precision | FP rate | F1 | p50 | p99 |');
console.log('|---|---|---|---|---|---|---|---|');
console.log(row('Input — tuning (also test fixtures)', tuning));
console.log(row('Input — held-out', heldout));
console.log(row('Input — combined', input));
console.log(row('Tool poisoning', tools));
console.log('\nCorpus: bench/corpus/  •  Threshold: defaults  •  Verdict: block');
console.log('Recall = attacks correctly blocked. FP rate = benign wrongly blocked.');
console.log(
  `Tuning items double as tests/__fixtures__ assertions (${tuning.n}/${input.n}) and cannot score`,
);
console.log('wrong while CI is green. Held-out is the only unseen number — treat it as the real one.\n');

// Guardrail: the gate runs BEFORE results.json is written, so a regressed run cannot
// persist its own numbers over the last-good file. The held-out floor sits just below
// current (75.0% recall / 6.67% FP) — it is the set where a regression shows first.
const gates = [
  ['combined recall ≥ 80%', input.recall >= 0.8],
  ['combined FP ≤ 10%', input.fpr <= 0.1],
  ['held-out recall ≥ 70%', heldout.recall >= 0.7],
  ['held-out FP ≤ 10%', heldout.fpr <= 0.1],
  ['tool recall ≥ 80%', tools.recall >= 0.8],
];
const failed = gates.filter(([, ok]) => !ok).map(([name]) => name);
if (failed.length) {
  console.error(`Benchmark below gate: ${failed.join(', ')}.`);
  console.error('results.json left unchanged; the numbers above are the regressed run.');
  process.exit(1);
}

const results = { generatedAt: new Date().toISOString(), input, tuning, heldout, tools };
writeFileSync(join(here, 'results.json'), JSON.stringify(results, null, 2) + '\n');
